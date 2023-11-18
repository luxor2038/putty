
#include <string.h>
#include <errno.h>

#include "putty.h"
#include "storage.h"
#include "misc.h"
#include "ssh.h"
#include "ssh/channel.h"
#include "portfwd.h"

typedef struct portfwd_connection portfwd_connection;

struct portfwd_state {
    PortFwdManager *portfwdmgr;

    int connections;
    unsigned long last_time;
    unsigned long idle_timeout;

    ConnectionLayer cl;
    Conf * conf;

    Seat *seat;
    LogContext *logctx;
};

struct portfwd_connection {
    portfwd_state *ps;
    Channel *chan;
    char *host, *realhost;
    int port;
    SockAddr *addr;
    Socket *socket;
    bool connecting, eof_pfmgr_to_socket, eof_socket_to_pfmgr;

    /* for interaction with the Seat */
    Interactor *clientitr;
    LogPolicy *clientlp;
    Seat *clientseat;

    Plug plug;
    SshChannel sc;
    Interactor interactor;
};

static SshChannel *portfwd_lportfwd_open(
    ConnectionLayer *cl, const char *hostname, int port,
    const char *description, const SocketPeerInfo *pi, Channel *chan);

static const ConnectionLayerVtable portfwd_clvt = {
    .lportfwd_open = portfwd_lportfwd_open,
    /* everything else is NULL */
};

static void portfwd_conn_free(portfwd_connection *conn);

static size_t portfwd_sc_write(SshChannel *sc, bool is_stderr,
                              const void *data, size_t len)
{
    portfwd_connection *conn = container_of(sc, portfwd_connection, sc);
    if (!conn->socket) return 0;

    return sk_write(conn->socket, data, len);
}

static void portfwd_check_close(void *vctx)
{
    portfwd_connection *conn = (portfwd_connection *)vctx;
    portfwd_conn_free(conn);
}

static void portfwd_sc_write_eof(SshChannel *sc)
{
    portfwd_connection *conn = container_of(sc, portfwd_connection, sc);
    if (!conn->socket) return;
    sk_write_eof(conn->socket);
    conn->eof_pfmgr_to_socket = true;

    queue_toplevel_callback(portfwd_check_close, conn);
}

static void portfwd_sc_initiate_close(SshChannel *sc, const char *err)
{
    portfwd_connection *conn = container_of(sc, portfwd_connection, sc);
    if(conn->socket) {
        sk_close(conn->socket);
        conn->socket = NULL;
        conn->eof_pfmgr_to_socket = true;

        queue_toplevel_callback(portfwd_check_close, conn);
    }
}

static void portfwd_sc_unthrottle(SshChannel *sc, size_t bufsize)
{
    portfwd_connection *conn = container_of(sc, portfwd_connection, sc);
}

static const SshChannelVtable portfwd_scvt = {
    .write = portfwd_sc_write,
    .write_eof = portfwd_sc_write_eof,
    .initiate_close = portfwd_sc_initiate_close,
    .unthrottle = portfwd_sc_unthrottle,
    /* all the rest are NULL */
};


static void portfwd_plug_log(Plug *plug, PlugLogType type, SockAddr *addr,
                            int port, const char *error_msg, int error_code)
{
    portfwd_connection *conn = container_of(plug, portfwd_connection, plug);

    switch (type) {
      case PLUGLOG_CONNECT_TRYING:
        break;
      case PLUGLOG_CONNECT_FAILED:
        break;
      case PLUGLOG_CONNECT_SUCCESS:
        if (conn->connecting) {
            chan_open_confirmation(conn->chan);
            conn->connecting = false;
        }
        break;
      case PLUGLOG_PROXY_MSG:
        break;
    };
}

static void portfwd_plug_closing(Plug *plug, PlugCloseType type,
                                const char *error_msg)
{
    portfwd_connection *conn = container_of(plug, portfwd_connection, plug);
    if (conn->connecting) {

        chan_open_failed(conn->chan, error_msg);
        conn->eof_socket_to_pfmgr = true;
        conn->eof_pfmgr_to_socket = true;
        conn->connecting = false;
    } else {

        chan_send_eof(conn->chan);
        conn->eof_socket_to_pfmgr = true;
    }
    queue_toplevel_callback(portfwd_check_close, conn);
}

static void portfwd_plug_receive(Plug *plug, int urgent,
                                const char *data, size_t len)
{
    portfwd_connection *conn = container_of(plug, portfwd_connection, plug);
    size_t bufsize = chan_send(conn->chan, false, data, len);
}

static void portfwd_plug_sent(Plug *plug, size_t bufsize)
{
    portfwd_connection *conn = container_of(plug, portfwd_connection, plug);
}

static char *portfwd_description(Interactor *itr)
{
    portfwd_connection *conn = container_of(itr, portfwd_connection, interactor);

    return dupprintf("portfwd connection to %s port %d", conn->host, conn->port);
}

static LogPolicy *portfwd_logpolicy(Interactor *itr)
{
    portfwd_connection *conn = container_of(itr, portfwd_connection, interactor);
    return log_get_policy(conn->ps->logctx);
}

static Seat *portfwd_get_seat(Interactor *itr)
{
    portfwd_connection *conn = container_of(itr, portfwd_connection, interactor);
    return conn->ps->seat;
}

static void portfwd_set_seat(Interactor *itr, Seat *seat)
{
    portfwd_connection *conn = container_of(itr, portfwd_connection, interactor);
    conn->ps->seat = seat;
}

static const InteractorVtable Portfwd_interactorvt = {
    .description = portfwd_description,
    .logpolicy = portfwd_logpolicy,
    .get_seat = portfwd_get_seat,
    .set_seat = portfwd_set_seat,
};


static const PlugVtable portfwd_plugvt = {
    .log = portfwd_plug_log,
    .closing = portfwd_plug_closing,
    .receive = portfwd_plug_receive,
    .sent = portfwd_plug_sent,
};

static void portfwd_connection_establish(void *vctx);

static SshChannel *portfwd_lportfwd_open(
    ConnectionLayer *cl, const char *hostname, int port,
    const char *description, const SocketPeerInfo *pi, Channel *chan)
{
    portfwd_state *ps = container_of(cl, portfwd_state, cl);
    portfwd_connection *conn = snew(portfwd_connection);
    memset(conn, 0, sizeof(*conn));
    conn->ps = ps;
    conn->sc.vt = &portfwd_scvt;
    conn->plug.vt = &portfwd_plugvt;
    conn->interactor.vt = &Portfwd_interactorvt;
    conn->chan = chan;
    conn->host = dupstr(hostname);
    conn->port = port;

    ps->connections++;
    ps->last_time = GETTICKCOUNT();

    queue_toplevel_callback(portfwd_connection_establish, conn);
    return &conn->sc;
}

static void portfwd_conn_free(portfwd_connection *conn)
{
    conn->ps->connections--;
    conn->ps->last_time = GETTICKCOUNT();

    sfree(conn->host);
    sfree(conn->realhost);
    if (conn->socket)
        sk_close(conn->socket);
    if (conn->chan)
        chan_free(conn->chan);
    delete_callbacks_for_context(conn);
    sfree(conn);
}

static void portfwd_connection_establish(void *vctx)
{
    portfwd_connection *conn = (portfwd_connection *)vctx;
    /*
     * Look up destination host name.
     */
    int addressfamily = conf_get_int(conn->ps->conf, CONF_addressfamily);

    conn->addr = name_lookup(conn->host, conn->port, &conn->realhost, 
                             conn->ps->conf, addressfamily, conn->ps->logctx, 
                             "Portfwd connection");

    const char *err = sk_addr_error(conn->addr);
    if (err) {
        char *msg = dupprintf("name lookup failed: %s", err);
        chan_open_failed(conn->chan, msg);
        sfree(msg);

        portfwd_conn_free(conn);
        return;
    }

    /*
     * Make the connection.
     */
    conn->connecting = true;
    conn->socket = new_connection(conn->addr, conn->realhost, conn->port,
                           false, true, false, false, &conn->plug, 
                           conn->ps->conf, &conn->interactor);
}


portfwd_state *portfwd_new(Seat *seat, LogContext *logctx, Conf * conf, unsigned long idle_timeout)
{
    portfwd_state *ps = snew(portfwd_state);
    memset(ps, 0, sizeof(*ps));

    ps->cl.vt = &portfwd_clvt;
    ps->portfwdmgr = portfwdmgr_new(&ps->cl);
    ps->conf = conf;
    ps->idle_timeout = idle_timeout;
    ps->seat = seat;
    ps->logctx = logctx;

    return ps;
}

void portfwd_free(portfwd_state *ps)
{
    portfwdmgr_free(ps->portfwdmgr);
    sfree(ps);
}

static void portfwd_idle_check(void *ctx, unsigned long now)
{
    portfwd_state *ps = (portfwd_state *)ctx;

    if(!ps->connections) {
        if((now - ps->last_time) >= ps->idle_timeout) {
            portfwdmgr_close_all(ps->portfwdmgr);
            cleanup_exit(0);
            return;
        }
    }

    schedule_timer(TICKSPERSEC*10, portfwd_idle_check, ps);
}

void portfwd_start(portfwd_state *ps)
{
    ps->last_time = GETTICKCOUNT();

    if(ps->idle_timeout) {
        schedule_timer(TICKSPERSEC*10, portfwd_idle_check, ps);
    }

    portfwdmgr_config(ps->portfwdmgr, ps->conf);
}

