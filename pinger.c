/*
 * pinger.c: centralised module that deals with sending SS_PING
 * keepalives, to avoid replicating this code in multiple backends.
 */

#include "putty.h"
#if SSH
#include "ssh.h"
#endif

struct Pinger {
    int interval;
    int keepalive_max;
    int keepalive_count;
    bool pending;
    unsigned long when_set, next;
    Backend *backend;
};

static void pinger_schedule(Pinger *pinger);

static void pinger_timer(void *ctx, unsigned long now)
{
    Pinger *pinger = (Pinger *)ctx;

    if (pinger->pending && now == pinger->next) {
#if SSH
        if((pinger->keepalive_max > 0) && (pinger->keepalive_count-- < 0)) {
            Ssh *ssh = ssh_get_ssh(pinger->backend);
            ssh_remote_error(ssh, "Timeout, server not responding");
            return;
        }
#endif
        backend_special(pinger->backend, SS_PING, pinger->keepalive_max);
        pinger->pending = false;
        pinger_schedule(pinger);
    }
}

static void pinger_schedule(Pinger *pinger)
{
    unsigned long next;

    if (!pinger->interval) {
        pinger->pending = false;       /* cancel any pending ping */
        return;
    }

    next = schedule_timer(pinger->interval * TICKSPERSEC,
                          pinger_timer, pinger);
    if (!pinger->pending ||
        (next - pinger->when_set) < (pinger->next - pinger->when_set)) {
        pinger->next = next;
        pinger->when_set = timing_last_clock();
        pinger->pending = true;
    }
}

Pinger *pinger_new(Conf *conf, Backend *backend)
{
    Pinger *pinger = snew(Pinger);

    pinger->keepalive_max = 0;
    if(backend->vt->protocol == PROT_SSH) {
        pinger->keepalive_max = conf_get_int(conf, CONF_ping_keepalive_max);
    }
    pinger->keepalive_count = pinger->keepalive_max;
    pinger->interval = conf_get_int(conf, CONF_ping_interval);
    pinger->pending = false;
    pinger->backend = backend;
    pinger_schedule(pinger);

    return pinger;
}

void pinger_reconfig(Pinger *pinger, Conf *oldconf, Conf *newconf)
{
    int newinterval = conf_get_int(newconf, CONF_ping_interval);
    if (conf_get_int(oldconf, CONF_ping_interval) != newinterval) {
        pinger->interval = newinterval;
        pinger_schedule(pinger);
    }
}

void pinger_free(Pinger *pinger)
{
    expire_timer_context(pinger);
    sfree(pinger);
}

void pinger_reset_keepalive(Pinger *pinger)
{
    pinger->keepalive_count = pinger->keepalive_max;
}
