typedef struct portfwd_state portfwd_state;

portfwd_state *portfwd_new(Seat *seat, LogContext *logctx, Conf * conf, unsigned long idle_timeout);
void portfwd_free(portfwd_state *ps);
void portfwd_start(portfwd_state *ps);
