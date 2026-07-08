/*
 * MsQuic client: dial, build the session, request the WebTransport
 * CONNECT (deferred inside the engine until the peer's SETTINGS prove
 * support), and start the connection.
 *
 * Everything here runs on the application thread BEFORE ConnectionStart
 * — no event can fire until then, so the bring-up needs no locking. The
 * per-connection Configuration is closed right after ConnectionStart:
 * the start operation holds its own reference.
 */

#include <stddef.h>
#include <string.h>

#include "msq_internal.h"

void wtq_msquic_client_cfg_init_ex(wtq_msquic_client_cfg_t *cfg,
                                   size_t struct_size)
{
    static const wtq_msquic_client_cfg_t def = WTQ_MSQUIC_CLIENT_CFG_INIT;
    size_t n = struct_size < sizeof(def) ? struct_size : sizeof(def);

    if (cfg == NULL)
        return;
    memcpy(cfg, &def, n);
    /* Record what was actually initialised, so a smaller (older) object
     * never claims to carry tail fields it has no room for. */
    if (n >= sizeof(cfg->struct_size))
        cfg->struct_size = (uint32_t)n;
}

/* ABI-frozen entry: initialises ONLY the pre-managed-domain prefix, so an
 * old binary that linked this symbol against the smaller struct is never
 * written past its object. New source reaches the current-size path through
 * the header macro (-> _ex with sizeof *cfg). */
#undef wtq_msquic_client_cfg_init
void wtq_msquic_client_cfg_init(wtq_msquic_client_cfg_t *cfg)
{
    wtq_msquic_client_cfg_init_ex(cfg, sizeof(wtq_msquic_client_cfg_v1_t));
}

/* Copy a struct_size-prefixed config into a full-size zeroed local. */
static void cfg_copy(void *dst, size_t dst_size, const void *src,
                     uint32_t src_size)
{
    size_t n = src_size < dst_size ? src_size : dst_size;

    memset(dst, 0, dst_size);
    memcpy(dst, src, n);
}

wtq_result_t wtq_msquic_client_connect(wtq_msquic_env_t *env,
                                       const wtq_msquic_client_cfg_t *cfg_in,
                                       wtq_session_t **session_out)
{
    if (session_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *session_out = NULL;
    if (env == NULL || cfg_in == NULL)
        return WTQ_ERR_INVALID_ARG;
    /* Require the COMPLETE frozen v1 prefix (through `user`). A shorter
     * struct_size could leave a required field — a pointer among them —
     * half-copied, and a truncated pointer must never reach validation, let
     * alone use. Uses the frozen v1 size, not offsetof of the current tail. */
    if (cfg_in->struct_size < sizeof(wtq_msquic_client_cfg_v1_t))
        return WTQ_ERR_INVALID_ARG;

    wtq_msquic_client_cfg_t cfg;
    cfg_copy(&cfg, sizeof(cfg), cfg_in, cfg_in->struct_size);
    /* Honour each optional tail field only when it is WHOLLY present; a
     * struct_size landing mid-field is treated as absent so a partial
     * guard/callback pointer can never be dispatched through. Clear the guard
     * with TYPED NULL assignments, not memset: an all-zero-bytes struct is not
     * guaranteed to be an all-NULL guard on every target. */
    if (!wtq_cfg_has(cfg_in->struct_size,
                     offsetof(wtq_msquic_client_cfg_t, guard),
                     sizeof(cfg.guard))) {
        cfg.guard.enter = NULL;
        cfg.guard.leave = NULL;
        cfg.guard.ctx = NULL;
    }
    if (!wtq_cfg_has(cfg_in->struct_size,
                     offsetof(wtq_msquic_client_cfg_t, on_transport_quiesced),
                     sizeof(cfg.on_transport_quiesced)))
        cfg.on_transport_quiesced = NULL;

    if (cfg.server_name == NULL || cfg.port == 0 || cfg.connect == NULL ||
        cfg.events == NULL || cfg.events->struct_size == 0)
        return WTQ_ERR_INVALID_ARG;
    /* A guard's enter/leave are both-or-neither. */
    if ((cfg.guard.enter != NULL) != (cfg.guard.leave != NULL))
        return WTQ_ERR_INVALID_ARG;

    struct wtq_driver *drv =
        wtq_msq_conn_new(&env->alloc, env->api, true);
    if (drv == NULL)
        return WTQ_ERR_NOMEM;

    /* Managed-domain wiring, installed BEFORE ConnectionOpen so the guard
     * is in place before any event can fire: a caller holding guard.ctx
     * across this whole call publishes its handle before a callback that
     * began at ConnectionStart proceeds. cfg is a size-checked local, so
     * these are NULL for a legacy (smaller-struct) caller. */
    drv->guard = cfg.guard;
    drv->on_transport_quiesced = cfg.on_transport_quiesced;
    drv->quiesced_user = cfg.user;

    /* client Configuration: ALPN h3, tuning-derived settings, creds */
    QUIC_SETTINGS qs;
    wtq_msq_settings_init(&qs, &env->tuning);
    QUIC_BUFFER alpn = { 2, (uint8_t *)"h3" };
    HQUIC config = NULL;
    if (QUIC_FAILED(env->api->ConfigurationOpen(
            env->registration, &alpn, 1, &qs, sizeof(qs), NULL,
            &config))) {
        wtq_msq_conn_free(drv);
        return WTQ_ERR_BACKEND;
    }
    QUIC_CREDENTIAL_CONFIG cred;
    memset(&cred, 0, sizeof(cred));
    cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (cfg.insecure_skip_verify)
        cred.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    if (QUIC_FAILED(env->api->ConfigurationLoadCredential(config,
                                                          &cred))) {
        env->api->ConfigurationClose(config);
        wtq_msq_conn_free(drv);
        return WTQ_ERR_BACKEND;
    }

    if (QUIC_FAILED(env->api->ConnectionOpen(env->registration,
                                             wtq_msq_conn_callback, drv,
                                             &drv->conn))) {
        env->api->ConfigurationClose(config);
        drv->conn = NULL;
        wtq_msq_conn_free(drv);
        return WTQ_ERR_BACKEND;
    }

    wtq_api_session_cfg_t scfg = {
        .alloc = &env->alloc,
        .perspective = WTQ_PERSPECTIVE_CLIENT,
        .events = cfg.events,
        .user = cfg.user,
        .drv = drv,
        .ops = wtq_msq_driver_ops(),
    };
    wtq_session_t *session = NULL;
    wtq_result_t rc = wtq_api_session_create(&scfg, &session);
    if (rc == WTQ_OK)
        rc = wtq_api_session_connect(session, cfg.connect);
    if (rc != WTQ_OK) {
        if (session != NULL)
            wtq_session_release(session);
        env->api->ConfigurationClose(config);
        /* opened but never started/published: ConnectionClose delivers a
         * synchronous SHUTDOWN_COMPLETE, so free it via the abandon path — a
         * plain wtq_msq_conn_free() here would deadlock a guard-holding caller
         * (or double-free without the guard) on the re-entrant callback */
        wtq_msq_conn_abandon(drv);
        return rc;
    }

    drv->session = session;        /* the backend's reference */
    wtq_session_add_ref(session);  /* the caller's reference */

    /* Register and start under the environment lock: either this
     * connection is on the list before env_close snapshots it (and
     * gets shut down + waited for), or env_close latched first and the
     * registration is refused — a started-but-untracked connection can
     * never exist. ConnectionStart is asynchronous (never blocks), so
     * holding the lock across it is safe. */
    pthread_mutex_lock(&env->mu);
    QUIC_STATUS status;
    bool refused = false;
    if (env->closing) {
        status = QUIC_STATUS_ABORTED;
        refused = true;
    } else {
        drv->env = env;
        drv->env_prev = NULL;
        drv->env_next = env->conns;
        if (env->conns != NULL)
            env->conns->env_prev = drv;
        env->conns = drv;
        env->conn_count++;
        /* events may fire the moment this is called */
        status = env->api->ConnectionStart(drv->conn, config,
                                           QUIC_ADDRESS_FAMILY_UNSPEC,
                                           cfg.server_name, cfg.port);
        if (QUIC_FAILED(status)) {
            /* a synchronous failure means the start was never queued,
             * so no event has or will fire — unlink while still under
             * the lock, then unwind single-threadedly */
            env->conns = drv->env_next;
            if (drv->env_next != NULL)
                drv->env_next->env_prev = NULL;
            env->conn_count--;
            drv->env = NULL;
            drv->env_next = NULL;
        }
    }
    pthread_mutex_unlock(&env->mu);

    if (QUIC_FAILED(status)) {
        env->api->ConfigurationClose(config);
        drv->session = NULL;
        wtq_session_release(session); /* the caller's ref */
        wtq_session_release(session); /* the backend's ref (destroys) */
        /* session detached above; discard the opened connection via the
         * abandon path so the synchronous close-time SHUTDOWN_COMPLETE neither
         * deadlocks a guard-holding caller nor double-frees the driver */
        wtq_msq_conn_abandon(drv);
        return refused ? WTQ_ERR_CLOSED : WTQ_ERR_BACKEND;
    }
    /* the queued start holds its own Configuration reference */
    env->api->ConfigurationClose(config);

    *session_out = session;
    return WTQ_OK;
}
