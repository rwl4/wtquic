/*
 * MsQuic listener: owns the server Configuration (certificate loaded)
 * and a deep copy of the accept policy; each accepted connection gets
 * its own backend connection + session built inside the NEW_CONNECTION
 * callback.
 *
 * Rejecting an accept = return a failure status WITHOUT ConnectionClose
 * (MsQuic owns an unaccepted connection and closes it itself; it also
 * guarantees no event ever reaches a handler set before a failure
 * return).
 */

#include <string.h>

#include "msq_internal.h"

#ifdef WTQ_MSQ_TESTING
_Atomic int wtq_msq_test_fail_set_configuration;
#endif

void wtq_msquic_listener_cfg_init(wtq_msquic_listener_cfg_t *cfg)
{
    static const wtq_msquic_listener_cfg_t def =
        WTQ_MSQUIC_LISTENER_CFG_INIT;

    if (cfg != NULL)
        *cfg = def;
}

/* Copy a struct_size-prefixed config into a full-size zeroed local. */
static void cfg_copy(void *dst, size_t dst_size, const void *src,
                     uint32_t src_size)
{
    size_t n = src_size < dst_size ? src_size : dst_size;

    memset(dst, 0, dst_size);
    memcpy(dst, src, n);
}

/* Deep-copy the accept policy into listener-owned storage, enforcing
 * the same bounds the engine applies at serve time so a bad table
 * fails here, not on the first accept. */
static wtq_result_t copy_paths(struct wtq_msquic_listener *l,
                               const wtq_serve_config_t *paths,
                               size_t count)
{
    if (count == 0 || count > WTQ_MSQ_MAX_PATHS || paths == NULL)
        return WTQ_ERR_INVALID_ARG;

    for (size_t i = 0; i < count; i++) {
        if (paths[i].struct_size == 0)
            return WTQ_ERR_INVALID_ARG;
        wtq_serve_config_t p;
        cfg_copy(&p, sizeof(p), &paths[i], paths[i].struct_size);
        if (p.path == NULL ||
            (p.subprotocol_count > 0 && p.subprotocols == NULL))
            return WTQ_ERR_INVALID_ARG;

        size_t plen = strlen(p.path);
        if (plen == 0 || plen > WTQ_MSQ_PATH_CAP ||
            p.subprotocol_count > WTQ_MSQ_MAX_PROTOS)
            return WTQ_ERR_TOO_LARGE;

        /*
         * Reject a policy the ENGINE could never honour, here — not on
         * the first accepted connection, where wtq_api_session_serve
         * would fail and every peer would see an internal error. This
         * is the same transport-neutral validator the engine applies,
         * so the two can never disagree.
         */
        wtq_result_t prc =
            wtq_conn_validate_protocols(p.subprotocols,
                                        p.subprotocol_count);
        if (prc != WTQ_OK)
            return prc;

        memcpy(l->paths[i].path, p.path, plen + 1);

        size_t off = 0;
        for (size_t j = 0; j < p.subprotocol_count; j++) {
            size_t sl = strlen(p.subprotocols[j]);
            if (off + sl + 1 > sizeof(l->paths[i].protos))
                return WTQ_ERR_TOO_LARGE;
            memcpy(l->paths[i].protos + off, p.subprotocols[j], sl + 1);
            l->paths[i].proto_ptr[j] = l->paths[i].protos + off;
            off += sl + 1;
        }
        l->paths[i].proto_count = p.subprotocol_count;
        l->paths[i].require = p.require_subprotocol;
    }
    l->path_count = count;
    return WTQ_OK;
}

/* Build the engine-facing accept policy from the listener's copy. */
static void build_serve(const struct wtq_msquic_listener *l,
                        wtq_serve_config_t *out)
{
    for (size_t i = 0; i < l->path_count; i++) {
        wtq_serve_config_init(&out[i]);
        out[i].path = l->paths[i].path;
        out[i].subprotocols = l->paths[i].proto_ptr;
        out[i].subprotocol_count = l->paths[i].proto_count;
        out[i].require_subprotocol = l->paths[i].require;
    }
}

static QUIC_STATUS QUIC_API listener_callback(HQUIC listener, void *ctx,
                                              QUIC_LISTENER_EVENT *ev)
{
    struct wtq_msquic_listener *l = ctx;

    (void)listener;
    if (ev->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
        return QUIC_STATUS_SUCCESS;

    struct wtq_driver *drv =
        wtq_msq_conn_new(&l->alloc, l->env->api, false);
    if (drv == NULL)
        return QUIC_STATUS_OUT_OF_MEMORY;

    /* Session construction runs UNTRACKED: MsQuic owns the unaccepted
     * connection, no handler is set, so no event can reach this state
     * and nothing here needs the environment's shutdown walk yet. */
    wtq_api_session_cfg_t scfg = {
        .alloc = &l->alloc,
        .perspective = WTQ_PERSPECTIVE_SERVER,
        .events = &l->events,
        .user = l->user,
        .drv = drv,
        .ops = wtq_msq_driver_ops(),
    };
    wtq_session_t *session = NULL;
    if (wtq_api_session_create(&scfg, &session) != WTQ_OK) {
        wtq_msq_conn_free(drv); /* drv->conn unset: no ConnectionClose */
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    wtq_serve_config_t serve[WTQ_MSQ_MAX_PATHS];
    build_serve(l, serve);
    if (wtq_api_session_serve(session, serve, l->path_count) != WTQ_OK) {
        wtq_session_release(session);
        wtq_msq_conn_free(drv);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    /* Accept-registration: the session (backend's creator reference),
     * the shutdown-capable handle, and list membership publish in one
     * critical section — refused once the environment is closing. The
     * handler is set only AFTER publication, so either env_close's
     * walk shuts this connection down (and the SHUTDOWN_COMPLETE
     * reaches our handler once the accept returns success) or the
     * accept was refused and MsQuic closes the never-accepted
     * connection itself. */
    if (!wtq_msq_env_conn_accept(l->env, drv, session,
                                 ev->NEW_CONNECTION.Connection)) {
        wtq_session_release(session);
        wtq_msq_conn_free(drv); /* conn never stored: no ConnectionClose */
        return QUIC_STATUS_ABORTED;
    }
    l->env->api->SetCallbackHandler(ev->NEW_CONNECTION.Connection,
                                    (void *)wtq_msq_conn_callback, drv);
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
#ifdef WTQ_MSQ_TESTING
    if (atomic_load(&wtq_msq_test_fail_set_configuration) > 0) {
        atomic_fetch_sub(&wtq_msq_test_fail_set_configuration, 1);
        status = QUIC_STATUS_INTERNAL_ERROR;
    }
#endif
    if (status == QUIC_STATUS_SUCCESS)
        status = l->env->api->ConnectionSetConfiguration(
            ev->NEW_CONNECTION.Connection, l->configuration);
    if (QUIC_FAILED(status)) {
        /* never accepted: report the failure and MsQuic closes the
         * connection itself — it guarantees no event is ever delivered
         * to a handler set before a failure return, so ours may simply
         * be abandoned while we free our state. Unregister FIRST: the
         * close walk shuts down under env->mu, so after the unlink no
         * walker can reach this driver, and any shutdown it already
         * issued completed while the handle was still live. */
        wtq_msq_env_conn_unregister(drv);
        drv->conn = NULL;
        drv->session = NULL;
        wtq_session_release(session);
        wtq_msq_conn_free(drv);
        return status;
    }
    return QUIC_STATUS_SUCCESS;
}

wtq_result_t wtq_msquic_listener_start(wtq_msquic_env_t *env,
                                       const wtq_msquic_listener_cfg_t *cfg_in,
                                       wtq_msquic_listener_t **listener_out)
{
    if (listener_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *listener_out = NULL;
    if (env == NULL || cfg_in == NULL || cfg_in->struct_size == 0)
        return WTQ_ERR_INVALID_ARG;

    wtq_msquic_listener_cfg_t cfg;
    cfg_copy(&cfg, sizeof(cfg), cfg_in, cfg_in->struct_size);
    if (cfg.cert_file == NULL || cfg.key_file == NULL ||
        cfg.events == NULL || cfg.events->struct_size == 0)
        return WTQ_ERR_INVALID_ARG;

    struct wtq_msquic_listener *l =
        env->alloc.alloc(sizeof(*l), env->alloc.ctx);
    if (l == NULL)
        return WTQ_ERR_NOMEM;
    memset(l, 0, sizeof(*l));
    l->alloc = env->alloc;
    l->env = env;
    /* size-checked copy of the app's event table */
    cfg_copy(&l->events, sizeof(l->events), cfg.events,
             cfg.events->struct_size);
    l->events.struct_size = (uint32_t)sizeof(l->events);
    l->user = cfg.user;

    wtq_result_t rc = copy_paths(l, cfg.paths, cfg.path_count);
    if (rc != WTQ_OK) {
        env->alloc.free(l, sizeof(*l), env->alloc.ctx);
        return rc;
    }

    /* server Configuration: ALPN h3, tuning-derived settings, cert */
    QUIC_SETTINGS qs;
    wtq_msq_settings_init(&qs, &env->tuning);
    QUIC_BUFFER alpn = { 2, (uint8_t *)"h3" };
    if (QUIC_FAILED(env->api->ConfigurationOpen(
            env->registration, &alpn, 1, &qs, sizeof(qs), NULL,
            &l->configuration))) {
        env->alloc.free(l, sizeof(*l), env->alloc.ctx);
        return WTQ_ERR_BACKEND;
    }

    QUIC_CERTIFICATE_FILE cert_file = {
        .PrivateKeyFile = cfg.key_file,
        .CertificateFile = cfg.cert_file,
    };
    QUIC_CREDENTIAL_CONFIG cred;
    memset(&cred, 0, sizeof(cred));
    cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    cred.CertificateFile = &cert_file;
    if (QUIC_FAILED(env->api->ConfigurationLoadCredential(
            l->configuration, &cred))) {
        env->api->ConfigurationClose(l->configuration);
        env->alloc.free(l, sizeof(*l), env->alloc.ctx);
        return WTQ_ERR_BACKEND;
    }

    if (QUIC_FAILED(env->api->ListenerOpen(env->registration,
                                           listener_callback, l,
                                           &l->listener))) {
        env->api->ConfigurationClose(l->configuration);
        env->alloc.free(l, sizeof(*l), env->alloc.ctx);
        return WTQ_ERR_BACKEND;
    }

    QUIC_ADDR addr;
    memset(&addr, 0, sizeof(addr));
    if (cfg.bind_address != NULL) {
        if (!QuicAddrFromString(cfg.bind_address, cfg.port, &addr)) {
            env->api->ListenerClose(l->listener);
            env->api->ConfigurationClose(l->configuration);
            env->alloc.free(l, sizeof(*l), env->alloc.ctx);
            return WTQ_ERR_INVALID_ARG;
        }
    } else {
        QuicAddrSetFamily(&addr, QUIC_ADDRESS_FAMILY_UNSPEC);
        QuicAddrSetPort(&addr, cfg.port);
    }
    if (QUIC_FAILED(env->api->ListenerStart(l->listener, &alpn, 1,
                                            &addr))) {
        env->api->ListenerClose(l->listener);
        env->api->ConfigurationClose(l->configuration);
        env->alloc.free(l, sizeof(*l), env->alloc.ctx);
        return WTQ_ERR_BACKEND;
    }

    /* Track under the environment; refused when a close raced the
     * start — unwind as if the start had failed. (Accepts that slipped
     * in before this are refused by the register check in the accept
     * callback: the closing latch was already up.) */
    if (!wtq_msq_env_listener_register(env, l)) {
        env->api->ListenerClose(l->listener);
        env->api->ConfigurationClose(l->configuration);
        env->alloc.free(l, sizeof(*l), env->alloc.ctx);
        return WTQ_ERR_CLOSED;
    }

    *listener_out = l;
    return WTQ_OK;
}

void wtq_msq_listener_free(struct wtq_msquic_listener *l)
{
    /* ListenerClose stops accepting and waits for in-flight listener
     * callbacks; accepted connections live on under the registration */
    l->env->api->ListenerClose(l->listener);
    l->env->api->ConfigurationClose(l->configuration);
    l->alloc.free(l, sizeof(*l), l->alloc.ctx);
}

void wtq_msquic_listener_stop(wtq_msquic_listener_t *l)
{
    if (l == NULL)
        return;
    wtq_msq_env_listener_unregister(l);
    wtq_msq_listener_free(l);
}

uint16_t wtq_msquic_listener_port(const wtq_msquic_listener_t *l)
{
    QUIC_ADDR addr;
    uint32_t size = sizeof(addr);

    if (l == NULL)
        return 0;
    if (QUIC_FAILED(l->env->api->GetParam(
            l->listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &size,
            &addr)))
        return 0;
    return QuicAddrGetPort(&addr);
}
