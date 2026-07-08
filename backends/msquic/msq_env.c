/*
 * MsQuic environment: the root backend object. It owns (or borrows) the
 * MsQuic API function table and a Registration, and carries the tuning
 * that connections apply to their QUIC configuration.
 *
 * Ownership is tracked per resource so a borrowed table/registration is
 * never closed and every failure path releases exactly what it acquired.
 */

#include <string.h>

#include <wtquic/error.h>
#include <wtquic/types.h>
#include <wtquic/wtquic_msquic.h>

#include "msq_internal.h"

/* Copy a struct_size-prefixed config into a full-size zeroed local:
 * fields past the caller's (older) size read as zero/NULL. */
static void cfg_copy(void *dst, size_t dst_size, const void *src,
                     uint32_t src_size)
{
    size_t n = src_size < dst_size ? src_size : dst_size;

    memset(dst, 0, dst_size);
    memcpy(dst, src, n);
}

void wtq_msquic_tuning_init(wtq_msquic_tuning_t *tuning)
{
    static const wtq_msquic_tuning_t def = WTQ_MSQUIC_TUNING_INIT;

    if (tuning != NULL)
        *tuning = def;
}

void wtq_msquic_env_cfg_init(wtq_msquic_env_cfg_t *cfg)
{
    static const wtq_msquic_env_cfg_t def = WTQ_MSQUIC_ENV_CFG_INIT;

    if (cfg != NULL)
        *cfg = def;
}

/* Release every owned resource and free the object. Safe on a partially
 * constructed env: the owns_* flags gate each close. Children must
 * already be gone (env_close waits; open-failure paths have none). */
static void env_free(wtq_msquic_env_t *env)
{
    wtq_alloc_t alloc = env->alloc;

    if (env->owns_registration && env->registration != NULL)
        env->api->RegistrationClose(env->registration);
    if (env->owns_api && env->api != NULL)
        MsQuicClose(env->api);
    if (env->app_name != NULL)
        alloc.free(env->app_name, env->app_name_size, alloc.ctx);
    pthread_cond_destroy(&env->cv);
    pthread_mutex_destroy(&env->mu);
    alloc.free(env, sizeof(*env), alloc.ctx);
}

/* --- child tracking --------------------------------------------------------
 * Registration is refused once the environment is closing; removal is
 * exactly once per registered child (the backlink is the latch) and
 * signals the close waiter when the last connection goes. */

bool wtq_msq_env_conn_register(wtq_msquic_env_t *env,
                               struct wtq_driver *drv)
{
    pthread_mutex_lock(&env->mu);
    if (env->closing) {
        pthread_mutex_unlock(&env->mu);
        return false;
    }
    drv->env = env;
    drv->env_prev = NULL;
    drv->env_next = env->conns;
    if (env->conns != NULL)
        env->conns->env_prev = drv;
    env->conns = drv;
    env->conn_count++;
    pthread_mutex_unlock(&env->mu);
    return true;
}

bool wtq_msq_env_conn_accept(wtq_msquic_env_t *env,
                             struct wtq_driver *drv,
                             wtq_session_t *session, HQUIC conn)
{
    pthread_mutex_lock(&env->mu);
    if (env->closing) {
        pthread_mutex_unlock(&env->mu);
        return false;
    }
    /* session + shutdown-capable handle + list membership publish in
     * ONE critical section: the close walk (which reads drv->conn
     * under this lock) can never meet a tracked driver it cannot shut
     * down, and never misses one it should. */
    drv->session = session;
    drv->conn = conn;
    drv->env = env;
    drv->env_prev = NULL;
    drv->env_next = env->conns;
    if (env->conns != NULL)
        env->conns->env_prev = drv;
    env->conns = drv;
    env->conn_count++;
    pthread_mutex_unlock(&env->mu);
    return true;
}

void wtq_msq_env_conn_unregister(struct wtq_driver *drv)
{
    wtq_msquic_env_t *env = drv->env;

    if (env == NULL)
        return; /* untracked (unit rigs) or already removed */
    pthread_mutex_lock(&env->mu);
    if (drv->env_prev != NULL)
        drv->env_prev->env_next = drv->env_next;
    else
        env->conns = drv->env_next;
    if (drv->env_next != NULL)
        drv->env_next->env_prev = drv->env_prev;
    drv->env = NULL;
    drv->env_next = NULL;
    drv->env_prev = NULL;
    env->conn_count--;
    if (env->conn_count == 0)
        pthread_cond_broadcast(&env->cv);
    pthread_mutex_unlock(&env->mu);
}

bool wtq_msq_env_listener_register(wtq_msquic_env_t *env,
                                   struct wtq_msquic_listener *l)
{
    pthread_mutex_lock(&env->mu);
    if (env->closing) {
        pthread_mutex_unlock(&env->mu);
        return false;
    }
    l->tracked = true;
    l->env_prev = NULL;
    l->env_next = env->listeners;
    if (env->listeners != NULL)
        env->listeners->env_prev = l;
    env->listeners = l;
    pthread_mutex_unlock(&env->mu);
    return true;
}

void wtq_msq_env_listener_unregister(struct wtq_msquic_listener *l)
{
    wtq_msquic_env_t *env = l->env;

    pthread_mutex_lock(&env->mu);
    if (!l->tracked) {
        pthread_mutex_unlock(&env->mu);
        return;
    }
    l->tracked = false;
    if (l->env_prev != NULL)
        l->env_prev->env_next = l->env_next;
    else
        env->listeners = l->env_next;
    if (l->env_next != NULL)
        l->env_next->env_prev = l->env_prev;
    l->env_next = NULL;
    l->env_prev = NULL;
    pthread_mutex_unlock(&env->mu);
}

wtq_result_t wtq_msquic_env_open(const wtq_msquic_env_cfg_t *cfg_in,
                                 wtq_msquic_env_t **env_out)
{
    wtq_msquic_env_cfg_t cfg;
    wtq_alloc_t alloc;
    wtq_msquic_env_t *env;

    if (env_out == NULL)
        return WTQ_ERR_INVALID_ARG;
    *env_out = NULL;
    if (cfg_in == NULL || cfg_in->struct_size == 0)
        return WTQ_ERR_INVALID_ARG;

    cfg_copy(&cfg, sizeof(cfg), cfg_in, cfg_in->struct_size);

    /* A borrowed Registration is only usable through the table that owns
     * it, so the caller must supply that table too. */
    if (cfg.existing_registration != NULL && cfg.existing_api == NULL)
        return WTQ_ERR_INVALID_ARG;

    alloc = (cfg.alloc != NULL) ? *cfg.alloc : *wtq_alloc_default();

    env = alloc.alloc(sizeof(*env), alloc.ctx);
    if (env == NULL)
        return WTQ_ERR_NOMEM;
    memset(env, 0, sizeof(*env));
    env->alloc = alloc;
    if (pthread_mutex_init(&env->mu, NULL) != 0) {
        alloc.free(env, sizeof(*env), alloc.ctx);
        return WTQ_ERR_BACKEND;
    }
    if (pthread_cond_init(&env->cv, NULL) != 0) {
        pthread_mutex_destroy(&env->mu);
        alloc.free(env, sizeof(*env), alloc.ctx);
        return WTQ_ERR_BACKEND;
    }
    env->tuning = cfg.tuning;
    if (env->tuning.struct_size == 0)
        wtq_msquic_tuning_init(&env->tuning);

    /* API table: borrow the caller's or open our own. */
    if (cfg.existing_api != NULL) {
        env->api = cfg.existing_api;
    } else {
        if (QUIC_FAILED(MsQuicOpen2(&env->api))) {
            env_free(env);
            return WTQ_ERR_BACKEND;
        }
        env->owns_api = true;
    }

    /* Registration: borrow the caller's or open our own. */
    if (cfg.existing_registration != NULL) {
        env->registration = cfg.existing_registration;
    } else {
        QUIC_REGISTRATION_CONFIG rc;

        if (cfg.app_name != NULL) {
            size_t n = strlen(cfg.app_name) + 1;
            char *copy = alloc.alloc(n, alloc.ctx);

            if (copy == NULL) {
                env_free(env);
                return WTQ_ERR_NOMEM;
            }
            memcpy(copy, cfg.app_name, n);
            env->app_name = copy;
            env->app_name_size = n;
        }

        memset(&rc, 0, sizeof(rc));
        rc.AppName = env->app_name;
        rc.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
        if (QUIC_FAILED(env->api->RegistrationOpen(&rc,
                                                   &env->registration))) {
            env->registration = NULL;
            env_free(env);
            return WTQ_ERR_BACKEND;
        }
        env->owns_registration = true;
    }

    *env_out = env;
    return WTQ_OK;
}

void wtq_msquic_env_close(wtq_msquic_env_t *env)
{
    if (env == NULL)
        return;

    /* 1. Latch: no new listeners, clients, or accepted connections
     * register from here on. Detach the listener list so the blocking
     * stops below run without the lock. */
    pthread_mutex_lock(&env->mu);
    env->closing = true;
    struct wtq_msquic_listener *ls = env->listeners;
    env->listeners = NULL;
    for (struct wtq_msquic_listener *l = ls; l != NULL; l = l->env_next)
        l->tracked = false;
    pthread_mutex_unlock(&env->mu);

    /* 2. Stop and free every listener (blocks for in-flight accepts —
     * lock NOT held). After this no connection can appear that step 1
     * didn't already refuse, and listener handles are invalid. */
    while (ls != NULL) {
        struct wtq_msquic_listener *next = ls->env_next;
        wtq_msq_listener_free(ls);
        ls = next;
    }

    /* 3. Actively shut down every tracked connection — including under
     * a borrowed Registration, and regardless of idle timeout. Only
     * OUR children: unrelated connections sharing a borrowed
     * Registration are untouched. ConnectionShutdown is queue-only, so
     * holding the lock here cannot deadlock with the workers' O(1)
     * unregister. 0x100 = H3_NO_ERROR. */
    pthread_mutex_lock(&env->mu);
    for (struct wtq_driver *drv = env->conns; drv != NULL;
         drv = drv->env_next)
        if (drv->conn != NULL) {
            /* environment close is a CAUSAL local error. Only this
             * atomic latch crosses threads: the WORKER consumes it and
             * stages {LOCAL, 0x100} on the serialization domain before
             * classifying any shutdown event. */
            atomic_store_explicit(&drv->env_close_req, true,
                                  memory_order_release);
            env->api->ConnectionShutdown(
                drv->conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                UINT64_C(0x100));
        }

    /* 4. Block until each reaches SHUTDOWN_COMPLETE, drops its backend
     * session reference, and unregisters. */
    while (env->conn_count > 0)
        pthread_cond_wait(&env->cv, &env->mu);
    pthread_mutex_unlock(&env->mu);

    /* 5. Only now: owned Registration/API handles and the memory.
     * Borrowed handles are untouched and remain usable. */
    env_free(env);
}
