#include "scanner_internal.h"
#include "scanner_parallel.h"
#include "service_version.h"
#include "service_detect.h"
#include "tls_probe.h"
#include "thread_pool.h"
#include "runtime/full_runtime.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "recon/submodules/os_detect/os_pipeline_config.h"
#include "netpeek.h"
#include "syn_sender.h"
#include "runtime/stats.h"
#include "logger.h"
#include "core/arena.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <string.h>
#include <pthread.h>

/* ───────────────────────────────────────────── */
/* External SYN receiver API                     */
/* ───────────────────────────────────────────── */

extern void np_start_receiver(np_config_t *cfg);
extern void np_stop_receiver(void);

static bool np_scan_type_requires_raw(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN:
    case NP_SCAN_TCP_ACK:
    case NP_SCAN_TCP_WINDOW:
    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
    case NP_SCAN_IDLE:
    case NP_SCAN_SCTP_INIT:
    case NP_SCAN_SCTP_COOKIE_ECHO:
    case NP_SCAN_IP_PROTOCOL:
    case NP_SCAN_UDP:
        return true;
    default:
        return false;
    }
}

static bool np_scan_type_is_raw_tcp(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN:
    case NP_SCAN_TCP_ACK:
    case NP_SCAN_TCP_WINDOW:
    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
        return true;
    default:
        return false;
    }
}

static const char *np_scan_type_name(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN: return "TCP SYN";
    case NP_SCAN_TCP_CONNECT: return "TCP connect";
    case NP_SCAN_TCP_ACK: return "TCP ACK";
    case NP_SCAN_TCP_WINDOW: return "TCP Window";
    case NP_SCAN_TCP_MAIMON: return "TCP Maimon";
    case NP_SCAN_UDP: return "UDP";
    case NP_SCAN_TCP_NULL: return "TCP Null";
    case NP_SCAN_TCP_FIN: return "TCP FIN";
    case NP_SCAN_TCP_XMAS: return "TCP Xmas";
    case NP_SCAN_TCP_CUSTOM_FLAGS: return "TCP custom-flags";
    case NP_SCAN_IDLE: return "Idle";
    case NP_SCAN_SCTP_INIT: return "SCTP INIT";
    case NP_SCAN_SCTP_COOKIE_ECHO: return "SCTP COOKIE-ECHO";
    case NP_SCAN_IP_PROTOCOL: return "IP protocol";
    default: return "Unknown";
    }
}

static const char *np_scan_type_proto_name(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_UDP:
        return "udp";
    case NP_SCAN_SCTP_INIT:
    case NP_SCAN_SCTP_COOKIE_ECHO:
        return "sctp";
    case NP_SCAN_IP_PROTOCOL:
        return "ip";
    default:
        return "tcp";
    }
}

static uint8_t np_scan_type_tcp_flags(const np_config_t *cfg)
{
    switch (cfg->scan_type)
    {
    case NP_SCAN_TCP_SYN: return TH_SYN;
    case NP_SCAN_TCP_ACK: return TH_ACK;
    case NP_SCAN_TCP_WINDOW: return TH_ACK;
    case NP_SCAN_TCP_MAIMON: return (TH_FIN | TH_ACK);
    case NP_SCAN_TCP_NULL: return 0;
    case NP_SCAN_TCP_FIN: return TH_FIN;
    case NP_SCAN_TCP_XMAS: return (TH_FIN | TH_PUSH | TH_URG);
    case NP_SCAN_TCP_CUSTOM_FLAGS: return cfg->tcp_custom_flags;
    default: return TH_SYN;
    }
}

static np_port_state_t np_default_noresp_state(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN:
    case NP_SCAN_TCP_ACK:
    case NP_SCAN_TCP_WINDOW:
        return NP_PORT_FILTERED;
    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
        return NP_PORT_OPEN_FILTERED;
    default:
        return NP_PORT_FILTERED;
    }
}

static bool np_target_os_detect_skipped(const np_config_t *cfg,
                                        const np_target_t *target)
{
    if (!cfg || !target)
        return true;

    if (target->is_ipv6)
        return true;

    if (cfg->host_discovery_mode == NP_HOST_DISCOVERY_DEFAULT &&
        cfg->host_discovery_done &&
        !target->host_up)
        return true;

    return false;
}

static void np_target_ip_string(const np_target_t *target,
                                char *out,
                                size_t out_len)
{
    if (!target || !out || out_len == 0)
        return;

    out[0] = 0;

    if (target->ip[0])
    {
        strncpy(out, target->ip, out_len - 1);
        out[out_len - 1] = 0;
        return;
    }

    if (target->is_ipv6)
        inet_ntop(AF_INET6, &target->addr6.sin6_addr, out, out_len);
    else
        inet_ntop(AF_INET, &target->addr4.sin_addr, out, out_len);
}

static uint16_t np_pick_os_probe_port(const np_target_t *target)
{
    if (!target || !target->results)
        return 0;

    for (uint32_t i = 0; i < target->port_count; i++)
    {
        np_port_state_t state = target->results[i].state;
        if (state == NP_PORT_OPEN || state == NP_PORT_OPEN_FILTERED)
            return target->results[i].port;
    }

    return 0;
}

static void np_append_port_csv(char *buf, size_t cap, uint16_t port, uint32_t *count)
{
    if (!buf || cap == 0 || !count)
        return;

    char frag[24];
    snprintf(frag, sizeof(frag), "%u", port);

    size_t used = strlen(buf);
    if (*count > 0)
    {
        if (used + 1 >= cap)
            return;
        buf[used++] = ',';
        buf[used] = '\0';
    }

    size_t left = cap - used;
    if (left <= 1)
        return;

    strncat(buf, frag, left - 1);
    (*count)++;
}

static void np_print_udp_host_summary(const np_target_t *target)
{
    if (!target || !target->results)
        return;

    char host[INET6_ADDRSTRLEN] = {0};
    np_target_ip_string(target, host, sizeof(host));
    if (host[0] == '\0' && target->hostname[0])
    {
        strncpy(host, target->hostname, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    char open_list[1024] = {0};
    char closed_list[1024] = {0};
    uint32_t open_count = 0;
    uint32_t closed_count = 0;

    for (uint32_t i = 0; i < target->port_count; i++)
    {
        const np_port_result_t *res = &target->results[i];
        if (res->state == NP_PORT_OPEN)
            np_append_port_csv(open_list, sizeof(open_list), res->port, &open_count);
        else if (res->state == NP_PORT_CLOSED)
            np_append_port_csv(closed_list, sizeof(closed_list), res->port, &closed_count);
    }

    np_error(NP_ERR_RUNTIME,
             "Host %s: Open ports: %s   Closed ports: %s\n",
             host[0] ? host : "unknown",
             open_count ? open_list : "none",
             closed_count ? closed_list : "none");
}

np_status_t np_scan_os_detect_run_target(np_config_t *cfg,
                                         uint32_t target_idx)
{
    if (!cfg || target_idx >= cfg->target_count)
        return NP_ERR_ARGS;

    np_target_t *target = &cfg->targets[target_idx];
    if (np_target_os_detect_skipped(cfg, target))
        return NP_OK;

    char ip[INET6_ADDRSTRLEN];
    np_target_ip_string(target, ip, sizeof(ip));
    if (ip[0] == 0)
        return NP_OK;

    uint16_t port = np_pick_os_probe_port(target);

    np_os_result_t previous = target->os_result;
    np_os_result_t active;
    memset(&active, 0, sizeof(active));

    /* Hand the SYN/connect scan's open ports to the OS pipeline. Without
     * this, the pipeline re-runs discovery with no ports and reports
     * open_ports=0 even though target->results lists open services. */
    uint16_t open_ports[NP_PIPELINE_MAX_OPEN_PORTS];
    uint32_t open_count = 0;
    for (uint32_t i = 0;
         i < target->port_count && open_count < NP_PIPELINE_MAX_OPEN_PORTS;
         i++)
    {
        if (target->results[i].state == NP_PORT_OPEN)
            open_ports[open_count++] = target->results[i].port;
    }

    np_status_t st = np_os_detect_pipeline_auto_ports(
        ip, port, open_count > 0 ? open_ports : NULL, open_count, NULL, &active);
    if (st != NP_OK)
    {
        LOGW("OS detection failed for %s: %s", ip, np_status_str(st));
        return NP_OK;
    }

    if (previous.os_guess_passive[0])
    {
        strncpy(active.os_guess_passive,
                previous.os_guess_passive,
                sizeof(active.os_guess_passive) - 1);
        active.os_guess_passive[sizeof(active.os_guess_passive) - 1] = 0;
        active.passive_confidence = previous.passive_confidence;
        active.passive_evidence_count = previous.passive_evidence_count;
        active.passive_low_confidence = previous.passive_low_confidence;
    }

    if (active.best_os[0] == 0 && previous.best_os[0] != 0)
    {
        strncpy(active.best_os, previous.best_os, sizeof(active.best_os) - 1);
        active.best_os[sizeof(active.best_os) - 1] = 0;

        strncpy(active.best_family,
                previous.best_family,
                sizeof(active.best_family) - 1);
        active.best_family[sizeof(active.best_family) - 1] = 0;

        strncpy(active.best_cpe, previous.best_cpe, sizeof(active.best_cpe) - 1);
        active.best_cpe[sizeof(active.best_cpe) - 1] = 0;
        active.best_confidence = previous.best_confidence;
    }

    target->os_result = active;
    target->os_result_valid =
        target->os_result.best_confidence > 0 ||
        target->os_result.os_guess_passive[0] != 0;

    return NP_OK;
}

typedef struct
{
    np_config_t *cfg;
    uint32_t target_idx;
    volatile sig_atomic_t *interrupted;
} np_os_detect_task_t;

static void np_os_detect_task_worker(void *arg)
{
    np_os_detect_task_t *task = (np_os_detect_task_t *)arg;
    if (!task)
        return;

    if (!task->interrupted || !*task->interrupted)
        (void)np_scan_os_detect_run_target(task->cfg, task->target_idx);

    free(task);
}

np_status_t np_scan_os_detect_run(np_config_t *cfg,
                                  volatile sig_atomic_t *interrupted)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (cfg->target_count == 0)
        return NP_OK;

    uint32_t workers = cfg->threads ? cfg->threads : NP_DEFAULT_THREADS;
    if (workers < 1)
        workers = 1;
    if (workers > cfg->target_count)
        workers = cfg->target_count;
    if (workers > 64)
        workers = 64;

    np_pool_t *pool = np_pool_create(workers, cfg->target_count);
    if (!pool)
    {
        for (uint32_t i = 0; i < cfg->target_count; i++)
        {
            if (interrupted && *interrupted)
                break;
            (void)np_scan_os_detect_run_target(cfg, i);
        }
        return NP_OK;
    }

    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        if (interrupted && *interrupted)
            break;

        np_os_detect_task_t *task = calloc(1, sizeof(*task));
        if (!task)
        {
            np_pool_wait(pool);
            np_pool_destroy(pool, true);
            return NP_ERR_MEMORY;
        }

        task->cfg = cfg;
        task->target_idx = i;
        task->interrupted = interrupted;

        if (np_pool_submit_bounded(pool, np_os_detect_task_worker, task) != 0)
        {
            free(task);
            np_pool_wait(pool);
            np_pool_destroy(pool, true);
            return NP_ERR_SYSTEM;
        }
    }

    np_pool_wait(pool);
    np_pool_destroy(pool, true);

    return NP_OK;
}

/* ───────────────────────────────────────────── */
/* Privilege detection                           */
/* ───────────────────────────────────────────── */

bool np_have_raw_socket_privilege(void)
{
    return geteuid() == 0;
}

/* ───────────────────────────────────────────── */
/* INTERNAL: TCP connect scan worker             */
/* ───────────────────────────────────────────── */

static void
np_connect_scan_task_worker(void *arg)
{
    np_scan_task(arg);
    free(arg);
}

static void
np_udp_scan_task_worker(void *arg)
{
    np_udp_scan_task(arg);
    free(arg);
}

static void
np_sctp_scan_task_worker(void *arg)
{
    np_sctp_scan_task(arg);
    free(arg);
}

static void
np_ipproto_scan_task_worker(void *arg)
{
    np_ipproto_scan_task(arg);
    free(arg);
}

static void
np_idle_scan_task_worker(void *arg)
{
    np_idle_scan_task(arg);
    free(arg);
}


/* ───────────────────────────────────────────── */
/* INTERNAL: Single‑target scan (unchanged core) */
/* ───────────────────────────────────────────── */

/*
 * Scans ONE target (cfg must have target_count == 1).
 *
 * Parameters:
 *   cfg         — config with exactly 1 target
 *   interrupted — shared interrupt flag
 *   syn_shared  — if true, SYN engine is already initialized
 *                 by the caller (parallel mode); do NOT
 *                 init/close SYN resources here.
 */

np_status_t
np_scanner_run_single_target_internal(np_config_t *cfg,
                                      volatile sig_atomic_t *interrupted,
                                      bool syn_shared)
{
    (void)syn_shared;
    if (!cfg || cfg->target_count != 1)
    {
        LOGE("run_single_target: bad args");
        return NP_ERR_ARGS;
    }

    np_target_t *t = &cfg->targets[0];
    if (cfg->host_discovery_done &&
        cfg->host_discovery_mode == NP_HOST_DISCOVERY_DEFAULT &&
        !t->host_up)
    {
        LOGI("Skipping host marked down by discovery: %s", t->hostname);
        return NP_OK;
    }

    /* ── Metrics & synchronization ───────────────────── */

    uint32_t completed_work = 0;
    pthread_mutex_t completed_lock;
    pthread_mutex_init(&completed_lock, NULL);

    np_metrics_t metrics;
    np_metrics_init(&metrics);

    pthread_mutex_t metrics_lock;
    pthread_mutex_init(&metrics_lock, NULL);

    /* ── Port enumeration ────────────────────────────── */

    uint64_t total_ports = (cfg->scan_type == NP_SCAN_IP_PROTOCOL)
                               ? 256
                               : np_ports_total(&cfg->ports);
    if (total_ports == 0)
    {
        LOGW("No ports to scan");
        goto cleanup_locks;
    }

    LOGI("Scanning %s — %lu port(s), scan_type=%d",
         t->hostname, (unsigned long)total_ports, cfg->scan_type);

    /* ── Allocate result slots ───────────────────────── */

    t->port_count = (uint32_t)total_ports;
    t->results = calloc(t->port_count, sizeof(np_port_result_t));
    if (!t->results)
    {
        LOGE("Failed to allocate result slots");
        goto cleanup_locks;
    }

    /* ── Thread pool ────────────────────────────────── */

    uint32_t nthreads = cfg->threads ? cfg->threads : 1;
    if (nthreads > total_ports)
        nthreads = (uint32_t)total_ports;

    np_pool_t *pool = np_pool_create(nthreads, 0);
    if (!pool)
    {
        LOGE("Thread pool creation failed");
        goto cleanup_results;
    }

    /* ── Work queue ─────────────────────────────────── */

    np_work_queue_t queue;
    np_wq_init(&queue, (uint32_t)total_ports);

    np_port_iter_t it;
    np_port_iter_init(&it);

    uint16_t port;
    uint32_t flat_idx = 0;

    if (cfg->scan_type == NP_SCAN_IP_PROTOCOL)
    {
        for (uint16_t proto = 0; proto <= 255; proto++)
        {
            t->results[flat_idx].port = proto;
            strncpy(t->results[flat_idx].proto,
                    np_scan_type_proto_name(cfg->scan_type),
                    sizeof(t->results[flat_idx].proto) - 1);
            t->results[flat_idx].state = NP_PORT_OPEN_FILTERED;
            t->results[flat_idx].completed = false;

            np_work_item_t item = {
                .port = proto,
                .target_idx = 0,
                .port_idx = flat_idx};
            np_wq_push(&queue, &item);
            flat_idx++;
        }
    }
    else
    {
        while (np_port_iter_next(&cfg->ports, &it, &port))
        {
            if (flat_idx >= t->port_count)
            {
                LOGE("Port iterator overflow (flat_idx=%u)", flat_idx);
                break;
            }

            t->results[flat_idx].port = port;
            strncpy(t->results[flat_idx].proto,
                    np_scan_type_proto_name(cfg->scan_type),
                    sizeof(t->results[flat_idx].proto) - 1);
            t->results[flat_idx].state = NP_PORT_FILTERED;
            t->results[flat_idx].completed = false;

            np_work_item_t item = {
                .port = port,
                .target_idx = 0,
                .port_idx = flat_idx};

            np_wq_push(&queue, &item);
            flat_idx++;
        }
    }

    LOGD("Work queue filled: %u items", flat_idx);

    /* ── Completion barrier ─────────────────────────── */

    np_completion_t completion;
    np_completion_init(&completion, nthreads);

    /* ── Submit workers ─────────────────────────────── */

    for (uint32_t i = 0; i < nthreads; i++)
    {
        np_task_arg_t *arg = calloc(1, sizeof(*arg));
        if (!arg)
        {
            np_completion_signal(&completion);
            continue;
        }

        arg->ctx.cfg = cfg;
        arg->ctx.queue = &queue;
        arg->ctx.interrupted = interrupted;
        arg->ctx.completed_work = &completed_work;
        arg->ctx.completed_lock = &completed_lock;
        arg->ctx.metrics = &metrics;
        arg->ctx.metrics_lock = &metrics_lock;
        arg->ctx.total_work = (uint32_t)total_ports;
        arg->completion = &completion;

        if (np_scan_type_is_raw_tcp(cfg->scan_type))
            np_pool_submit(pool, np_syn_scan_task, arg);
        else if (cfg->scan_type == NP_SCAN_UDP)
            np_pool_submit(pool, np_udp_scan_task_worker, arg);
        else if (cfg->scan_type == NP_SCAN_SCTP_INIT ||
                 cfg->scan_type == NP_SCAN_SCTP_COOKIE_ECHO)
            np_pool_submit(pool, np_sctp_scan_task_worker, arg);
        else if (cfg->scan_type == NP_SCAN_IP_PROTOCOL)
            np_pool_submit(pool, np_ipproto_scan_task_worker, arg);
        else if (cfg->scan_type == NP_SCAN_IDLE)
            np_pool_submit(pool, np_idle_scan_task_worker, arg);
        else
            np_pool_submit(pool, np_connect_scan_task_worker, arg);
    }

    np_completion_wait(&completion);

    /* ── Cleanup ───────────────────────────────────── */

    np_pool_destroy(pool, true);
    np_wq_destroy(&queue);
    np_completion_destroy(&completion);

cleanup_results:
    if (np_scan_type_is_raw_tcp(cfg->scan_type))
    {
        np_port_state_t noresp = np_default_noresp_state(cfg->scan_type);
        for (uint32_t i = 0; i < t->port_count; i++)
        {
            if (!t->results[i].completed)
            {
                t->results[i].state = noresp;
                strncpy(t->results[i].reason,
                        "no-response",
                        sizeof(t->results[i].reason) - 1);
            }
        }
    }

cleanup_locks:
    if (cfg->scan_type == NP_SCAN_UDP)
        np_print_udp_host_summary(t);

    pthread_mutex_destroy(&metrics_lock);
    pthread_mutex_destroy(&completed_lock);

    return NP_OK;
}

/* ═══════════════════════════════════════════════════════════════
 *  PARALLEL HOST SCANNING
 * ═══════════════════════════════════════════════════════════════ */

/* ── Host work queue: indices into cfg->targets[] ──────────── */

typedef struct
{
    uint32_t *indices; /* array of target indices       */
    uint32_t count;    /* total items                   */
    uint32_t next;     /* next index to hand out        */
    pthread_mutex_t lock;
} np_host_queue_t;

static void
np_hq_init(np_host_queue_t *hq, uint32_t count)
{
    hq->indices = calloc(count, sizeof(uint32_t));
    hq->count = count;
    hq->next = 0;
    pthread_mutex_init(&hq->lock, NULL);

    for (uint32_t i = 0; i < count; i++)
        hq->indices[i] = i;
}

static void
np_hq_destroy(np_host_queue_t *hq)
{
    free(hq->indices);
    hq->indices = NULL;
    pthread_mutex_destroy(&hq->lock);
}

/* Shuffle for scan randomization */
static void
np_hq_shuffle(np_host_queue_t *hq)
{
    if (hq->count < 2)
        return;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for (uint32_t i = hq->count - 1; i > 0; i--)
    {
        uint32_t j = (uint32_t)(rand() % (i + 1));
        uint32_t tmp = hq->indices[i];
        hq->indices[i] = hq->indices[j];
        hq->indices[j] = tmp;
    }
}

/*
 * Pop the next target index. Returns false when exhausted.
 */
static bool
np_hq_pop(np_host_queue_t *hq, uint32_t *out_idx)
{
    bool got = false;
    pthread_mutex_lock(&hq->lock);
    if (hq->next < hq->count)
    {
        *out_idx = hq->indices[hq->next++];
        got = true;
    }
    pthread_mutex_unlock(&hq->lock);
    return got;
}

/* ── Progress tracking for parallel mode ──────────────────── */

typedef struct
{
    uint32_t hosts_completed;
    uint32_t hosts_total;
    pthread_mutex_t lock;
} np_host_progress_t;

static void
np_hp_init(np_host_progress_t *hp, uint32_t total)
{
    hp->hosts_completed = 0;
    hp->hosts_total = total;
    pthread_mutex_init(&hp->lock, NULL);
    np_stats_set_hosts_total(total);
}

static void
np_hp_destroy(np_host_progress_t *hp)
{
    pthread_mutex_destroy(&hp->lock);
}

static void
np_hp_advance(np_host_progress_t *hp, const char *hostname)
{
    pthread_mutex_lock(&hp->lock);
    hp->hosts_completed++;
    uint32_t done = hp->hosts_completed;
    uint32_t total = hp->hosts_total;
    pthread_mutex_unlock(&hp->lock);

    np_stats_inc_hosts_completed();

    np_error(NP_ERR_RUNTIME, "\r[*] Progress: %u/%u hosts (%.0f%%) — finished %s    ",
            done, total,
            total > 0 ? (done * 100.0 / total) : 100.0,
            hostname);
}

/* ── Host worker argument ─────────────────────────────────── */

typedef struct
{
    np_config_t *cfg;                   /* original global config     */
    np_host_queue_t *host_queue;        /* shared host index queue    */
    np_host_progress_t *progress;       /* shared progress tracker    */
    volatile sig_atomic_t *interrupted; /* shared interrupt flag      */
    bool syn_shared;                    /* SYN engine pre-initialized */
    uint32_t threads_per_host;          /* port threads per host  */
} np_host_worker_arg_t;

/*
 * Host worker thread function.
 * Each invocation loops: pop a target index → scan it → repeat.
 */
static void *
np_host_worker(void *arg)
{
    np_host_worker_arg_t *wa = arg;
    uint32_t tidx;

    while (!*wa->interrupted && np_hq_pop(wa->host_queue, &tidx))
    {
        np_target_t *real_target = &wa->cfg->targets[tidx];

        /*
         * Build a lightweight per-target config.
         * We shallow-copy the global config and override only
         * target pointer/count and thread count.
         *
         * Each host gets its own copy so there are no data races
         * on mutable fields (results, etc.).
         */
        np_config_t per_host;
        memcpy(&per_host, wa->cfg, sizeof(np_config_t));

        per_host.targets = real_target;
        per_host.target_count = 1;
        per_host.threads = wa->threads_per_host;

        LOGD("Host worker starting target %u: %s",
             tidx, real_target->hostname);

        np_status_t rc = np_scanner_run_single_target_internal(
            &per_host, wa->interrupted, wa->syn_shared);

        if (rc != NP_OK && !*wa->interrupted)
        {
            LOGW("Scan failed for %s: %s",
                 real_target->hostname, np_status_str(rc));
        }

        np_hp_advance(wa->progress, real_target->hostname);
    }

    return NULL;
}

/* ───────────────────────────────────────────── */
/* Resolve scan type once for all targets        */
/* ───────────────────────────────────────────── */

static np_status_t
np_resolve_scan_type(np_config_t *cfg)
{
    if (cfg->scan_type_forced)
    {
        if (np_scan_type_requires_raw(cfg->scan_type) && !np_have_raw_socket_privilege())
        {
            np_error(NP_ERR_RUNTIME, "[!] Selected scan type requires root privileges\n");
            return NP_ERR_PRIVILEGE_REQUIRED;
        }

        return NP_OK;
    }

    if (cfg->scan_mode == NP_SCAN_AUTO)
    {
        cfg->scan_type = np_have_raw_socket_privilege()
                             ? NP_SCAN_TCP_SYN
                             : NP_SCAN_TCP_CONNECT;
    }
    else if (cfg->scan_mode == NP_SCAN_SYN)
    {
        if (!np_have_raw_socket_privilege())
        {
            np_error(NP_ERR_RUNTIME, "[!] SYN scan requires root privileges\n");
            return NP_ERR_PRIVILEGE_REQUIRED;
        }
        cfg->scan_type = NP_SCAN_TCP_SYN;
    }
    else
    {
        cfg->scan_type = NP_SCAN_TCP_CONNECT;
    }
    return NP_OK;
}

static uint64_t
np_progress_work_total_legacy(const np_config_t *cfg)
{
    if (!cfg)
        return 0;

    uint64_t total = cfg->target_count;

    if (np_scan_type_is_raw_tcp(cfg->scan_type))
        total += 1;

    if (!cfg->framework_mode && cfg->service_version_detect)
        total += 2;

    if (!cfg->framework_mode && cfg->tls_info)
        total += 1;

    if (!cfg->framework_mode && cfg->os_detect)
        total += 1;

    return total > 0 ? total : 1;
}

/* ═══════════════════════════════════════════════════════════════
 *  PUBLIC ENTRY — np_scanner_run()
 *
 *  ● 1 target  → direct single-target scan (no overhead)
 *  ● N targets → parallel host workers
 * ═══════════════════════════════════════════════════════════════ */

np_status_t
np_scanner_run(np_config_t *cfg,
               volatile sig_atomic_t *interrupted)
{
    if (!cfg || cfg->target_count == 0)
        return NP_ERR_ARGS;

    np_arena_t *scan_arena = np_arena_create(NP_ARENA_DEFAULT_BLOCK_SIZE);
    if (!scan_arena)
        return NP_ERR_MEMORY;

    np_stats_reset();
    np_stats_set_hosts_total(cfg->target_count);
    np_stats_set_work_total(cfg->target_count > 0 ? cfg->target_count : 1);
    (void)np_stats_display_start(cfg);

    /* ── Step 1: Resolve scan type globally ─────────────── */
    np_status_t rc = np_resolve_scan_type(cfg);
    if (rc != NP_OK)
    {
        np_arena_destroy(scan_arena);
        np_stats_display_stop();
        return rc;
    }

    if (cfg->scan_type == NP_SCAN_UDP)
    {
        rc = np_udp_require_icmp_support(cfg);
        if (rc != NP_OK)
        {
            np_arena_destroy(scan_arena);
            np_stats_display_stop();
            return rc;
        }
    }

    uint64_t total_ports = (cfg->scan_type == NP_SCAN_IP_PROTOCOL)
                               ? 256
                               : np_ports_total(&cfg->ports);

    np_error(NP_ERR_RUNTIME, "[*] %s scan: %u target(s), %lu port(s) each\n",
            np_scan_type_name(cfg->scan_type),
            cfg->target_count,
            (unsigned long)total_ports);

    if (cfg->engine_mode == NP_ENGINE_FULL)
    {
        if (np_full_mode_supported(cfg->scan_type))
        {
            np_stats_set_work_total(cfg->target_count > 0 ? cfg->target_count : 1);
            np_status_t full_rc = np_full_runtime_run(cfg, interrupted);
            np_arena_destroy(scan_arena);
            np_stats_display_stop();
            return full_rc;
        }

        np_error(NP_ERR_RUNTIME,
                 "[!] Full mode unsupported for this scan type, using legacy engine\n");
    }

    np_stats_set_work_total(np_progress_work_total_legacy(cfg));

    /* ── Step 2: Single target fast path ────────────────── */
    if (cfg->target_count == 1)
    {
        if (np_scan_type_is_raw_tcp(cfg->scan_type))
        {
            np_syn_set_tcp_flags(np_scan_type_tcp_flags(cfg));
            np_syn_init();
            np_icmp_init();
            np_start_receiver(cfg);
            usleep(20000);
        }

        rc = np_scanner_run_single_target_internal(cfg, interrupted,
                                                   np_scan_type_is_raw_tcp(cfg->scan_type));

        if (rc == NP_OK)
            np_stats_inc_hosts_completed();

        if (np_scan_type_is_raw_tcp(cfg->scan_type))
        {
            np_error(NP_ERR_RUNTIME, "[*] Waiting for final SYN replies...\n");
            sleep(2);
            np_stop_receiver();
            np_syn_close();
            np_icmp_close();

            if (rc == NP_OK)
                np_stats_inc_work_completed(1);
        }

        if (rc != NP_OK)
        {
            np_arena_destroy(scan_arena);
            np_stats_display_stop();
            return rc;
        }

        if (!cfg->framework_mode && cfg->service_version_detect)
        {
            np_status_t sv_rc = np_service_version_run(cfg);
            if (sv_rc != NP_OK)
            {
                np_arena_destroy(scan_arena);
                np_stats_display_stop();
                return sv_rc;
            }
            np_stats_inc_work_completed(1);

            sv_rc = np_service_detect_run(cfg);
            if (sv_rc != NP_OK)
            {
                np_arena_destroy(scan_arena);
                np_stats_display_stop();
                return sv_rc;
            }
            np_stats_inc_work_completed(1);
        }

        if (!cfg->framework_mode && cfg->tls_info)
        {
            np_status_t tls_rc = np_tls_probe_run(cfg);
            if (tls_rc != NP_OK)
            {
                np_arena_destroy(scan_arena);
                np_stats_display_stop();
                return tls_rc;
            }

            np_stats_inc_work_completed(1);
        }

        if (!cfg->framework_mode && cfg->os_detect)
        {
            (void)np_scan_os_detect_run(cfg, interrupted);
            np_stats_inc_work_completed(1);
        }

        np_arena_destroy(scan_arena);
        np_stats_display_stop();
        return NP_OK;
    }

    /* ── Step 3: Multi-target parallel path ─────────────── */

    uint32_t host_par = np_compute_host_parallelism(cfg);

    /*
     * Divide total thread budget across host workers.
     * If user said --threads 200 and we have 16 host workers,
     * each host gets 200/16 ≈ 12 port threads.
     */
    uint32_t total_threads = cfg->threads ? cfg->threads : NP_DEFAULT_THREADS;
    uint32_t threads_per_host = total_threads / host_par;
    if (threads_per_host < 1)
        threads_per_host = 1;

    if (cfg->min_parallelism > 0 && threads_per_host < cfg->min_parallelism)
        threads_per_host = cfg->min_parallelism;

    if (cfg->max_parallelism > 0 && threads_per_host > cfg->max_parallelism)
        threads_per_host = cfg->max_parallelism;

    np_error(NP_ERR_RUNTIME, "[*] Parallel mode: %u host workers, %u port threads each\n",
            host_par, threads_per_host);

    /* ── Step 3a: Initialize shared SYN engine (once) ───── */
    bool syn_shared = false;
    if (np_scan_type_is_raw_tcp(cfg->scan_type))
    {
        np_syn_set_tcp_flags(np_scan_type_tcp_flags(cfg));
        np_syn_init();
        np_icmp_init();
        np_start_receiver(cfg);
        usleep(20000);
        syn_shared = true;
    }

    /* ── Step 3b: Build host work queue ─────────────────── */
    np_host_queue_t host_queue;
    np_hq_init(&host_queue, cfg->target_count);

    /* Randomize host order to spread network load */
    if (cfg->randomize_hosts)
        np_hq_shuffle(&host_queue);

    /* ── Step 3c: Progress tracker ──────────────────────── */
    np_host_progress_t progress;
    np_hp_init(&progress, cfg->target_count);

    /* ── Step 3d: Launch host worker threads ────────────── */
    pthread_t *host_threads = np_arena_alloc(scan_arena, host_par * sizeof(pthread_t));
    np_host_worker_arg_t *worker_args = np_arena_alloc(scan_arena,
                                                       host_par * sizeof(np_host_worker_arg_t));

    if (!host_threads || !worker_args)
    {
        np_hq_destroy(&host_queue);
        np_hp_destroy(&progress);
        np_arena_destroy(scan_arena);
        np_stats_display_stop();
        if (syn_shared)
        {
            np_stop_receiver();
            np_syn_close();
            np_icmp_close();
        }
        return NP_ERR_MEMORY;
    }

    for (uint32_t i = 0; i < host_par; i++)
    {
        worker_args[i].cfg = cfg;
        worker_args[i].host_queue = &host_queue;
        worker_args[i].progress = &progress;
        worker_args[i].interrupted = interrupted;
        worker_args[i].syn_shared = syn_shared;
        worker_args[i].threads_per_host = threads_per_host;

        int err = pthread_create(&host_threads[i], NULL,
                                 np_host_worker, &worker_args[i]);
        if (err != 0)
        {
            LOGE("Failed to create host worker %u: %s", i, strerror(err));
            /* Mark remaining as not created */
            for (uint32_t j = i; j < host_par; j++)
                host_threads[j] = 0;
            break;
        }
    }

    /* ── Step 3e: Wait for all host workers ─────────────── */
    for (uint32_t i = 0; i < host_par; i++)
    {
        if (host_threads[i])
            pthread_join(host_threads[i], NULL);
    }

    np_error(NP_ERR_RUNTIME, "\n"); /* clear progress line */

    /* ── Step 3f: Teardown shared SYN engine ────────────── */
    if (syn_shared)
    {
        np_error(NP_ERR_RUNTIME, "[*] Waiting for final SYN replies...\n");
        sleep(2);
        np_stop_receiver();
        np_syn_close();
        np_icmp_close();

        /* Sweep all targets for unanswered SYN probes */
        for (uint32_t t = 0; t < cfg->target_count; t++)
        {
            np_target_t *tgt = &cfg->targets[t];
            if (!tgt->results)
                continue;
            for (uint32_t p = 0; p < tgt->port_count; p++)
            {
                if (!tgt->results[p].completed)
                {
                    tgt->results[p].state = np_default_noresp_state(cfg->scan_type);
                    strncpy(tgt->results[p].reason,
                            "no-response",
                            sizeof(tgt->results[p].reason) - 1);
                }
            }
        }

        np_stats_inc_work_completed(1);
    }

    /* ── Cleanup ────────────────────────────────────────── */
    np_hq_destroy(&host_queue);
    np_hp_destroy(&progress);
    np_arena_destroy(scan_arena);

    if (!cfg->framework_mode && cfg->service_version_detect)
    {
        np_status_t sv_rc = np_service_version_run(cfg);
        if (sv_rc != NP_OK)
        {
            np_stats_display_stop();
            return sv_rc;
        }

        np_stats_inc_work_completed(1);

        sv_rc = np_service_detect_run(cfg);
        if (sv_rc != NP_OK)
        {
            np_stats_display_stop();
            return sv_rc;
        }

        np_stats_inc_work_completed(1);
    }

    if (!cfg->framework_mode && cfg->tls_info)
    {
        np_status_t tls_rc = np_tls_probe_run(cfg);
        if (tls_rc != NP_OK)
        {
            np_stats_display_stop();
            return tls_rc;
        }

        np_stats_inc_work_completed(1);
    }

    if (!cfg->framework_mode && cfg->os_detect)
    {
        (void)np_scan_os_detect_run(cfg, interrupted);
        np_stats_inc_work_completed(1);
    }

    np_stats_display_stop();

    return NP_OK;
}
