/* ================================================================
 * os_stages.c — Multi-stage OS Detection Pipeline
 *
 * REWRITTEN: Integrates np_os_banner library for robust banner
 * collection and matching, replacing the old sub_banner_worker /
 * stage_banner_collect / stage_banner_grab implementations.
 *
 * Key changes from original:
 *   - stage_banner_collect() now uses np_os_banner_grab() which
 *     provides protocol-specific probes (HTTP, SSH, FTP, SMTP,
 *     Telnet) with fallback probes for unknown ports.
 *   - stage_banner_grab() now uses np_os_banner_match() against
 *     a signature database instead of hardcoded substring checks.
 *   - sub_banner_worker() replaced by banner_worker_new() which
 *     delegates entirely to np_os_banner_grab().
 *   - All other stages (port discovery, TCP probes, fingerprint
 *     build/match, fusion, orchestrator) remain unchanged.
 *
 * Pipeline stages:
 *   0. Localhost detection
 *   1. Port discovery
 *   2. TCP fingerprint probes
 *   3. Fingerprint build
 *   4. Fingerprint match
 *   5. Banner collection   (REWRITTEN: np_os_banner_grab)
 *   6. Banner analysis      (REWRITTEN: np_os_banner_match)
 *   7. Result fusion
 * ================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "ports.h"
#include "logger.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "os_pipeline_priv.h"
#include "os_signatures.h"
#include "os_fingerprint_score.h"
#include "os_sigload.h"
#include "os_banner.h" /* NEW: robust banner grab + match API */
#include "passive_fp.h"

#define NP_MIN_PROBE_RESPONSES 3
#define NP_MAX_FP_SCORE 120
#define NP_MAX_CONFIDENCE 95.0
#define NP_CLOSED_PORT_FALLBACK 54321
#define NP_BANNER_TIMEOUT_SEC 2
#define NP_BANNER_TIMEOUT_USEC 0
#define NP_BANNER_CONNECT_TIMEOUT_MS 2000

/* ================================================================
 * File-local mutex for banner worker synchronization.
 *
 * Protects ctx->banner_count and ctx->banners[] during concurrent
 * writes from banner worker threads.
 * ================================================================ */
static pthread_mutex_t banner_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================================================================ */
/* Forward declarations                                             */
/* ================================================================ */

static uint16_t find_closed_port(np_pipeline_ctx_t *ctx);
static int try_connect_port(const char *ip, uint16_t port,
                            int timeout_ms);

/* NEW: banner worker context for the rewritten banner stage */
typedef struct
{
    np_pipeline_ctx_t *ctx;
    uint16_t port;
} banner_task_t;

static void *banner_worker_new(void *arg);

/* ================================================================ */
/* Localhost Detection                                              */
/* ================================================================ */

void detect_localhost_os(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_DEBUG, "stage",
             "localhost check target=%s",
             ctx ? ctx->target_ip : "NULL");

    if (!ctx)
        return;

    if (!strcmp(ctx->target_ip, "127.0.0.1") ||
        !strcmp(ctx->target_ip, "::1"))
    {
        ctx->is_localhost = 1;

#ifdef __APPLE__
        strncpy(ctx->os_result.best_family, "Darwin/macOS", 31);
#elif __linux__
        strncpy(ctx->os_result.best_family, "Linux", 31);
#else
        strncpy(ctx->os_result.best_family, "Localhost", 31);
#endif

        ctx->final_confidence = 100.0;

        pipe_log(NP_PIPE_LOG_INFO, "stage",
                 "localhost detected os=%s confidence=100",
                 ctx->os_result.best_family);
    }
    else
    {
        ctx->is_localhost = 0;
        pipe_log(NP_PIPE_LOG_DEBUG, "stage", "not localhost");
    }
}

/* ================================================================ */
/* Internal: Try connecting to a port (with timeout via select)     */
/* ================================================================ */

static int try_connect_port(const char *ip, uint16_t port,
                            int timeout_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0)
    {
        close(sock);
        return 1; /* Immediate connect — open */
    }

    if (errno != EINPROGRESS)
    {
        close(sock);
        return 0; /* Refused — closed */
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(sock + 1, NULL, &wset, NULL, &tv);
    if (ret > 0)
    {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        close(sock);
        return (err == 0) ? 1 : 0;
    }

    close(sock);
    return -1; /* Timeout / filtered */
}

/* ================================================================ */
/* Internal: Find a closed port                                     */
/* ================================================================ */

static uint16_t find_closed_port(np_pipeline_ctx_t *ctx)
{
    if (ctx && ctx->closed_port > 0)
    {
        pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                 "closed port already verified=%u",
                 ctx->closed_port);
        return ctx->closed_port;
    }

    static const uint16_t fallback_ports[] = {54321, 33456, 40000};
    int n_fallbacks = sizeof(fallback_ports) / sizeof(fallback_ports[0]);

    int timeout_ms = 300;
    if (ctx && ctx->config)
    {
        const np_config_t *cfg = (const np_config_t *)ctx->config;
        if (cfg->timeout_ms > 0 && cfg->timeout_ms < 500)
            timeout_ms = (int)cfg->timeout_ms;
    }

    /* Quick check on a small set of fallback candidate ports */
    for (int i = 0; i < n_fallbacks; i++)
    {
        int result = try_connect_port(ctx->target_ip, fallback_ports[i], timeout_ms);
        if (result == 0)
        {
            pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                     "closed port verified=%u (fallback probe)",
                     fallback_ports[i]);
            return fallback_ports[i];
        }
    }

    pipe_log(NP_PIPE_LOG_WARN, "stage",
             "no verified closed port (target drops closed ports), using fallback=%u",
             NP_CLOSED_PORT_FALLBACK);

    return NP_CLOSED_PORT_FALLBACK;
}

/* ================================================================ */
/* Port Discovery                                                   */
/* ================================================================ */

int stage_port_discovery(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "port discovery start target=%s",
             ctx ? ctx->target_ip : "NULL");

    if (!ctx || !ctx->target_ip[0])
        return -1;

    if (ctx->open_port_count > 0)
    {
        if (ctx->primary_open_port == 0)
            ctx->primary_open_port = ctx->open_ports[0];
        if (ctx->closed_port == 0)
            ctx->closed_port = find_closed_port(ctx);

        pipe_log(NP_PIPE_LOG_INFO, "stage",
                 "using pre-discovered ports: primary_open=%u closed=%u total_open=%u",
                 ctx->primary_open_port, ctx->closed_port, ctx->open_port_count);

        return 0;
    }

    if (ctx->user_port)
    {
        ctx->primary_open_port = ctx->user_port;
        if (ctx->open_port_count == 0)
        {
            ctx->open_ports[0] = ctx->user_port;
            ctx->open_port_count = 1;
        }
        if (ctx->closed_port == 0)
            ctx->closed_port = NP_CLOSED_PORT_FALLBACK;

        pipe_log(NP_PIPE_LOG_INFO, "stage",
                 "using user-specified port=%u closed=%u",
                 ctx->user_port, ctx->closed_port);

        return 0;
    }

    pthread_t threads[NUM_SCAN_THREADS];
    port_scan_task_t tasks[NUM_SCAN_THREADS];

    int total = np_top_ports_count;
    int per = total / NUM_SCAN_THREADS;
    int extra = total % NUM_SCAN_THREADS;
    int idx = 0;

    bool thread_started[NUM_SCAN_THREADS];
    memset(thread_started, 0, sizeof(thread_started));

    for (int i = 0; i < NUM_SCAN_THREADS; i++)
    {
        int count = per + (i < extra);
        tasks[i].ctx = ctx;
        tasks[i].ports_to_scan = &np_top_ports_top_1000[idx];
        tasks[i].num_ports = count;

        if (count > 0)
        {
            if (pthread_create(&threads[i], NULL,
                               thread_port_discovery_worker,
                               &tasks[i]) == 0)
            {
                thread_started[i] = true;
            }
        }
        idx += count;
    }

    for (int i = 0; i < NUM_SCAN_THREADS; i++)
        if (thread_started[i])
            pthread_join(threads[i], NULL);

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "port discovery finished open_ports=%u",
             ctx->open_port_count);

    if (!ctx->open_port_count)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "no open ports found");
        return -1;
    }

    /* Pick the first discovered open port as primary (default) */
    ctx->primary_open_port = ctx->open_ports[0];

    /* Prefer well-known ports for better fingerprint quality */
    static const uint16_t preferred[] = {80, 443, 22, 8080, 25, 21};
    int n_preferred = sizeof(preferred) / sizeof(preferred[0]);

    for (int p = 0; p < n_preferred; p++)
    {
        for (uint32_t j = 0; j < ctx->open_port_count; j++)
        {
            if (ctx->open_ports[j] == preferred[p])
            {
                ctx->primary_open_port = preferred[p];
                pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                         "preferred primary port=%u", preferred[p]);
                goto primary_selected;
            }
        }
    }
primary_selected:

    /* Discover a closed port for RST-based probes */
    ctx->closed_port = find_closed_port(ctx);

    if (ctx->config)
    {
        const np_config_t *cfg = (const np_config_t *)ctx->config;
        if (cfg->osscan_limit &&
            (ctx->open_port_count == 0 || ctx->closed_port == NP_CLOSED_PORT_FALLBACK))
        {
            pipe_log(NP_PIPE_LOG_WARN, "stage",
                     "osscan-limit active: insufficient open/closed evidence");
            return -1;
        }
    }

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "ports selected primary_open=%u closed=%u "
             "total_open=%u",
             ctx->primary_open_port,
             ctx->closed_port,
             ctx->open_port_count);

    return 0;
}

/* ================================================================ */
/* TCP Probes                                                       */
/* ================================================================ */

int np_os_pipeline_run_probes(
    const char *target_ip,
    uint16_t open_port,
    uint16_t closed_port,
    const np_config_t *config,
    np_tcp_probe_set_t *responses)
{
    pipe_log(NP_PIPE_LOG_INFO, "probes",
             "run probes target=%s open=%u closed=%u",
             target_ip, open_port, closed_port);

    if (!target_ip || !responses)
        return -1;

    if (closed_port == 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "probes",
                 "closed_port is 0, using fallback=%u",
                 NP_CLOSED_PORT_FALLBACK);
        closed_port = NP_CLOSED_PORT_FALLBACK;
    }

    if (open_port == 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "probes",
                 "open_port is 0 — probes will likely fail");
        return -1;
    }

    np_tcp_probe_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.target.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &cfg.target.sin_addr) <= 0)
        return -1;

    cfg.open_port = open_port;
    cfg.closed_port = closed_port;
    cfg.timeout_ms = (config && config->timeout_ms > 0)
                         ? config->timeout_ms
                         : 300;

    return np_run_tcp_probes(&cfg, responses);
}

int stage_tcp_probes(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "tcp probes start open=%u closed=%u",
             ctx ? ctx->primary_open_port : 0,
             ctx ? ctx->closed_port : 0);

    if (!ctx)
        return -1;

    if (ctx->primary_open_port == 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "no open port available for TCP fingerprint probes");
        return -1;
    }

    memset(&ctx->probe_results, 0, sizeof(ctx->probe_results));
    memset(&ctx->active_vector, 0, sizeof(ctx->active_vector));
    ctx->probe_response_count = 0;

    np_tcp_fp_cfg_t fp_cfg;
    memset(&fp_cfg, 0, sizeof(fp_cfg));
    fp_cfg.open_port = ctx->primary_open_port;
    fp_cfg.closed_port = ctx->closed_port;
    fp_cfg.timeout_ms = 300;

    if (ctx->config)
    {
        const np_config_t *cfg = (const np_config_t *)ctx->config;
        if (cfg->timeout_ms > 0)
            fp_cfg.timeout_ms = (int)cfg->timeout_ms;
        if (cfg->osscan_limit && ctx->open_port_count == 0)
            return -1;
    }

    fp_cfg.target.sin_family = AF_INET;
    if (inet_pton(AF_INET, ctx->target_ip, &fp_cfg.target.sin_addr) <= 0)
        return -1;

    if (np_tcp_fp_run(&fp_cfg, &ctx->active_vector) != 0)
        return -1;

    ctx->probe_results = ctx->active_vector.tcp;

    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
        if (ctx->probe_results.probes[i].responded)
            ctx->probe_response_count++;

    ctx->probes_valid =
        ctx->probe_response_count >= NP_MIN_PROBE_RESPONSES;

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "tcp probes responses=%d valid=%d",
             ctx->probe_response_count,
             ctx->probes_valid);

    if (!ctx->probes_valid)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "insufficient probe responses (min=%d)",
                 NP_MIN_PROBE_RESPONSES);
        return -1;
    }

    return 0;
}

/* ================================================================ */
/* Fingerprint Build                                                */
/* ================================================================ */

int stage_fingerprint_build(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "fingerprint build start");

    if (!ctx || !ctx->probes_valid)
        return -1;

    memset(&ctx->fingerprint, 0, sizeof(ctx->fingerprint));

    if (np_os_pipeline_build_fingerprint(
            &ctx->probe_results,
            &ctx->fingerprint) != 0)
        return -1;

    ctx->fingerprint.ipid_behavior = ctx->active_vector.ipid_behavior;
    ctx->fingerprint.u1_responded = ctx->active_vector.u1.responded;
    ctx->fingerprint.u1_icmp_type = ctx->active_vector.u1.type;
    ctx->fingerprint.u1_icmp_code = ctx->active_vector.u1.code;
    ctx->fingerprint.u1_ttl = ctx->active_vector.u1.ttl;
    ctx->fingerprint.ts_rate = ctx->active_vector.seq.isr;

    np_passive_fp_accum_t pacc;
    np_passive_fp_init(&pacc);
    for (int i = 0; i < NP_MAX_TCP_PROBES; i++)
    {
        const np_tcp_probe_result_t *p = &ctx->probe_results.probes[i];
        if (!p->responded)
            continue;

        np_passive_fp_observe(&pacc,
                              p->ttl,
                              p->window,
                              p->df,
                              p->ip_id,
                              p->mss,
                              p->wscale,
                              p->sack,
                              p->timestamp,
                              p->syn && p->ack);
    }

    bool include_low = true;
    if (ctx->config)
        include_low = ((const np_config_t *)ctx->config)->osscan_guess;
    np_passive_fp_finalize(&pacc, include_low, &ctx->os_result);

    for (int i = 0; i < NP_MAX_TCP_PROBES && i < 7; i++)
    {
        ctx->fingerprint.probe_responded[i] =
            ctx->probe_results.probes[i].responded;
    }

    int responded_count = 0;
    for (int i = 0; i < 7; i++)
        if (ctx->fingerprint.probe_responded[i])
            responded_count++;

    pipe_log(NP_PIPE_LOG_DEBUG, "stage",
             "probe_responded set: count=%d [%d%d%d%d%d%d%d]",
             responded_count,
             ctx->fingerprint.probe_responded[0],
             ctx->fingerprint.probe_responded[1],
             ctx->fingerprint.probe_responded[2],
             ctx->fingerprint.probe_responded[3],
             ctx->fingerprint.probe_responded[4],
             ctx->fingerprint.probe_responded[5],
             ctx->fingerprint.probe_responded[6]);

    ctx->fingerprint_all_zero =
        fingerprint_is_all_zero(&ctx->fingerprint);
    ctx->fingerprint_valid = !ctx->fingerprint_all_zero;

    pipe_log(NP_PIPE_LOG_DEBUG, "stage",
             "fingerprint all_zero=%d valid=%d",
             ctx->fingerprint_all_zero,
             ctx->fingerprint_valid);

    pipe_log(NP_PIPE_LOG_DEBUG, "stage",
             "fp details: ttl=%u win=%u mss=%u df=%u "
             "sack=%u wscale=%u ts=%u probes_responded=%d",
             ctx->fingerprint.ttl,
             ctx->fingerprint.window_size,
             ctx->fingerprint.mss,
             ctx->fingerprint.df_bit,
             ctx->fingerprint.sack_permitted,
             ctx->fingerprint.window_scale,
             ctx->fingerprint.timestamp,
             responded_count);

    if (!ctx->fingerprint_valid)
    {
        ctx->fp_valid = 0;
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "fingerprint invalid or empty");
        return -1;
    }

    ctx->fp_valid = 1;

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "fingerprint marked valid (fp_valid=1)");

    return 0;
}

/* ================================================================ */
/* Fingerprint Match                                                */
/* ================================================================ */

int stage_fingerprint_match(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "fingerprint match start");

    if (!ctx || !ctx->fingerprint_valid)
        return -1;

    if (!ctx->db)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "signature database is NULL");
        return -1;
    }

    int sig_count = np_sigdb_count(ctx->db);
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "signature db loaded sig_count=%d", sig_count);

    if (sig_count <= 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "signature database is EMPTY — cannot match");
        return -1;
    }

    double conf = 0.0;
    const char *os =
        np_sigdb_match_fp(ctx->db, &ctx->fingerprint, &conf);

    pipe_log(NP_PIPE_LOG_DEBUG, "stage",
             "sigdb raw match result os=%s conf=%.1f",
             os ? os : "(null)", conf);

    if (!os || conf < 15.0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "fingerprint match failed os=%s conf=%.1f "
                 "(threshold=15.0)",
                 os ? os : "(null)", conf);
        return -1;
    }

    ctx->fp_valid = true;
    ctx->fp_score = (uint8_t)(conf > 100.0 ? 100.0 : conf);

    ctx->candidate_count = 1;
    strncpy(ctx->candidates[0].os_name, os,
            sizeof(ctx->candidates[0].os_name) - 1);
    ctx->candidates[0].os_name[sizeof(ctx->candidates[0].os_name) - 1] = '\0';

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "fingerprint matched os=%s conf=%.1f",
             os, conf);

    return 0;
}
/* ================================================================ */
/* NEW: Banner Collection (uses np_os_banner_grab)                  */
/* ================================================================ */
/*
 * REPLACES: stage_banner_collect() + banner_worker_new()
 *
 * np_os_banner_grab() handles ALL ports in a single call.
 * It manages its own connections, protocol detection, probing,
 * and timeouts internally. No per-port worker threads needed.
 *
 * The Nmap engine performs BOTH collection AND matching in one pass:
 *   1. Connects to each port
 *   2. Sends protocol-appropriate probes
 *   3. Captures response banners
 *   4. Matches against Nmap signature database
 *   5. Populates service, product, version, os_hint, etc.
 *
 * Therefore stage_banner_collect does the grab, and
 * stage_banner_grab only needs to handle fallback heuristics
 * for any banners the Nmap engine couldn't identify.
 */

int stage_banner_collect(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "banner collection start (np_os_banner_grab) "
             "open_ports=%u",
             ctx ? ctx->open_port_count : 0);

    if (!ctx)
        return -1;

    if (ctx->open_port_count == 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "no open ports for banner collection");
        return 0;
    }

    /* Zero out ALL prior results — critical for safety */
    memset(&ctx->os_result, 0, sizeof(ctx->os_result));
    ctx->banner_count = 0;
    ctx->banner_match_count = 0;

    if (ctx->open_port_count == 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "banner collection skipped: no open ports "
                 "available (port discovery may have failed)");
        return -1;
    }

    /* ============================================================
     * Build an np_target_t from the pipeline context.
     * ============================================================ */
    np_target_t target;
    memset(&target, 0, sizeof(target));
    strncpy(target.ip, ctx->target_ip, sizeof(target.ip) - 1);
    target.ip[sizeof(target.ip) - 1] = '\0';

    /* Clamp port count to our internal max */
    uint32_t port_count = ctx->open_port_count;
    if (port_count > NP_PIPELINE_MAX_BANNER_PORTS)
        port_count = NP_PIPELINE_MAX_BANNER_PORTS;

    pipe_log(NP_PIPE_LOG_DEBUG, "stage",
             "calling np_os_banner_grab for %u ports, "
             "timeout=%d ms",
             port_count, NP_BANNER_CONNECT_TIMEOUT_MS);

    /* ============================================================
     * Single call — the Nmap engine handles everything.
     * Results go directly into ctx->os_result.
     * ============================================================ */
    np_status_t rc = np_os_banner_grab(
        &target,
        ctx->open_ports,
        port_count,
        NP_BANNER_CONNECT_TIMEOUT_MS,
        NULL,
        &ctx->os_result
    );

    if (rc != NP_STATUS_OK)
    {
        pipe_log(NP_PIPE_LOG_WARN, "stage",
                 "np_os_banner_grab failed rc=%d", (int)rc);
        /* Zero out to be safe — don't trust partial results */
        ctx->os_result.banner_count = 0;
        ctx->banner_count = 0;
        return 0;
    }

    /* ============================================================
     * Sanitize results: np_os_banner_grab may have returned
     * entries with garbage or uninitialized fields. Validate
     * each banner entry before trusting it.
     * ============================================================ */
    uint32_t valid_count = 0;

    for (uint32_t i = 0; i < ctx->os_result.banner_count &&
                          i < NP_OS_MAX_BANNERS; i++)
    {
        np_os_banner_t *b = &ctx->os_result.banners[i];

        /* ── Validate port is one we actually requested ── */
        bool port_valid = false;
        for (uint32_t p = 0; p < port_count; p++)
        {
            if (b->port == ctx->open_ports[p])
            {
                port_valid = true;
                break;
            }
        }

        if (!port_valid)
        {
            pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                     "banner[%u] has invalid port=%u, skipping",
                     i, b->port);
            /* Zero out this entry so downstream won't use it */
            memset(b, 0, sizeof(*b));
            continue;
        }

        /* ── Ensure all strings are NUL-terminated ── */
        b->banner[sizeof(b->banner) - 1] = '\0';
        b->service[sizeof(b->service) - 1] = '\0';
        b->os_hint[sizeof(b->os_hint) - 1] = '\0';

        /* ── Clamp banner_len to actual buffer size ── */
        if (b->banner_len > sizeof(b->banner) - 1)
            b->banner_len = (uint32_t)strlen(b->banner);

        /* ── Clamp confidence to sane range ── */
        if (b->os_hint_confidence < 0 || b->os_hint_confidence > 100)
            b->os_hint_confidence = 0;


        valid_count++;

        /* ── Safe logging: use empty string instead of NULL ── */
        pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                 "banner[%u] port=%u len=%u svc='%s' "
                 "os_hint='%s' conf=%d "
                 "'%.80s'",
                 i, b->port, (unsigned)b->banner_len,
                 b->service[0]  ? b->service  : "(none)",
                 b->os_hint[0]  ? b->os_hint  : "(none)",
                 b->os_hint_confidence,
                 b->banner_len > 0 ? b->banner : "(empty)");
    }

    ctx->banner_count = (int)valid_count;

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "banner collection done banners=%d valid=%u "
             "(from %u ports)",
             (int)ctx->os_result.banner_count,
             valid_count, port_count);

    return 0;
}

/* ================================================================ */
/* NEW: Banner Analysis (fallback heuristics for unmatched banners)  */
/* ================================================================ */
/*
 * REPLACES: stage_banner_grab()
 *
 * The Nmap engine already performed signature matching during
 * np_os_banner_grab(). This stage only applies legacy heuristic
 * fallbacks for banners where the Nmap engine found no match
 * (os_hint is empty or confidence == 0).
 *
 * This preserves backward compatibility and catches common
 * cases that might not be in the Nmap signature DB.
 */

/* Hardcoded fallback heuristics (kept from original for resilience) */
static int banner_match_fallback(const char *banner,
                                 uint16_t port __attribute__((unused)),
                                 char *os_out, size_t os_out_sz)
{
    int conf = 0;

    if (!banner || !banner[0])
        return 0;

    /* --- SSH banners --- */
    if (strstr(banner, "OpenSSH"))
    {
        if (strstr(banner, "Ubuntu"))
        {
            strncpy(os_out, "Linux/Ubuntu", os_out_sz - 1);
            conf = 85;
        }
        else if (strstr(banner, "Debian"))
        {
            strncpy(os_out, "Linux/Debian", os_out_sz - 1);
            conf = 85;
        }
        else if (strstr(banner, "Raspbian"))
        {
            strncpy(os_out, "Linux/Raspbian", os_out_sz - 1);
            conf = 80;
        }
        else
        {
            strncpy(os_out, "Linux", os_out_sz - 1);
            conf = 55;
        }
    }
    /* --- HTTP banners --- */
    else if (strstr(banner, "Microsoft-IIS"))
    {
        strncpy(os_out, "Windows", os_out_sz - 1);
        conf = 90;
    }
    else if (strstr(banner, "Apache"))
    {
        /* Apache alone doesn't identify OS well */
        if (strstr(banner, "Ubuntu"))
        {
            strncpy(os_out, "Linux/Ubuntu", os_out_sz - 1);
            conf = 70;
        }
        else if (strstr(banner, "Debian"))
        {
            strncpy(os_out, "Linux/Debian", os_out_sz - 1);
            conf = 70;
        }
        else if (strstr(banner, "CentOS"))
        {
            strncpy(os_out, "Linux/CentOS", os_out_sz - 1);
            conf = 70;
        }
        else if (strstr(banner, "Red Hat"))
        {
            strncpy(os_out, "Linux/RHEL", os_out_sz - 1);
            conf = 70;
        }
        else
        {
            strncpy(os_out, "Linux", os_out_sz - 1);
            conf = 40;
        }
    }
    else if (strstr(banner, "nginx"))
    {
        strncpy(os_out, "Linux", os_out_sz - 1);
        conf = 35;
    }
    /* --- BSD --- */
    else if (strstr(banner, "FreeBSD"))
    {
        strncpy(os_out, "FreeBSD", os_out_sz - 1);
        conf = 75;
    }
    else if (strstr(banner, "OpenBSD"))
    {
        strncpy(os_out, "OpenBSD", os_out_sz - 1);
        conf = 75;
    }
    /* --- macOS / Darwin --- */
    else if (strstr(banner, "Darwin") || strstr(banner, "macOS"))
    {
        strncpy(os_out, "Darwin/macOS", os_out_sz - 1);
        conf = 80;
    }
    /* --- Windows other --- */
    else if (strstr(banner, "Windows") || strstr(banner, "Win32") ||
             strstr(banner, "Win64"))
    {
        strncpy(os_out, "Windows", os_out_sz - 1);
        conf = 65;
    }

    if (conf > 0)
        os_out[os_out_sz - 1] = '\0';

    return conf;
}

int stage_banner_grab(np_pipeline_ctx_t *ctx)
{
    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "banner analysis start count=%d",
             ctx ? ctx->banner_count : -1);

    if (!ctx)
        return -1;

    if (ctx->banner_count == 0)
    {
        pipe_log(NP_PIPE_LOG_INFO, "stage",
                 "no banners to analyze — skipping");
        return 0;
    }

    /* ============================================================
     * The Nmap engine already matched during np_os_banner_grab().
     * Here we only apply fallback heuristics for banners that
     * the engine couldn't identify (os_hint empty, confidence 0).
     * ============================================================ */
    int matched = 0;
    int fallback_applied = 0;

    for (uint32_t i = 0; i < ctx->os_result.banner_count &&
                          i < NP_OS_MAX_BANNERS; i++)
    {
        np_os_banner_t *b = &ctx->os_result.banners[i];

        /* Skip banners with no captured data */
        if (b->banner_len == 0)
            continue;

        /* ── Already matched by Nmap engine ── */
        if (b->os_hint[0] != '\0' && b->os_hint_confidence > 0)
        {
            matched++;
            pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                     "banner[%u] port=%u nmap matched "
                     "os='%s' conf=%d svc='%s'",
                     i, b->port, b->os_hint,
                     b->os_hint_confidence,
                     b->service);
            continue;
        }

        /* ── Fallback: try hardcoded heuristics ── */
        char os_name[NP_MAX_OS_HINT];
        memset(os_name, 0, sizeof(os_name));

        int conf = banner_match_fallback(b->banner, b->port,
                                         os_name, sizeof(os_name));
        if (conf > 0)
        {
            b->os_hint_confidence = conf;
            strncpy(b->os_hint, os_name, sizeof(b->os_hint) - 1);
            b->os_hint[sizeof(b->os_hint) - 1] = '\0';

            matched++;
            fallback_applied++;

            pipe_log(NP_PIPE_LOG_INFO, "stage",
                     "banner[%u] port=%u fallback matched "
                     "os='%s' conf=%d",
                     i, b->port, os_name, conf);
        }
        else
        {
            b->os_hint_confidence = 0;
            b->os_hint[0] = '\0';

            pipe_log(NP_PIPE_LOG_DEBUG, "stage",
                     "banner[%u] port=%u no OS match "
                     "(nmap or fallback) banner='%.60s'",
                     i, b->port, b->banner);
        }
    }

    ctx->banner_match_count = matched;

    pipe_log(NP_PIPE_LOG_INFO, "stage",
             "banner analysis done: %d/%d matched "
             "(%d via nmap engine, %d via fallback)",
             matched, ctx->banner_count,
             matched - fallback_applied, fallback_applied);

    return 0;
}
