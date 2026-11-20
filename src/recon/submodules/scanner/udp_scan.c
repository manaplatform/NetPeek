/*
 * sendmmsg(2), recvmmsg(2) and struct mmsghdr are glibc extensions gated by
 * _GNU_SOURCE. scanner_internal.h pins _POSIX_C_SOURCE, which hides them, so
 * request _GNU_SOURCE before any system header is pulled in. Linux only: the
 * call sites below are themselves guarded by __linux__.
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "scanner_internal.h"
#include "core/error.h"
#include "logger.h"
#include "runtime/stats.h"
#include "udp_probe_cache.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/errqueue.h>
#include <sys/uio.h>
#endif

#define UDP_EVENT_TIMEOUT_MS 10
#define UDP_RECV_BUF 2048
#define UDP_LATE_ICMP_GRACE_MS 250
#define UDP_MIN_TIMEOUT_MS 50
#define UDP_ICMP_BUDGET_PER_TICK 128
#define UDP_ICMP_BUDGET_FAST_PER_TICK 512

typedef struct udp_worker_stats
{
    uint64_t probes_sent;
    uint64_t retransmissions;
    uint64_t icmp_seen;
    uint64_t send_eagain;
} udp_worker_stats_t;

typedef struct udp_icmp_event
{
    bool matched;
    bool is_ipv6;
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t inner_src_port;
    uint16_t inner_dst_port;
    struct in_addr outer_src4;
    struct in6_addr outer_src6;
    np_port_state_t state;
    const char *reason;
} udp_icmp_event_t;

typedef struct udp_tx_entry
{
    int slot_idx;
} udp_tx_entry_t;

static int np_udp_icmp_budget_per_tick(const np_config_t *cfg)
{
    if (cfg && cfg->timing_template >= NP_TIMING_TEMPLATE_4)
        return UDP_ICMP_BUDGET_FAST_PER_TICK;
    return UDP_ICMP_BUDGET_PER_TICK;
}

static uint32_t np_udp_effective_min_probe_interval_us(const np_config_t *cfg)
{
    uint32_t base = (cfg && cfg->udp_min_probe_interval_us > 0) ? cfg->udp_min_probe_interval_us : 50000u;

    if (cfg && cfg->timing_template >= NP_TIMING_TEMPLATE_4 && base > 25000u)
        base = 25000u;

    if (cfg && cfg->scan_delay_us > base)
        base = cfg->scan_delay_us;

    return base;
}

static void np_wait_udp_probe_budget(const np_config_t *cfg, uint64_t *last_probe_us)
{
    if (!last_probe_us)
        return;

    uint64_t now = np_now_monotonic_us();
    if (*last_probe_us == 0)
    {
        *last_probe_us = now;
        return;
    }

    uint64_t min_interval = np_udp_effective_min_probe_interval_us(cfg);
    uint64_t earliest = *last_probe_us + min_interval;
    if (now < earliest)
        usleep((useconds_t)(earliest - now));

    *last_probe_us = np_now_monotonic_us();
}

static const char *np_udp_state_str(np_port_state_t state)
{
    switch (state)
    {
    case NP_PORT_OPEN:
        return "open";
    case NP_PORT_CLOSED:
        return "closed";
    case NP_PORT_FILTERED:
        return "filtered";
    case NP_PORT_OPEN_FILTERED:
        return "open|filtered";
    default:
        return "unknown";
    }
}

static void np_udp_log_result(const np_worker_ctx_t *ctx,
                              const np_work_item_t *item,
                              np_port_state_t state,
                              double rtt_ms,
                              const char *reason,
                              double confidence)
{
    const char *host = "unknown";
    if (ctx && ctx->cfg && item && item->target_idx < ctx->cfg->target_count)
    {
        const np_target_t *target = &ctx->cfg->targets[item->target_idx];
        if (target->hostname[0])
            host = target->hostname;
        else if (target->ip[0])
            host = target->ip;
    }

    LOGD("[udp] host=%s target_idx=%u port=%u attempt=%u state=%s rtt=%.2fms reason=%s conf=%.2f",
         host,
         item ? item->target_idx : 0,
         item ? item->port : 0,
         item ? item->attempt : 0,
         np_udp_state_str(state),
         rtt_ms,
         reason ? reason : "n/a",
         confidence);
}

static void np_udp_set_reason(np_worker_ctx_t *ctx,
                              const np_work_item_t *item,
                              const char *reason)
{
    if (!ctx || !ctx->cfg || !item || item->target_idx >= ctx->cfg->target_count)
        return;

    np_target_t *target = &ctx->cfg->targets[item->target_idx];
    if (item->port_idx >= target->port_count)
        return;

    np_port_result_t *res = &target->results[item->port_idx];
    if (!reason || !reason[0])
        res->reason[0] = '\0';
    else
    {
        strncpy(res->reason, reason, sizeof(res->reason) - 1);
        res->reason[sizeof(res->reason) - 1] = '\0';
    }
}

static void np_udp_set_confidence(np_worker_ctx_t *ctx,
                                  const np_work_item_t *item,
                                  double confidence)
{
    if (!ctx || !ctx->cfg || !item || item->target_idx >= ctx->cfg->target_count)
        return;

    np_target_t *target = &ctx->cfg->targets[item->target_idx];
    if (item->port_idx >= target->port_count)
        return;

    if (confidence < 0.0)
        confidence = 0.0;
    else if (confidence > 1.0)
        confidence = 1.0;

    target->results[item->port_idx].scan_confidence = confidence;
}

static void np_udp_note_rtt(conn_slot_t *slot, double sample_ms)
{
    if (!slot || sample_ms <= 0.0)
        return;

    if (slot->srtt_ms <= 0.0)
    {
        slot->srtt_ms = sample_ms;
        slot->rttvar_ms = sample_ms / 2.0;
        return;
    }

    double err = sample_ms - slot->srtt_ms;
    double abs_err = (err < 0.0) ? -err : err;
    slot->srtt_ms += 0.125 * err;
    slot->rttvar_ms += 0.25 * (abs_err - slot->rttvar_ms);
}

static void np_udp_record_result(np_worker_ctx_t *ctx,
                                 const np_work_item_t *item,
                                 np_port_state_t state,
                                 double rtt_ms,
                                 const char *reason,
                                 double confidence)
{
    np_udp_set_reason(ctx, item, reason);
    np_udp_set_confidence(ctx, item, confidence);

    bool drop_filtered = (ctx && ctx->cfg && ctx->cfg->drop_filtered_states);
    if (!(drop_filtered && state != NP_PORT_OPEN && state != NP_PORT_CLOSED))
        np_udp_log_result(ctx, item, state, rtt_ms, reason, confidence);

    np_record_result(ctx,
                     item->target_idx,
                     item->port_idx,
                     item->port,
                     state,
                     rtt_ms);
}

static uint8_t np_udp_dynamic_max_retries(const np_config_t *cfg,
                                          const conn_slot_t *slot,
                                          const udp_worker_stats_t *stats)
{
    uint8_t base = cfg ? (uint8_t)cfg->max_retries : 0;
    uint8_t extra = 0;

    if (stats && stats->probes_sent > 0)
    {
        double loss_ratio = (double)stats->retransmissions / (double)stats->probes_sent;
        if (loss_ratio >= 0.30)
            extra += 2;
        else if (loss_ratio >= 0.15)
            extra += 1;
    }

    if (slot && slot->rttvar_ms > 100.0)
        extra += 1;

    if (extra > 3)
        extra = 3;

    return (uint8_t)(base + extra);
}

static uint32_t np_udp_probe_timeout_ms(const np_config_t *cfg,
                                        const conn_slot_t *slot,
                                        uint32_t probe_wait_ms)
{
    uint32_t min_cfg = (cfg && cfg->min_rtt_timeout_ms > 0) ? cfg->min_rtt_timeout_ms : UDP_MIN_TIMEOUT_MS;
    uint32_t max_cfg = (cfg && cfg->max_rtt_timeout_ms > 0) ? cfg->max_rtt_timeout_ms : 10000;

    double srtt = (slot && slot->srtt_ms > 0.0)
                      ? slot->srtt_ms
                      : (double)np_effective_timeout_ms(cfg);
    double rttvar = (slot && slot->rttvar_ms > 0.0) ? slot->rttvar_ms : (srtt / 2.0);
    double scaled = (srtt * 2.5) + (4.0 * rttvar);

    uint32_t timeout = (uint32_t)((scaled > 0.0) ? scaled : UDP_MIN_TIMEOUT_MS);
    if (timeout < UDP_MIN_TIMEOUT_MS)
        timeout = UDP_MIN_TIMEOUT_MS;

    if (probe_wait_ms > timeout)
        timeout = probe_wait_ms;

    if (timeout < min_cfg)
        timeout = min_cfg;
    if (timeout > max_cfg)
        timeout = max_cfg;

    if (cfg && cfg->timing_template >= NP_TIMING_TEMPLATE_4)
    {
        timeout = timeout / 2u;
        if (timeout < 20u)
            timeout = 20u;
    }

    return timeout;
}

static int find_free_slot(conn_slot_t *slots, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (!slots[i].active)
            return i;
    }
    return -1;
}

static void close_slot(conn_slot_t *slot)
{
    if (!slot)
        return;

    slot->active = false;
    slot->zombie = false;
    slot->completed = false;
    slot->done = false;
    slot->peer_addr_len = 0;
    slot->peer_af = AF_UNSPEC;
    slot->peer_port = 0;
}

static void finalize_slot(conn_slot_t *slot,
                          np_worker_ctx_t *ctx,
                          int *active_count,
                          np_port_state_t state,
                          const char *reason,
                          double confidence)
{
    if (!slot || !slot->active)
        return;

    double rtt = np_timer_elapsed_ms(&slot->timer);
    np_udp_note_rtt(slot, rtt);
    np_udp_record_result(ctx, &slot->item, state, rtt, reason, confidence);
    close_slot(slot);
    if (active_count && *active_count > 0)
        (*active_count)--;
}

static bool requeue_slot_attempt(np_worker_ctx_t *ctx,
                                 conn_slot_t *slot,
                                 const udp_worker_stats_t *stats)
{
    if (!ctx || !slot)
        return false;

    uint8_t max_retry = np_udp_dynamic_max_retries(ctx->cfg, slot, stats);
    slot->dynamic_max_retries = max_retry;

    if (slot->item.attempt >= max_retry)
        return false;

    np_work_item_t retry = slot->item;
    retry.attempt = (uint8_t)(slot->item.attempt + 1);
    np_note_probe_retransmission(ctx->cfg);

    return np_wq_push(ctx->queue, &retry);
}

static bool np_udp_parse_icmp4_unreachable(const uint8_t *buf,
                                           ssize_t n,
                                           udp_icmp_event_t *ev)
{
    if (!buf || n <= 0 || !ev)
        return false;

    memset(ev, 0, sizeof(*ev));

    if ((size_t)n < sizeof(struct ip) + 8 + sizeof(struct ip) + sizeof(struct udphdr))
        return false;

    const struct ip *outer_ip = (const struct ip *)buf;
    size_t outer_hlen = (size_t)outer_ip->ip_hl * 4u;
    if (outer_hlen < sizeof(struct ip) || (size_t)n < outer_hlen + 8 + sizeof(struct ip) + sizeof(struct udphdr))
        return false;

    const struct icmp *icmp = (const struct icmp *)(buf + outer_hlen);
    if (icmp->icmp_type != ICMP_UNREACH)
        return false;

    const uint8_t *inner_packet = buf + outer_hlen + 8;
    ssize_t inner_len = n - (ssize_t)(outer_hlen + 8);
    if (inner_len < (ssize_t)(sizeof(struct ip) + sizeof(struct udphdr)))
        return false;

    const struct ip *inner_ip = (const struct ip *)inner_packet;
    size_t inner_hlen = (size_t)inner_ip->ip_hl * 4u;
    if (inner_hlen < sizeof(struct ip) || inner_len < (ssize_t)(inner_hlen + sizeof(struct udphdr)))
        return false;

    if (inner_ip->ip_p != IPPROTO_UDP)
        return false;

    const struct udphdr *inner_udp = (const struct udphdr *)(inner_packet + inner_hlen);
#if defined(__APPLE__) || defined(__FreeBSD__)
    ev->inner_src_port = ntohs(inner_udp->uh_sport);
    ev->inner_dst_port = ntohs(inner_udp->uh_dport);
#else
    ev->inner_src_port = ntohs(inner_udp->source);
    ev->inner_dst_port = ntohs(inner_udp->dest);
#endif

    ev->matched = true;
    ev->icmp_type = (uint8_t)icmp->icmp_type;
    ev->icmp_code = (uint8_t)icmp->icmp_code;
    ev->is_ipv6 = false;
    ev->outer_src4 = outer_ip->ip_src;

    switch (icmp->icmp_code)
    {
    case ICMP_UNREACH_PORT:
        ev->state = NP_PORT_CLOSED;
        ev->reason = "port-unreachable";
        return true;
    case ICMP_UNREACH_HOST:
        ev->state = NP_PORT_FILTERED;
        ev->reason = "host-unreach";
        return true;
    case ICMP_UNREACH_PROTOCOL:
        ev->state = NP_PORT_FILTERED;
        ev->reason = "protocol-unreach";
        return true;
    case ICMP_UNREACH_NET:
        ev->state = NP_PORT_FILTERED;
        ev->reason = "net-unreach";
        return true;
    case 9:
    case 10:
    case 13:
        ev->state = NP_PORT_FILTERED;
        ev->reason = "admin-prohibited";
        return true;
    default:
        return false;
    }
}

static bool np_udp_parse_icmp6_unreachable(const uint8_t *buf,
                                           ssize_t n,
                                           const struct in6_addr *outer_src,
                                           udp_icmp_event_t *ev)
{
    if (!buf || n <= 0 || !ev)
        return false;

    memset(ev, 0, sizeof(*ev));

    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)buf;
    const uint8_t *inner = NULL;
    ssize_t inner_len = 0;

    if ((size_t)n >= sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) && ((buf[0] >> 4) == 6))
    {
        const struct ip6_hdr *outer_ip6 = (const struct ip6_hdr *)buf;
        outer_src = &outer_ip6->ip6_src;
        icmp6 = (const struct icmp6_hdr *)(buf + sizeof(struct ip6_hdr));
        inner = (const uint8_t *)(icmp6 + 1);
        inner_len = n - (ssize_t)sizeof(struct ip6_hdr) - (ssize_t)sizeof(struct icmp6_hdr);
    }
    else
    {
        inner = buf + sizeof(struct icmp6_hdr);
        inner_len = n - (ssize_t)sizeof(struct icmp6_hdr);
    }

    if (inner_len < (ssize_t)(sizeof(struct ip6_hdr) + sizeof(struct udphdr)))
        return false;

    if (icmp6->icmp6_type != ICMP6_DST_UNREACH)
        return false;

    const struct ip6_hdr *inner_ip6 = (const struct ip6_hdr *)inner;
    if (inner_ip6->ip6_nxt != IPPROTO_UDP)
        return false;

    const struct udphdr *inner_udp = (const struct udphdr *)(inner + sizeof(struct ip6_hdr));
#if defined(__APPLE__) || defined(__FreeBSD__)
    ev->inner_src_port = ntohs(inner_udp->uh_sport);
    ev->inner_dst_port = ntohs(inner_udp->uh_dport);
#else
    ev->inner_src_port = ntohs(inner_udp->source);
    ev->inner_dst_port = ntohs(inner_udp->dest);
#endif

    ev->matched = true;
    ev->icmp_type = icmp6->icmp6_type;
    ev->icmp_code = icmp6->icmp6_code;
    ev->is_ipv6 = true;
    if (outer_src)
        ev->outer_src6 = *outer_src;

    if (icmp6->icmp6_code == ICMP6_DST_UNREACH_NOPORT)
    {
        ev->state = NP_PORT_CLOSED;
        ev->reason = "port-unreachable";
        return true;
    }

#ifdef ICMP6_DST_UNREACH_ADMIN
    if (icmp6->icmp6_code == ICMP6_DST_UNREACH_ADMIN)
    {
        ev->state = NP_PORT_FILTERED;
        ev->reason = "admin-prohibited";
        return true;
    }
#endif

    return false;
}

static conn_slot_t *find_slot_by_endpoint(conn_slot_t *slots,
                                          int n,
                                          int af,
                                          const struct sockaddr *addr,
                                          uint16_t port)
{
    for (int i = 0; i < n; i++)
    {
        if (!slots[i].active)
            continue;
        if (slots[i].peer_af != af || slots[i].peer_port != port)
            continue;

        if (af == AF_INET)
        {
            const struct sockaddr_in *lhs = (const struct sockaddr_in *)&slots[i].peer_addr;
            const struct sockaddr_in *rhs = (const struct sockaddr_in *)addr;
            if (lhs->sin_addr.s_addr == rhs->sin_addr.s_addr)
                return &slots[i];
        }
        else if (af == AF_INET6)
        {
            const struct sockaddr_in6 *lhs = (const struct sockaddr_in6 *)&slots[i].peer_addr;
            const struct sockaddr_in6 *rhs = (const struct sockaddr_in6 *)addr;
            if (memcmp(&lhs->sin6_addr, &rhs->sin6_addr, sizeof(lhs->sin6_addr)) == 0)
                return &slots[i];
        }
    }

    return NULL;
}

static conn_slot_t *find_slot_by_icmp_event(conn_slot_t *slots,
                                            int n,
                                            const np_worker_ctx_t *ctx,
                                            const udp_icmp_event_t *ev,
                                            uint16_t local_port4,
                                            uint16_t local_port6)
{
    if (!ctx || !ctx->cfg || !ev || !ev->matched)
        return NULL;

    uint16_t expected_local = ev->is_ipv6 ? local_port6 : local_port4;
    if (expected_local != 0 && ev->inner_src_port != expected_local)
        return NULL;

    for (int i = 0; i < n; i++)
    {
        if (!slots[i].active)
            continue;

        if (slots[i].item.port != ev->inner_dst_port)
            continue;

        const np_target_t *target = &ctx->cfg->targets[slots[i].item.target_idx];
        if (ev->is_ipv6)
        {
            if (!target->is_ipv6)
                continue;
            if (memcmp(&target->addr6.sin6_addr, &ev->outer_src6, sizeof(ev->outer_src6)) != 0)
                continue;
        }
        else
        {
            if (target->is_ipv6)
                continue;
            if (target->addr4.sin_addr.s_addr != ev->outer_src4.s_addr)
                continue;
        }

        return &slots[i];
    }

    return NULL;
}

static void maybe_promote_zombie_timeout(conn_slot_t *slot,
                                         np_worker_ctx_t *ctx,
                                         int *active_count)
{
    if (!slot || !slot->active || !slot->zombie)
        return;

    uint64_t now_us = np_now_monotonic_us();
    if (now_us < slot->zombie_until_us)
        return;

    finalize_slot(slot,
                  ctx,
                  active_count,
                  slot->final_pending_state,
                  slot->final_pending_reason,
                  slot->final_pending_confidence);
}

static int capture_local_port(int fd, uint16_t *out_port)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    memset(&ss, 0, sizeof(ss));

    if (!out_port)
        return -1;

    if (getsockname(fd, (struct sockaddr *)&ss, &slen) < 0)
        return -1;

    if (ss.ss_family == AF_INET)
    {
        *out_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
        return 0;
    }

    if (ss.ss_family == AF_INET6)
    {
        *out_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        return 0;
    }

    return -1;
}

static int open_shared_udp_socket(int af, bool linux_advanced, uint16_t *out_port)
{
    int fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;

    if (np_set_nonblocking(fd) < 0)
    {
        close(fd);
        return -1;
    }

    if (af == AF_INET)
    {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = 0;
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0)
        {
            close(fd);
            return -1;
        }
#if defined(__linux__)
        if (linux_advanced)
        {
            int one = 1;
            setsockopt(fd, SOL_IP, IP_RECVERR, &one, sizeof(one));
        }
#endif
    }
    else
    {
        struct sockaddr_in6 bind_addr6;
        memset(&bind_addr6, 0, sizeof(bind_addr6));
        bind_addr6.sin6_family = AF_INET6;
        bind_addr6.sin6_port = 0;
        bind_addr6.sin6_addr = in6addr_any;
        if (bind(fd, (struct sockaddr *)&bind_addr6, sizeof(bind_addr6)) < 0)
        {
            close(fd);
            return -1;
        }
#if defined(__linux__)
        if (linux_advanced)
        {
            int one = 1;
            setsockopt(fd, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one));
        }
#endif
    }

    if (capture_local_port(fd, out_port) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static int enqueue_tx(udp_tx_entry_t *queue,
                      int cap,
                      int *count,
                      int slot_idx)
{
    if (!queue || !count || *count >= cap)
        return -1;
    queue[*count].slot_idx = slot_idx;
    (*count)++;
    return 0;
}

static bool slot_probe_lookup(const np_udp_probe_cache_t *cache,
                              const conn_slot_t *slot,
                              const np_udp_probe_desc_t **out_probe,
                              size_t *out_total)
{
    if (!cache || !slot)
        return false;

    const np_udp_probe_chain_t *chain = np_udp_probe_cache_find(cache, slot->item.port);
    if (!chain || slot->current_probe_idx >= chain->probe_count)
        return false;

    if (out_probe)
        *out_probe = &chain->probes[slot->current_probe_idx];
    if (out_total)
        *out_total = chain->probe_count;
    return true;
}

static int flush_tx_batch(int fd,
                          int af,
                          conn_slot_t *slots,
                          const np_udp_probe_cache_t *cache,
                          udp_tx_entry_t *tx_queue,
                          int *tx_count,
                          int batch_size,
                          np_worker_ctx_t *ctx,
                          uint64_t *last_probe_us,
                          udp_worker_stats_t *stats)
{
    if (fd < 0 || !slots || !tx_queue || !tx_count || *tx_count <= 0)
        return 0;

    int sent_now = 0;
    int consumed = 0;

#if defined(__linux__)
    struct mmsghdr msgs[128];
    struct iovec iov[128];
    const np_udp_probe_desc_t *probes[128];
    if (batch_size > 128)
        batch_size = 128;

    while (consumed < *tx_count)
    {
        int chunk = 0;
        for (; chunk < batch_size && (consumed + chunk) < *tx_count; chunk++)
        {
            int si = tx_queue[consumed + chunk].slot_idx;
            conn_slot_t *slot = &slots[si];
            const np_udp_probe_desc_t *probe = NULL;
            if (!slot->active || slot->peer_af != af || !slot_probe_lookup(cache, slot, &probe, NULL))
                break;

            memset(&msgs[chunk], 0, sizeof(msgs[chunk]));
            iov[chunk].iov_base = (void *)probe->payload;
            iov[chunk].iov_len = probe->len;
            msgs[chunk].msg_hdr.msg_iov = &iov[chunk];
            msgs[chunk].msg_hdr.msg_iovlen = 1;
            msgs[chunk].msg_hdr.msg_name = &slot->peer_addr;
            msgs[chunk].msg_hdr.msg_namelen = slot->peer_addr_len;
            probes[chunk] = probe;
        }

        if (chunk == 0)
            break;

        np_wait_udp_probe_budget(ctx->cfg, last_probe_us);
        int rc = sendmmsg(fd, msgs, (unsigned int)chunk, MSG_DONTWAIT);
        if (rc < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (stats)
                    stats->send_eagain++;
                return sent_now;
            }
            rc = 0;
        }

        for (int i = 0; i < rc; i++)
        {
            int si = tx_queue[consumed + i].slot_idx;
            conn_slot_t *slot = &slots[si];
            if (!slot->active)
                continue;
            slot->last_sent_len = (size_t)msgs[i].msg_len;
            slot->probes_sent++;
            slot->istate = UDP_STATE_PROBING;
            np_timer_start(&slot->timer);
            np_note_probe_sent(ctx->cfg);
            if (stats)
                stats->probes_sent++;
            sent_now++;
        }

        consumed += (rc > 0) ? rc : 0;
        if (rc < chunk)
            break;
    }
#else
    if (batch_size > 128)
        batch_size = 128;
    while (consumed < *tx_count && sent_now < batch_size)
    {
        int si = tx_queue[consumed].slot_idx;
        conn_slot_t *slot = &slots[si];
        const np_udp_probe_desc_t *probe = NULL;
        if (!slot->active || slot->peer_af != af || !slot_probe_lookup(cache, slot, &probe, NULL))
            break;

        np_wait_udp_probe_budget(ctx->cfg, last_probe_us);
        ssize_t n = sendto(fd,
                           probe->payload,
                           probe->len,
                           MSG_DONTWAIT,
                           (const struct sockaddr *)&slot->peer_addr,
                           slot->peer_addr_len);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (stats)
                    stats->send_eagain++;
                break;
            }
            consumed++;
            continue;
        }

        slot->last_sent_len = (size_t)n;
        slot->probes_sent++;
        slot->istate = UDP_STATE_PROBING;
        np_timer_start(&slot->timer);
        np_note_probe_sent(ctx->cfg);
        if (stats)
            stats->probes_sent++;
        sent_now++;
        consumed++;
    }
#endif

    if (consumed > 0 && consumed < *tx_count)
        memmove(tx_queue, tx_queue + consumed, (size_t)(*tx_count - consumed) * sizeof(tx_queue[0]));
    *tx_count -= consumed;

    return sent_now;
}

static void handle_udp_data_socket(int fd,
                                   int af,
                                   conn_slot_t *slots,
                                   int nslots,
                                   np_worker_ctx_t *ctx,
                                   int *active_count)
{
    (void)af;
#if defined(__linux__)
    uint8_t bufs[32][UDP_RECV_BUF];
    struct sockaddr_storage addrs[32];
    struct mmsghdr msgs[32];
    struct iovec iov[32];

    for (;;)
    {
        for (int i = 0; i < 32; i++)
        {
            memset(&msgs[i], 0, sizeof(msgs[i]));
            memset(&addrs[i], 0, sizeof(addrs[i]));
            iov[i].iov_base = bufs[i];
            iov[i].iov_len = sizeof(bufs[i]);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
        }

        int rc = recvmmsg(fd, msgs, 32, MSG_DONTWAIT, NULL);
        if (rc < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return;
        }
        if (rc == 0)
            break;

        for (int i = 0; i < rc; i++)
        {
            uint16_t sport = 0;
            int family = ((struct sockaddr_storage *)msgs[i].msg_hdr.msg_name)->ss_family;
            if (family == AF_INET)
                sport = ntohs(((struct sockaddr_in *)msgs[i].msg_hdr.msg_name)->sin_port);
            else if (family == AF_INET6)
                sport = ntohs(((struct sockaddr_in6 *)msgs[i].msg_hdr.msg_name)->sin6_port);

            conn_slot_t *slot = find_slot_by_endpoint(slots,
                                                      nslots,
                                                      family,
                                                      (const struct sockaddr *)msgs[i].msg_hdr.msg_name,
                                                      sport);
            if (!slot)
                continue;

            np_stats_inc_pkts_recv(1);
            slot->istate = UDP_STATE_RESPONDED;
            slot->probes_acked++;
            const char *reason = ((size_t)msgs[i].msg_len > slot->last_sent_len) ? "udp-amplified-response" : "udp-response";
            finalize_slot(slot, ctx, active_count, NP_PORT_OPEN, reason, 1.0);
        }
    }
#else
    for (;;)
    {
        uint8_t buf[UDP_RECV_BUF];
        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        ssize_t nread = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&src, &slen);
        if (nread < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return;
        }
        if (nread == 0)
            break;

        uint16_t sport = 0;
        if (src.ss_family == AF_INET)
            sport = ntohs(((struct sockaddr_in *)&src)->sin_port);
        else if (src.ss_family == AF_INET6)
            sport = ntohs(((struct sockaddr_in6 *)&src)->sin6_port);

        conn_slot_t *slot = find_slot_by_endpoint(slots, nslots, src.ss_family, (struct sockaddr *)&src, sport);
        if (!slot)
            continue;

        np_stats_inc_pkts_recv(1);
        slot->istate = UDP_STATE_RESPONDED;
        slot->probes_acked++;
        const char *reason = ((size_t)nread > slot->last_sent_len) ? "udp-amplified-response" : "udp-response";
        finalize_slot(slot, ctx, active_count, NP_PORT_OPEN, reason, 1.0);
    }
#endif
}

#if defined(__linux__)
static void handle_udp_errqueue_socket(int fd,
                                       int af,
                                       conn_slot_t *slots,
                                       int nslots,
                                       np_worker_ctx_t *ctx,
                                       int *active_count,
                                       udp_worker_stats_t *stats)
{
    for (;;)
    {
        uint8_t control[512];
        uint8_t payload[64];
        struct sockaddr_storage offender;
        struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        memset(&offender, 0, sizeof(offender));
        msg.msg_name = &offender;
        msg.msg_namelen = sizeof(offender);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        ssize_t nread = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (nread < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            return;
        }

        struct sock_extended_err *ext = NULL;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR)
                ext = (struct sock_extended_err *)CMSG_DATA(cmsg);
            if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR)
                ext = (struct sock_extended_err *)CMSG_DATA(cmsg);
        }
        if (!ext)
            continue;

        uint16_t dport = 0;
        if (offender.ss_family == AF_INET)
            dport = ntohs(((struct sockaddr_in *)&offender)->sin_port);
        else if (offender.ss_family == AF_INET6)
            dport = ntohs(((struct sockaddr_in6 *)&offender)->sin6_port);

        conn_slot_t *slot = find_slot_by_endpoint(slots,
                                                  nslots,
                                                  af,
                                                  (const struct sockaddr *)&offender,
                                                  dport);
        if (!slot)
            continue;

        np_port_state_t state = NP_PORT_FILTERED;
        const char *reason = "icmp-unreachable";

        if (ext->ee_origin == SO_EE_ORIGIN_ICMP && ext->ee_type == ICMP_DEST_UNREACH && ext->ee_code == ICMP_PORT_UNREACH)
        {
            state = NP_PORT_CLOSED;
            reason = "port-unreachable";
        }
        else if (ext->ee_origin == SO_EE_ORIGIN_ICMP6 && ext->ee_type == ICMP6_DST_UNREACH && ext->ee_code == ICMP6_DST_UNREACH_NOPORT)
        {
            state = NP_PORT_CLOSED;
            reason = "port-unreachable";
        }

        if (stats)
            stats->icmp_seen++;
        np_stats_inc_pkts_recv(1);
        slot->istate = UDP_STATE_ICMP_SEEN;
        finalize_slot(slot, ctx, active_count, state, reason, 1.0);
    }
}
#endif

static void handle_udp_icmp_v4(int icmp4_fd,
                               conn_slot_t *slots,
                               int n,
                               np_worker_ctx_t *ctx,
                               int *active_count,
                               udp_worker_stats_t *stats,
                               uint16_t local_port4,
                               uint16_t local_port6)
{
    uint8_t buf[4096];

    for (int budget = 0, cap = np_udp_icmp_budget_per_tick(ctx ? ctx->cfg : NULL); budget < cap; budget++)
    {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t nread = recvfrom(icmp4_fd,
                                 buf,
                                 sizeof(buf),
                                 0,
                                 (struct sockaddr *)&src,
                                 &slen);
        if (nread < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            return;
        }

        udp_icmp_event_t ev;
        if (!np_udp_parse_icmp4_unreachable(buf, nread, &ev))
            continue;

        conn_slot_t *slot = find_slot_by_icmp_event(slots, n, ctx, &ev, local_port4, local_port6);
        if (!slot)
            continue;

        if (stats)
            stats->icmp_seen++;

        np_stats_inc_pkts_recv(1);
        slot->istate = UDP_STATE_ICMP_SEEN;
        finalize_slot(slot, ctx, active_count, ev.state, ev.reason, 1.0);
    }
}

static void handle_udp_icmp_v6(int icmp6_fd,
                               conn_slot_t *slots,
                               int n,
                               np_worker_ctx_t *ctx,
                               int *active_count,
                               udp_worker_stats_t *stats,
                               uint16_t local_port4,
                               uint16_t local_port6)
{
    uint8_t buf[4096];

    for (int budget = 0, cap = np_udp_icmp_budget_per_tick(ctx ? ctx->cfg : NULL); budget < cap; budget++)
    {
        struct sockaddr_in6 src6;
        socklen_t slen = sizeof(src6);
        ssize_t nread = recvfrom(icmp6_fd,
                                 buf,
                                 sizeof(buf),
                                 0,
                                 (struct sockaddr *)&src6,
                                 &slen);
        if (nread < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            return;
        }

        udp_icmp_event_t ev;
        if (!np_udp_parse_icmp6_unreachable(buf, nread, &src6.sin6_addr, &ev))
            continue;

        conn_slot_t *slot = find_slot_by_icmp_event(slots, n, ctx, &ev, local_port4, local_port6);
        if (!slot)
            continue;

        if (stats)
            stats->icmp_seen++;

        np_stats_inc_pkts_recv(1);
        slot->istate = UDP_STATE_ICMP_SEEN;
        finalize_slot(slot, ctx, active_count, ev.state, ev.reason, 1.0);
    }
}

static void expire_stale_udp(conn_slot_t *slots,
                             int n,
                             np_worker_ctx_t *ctx,
                             udp_tx_entry_t *tx_queue,
                             int tx_cap,
                             int *tx_count,
                             int *active_count,
                             udp_worker_stats_t *stats,
                             const np_udp_probe_cache_t *cache)
{
    for (int i = 0; i < n; i++)
    {
        if (!slots[i].active)
            continue;

        if (slots[i].zombie)
        {
            maybe_promote_zombie_timeout(&slots[i], ctx, active_count);
            continue;
        }

        const np_udp_probe_desc_t *probe = NULL;
        size_t total = 0;
        if (!slot_probe_lookup(cache, &slots[i], &probe, &total))
            continue;

        uint32_t timeout_ms = np_udp_probe_timeout_ms(ctx->cfg, &slots[i], probe->wait_ms);
        double elapsed = np_timer_elapsed_ms(&slots[i].timer);
        if (elapsed < (double)timeout_ms)
            continue;

        if ((size_t)(slots[i].current_probe_idx + 1) < total)
        {
            slots[i].current_probe_idx++;
            if (enqueue_tx(tx_queue, tx_cap, tx_count, i) < 0)
            {
                slots[i].zombie = true;
                slots[i].zombie_until_us = np_now_monotonic_us() + (uint64_t)UDP_LATE_ICMP_GRACE_MS * 1000ull;
                slots[i].final_pending_state = NP_PORT_OPEN_FILTERED;
                strncpy(slots[i].final_pending_reason, "no-response", sizeof(slots[i].final_pending_reason) - 1);
                slots[i].final_pending_reason[sizeof(slots[i].final_pending_reason) - 1] = '\0';
                slots[i].final_pending_confidence = 0.2;
            }
            continue;
        }

        if (requeue_slot_attempt(ctx, &slots[i], stats))
        {
            if (stats)
                stats->retransmissions++;
            close_slot(&slots[i]);
            if (*active_count > 0)
                (*active_count)--;
            continue;
        }

        slots[i].zombie = true;
        slots[i].istate = UDP_STATE_TIMED_OUT;
        slots[i].zombie_until_us = np_now_monotonic_us() + (uint64_t)UDP_LATE_ICMP_GRACE_MS * 1000ull;
        slots[i].final_pending_state = NP_PORT_OPEN_FILTERED;
        strncpy(slots[i].final_pending_reason, "no-response", sizeof(slots[i].final_pending_reason) - 1);
        slots[i].final_pending_reason[sizeof(slots[i].final_pending_reason) - 1] = '\0';
        slots[i].final_pending_confidence = (slots[i].probes_sent > 1 || slots[i].item.attempt > 0) ? 0.4 : 0.2;
    }
}

static void cleanup_active_slots(conn_slot_t *slots,
                                 int n,
                                 np_worker_ctx_t *ctx,
                                 int *active_count)
{
    for (int i = 0; i < n; i++)
    {
        if (!slots[i].active)
            continue;

        if (slots[i].zombie)
        {
            finalize_slot(&slots[i],
                          ctx,
                          active_count,
                          slots[i].final_pending_state,
                          slots[i].final_pending_reason,
                          slots[i].final_pending_confidence);
            continue;
        }

        finalize_slot(&slots[i], ctx, active_count, NP_PORT_OPEN_FILTERED, "no-response", 0.2);
    }
}

np_status_t np_udp_require_icmp_support(const np_config_t *cfg)
{
    if (!cfg || cfg->scan_type != NP_SCAN_UDP)
        return NP_OK;

    bool need_ipv4_icmp = false;
    bool need_ipv6_icmp = false;

    for (uint32_t i = 0; i < cfg->target_count; i++)
    {
        if (cfg->targets[i].is_ipv6)
            need_ipv6_icmp = true;
        else
            need_ipv4_icmp = true;
    }

    if (need_ipv4_icmp)
    {
        int fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fd4 < 0)
        {
            np_error(NP_ERR_RUNTIME,
                     "[!] UDP scan requires raw ICMP capture for accurate closed detection\n");
            np_error(NP_ERR_RUNTIME,
                     "[!] Re-run with sudo/root to match Nmap-style UDP closed results\n");
            return NP_ERR_PRIVILEGE_REQUIRED;
        }
        close(fd4);
    }

    if (need_ipv6_icmp)
    {
        int fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (fd6 < 0)
        {
            np_error(NP_ERR_RUNTIME,
                     "[!] UDP IPv6 scan requires raw ICMPv6 capture for accurate closed detection\n");
            np_error(NP_ERR_RUNTIME,
                     "[!] Re-run with sudo/root to match Nmap-style UDP closed results\n");
            return NP_ERR_PRIVILEGE_REQUIRED;
        }
        close(fd6);
    }

    return NP_OK;
}

void np_udp_scan_task(void *arg)
{
    np_task_arg_t *targ = arg;
    np_scan_ctx_t *scan_ctx = &targ->ctx;
    np_worker_ctx_t worker_ctx = {
        .cfg = scan_ctx->cfg,
        .queue = scan_ctx->queue,
        .interrupted = scan_ctx->interrupted,
        .metrics = scan_ctx->metrics,
        .metrics_lock = scan_ctx->metrics_lock,
        .total_work = scan_ctx->total_work,
        .completed_work = scan_ctx->completed_work,
        .completed_lock = scan_ctx->completed_lock,
    };
    np_worker_ctx_t *ctx = &worker_ctx;

    bool linux_advanced = ctx->cfg->udp_linux_advanced;
#if !defined(__linux__)
    linux_advanced = false;
#endif

    int max_slots = (int)ctx->cfg->udp_inflight_per_thread;
    if (ctx->cfg->timing_template >= NP_TIMING_TEMPLATE_4)
    {
        int boosted = max_slots * 2;
        if (boosted > 8192)
            boosted = 8192;
        max_slots = boosted;
    }

    if (max_slots < CONNS_PER_THREAD)
        max_slots = CONNS_PER_THREAD;
    if (max_slots > 8192)
        max_slots = 8192;

    conn_slot_t *slots = calloc((size_t)max_slots, sizeof(*slots));
    udp_tx_entry_t *tx_queue = calloc((size_t)max_slots * 2, sizeof(*tx_queue));
    event_loop_event_t *events = calloc((size_t)max_slots + 4, sizeof(*events));
    if (!slots || !tx_queue || !events)
    {
        free(slots);
        free(tx_queue);
        free(events);
        np_completion_signal(targ->completion);
        return;
    }

    event_loop_t loop = {.backend_fd = -1};
    np_udp_probe_cache_t probe_cache;
    memset(&probe_cache, 0, sizeof(probe_cache));

    int udp4_fd = -1;
    int udp6_fd = -1;
    int icmp4_fd = -1;
    int icmp6_fd = -1;
    uint16_t local_port4 = 0;
    uint16_t local_port6 = 0;
    int active = 0;
    int tx_count = 0;
    uint64_t host_started_us = np_now_monotonic_us();
    uint64_t last_probe_us = 0;
    bool need_icmp_v4 = false;
    bool need_icmp_v6 = false;
    udp_worker_stats_t stats = {0};

    for (uint32_t ti = 0; ti < ctx->cfg->target_count; ti++)
    {
        if (ctx->cfg->targets[ti].is_ipv6)
            need_icmp_v6 = true;
        else
            need_icmp_v4 = true;
    }

    if (np_udp_probe_cache_init(&probe_cache, ctx->cfg) < 0)
    {
        np_completion_signal(targ->completion);
        goto out;
    }

    if (event_loop_init(&loop) < 0)
    {
        np_error(NP_ERR_RUNTIME, "[!] event_loop_init failed (udp)\n");
        np_completion_signal(targ->completion);
        goto out;
    }

    if (need_icmp_v4)
    {
        icmp4_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp4_fd < 0)
            goto out;

        if (np_set_nonblocking(icmp4_fd) < 0 || event_loop_add(&loop, icmp4_fd) < 0)
            goto out;
    }

    if (need_icmp_v6)
    {
        icmp6_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (icmp6_fd < 0)
            goto out;

        if (np_set_nonblocking(icmp6_fd) < 0 || event_loop_add(&loop, icmp6_fd) < 0)
            goto out;
    }

    if (need_icmp_v4)
    {
        udp4_fd = open_shared_udp_socket(AF_INET, linux_advanced, &local_port4);
        if (udp4_fd < 0 || event_loop_add(&loop, udp4_fd) < 0)
            goto out;
    }

    if (need_icmp_v6)
    {
        udp6_fd = open_shared_udp_socket(AF_INET6, linux_advanced, &local_port6);
        if (udp6_fd < 0 || event_loop_add(&loop, udp6_fd) < 0)
            goto out;
    }

    while (!(*ctx->interrupted))
    {
        if (np_host_timeout_reached(ctx->cfg, host_started_us))
            break;

        while (active < max_slots)
        {
            np_work_item_t item;
            int si = find_free_slot(slots, max_slots);

            if (si < 0)
                break;

            if (!np_wq_pop(ctx->queue, &item))
                break;

            if (np_host_timeout_reached(ctx->cfg, host_started_us))
                break;

            np_target_t *target = &ctx->cfg->targets[item.target_idx];
            if (!item.port)
            {
                np_udp_record_result(ctx, &item, NP_PORT_FILTERED, 0.0, "invalid-port", 0.0);
                continue;
            }

            memset(&slots[si], 0, sizeof(slots[si]));
            slots[si].item = item;
            slots[si].active = true;
            slots[si].current_probe_idx = 0;
            slots[si].dynamic_max_retries = np_udp_dynamic_max_retries(ctx->cfg, &slots[si], &stats);
            slots[si].peer_port = item.port;
            slots[si].peer_af = target->is_ipv6 ? AF_INET6 : AF_INET;

            if (target->is_ipv6)
            {
                struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&slots[si].peer_addr;
                memset(dst, 0, sizeof(*dst));
                dst->sin6_family = AF_INET6;
                dst->sin6_port = htons(item.port);
                dst->sin6_addr = target->addr6.sin6_addr;
                slots[si].peer_addr_len = sizeof(*dst);
                slots[si].local_src_port = local_port6;
            }
            else
            {
                struct sockaddr_in *dst = (struct sockaddr_in *)&slots[si].peer_addr;
                memset(dst, 0, sizeof(*dst));
                dst->sin_family = AF_INET;
                dst->sin_port = htons(item.port);
                dst->sin_addr = target->addr4.sin_addr;
                slots[si].peer_addr_len = sizeof(*dst);
                slots[si].local_src_port = local_port4;
            }

            np_timer_start(&slots[si].timer);
            if (enqueue_tx(tx_queue, max_slots * 2, &tx_count, si) < 0)
            {
                np_udp_record_result(ctx, &item, NP_PORT_FILTERED, 0.0, "send-queue-full", 0.2);
                close_slot(&slots[si]);
                continue;
            }

            active++;
        }

        if (tx_count > 0)
        {
            int batch = (ctx->cfg->timing_template >= NP_TIMING_TEMPLATE_4)
                            ? 256
                            : (int)ctx->cfg->udp_batch_size;
            if (batch < 1)
                batch = 1;

            if (udp4_fd >= 0)
                (void)flush_tx_batch(udp4_fd, AF_INET, slots, &probe_cache, tx_queue, &tx_count, batch, ctx, &last_probe_us, &stats);
            if (udp6_fd >= 0)
                (void)flush_tx_batch(udp6_fd, AF_INET6, slots, &probe_cache, tx_queue, &tx_count, batch, ctx, &last_probe_us, &stats);
        }

        if (active == 0)
            break;

        int nev = event_loop_wait(&loop, events, max_slots + 4);
        if (nev < 0)
            nev = 0;

        for (int i = 0; i < nev; i++)
        {
            if (events[i].fd == udp4_fd)
            {
                handle_udp_data_socket(udp4_fd, AF_INET, slots, max_slots, ctx, &active);
#if defined(__linux__)
                if (linux_advanced)
                    handle_udp_errqueue_socket(udp4_fd, AF_INET, slots, max_slots, ctx, &active, &stats);
#endif
                continue;
            }

            if (events[i].fd == udp6_fd)
            {
                handle_udp_data_socket(udp6_fd, AF_INET6, slots, max_slots, ctx, &active);
#if defined(__linux__)
                if (linux_advanced)
                    handle_udp_errqueue_socket(udp6_fd, AF_INET6, slots, max_slots, ctx, &active, &stats);
#endif
                continue;
            }

            if (events[i].fd == icmp4_fd)
            {
                handle_udp_icmp_v4(icmp4_fd,
                                   slots,
                                   max_slots,
                                   ctx,
                                   &active,
                                   &stats,
                                   local_port4,
                                   local_port6);
                continue;
            }

            if (events[i].fd == icmp6_fd)
            {
                handle_udp_icmp_v6(icmp6_fd,
                                   slots,
                                   max_slots,
                                   ctx,
                                   &active,
                                   &stats,
                                   local_port4,
                                   local_port6);
                continue;
            }
        }

        expire_stale_udp(slots,
                         max_slots,
                         ctx,
                         tx_queue,
                         max_slots * 2,
                         &tx_count,
                         &active,
                         &stats,
                         &probe_cache);
    }

    if (np_host_timeout_reached(ctx->cfg, host_started_us))
        np_mark_unstarted_remaining(ctx);

    cleanup_active_slots(slots, max_slots, ctx, &active);

out:
    if (udp4_fd >= 0)
    {
        event_loop_remove(&loop, udp4_fd);
        close(udp4_fd);
    }
    if (udp6_fd >= 0)
    {
        event_loop_remove(&loop, udp6_fd);
        close(udp6_fd);
    }
    if (icmp4_fd >= 0)
    {
        event_loop_remove(&loop, icmp4_fd);
        close(icmp4_fd);
    }
    if (icmp6_fd >= 0)
    {
        event_loop_remove(&loop, icmp6_fd);
        close(icmp6_fd);
    }
    event_loop_destroy(&loop);
    np_udp_probe_cache_destroy(&probe_cache);
    free(events);
    free(tx_queue);
    free(slots);
    np_completion_signal(targ->completion);
}
