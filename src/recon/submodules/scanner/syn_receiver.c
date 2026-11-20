#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "logger.h"
#include "scanner_internal.h"
#include "runtime/stats.h"
#include "recon/submodules/os_detect/passive_fp.h"

/* ───────────────────────────────────────────── */
/* Receiver logging helpers                      */
/* ───────────────────────────────────────────── */

#define RX_LOG(level, fmt, ...) \
    np_log(level, "[RX] " fmt, ##__VA_ARGS__)

#define RX_LOGE(...) RX_LOG(NP_LOG_ERROR, __VA_ARGS__)
#define RX_LOGW(...) RX_LOG(NP_LOG_WARN,  __VA_ARGS__)
#define RX_LOGI(...) RX_LOG(NP_LOG_INFO,  __VA_ARGS__)
#define RX_LOGD(...) RX_LOG(NP_LOG_DEBUG, __VA_ARGS__)

/* ───────────────────────────────────────────── */
/* SYN probe table                               */
/* ───────────────────────────────────────────── */

#define MAX_SYN_PROBES 65536

typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    struct timeval sent_at;
    bool answered;
} syn_probe_t;

static syn_probe_t probes[MAX_SYN_PROBES];
static uint32_t probe_count = 0;

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;

/* Called by SYN sender */
void
np_syn_register_probe(uint16_t src_port,
                      uint16_t dst_port,
                      struct timeval *ts)
{
    pthread_mutex_lock(&probe_lock);

    if (probe_count < MAX_SYN_PROBES)
    {
        probes[probe_count++] = (syn_probe_t){
            .src_port = src_port,
            .dst_port = dst_port,
            .sent_at  = *ts,
            .answered = false
        };

        // RX_LOGD("probe registered src=%u dst=%u total=%u",
        //         src_port, dst_port, probe_count);
    }

    pthread_mutex_unlock(&probe_lock);
}

/* ───────────────────────────────────────────── */
/* Receiver state                                */
/* ───────────────────────────────────────────── */

static pcap_t *pcap_handle = NULL;
static pthread_t rx_thread;
static volatile int running = 0;

static np_config_t *rx_cfg = NULL;
static int link_hdr_len = 0;
static np_passive_fp_accum_t *passive_acc = NULL;

static void parse_tcp_synack_opts(const struct tcphdr *tcp,
                                  uint16_t *mss,
                                  uint8_t *wscale,
                                  bool *sack,
                                  bool *ts)
{
    if (!tcp || !mss || !wscale || !sack || !ts)
        return;

    *mss = 0;
    *wscale = 0;
    *sack = false;
    *ts = false;

    uint8_t hdr_len = (uint8_t)(tcp->th_off * 4);
    if (hdr_len <= 20)
        return;

    const uint8_t *opts = (const uint8_t *)tcp + 20;
    const uint8_t *end = (const uint8_t *)tcp + hdr_len;
    while (opts < end) {
        uint8_t kind = opts[0];
        if (kind == 0)
            break;
        if (kind == 1) {
            opts++;
            continue;
        }
        if (opts + 1 >= end)
            break;
        uint8_t olen = opts[1];
        if (olen < 2 || opts + olen > end)
            break;

        switch (kind) {
            case 2:
                if (olen == 4) {
                    uint16_t mv;
                    memcpy(&mv, opts + 2, 2);
                    *mss = ntohs(mv);
                }
                break;
            case 3:
                if (olen == 3)
                    *wscale = opts[2];
                break;
            case 4:
                if (olen == 2)
                    *sack = true;
                break;
            case 8:
                if (olen == 10)
                    *ts = true;
                break;
            default:
                break;
        }

        opts += olen;
    }
}

static bool is_raw_tcp_mode(np_scan_type_t scan_type)
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

static bool classify_tcp_reply(np_scan_type_t scan_type,
                               uint8_t flags,
                               uint16_t window,
                               np_port_state_t *out_state,
                               const char **out_reason)
{
    if (!out_state || !out_reason)
        return false;

    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN:
        if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            *out_state = NP_PORT_OPEN;
            *out_reason = "syn-ack";
            return true;
        }
        if (flags & TH_RST) {
            *out_state = NP_PORT_CLOSED;
            *out_reason = "rst";
            return true;
        }
        return false;

    case NP_SCAN_TCP_ACK:
        if (flags & TH_RST) {
            *out_state = NP_PORT_OPEN;
            *out_reason = "rst-unfiltered";
            return true;
        }
        return false;

    case NP_SCAN_TCP_WINDOW:
        if (flags & TH_RST) {
            if (window > 0) {
                *out_state = NP_PORT_OPEN;
                *out_reason = "rst-window-nonzero";
            } else {
                *out_state = NP_PORT_CLOSED;
                *out_reason = "rst-window-zero";
            }
            return true;
        }
        return false;

    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
        if (flags & TH_RST) {
            *out_state = NP_PORT_CLOSED;
            *out_reason = "rst";
            return true;
        }
        return false;

    default:
        return false;
    }
}

/* ───────────────────────────────────────────── */
/* Packet handler                                */
/* ───────────────────────────────────────────── */

static void
handle_packet(u_char *user,
              const struct pcap_pkthdr *hdr,
              const u_char *packet)
{
    (void)user;
    (void)hdr;

    np_stats_inc_pkts_recv(1);

    if (!rx_cfg || rx_cfg->target_count == 0)
        return;

    const struct ip *ip = (const struct ip *)(packet + link_hdr_len);
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + link_hdr_len);

    bool is_v6 = false;
    const struct tcphdr *tcp = NULL;

    if (ip->ip_v == 4 && ip->ip_p == IPPROTO_TCP)
    {
        tcp = (const struct tcphdr *)((const uint8_t *)ip + ip->ip_hl * 4);
    }
    else if (((ip6->ip6_vfc >> 4) & 0x0f) == 6 && ip6->ip6_nxt == IPPROTO_TCP)
    {
        is_v6 = true;
        tcp = (const struct tcphdr *)((const uint8_t *)ip6 + sizeof(struct ip6_hdr));
    }
    else
    {
        return;
    }

    uint16_t tcp_src = ntohs(tcp->th_sport);
    uint16_t tcp_dst = ntohs(tcp->th_dport);
    uint8_t flags = tcp->th_flags;

    if ((flags & TH_RST) && rx_cfg)
        np_timing_note_rst_observation(rx_cfg, np_now_monotonic_us());

    if (!rx_cfg || !is_raw_tcp_mode(rx_cfg->scan_type))
        return;

    if (!(flags & (TH_SYN | TH_RST)))
        return;

    struct timeval now;
    gettimeofday(&now, NULL);

    pthread_mutex_lock(&probe_lock);

    for (uint32_t i = 0; i < probe_count; i++)
    {
        syn_probe_t *p = &probes[i];

        if (p->answered)
            continue;

        if (p->src_port != tcp_dst ||
            p->dst_port != tcp_src)
            continue;

        double rtt =
            (now.tv_sec - p->sent_at.tv_sec) * 1000.0 +
            (now.tv_usec - p->sent_at.tv_usec) / 1000.0;

        np_port_state_t state;
        const char *reason = NULL;

        if (!classify_tcp_reply(rx_cfg->scan_type, flags, ntohs(tcp->th_win), &state, &reason))
            goto done;

        RX_LOGD("probe matched dst_port=%u state=%s rtt=%.2fms",
                p->dst_port,
                state == NP_PORT_OPEN ? "OPEN" : "CLOSED",
                rtt);

        for (uint32_t k = 0; k < rx_cfg->target_count; k++)
        {
            np_target_t *t = &rx_cfg->targets[k];

            if (is_v6)
            {
                if (!t->is_ipv6)
                    continue;
                if (memcmp(&t->addr6.sin6_addr, &ip6->ip6_src, sizeof(struct in6_addr)) != 0)
                    continue;
            }
            else
            {
                if (t->is_ipv6)
                    continue;
                if (t->addr4.sin_addr.s_addr != ip->ip_src.s_addr)
                    continue;
            }

            for (size_t j = 0; j < t->port_count; j++)
            {
                if (t->results[j].port == p->dst_port)
                {
                    t->results[j].state = state;
                    t->results[j].rtt_ms = rtt;
                    t->results[j].completed = true;
                    if (reason)
                        strncpy(t->results[j].reason, reason, sizeof(t->results[j].reason) - 1);

                    RX_LOGD("result updated port=%u", p->dst_port);

                    if (passive_acc && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) && !is_v6)
                    {
                        uint16_t mss = 0;
                        uint8_t wscale = 0;
                        bool sack = false;
                        bool ts = false;
                        parse_tcp_synack_opts(tcp, &mss, &wscale, &sack, &ts);
                        np_passive_fp_observe(&passive_acc[k],
                                              ip->ip_ttl,
                                              ntohs(tcp->th_win),
                                              (ntohs(ip->ip_off) & IP_DF) != 0,
                                              ntohs(ip->ip_id),
                                              mss,
                                              wscale,
                                              sack,
                                              ts,
                                              true);

                        np_passive_fp_finalize(&passive_acc[k],
                                               rx_cfg ? rx_cfg->osscan_guess : false,
                                               &t->os_result);
                        if (t->os_result.os_guess_passive[0] != '\0')
                            t->os_result_valid = true;
                    }
                    break;
                }
            }
        }

        p->answered = true;
        break;
    }

done:
    pthread_mutex_unlock(&probe_lock);
}

/* ───────────────────────────────────────────── */
/* Receiver thread                               */
/* ───────────────────────────────────────────── */

/*
 * Pick the capture interface the kernel routes to the primary target.
 * pcap_lookupdev() returns the first device (e.g. Wi-Fi/ap1), which may be
 * the wrong link; every SYN reply is then missed and recon reports
 * "Coverage: 0/0 services identified".
 */
static bool
rx_route_device(char *out, size_t out_len)
{
    if (!out || out_len == 0 || !rx_cfg || rx_cfg->target_count == 0)
        return false;

    struct sockaddr_in dst = rx_cfg->targets[0].addr4;
    if (dst.sin_family != AF_INET || dst.sin_addr.s_addr == 0)
        return false;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    dst.sin_port = htons(53);

    struct sockaddr_in local;
    socklen_t slen = sizeof(local);
    memset(&local, 0, sizeof(local));

    bool ok = connect(fd, (const struct sockaddr *)&dst, sizeof(dst)) == 0 &&
              getsockname(fd, (struct sockaddr *)&local, &slen) == 0;
    close(fd);

    if (!ok || local.sin_addr.s_addr == 0)
        return false;

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
        return false;

    bool found = false;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr ==
            local.sin_addr.s_addr)
        {
            snprintf(out, out_len, "%s", ifa->ifa_name);
            found = true;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return found;
}

static void *
receiver_thread(void *arg)
{
    (void)arg;

    char errbuf[PCAP_ERRBUF_SIZE];
    char route_dev[64];

    char *dev = rx_route_device(route_dev, sizeof(route_dev))
                    ? route_dev
                    : pcap_lookupdev(errbuf);
    if (!dev)
    {
        RX_LOGE("could not determine capture device: %s", errbuf);
        return NULL;
    }

    RX_LOGI("using pcap device: %s", dev);

    pcap_handle = pcap_create(dev, errbuf);
    if (!pcap_handle)
    {
        RX_LOGE("pcap_create failed: %s", errbuf);
        return NULL;
    }

    pcap_set_snaplen(pcap_handle, 65535);
    pcap_set_promisc(pcap_handle, 1);
    pcap_set_timeout(pcap_handle, 10);
    pcap_set_immediate_mode(pcap_handle, 1);

    if (pcap_activate(pcap_handle) != 0)
    {
        RX_LOGE("pcap_activate failed: %s", pcap_geterr(pcap_handle));
        return NULL;
    }

    switch (pcap_datalink(pcap_handle))
    {
        case DLT_EN10MB:     link_hdr_len = 14; break;
        case DLT_LINUX_SLL:  link_hdr_len = 16; break;
        case DLT_NULL:       link_hdr_len = 4;  break;
        default:             link_hdr_len = 0;  break;
    }

    RX_LOGD("link header length = %d", link_hdr_len);

    struct bpf_program fp;
    const char *filter =
        "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) != 0)";

    if (pcap_compile(pcap_handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0)
    {
        pcap_setfilter(pcap_handle, &fp);
        pcap_freecode(&fp);
        RX_LOGD("BPF filter installed");
    }

    while (running)
        pcap_dispatch(pcap_handle, -1, handle_packet, NULL);

    pcap_close(pcap_handle);
    pcap_handle = NULL;

    RX_LOGI("receiver stopped");
    return NULL;
}

/* ───────────────────────────────────────────── */
/* Public API                                   */
/* ───────────────────────────────────────────── */

void
np_start_receiver(np_config_t *cfg)
{
    rx_cfg = cfg;
    running = 1;
    probe_count = 0;

    free(passive_acc);
    passive_acc = NULL;
    if (cfg && cfg->target_count > 0)
    {
        passive_acc = calloc(cfg->target_count, sizeof(*passive_acc));
        if (passive_acc)
        {
            for (uint32_t i = 0; i < cfg->target_count; i++)
                np_passive_fp_init(&passive_acc[i]);
        }
    }

    RX_LOGI("receiver starting");
    pthread_create(&rx_thread, NULL, receiver_thread, NULL);
}

void
np_stop_receiver(void)
{
    RX_LOGI("receiver stop requested");

    running = 0;

    if (pcap_handle)
        pcap_breakloop(pcap_handle);

    pthread_join(rx_thread, NULL);

    free(passive_acc);
    passive_acc = NULL;
}
