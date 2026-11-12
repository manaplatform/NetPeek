#define _GNU_SOURCE
#include "os_tcp_probes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>

/* ============================================================
   Helpers
   ============================================================ */

static uint16_t checksum(const void *buf, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *p = buf;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len)
        sum += *(const uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

static int get_local_ip(const struct sockaddr_in *dst, char *out)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;

    connect(s, (const struct sockaddr *)dst, sizeof(*dst));

    struct sockaddr_in src;
    socklen_t len = sizeof(src);
    getsockname(s, (struct sockaddr *)&src, &len);
    close(s);

    inet_ntop(AF_INET, &src.sin_addr, out, INET_ADDRSTRLEN);
    return 0;
}

static int get_interface_for_ip(const char *src_ip, char *dev_out, size_t dev_len)
{
    if (!src_ip || !dev_out || dev_len == 0)
        return -1;

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
        return -1;

    int found = -1;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)) &&
            strcmp(ip, src_ip) == 0)
        {
            strncpy(dev_out, ifa->ifa_name, dev_len - 1);
            dev_out[dev_len - 1] = '\0';
            found = 0;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return found;
}

static size_t pcap_l2_offset(pcap_t *pc)
{
    switch (pcap_datalink(pc)) {
        case DLT_EN10MB:    return 14;
        case DLT_LINUX_SLL: return 16;
        case DLT_NULL:      return 4;
#ifdef DLT_LOOP
        case DLT_LOOP:      return 4;
#endif
#ifdef DLT_RAW
        case DLT_RAW:       return 0;
#endif
#ifdef DLT_IPV4
        case DLT_IPV4:      return 0;
#endif
        default:            return 0;
    }
}

/* ============================================================
   Packet sender
   ============================================================ */

#ifdef __APPLE__
/* macOS: kernel TCP, MUST bind source port */
static int os_tcp_send_probe_internal(
    const char *src_ip,
    const char *dst_ip,
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    np_tcp_probe_type_t type)
{
    (void)seq;
    (void)type;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;

    fcntl(s, F_SETFL, O_NONBLOCK);

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    struct sockaddr_in src = {0};
    src.sin_family = AF_INET;
    src.sin_port   = htons(sport);
    inet_pton(AF_INET, src_ip, &src.sin_addr);

    if (bind(s, (struct sockaddr *)&src, sizeof(src)) < 0) {
        close(s);
        return -1;
    }

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(dport);
    inet_pton(AF_INET, dst_ip, &dst.sin_addr);

    connect(s, (struct sockaddr *)&dst, sizeof(dst));
    return s;
}
#endif

#ifdef __linux__
/* Linux: raw TCP SYN */
static int os_tcp_send_probe_internal(
    const char *src_ip,
    const char *dst_ip,
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    np_tcp_probe_type_t type)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
        return -1;

    int on = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    uint8_t pkt[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(pkt, 0, sizeof(pkt));

    struct ip *ip = (struct ip *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(*ip));

    ip->ip_v   = 4;
    ip->ip_hl  = 5;
    ip->ip_ttl = 64;
    ip->ip_p   = IPPROTO_TCP;
    ip->ip_len = htons(sizeof(pkt));
    ip->ip_id  = htons(rand());
    inet_pton(AF_INET, src_ip, &ip->ip_src);
    inet_pton(AF_INET, dst_ip, &ip->ip_dst);
    ip->ip_sum = checksum(ip, sizeof(*ip));

    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);
    tcp->th_seq   = htonl(seq);
    tcp->th_off   = 5;
    uint8_t flags = TH_SYN;
    switch (type) {
        case NP_PROBE_T2: flags = 0; break;
        case NP_PROBE_T3: flags = TH_SYN | TH_FIN | TH_URG | TH_PUSH; break;
        case NP_PROBE_T4: flags = TH_ACK; break;
        case NP_PROBE_T5: flags = TH_SYN; break;
        case NP_PROBE_T6: flags = TH_ACK; break;
        case NP_PROBE_T7: flags = TH_FIN | TH_URG | TH_PUSH; break;
        case NP_PROBE_ECN: flags = TH_SYN | TH_ECE | TH_CWR; break;
        case NP_PROBE_T1:
        case NP_PROBE_IE:
        default: flags = TH_SYN; break;
    }
    tcp->th_flags = flags;
    tcp->th_win   = htons(64240);

    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo = {
        ip->ip_src.s_addr,
        ip->ip_dst.s_addr,
        0,
        IPPROTO_TCP,
        htons(sizeof(struct tcphdr))
    };

    uint8_t buf[sizeof(pseudo) + sizeof(struct tcphdr)];
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcp, sizeof(*tcp));
    tcp->th_sum = checksum(buf, sizeof(buf));

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr   = ip->ip_dst;

    int r = sendto(fd, pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&sin, sizeof(sin));

    close(fd);
    return r > 0 ? 0 : -1;
}
#endif

/* ============================================================
   TCP probe
   ============================================================ */
int np_send_tcp_probe(
    const np_tcp_probe_cfg_t *cfg,
    np_tcp_probe_type_t type,
    np_tcp_probe_result_t *out)
{
    memset(out, 0, sizeof(*out));
    out->type = type;

    char dst_ip[INET_ADDRSTRLEN];
    char src_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &cfg->target.sin_addr, dst_ip, sizeof(dst_ip));
    if (get_local_ip(&cfg->target, src_ip) < 0)
        return -1;

    uint16_t sport = 40000 + (rand() & 0x0fff);
    uint16_t dport = cfg->open_port;
    if (type == NP_PROBE_T5 || type == NP_PROBE_T6 || type == NP_PROBE_T7)
        dport = cfg->closed_port;
    uint32_t seq   = rand();

    char dev_buf[IFNAMSIZ] = {0};
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (get_interface_for_ip(src_ip, dev_buf, sizeof(dev_buf)) == 0)
        dev = dev_buf;
    else
        dev = pcap_lookupdev(errbuf);

    if (!dev || !dev[0])
        return -1;

    pcap_t *pc = pcap_create(dev, errbuf);
    if (!pc)
        return -1;

    pcap_set_snaplen(pc, 65535);
    pcap_set_promisc(pc, 0);
    pcap_set_timeout(pc, cfg->timeout_ms);
    pcap_set_immediate_mode(pc, 1);

    if (pcap_activate(pc) != 0) {
        pcap_close(pc);
        return -1;
    }

    char filter[256];
    snprintf(filter, sizeof(filter),
        "tcp and host %s and (tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) != 0)",
        dst_ip);

    struct bpf_program fp;
    if (pcap_compile(pc, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pc, &fp);
        pcap_freecode(&fp);
    }

    int probe_fd = os_tcp_send_probe_internal(src_ip, dst_ip, sport, dport, seq, type);

    size_t l2 = pcap_l2_offset(pc);
    time_t start = time(NULL);

    while (time(NULL) - start < 2) {
        struct pcap_pkthdr *h;
        const u_char *pkt;

        if (pcap_next_ex(pc, &h, &pkt) <= 0)
            continue;

        const struct ip *ip = (void *)(pkt + l2);
        if (ip->ip_p != IPPROTO_TCP)
            continue;

        const struct tcphdr *tcp =
            (void *)((const uint8_t *)ip + ip->ip_hl * 4);

#ifdef __linux__
        if (ntohl(tcp->th_ack) != seq + 1 &&
            !(tcp->th_flags & TH_RST))
            continue;
#else
        if (ntohs(tcp->th_dport) != sport)
            continue;
#endif

        out->responded = true;
        out->ttl       = ip->ip_ttl;
        out->window    = ntohs(tcp->th_win);
        out->ip_id     = ntohs(ip->ip_id);
        out->df        = (ntohs(ip->ip_off) & IP_DF) != 0;
        out->tcp_flags = tcp->th_flags;
        out->syn       = (tcp->th_flags & TH_SYN) != 0;
        out->ack       = (tcp->th_flags & TH_ACK) != 0;
        out->rst       = (tcp->th_flags & TH_RST) != 0;
        out->seq       = ntohl(tcp->th_seq);
        out->ack_seq   = ntohl(tcp->th_ack);

        /* ====================================================
         * Parse TCP options: MSS, SACK, Window Scale, Timestamps
         * ==================================================== */
        {
            uint8_t tcp_hdr_len = tcp->th_off * 4;
            const uint8_t *opts     = (const uint8_t *)tcp + 20;
            const uint8_t *opts_end = (const uint8_t *)tcp + tcp_hdr_len;

            /* Safety: clamp to captured packet boundary */
            const uint8_t *pkt_end = pkt + h->caplen;
            if (opts_end > pkt_end)
                opts_end = pkt_end;

            /* Defaults */
            out->mss       = 0;
            out->sack      = false;
            out->wscale    = 0;
            out->timestamp = false;
            out->tsval     = 0;
            out->tsecr     = 0;
            out->opts_len  = 0;

            /* Save raw options */
            if (tcp_hdr_len > 20) {
                size_t raw_len = tcp_hdr_len - 20;
                if (raw_len > sizeof(out->opts_raw))
                    raw_len = sizeof(out->opts_raw);
                /* Clamp to captured data */
                if (opts + raw_len > pkt_end)
                    raw_len = (size_t)(pkt_end - opts);
                memcpy(out->opts_raw, opts, raw_len);
                out->opts_len = (uint8_t)raw_len;
            }

            /* Walk option TLVs */
            while (opts < opts_end) {
                uint8_t kind = opts[0];

                /* End of Option List */
                if (kind == 0)
                    break;

                /* NOP — single byte, no length field */
                if (kind == 1) {
                    opts++;
                    continue;
                }

                /* All other options: need at least kind + length */
                if (opts + 1 >= opts_end)
                    break;

                uint8_t olen = opts[1];
                if (olen < 2 || opts + olen > opts_end)
                    break;

                switch (kind) {
                case 2:  /* MSS — length must be 4 */
                    if (olen == 4) {
                        uint16_t mss_val;
                        memcpy(&mss_val, opts + 2, 2);
                        out->mss = ntohs(mss_val);
                    }
                    break;

                case 3:  /* Window Scale — length must be 3 */
                    if (olen == 3) {
                        out->wscale = opts[2];
                    }
                    break;

                case 4:  /* SACK Permitted — length must be 2 */
                    if (olen == 2) {
                        out->sack = true;
                    }
                    break;

                case 8:  /* Timestamps — length must be 10 */
                    if (olen == 10) {
                        out->timestamp = true;
                        uint32_t tv, te;
                        memcpy(&tv, opts + 2, 4);
                        memcpy(&te, opts + 6, 4);
                        out->tsval = ntohl(tv);
                        out->tsecr = ntohl(te);
                    }
                    break;

                default:
                    /* Unknown option — skip by length */
                    break;
                }

                opts += olen;
            }
        }

        /* ECN support detection (for ECN probe) */
        if (type == NP_PROBE_ECN) {
            out->ecn_supported = (tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK);
            out->ecn_flags     = tcp->th_flags & 0xC0; /* CWR + ECE bits */
        }

        if (probe_fd >= 0)
            close(probe_fd);
        pcap_close(pc);
        return 0;
    }

    if (probe_fd >= 0)
        close(probe_fd);
    pcap_close(pc);
    return -1;
}

/* ============================================================
   Probe set runner
   ============================================================ */

int np_run_tcp_probes(
    const np_tcp_probe_cfg_t *cfg,
    np_tcp_probe_set_t *results)
{
    memset(results, 0, sizeof(*results));

    for (int i = 0; i < NP_MAX_TCP_PROBES; i++) {
        np_send_tcp_probe(cfg, (np_tcp_probe_type_t)i,
                          &results->probes[i]);
        usleep(150000);
    }
    return 0;
}
