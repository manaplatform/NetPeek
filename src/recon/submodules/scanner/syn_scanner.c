#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include "scanner_internal.h"
#include "core/error.h"
#include "evasion.h"
#include "evasion/decoy.h"
#include "evasion/fragment.h"
#include "evasion/spoof.h"
#include "packet/fast_tx.h"
#include "packet/ip6.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/time.h>

/* ───────────────────────────────────────────── */
/* Raw SYN send socket (process-wide)            */
/* ───────────────────────────────────────────── */

static int syn_sock4 = -1;
static int syn_sock6 = -1;
static uint8_t tcp_probe_flags = TH_SYN;
static np_fast_tx_ctx_t fast_tx_ctx;
static bool fast_tx_enabled = false;

void np_syn_set_tcp_flags(uint8_t flags)
{
    tcp_probe_flags = flags;
}

/* ───────────────────────────────────────────── */
/* TCP pseudo-header for checksum                */
/* ───────────────────────────────────────────── */

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

/* ───────────────────────────────────────────── */
/* RFC 1071 checksum                             */
/* ───────────────────────────────────────────── */

static uint16_t
calculate_checksum(uint16_t *ptr, int nbytes)
{
    uint32_t sum = 0;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        uint16_t odd = 0;
        *(uint8_t *)&odd = *(uint8_t *)ptr;
        sum += odd;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/* ───────────────────────────────────────────── */
/* Resolve a usable local IPv4 address           */
/* ───────────────────────────────────────────── */

static uint32_t
get_local_ip(void)
{
    struct ifaddrs *ifaddr = NULL;
    uint32_t addr = 0;

    if (getifaddrs(&ifaddr) != 0)
        return 0;

    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

        addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
        break;
    }

    freeifaddrs(ifaddr);
    return addr;
}

/*
 * Resolve the local IPv4 address the kernel would use to reach @dst.
 * The plain get_local_ip() above returns the first UP address, which is the
 * wrong source on multi-homed hosts: SYN-ACKs then arrive on an interface we
 * are not capturing on and recon reports an empty service list.
 */
static uint32_t
get_local_ip_for_target(const struct sockaddr_in *dst)
{
    if (dst)
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0)
        {
            struct sockaddr_in tmp = *dst;
            tmp.sin_port = htons(53);

            if (connect(fd, (const struct sockaddr *)&tmp, sizeof(tmp)) == 0)
            {
                struct sockaddr_in local;
                socklen_t slen = sizeof(local);
                memset(&local, 0, sizeof(local));

                if (getsockname(fd, (struct sockaddr *)&local, &slen) == 0 &&
                    local.sin_addr.s_addr != 0)
                {
                    close(fd);
                    return local.sin_addr.s_addr;
                }
            }

            close(fd);
        }
    }

    return get_local_ip();
}

static bool get_local_ip6_for_target(const struct in6_addr *dst,
                                     struct in6_addr *out_src)
{
    if (!dst || !out_src)
        return false;

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    struct sockaddr_in6 tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.sin6_family = AF_INET6;
    tmp.sin6_port = htons(53);
    tmp.sin6_addr = *dst;
    (void)connect(fd, (const struct sockaddr *)&tmp, sizeof(tmp));

    struct sockaddr_in6 local;
    socklen_t slen = sizeof(local);
    memset(&local, 0, sizeof(local));

    bool ok = false;
    if (getsockname(fd, (struct sockaddr *)&local, &slen) == 0)
    {
        *out_src = local.sin6_addr;
        ok = true;
    }

    close(fd);
    return ok;
}

/* ───────────────────────────────────────────── */
/* Raw socket init / close                       */
/* ───────────────────────────────────────────── */

np_status_t
np_syn_init(void)
{
    if (syn_sock4 >= 0 || syn_sock6 >= 0)
        return NP_OK;

    syn_sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (syn_sock4 >= 0)
    {
        int one = 1;
        if (setsockopt(syn_sock4,
                       IPPROTO_IP,
                       IP_HDRINCL,
                       &one,
                       sizeof(one)) < 0)
        {
            np_perror("setsockopt(IP_HDRINCL)");
            close(syn_sock4);
            syn_sock4 = -1;
        }
    }

    syn_sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

    if (syn_sock4 < 0 && syn_sock6 < 0)
    {
        np_perror("socket(IPPROTO_RAW)");
        return NP_ERR_SYSTEM;
    }

#if defined(__linux__)
    const char *enable_fast = getenv("NP_ENABLE_PACKET_MMAP");
    if (enable_fast && strcmp(enable_fast, "1") == 0)
    {
        const char *iface = getenv("NP_PACKET_IFACE");
        if (!iface || iface[0] == '\0')
            iface = "eth0";

        if (np_fast_tx_init(&fast_tx_ctx, iface, 4096u, 2048u) == 0)
            fast_tx_enabled = true;
    }
#endif

    return NP_OK;
}

void
np_syn_close(void)
{
    if (fast_tx_enabled)
    {
        np_fast_tx_close(&fast_tx_ctx);
        fast_tx_enabled = false;
    }

    if (syn_sock4 >= 0)
    {
        close(syn_sock4);
        syn_sock4 = -1;
    }

    if (syn_sock6 >= 0)
    {
        close(syn_sock6);
        syn_sock6 = -1;
    }
}

/* ───────────────────────────────────────────── */
/* Send one TCP SYN                              */
/* ───────────────────────────────────────────── */

void
np_send_syn(const np_target_t *t,
            uint16_t port,
            const np_evasion_t *ev)
{
    if (!t)
        return;

    if (t->is_ipv6 && syn_sock6 < 0)
        return;
    if (!t->is_ipv6 && syn_sock4 < 0)
        return;

    if (t->is_ipv6)
    {
        uint8_t packet[sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
        memset(packet, 0, sizeof(packet));

        struct in6_addr src6;
        if (!get_local_ip6_for_target(&t->addr6.sin6_addr, &src6))
            return;

        uint16_t src_port = np_spoof_pick_source_port(ev,
                                                      (uint16_t)(40000 + (rand() % 20000)));
        size_t out_len = 0;
        if (!np_build_ipv6_tcp_packet(packet,
                                      sizeof(packet),
                                      &src6,
                                      &t->addr6.sin6_addr,
                                      src_port,
                                      port,
                                      tcp_probe_flags,
                                      (uint32_t)rand(),
                                      8192,
                                      np_spoof_pick_ttl(ev, 64),
                                      0,
                                      &out_len))
            return;

        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ip6_hdr));
        struct timeval now;
        gettimeofday(&now, NULL);
        np_syn_register_probe(ntohs(tcp->th_sport), port, &now);

        struct sockaddr_in6 sdst;
        memset(&sdst, 0, sizeof(sdst));
        sdst.sin6_family = AF_INET6;
        sdst.sin6_port = tcp->th_dport;
        sdst.sin6_addr = t->addr6.sin6_addr;

        sendto(syn_sock6,
               packet,
               sizeof(struct ip6_hdr) + sizeof(struct tcphdr),
               0,
               (struct sockaddr *)&sdst,
               sizeof(sdst));
        return;
    }

    uint32_t local_ip = get_local_ip_for_target(&t->addr4);
    if (local_ip == 0)
        return;

    if (fast_tx_enabled)
    {
        uint8_t spoof_mac[6];
        if (ev && ev->spoof_mac_set && np_spoof_resolve_mac(ev, spoof_mac))
            np_fast_tx_set_src_mac(&fast_tx_ctx, spoof_mac);
        else
            np_fast_tx_clear_src_mac(&fast_tx_ctx);
    }

    uint32_t send_src[NP_MAX_DECOYS + 1];
    size_t send_count = np_decoy_build_send_list(ev,
                                                 local_ip,
                                                 send_src,
                                                 NP_MAX_DECOYS + 1);
    if (send_count == 0)
    {
        send_src[0] = local_ip;
        send_count = 1;
    }

    uint16_t src_port = np_spoof_pick_source_port(ev,
                                                  (uint16_t)(40000 + (rand() % 20000)));
    bool real_registered = false;

    for (size_t si = 0; si < send_count; si++)
    {
        uint8_t packet4[sizeof(struct ip) + sizeof(struct tcphdr)];
        memset(packet4, 0, sizeof(packet4));

        struct ip *ip = (struct ip *)packet4;
        struct tcphdr *tcp = (struct tcphdr *)(packet4 + sizeof(struct ip));

        ip->ip_v = 4;
        ip->ip_hl = 5;
        ip->ip_tos = 0;
        ip->ip_id = htons((uint16_t)rand());
        ip->ip_ttl = np_spoof_pick_ttl(ev, 64);
        ip->ip_p = IPPROTO_TCP;
        ip->ip_src.s_addr = send_src[si];
        ip->ip_dst = t->addr4.sin_addr;

#if defined(__APPLE__) || defined(__FreeBSD__)
        ip->ip_len = sizeof(packet4);
        ip->ip_off = 0;
#else
        ip->ip_len = htons(sizeof(packet4));
        ip->ip_off = htons(0);
#endif

        tcp->th_sport = htons(src_port);
        tcp->th_dport = htons(port);
        tcp->th_seq = htonl((uint32_t)rand());
        tcp->th_ack = 0;
        tcp->th_off = 5;
        tcp->th_flags = tcp_probe_flags;
        tcp->th_win = htons(8192);
        tcp->th_sum = 0;

        struct pseudo_header psh;
        psh.source_address = ip->ip_src.s_addr;
        psh.dest_address = ip->ip_dst.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        uint8_t pseudo[sizeof(psh) + sizeof(struct tcphdr)];
        memcpy(pseudo, &psh, sizeof(psh));
        memcpy(pseudo + sizeof(psh), tcp, sizeof(struct tcphdr));
        tcp->th_sum = calculate_checksum((uint16_t *)pseudo, sizeof(pseudo));

        struct sockaddr_in sdst;
        memset(&sdst, 0, sizeof(sdst));
        sdst.sin_family = AF_INET;
        sdst.sin_port = tcp->th_dport;
        sdst.sin_addr = ip->ip_dst;

        if (send_src[si] == local_ip && !real_registered)
        {
            struct timeval now;
            gettimeofday(&now, NULL);
            np_syn_register_probe(src_port, port, &now);
            real_registered = true;
        }

        bool sent = false;
        uint16_t frag_mtu = (ev && ev->fragment_mtu > 0)
            ? ev->fragment_mtu
            : (uint16_t)sizeof(packet4);

        if (ev && ev->fragment_packets)
        {
            np_fragment_desc_t frags[NP_MAX_FRAGMENTS];
            size_t frag_count = 0;

            if (np_fragment_plan_ipv4((uint16_t)sizeof(struct ip),
                                      (uint16_t)sizeof(struct tcphdr),
                                      frag_mtu,
                                      frags,
                                      &frag_count,
                                      NP_MAX_FRAGMENTS))
            {
                if (ev->fragment_order == NP_FRAG_ORDER_RANDOM)
                    np_fragment_shuffle(frags, frag_count);

                for (size_t fi = 0; fi < frag_count; fi++)
                {
                    uint8_t frag[sizeof(struct ip) + sizeof(struct tcphdr)];
                    memset(frag, 0, sizeof(frag));

                    struct ip *fip = (struct ip *)frag;
                    memcpy(fip, ip, sizeof(struct ip));

                    uint16_t payload_len = frags[fi].payload_len;
                    uint16_t payload_off = frags[fi].payload_offset;

                    memcpy(frag + sizeof(struct ip),
                           packet4 + sizeof(struct ip) + payload_off,
                           payload_len);

#if defined(__APPLE__) || defined(__FreeBSD__)
                    fip->ip_len = (uint16_t)(sizeof(struct ip) + payload_len);
                    fip->ip_off = (uint16_t)((payload_off / 8u) |
                                  (frags[fi].mf ? IP_MF : 0u));
#else
                    fip->ip_len = htons((uint16_t)(sizeof(struct ip) + payload_len));
                    fip->ip_off = htons((uint16_t)((payload_off / 8u) |
                                  (frags[fi].mf ? IP_MF : 0u)));
#endif
                    fip->ip_sum = 0;
                    fip->ip_sum = calculate_checksum((uint16_t *)fip, sizeof(struct ip));

                    sendto(syn_sock4,
                           frag,
                           sizeof(struct ip) + payload_len,
                           0,
                           (struct sockaddr *)&sdst,
                           sizeof(sdst));
                }

                sent = true;
            }
        }

        if (sent)
            continue;

        ip->ip_sum = 0;
        ip->ip_sum = calculate_checksum((uint16_t *)ip, sizeof(struct ip));

        if (fast_tx_enabled && send_count == 1)
        {
            if (np_fast_tx_send(&fast_tx_ctx, packet4, sizeof(packet4)) < 0)
            {
                sendto(syn_sock4,
                       packet4,
                       sizeof(packet4),
                       0,
                       (struct sockaddr *)&sdst,
                       sizeof(sdst));
            }
        }
        else
        {
            sendto(syn_sock4,
                   packet4,
                   sizeof(packet4),
                   0,
                   (struct sockaddr *)&sdst,
                   sizeof(sdst));
        }
    }
}
