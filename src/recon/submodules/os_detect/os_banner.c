/*
 * NetPeek - Banner Grabbing (Nmap Probe Engine)
 *
 * Replaces the old hardcoded probe/match logic with a full Nmap-based engine:
 *   - Probe selection by port + rarity
 *   - Raw Nmap probe payloads
 *   - PCRE2 regex matching
 *   - Version-info template expansion ($1..$9 capture groups)
 *   - Fallback probe chains
 */

#include "os_banner.h"
#include "recon/submodules/os_detect/os_detect.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

/* ------------------------------------------------------------------ */
/* Generated Nmap data                                                */
/* ------------------------------------------------------------------ */

#include "nmap_probes_generated.h"
#include "nmap_matches_generated.h"

/* ================================================================== */
/*  SECTION 1: PCRE2 Regex Cache                                      */
/* ================================================================== */

static pcre2_code **g_compiled_patterns = NULL; /* [NP_NMAP_MATCH_COUNT] */
static bool g_engine_initialized = false;

static uint32_t _flags_to_pcre2_options(const char *flags)
{
    uint32_t opts = 0;
    if (!flags)
        return opts;
    for (const char *p = flags; *p; p++)
    {
        switch (*p)
        {
        case 'i':
            opts |= PCRE2_CASELESS;
            break;
        case 's':
            opts |= PCRE2_DOTALL;
            break;
        case 'm':
            opts |= PCRE2_MULTILINE;
            break;
        case 'x':
            opts |= PCRE2_EXTENDED;
            break;
        default:
            break;
        }
    }
    return opts;
}

int np_banner_engine_init(void)
{
    if (g_engine_initialized)
        return 0;

    g_compiled_patterns = calloc(NP_NMAP_MATCH_COUNT, sizeof(pcre2_code *));
    if (!g_compiled_patterns)
    {
        /* Errors always print */
        np_error(NP_ERR_RUNTIME, "[netpeek][banner] failed to allocate regex cache\n");
        return -1;
    }

    int compiled = 0, failed = 0;

    for (int i = 0; i < NP_NMAP_MATCH_COUNT; i++)
    {
        const np_nmap_match_t *m = &g_nmap_matches[i];
        if (!m->pattern || !m->pattern[0])
        {
            g_compiled_patterns[i] = NULL;
            continue;
        }

        uint32_t options = _flags_to_pcre2_options(m->pattern_flags);
        int errcode;
        PCRE2_SIZE erroffset;

        pcre2_code *re = pcre2_compile(
            (PCRE2_SPTR)m->pattern,
            PCRE2_ZERO_TERMINATED,
            options,
            &errcode,
            &erroffset,
            NULL);

        if (re == NULL)
        {
#ifdef NP_BANNER_DEBUG
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
            np_error(NP_ERR_RUNTIME, "[netpeek][banner] PCRE2 compile failed for match[%d] "
                            "(service=%s): %s at offset %zu\n",
                    i, m->service ? m->service : "(null)",
                    (char *)errbuf, (size_t)erroffset);
#endif
            g_compiled_patterns[i] = NULL;
            failed++;
        }
        else
        {
            pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
            g_compiled_patterns[i] = re;
            compiled++;
        }
    }

    /* ── Only print summary in verbose mode ── */
    if (np_logger_is_verbose())
    {
        np_error(NP_ERR_RUNTIME, "[netpeek][banner] regex cache: %d compiled, %d failed, %d total\n",
                compiled, failed, NP_NMAP_MATCH_COUNT);
    }

    g_engine_initialized = true;
    return 0;
}

void np_banner_engine_cleanup(void)
{
    if (!g_compiled_patterns)
        return;

    for (int i = 0; i < NP_NMAP_MATCH_COUNT; i++)
    {
        if (g_compiled_patterns[i])
            pcre2_code_free(g_compiled_patterns[i]);
    }

    free(g_compiled_patterns);
    g_compiled_patterns = NULL;
    g_engine_initialized = false;
}

/* ================================================================== */
/*  SECTION 2: Internal Logging                                       */
/* ================================================================== */

static void banner_log(const char *fmt, ...)
{
    /* Only print when verbose/debug logging is active */
    if (!np_logger_is_verbose())
        return;

    va_list ap;
    va_start(ap, fmt);
    np_error(NP_ERR_RUNTIME, "[netpeek][banner] ");
    np_verror(NP_ERR_RUNTIME, fmt, ap);
    np_error(NP_ERR_RUNTIME, "\n");
    va_end(ap);
}

/* ================================================================== */
/*  SECTION 3: Socket Helpers                                         */
/* ================================================================== */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static int connect_with_timeout(int sock, struct sockaddr_in *addr,
                                uint32_t timeout_ms)
{
    if (set_nonblocking(sock) < 0)
        return -1;

    int ret = connect(sock, (struct sockaddr *)addr, sizeof(*addr));

    if (ret == 0)
    {
        set_blocking(sock);
        return 0;
    }

    if (errno != EINPROGRESS)
        return -1;

    struct pollfd pfd = {.fd = sock, .events = POLLOUT};
    ret = poll(&pfd, 1, (int)timeout_ms);

    if (ret <= 0)
        return -1;
    if (!(pfd.revents & POLLOUT))
        return -1;

    int err = 0;
    socklen_t errlen = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0)
        return -1;
    if (err != 0)
    {
        errno = err;
        return -1;
    }

    set_blocking(sock);
    return 0;
}

static ssize_t read_with_timeout(int sock, char *buf, size_t bufsz,
                                 uint32_t timeout_ms)
{
    if (!buf || bufsz < 2)
        return -1;

    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int r = poll(&pfd, 1, (int)timeout_ms);

    if (r <= 0)
        return -1;
    if (!(pfd.revents & POLLIN))
        return -1;

    ssize_t n = recv(sock, buf, bufsz - 1, 0);
    if (n <= 0)
        return -1;

    buf[n] = '\0';
    return n;
}

static int open_connection(const char *ip, uint16_t port, uint32_t timeout_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        banner_log("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
    {
        banner_log("inet_pton failed for %s", ip);
        close(sock);
        return -1;
    }

    if (connect_with_timeout(sock, &addr, timeout_ms) < 0)
    {
        close(sock);
        return -1;
    }

    return sock;
}

/* ================================================================== */
/*  SECTION 4: Probe Selection                                        */
/* ================================================================== */

static int find_probes_for_port(uint16_t port, int max_rarity,
                                int *out_indices, int max_out)
{
    typedef struct
    {
        int idx;
        int rarity;
    } probe_entry_t;

    probe_entry_t *entries = calloc(NP_NMAP_PROBE_COUNT, sizeof(probe_entry_t));
    if (!entries)
        return 0;

    int entry_count = 0;

    for (int i = 0; i < NP_NMAP_PROBE_COUNT; i++)
    {
        const np_nmap_probe_t *p = &g_nmap_probes[i];

        if (p->rarity > max_rarity)
            continue;

        if (strcmp(p->protocol, "TCP") != 0)
            continue;

        bool port_match = false;

        /* NULL probe (send_len == 0) is always eligible */
        if (p->send_len == 0 && strcmp(p->name, "NULL") == 0)
        {
            port_match = true;
        }

        if (!port_match)
        {
            for (int j = 0; j < p->port_count; j++)
            {
                if (p->ports[j] == port)
                {
                    port_match = true;
                    break;
                }
            }
        }

        if (!port_match)
        {
            for (int j = 0; j < p->ssl_port_count; j++)
            {
                if (p->ssl_ports[j] == port)
                {
                    port_match = true;
                    break;
                }
            }
        }

        if (!port_match)
            continue;

        entries[entry_count].idx = i;
        entries[entry_count].rarity = p->rarity;
        entry_count++;
    }

    /* Insertion sort by rarity */
    for (int i = 1; i < entry_count; i++)
    {
        probe_entry_t key = entries[i];
        int j = i - 1;
        while (j >= 0 && entries[j].rarity > key.rarity)
        {
            entries[j + 1] = entries[j];
            j--;
        }
        entries[j + 1] = key;
    }

    int count = entry_count < max_out ? entry_count : max_out;
    for (int i = 0; i < count; i++)
    {
        out_indices[i] = entries[i].idx;
    }

    free(entries);
    return count;
}

/* ================================================================== */
/*  SECTION 5: Version-Info Template Expansion                        */
/* ================================================================== */

static const char *_extract_vi_field(const char *tmpl, const char *tag,
                                     char *out, size_t out_sz)
{
    const char *p = strstr(tmpl, tag);
    if (!p)
        return NULL;

    p += strlen(tag);

    const char *end = p;
    while (*end && *end != '/')
    {
        if (*end == '\\' && *(end + 1))
            end += 2;
        else
            end++;
    }

    size_t len = (size_t)(end - p);
    if (len >= out_sz)
        len = out_sz - 1;
    memcpy(out, p, len);
    out[len] = '\0';

    return out;
}

static void _expand_captures(char *buf, size_t bufsz,
                             const char captures[NP_MAX_CAPTURES][NP_CAPTURE_MAX_LEN])
{
    char *tmp = malloc(bufsz);
    if (!tmp)
        return;

    size_t out_pos = 0;
    size_t i = 0;
    size_t slen = strlen(buf);

    while (i < slen && out_pos < bufsz - 1)
    {
        if (buf[i] == '$' && i + 1 < slen && buf[i + 1] >= '1' && buf[i + 1] <= '9')
        {
            int group = buf[i + 1] - '0';
            const char *replacement = captures[group];
            size_t rlen = strlen(replacement);
            if (out_pos + rlen < bufsz - 1)
            {
                memcpy(tmp + out_pos, replacement, rlen);
                out_pos += rlen;
            }
            i += 2;
        }
        else
        {
            tmp[out_pos++] = buf[i++];
        }
    }
    tmp[out_pos] = '\0';

    memcpy(buf, tmp, out_pos + 1);
    free(tmp);
}

static void expand_version_info(const char *vi_template,
                                const char captures[NP_MAX_CAPTURES][NP_CAPTURE_MAX_LEN],
                                np_banner_result_t *res)
{
    if (!vi_template || !vi_template[0])
        return;

    char expanded[1024];
    size_t len = strlen(vi_template);
    if (len >= sizeof(expanded))
        len = sizeof(expanded) - 1;
    memcpy(expanded, vi_template, len);
    expanded[len] = '\0';

    _expand_captures(expanded, sizeof(expanded), captures);

    _extract_vi_field(expanded, "p/", res->product, sizeof(res->product));
    _extract_vi_field(expanded, "v/", res->version, sizeof(res->version));
    _extract_vi_field(expanded, "i/", res->info, sizeof(res->info));
    _extract_vi_field(expanded, "h/", res->hostname, sizeof(res->hostname));
    _extract_vi_field(expanded, "o/", res->os_name, sizeof(res->os_name));
    _extract_vi_field(expanded, "d/", res->device_type, sizeof(res->device_type));

    /* CPE — note: tag is "cpe:/" so content starts after that */
    const char *cpe_pos = strstr(expanded, "cpe:/");
    if (cpe_pos)
    {
        /* Extract the whole "cpe:/a:vendor:product:version" up to next space or end */
        const char *start = cpe_pos; /* include "cpe:/" prefix */
        const char *end = start;
        while (*end && *end != ' ' && *end != '\t' && *end != '\n')
            end++;
        size_t clen = (size_t)(end - start);
        if (clen >= sizeof(res->cpe))
            clen = sizeof(res->cpe) - 1;
        memcpy(res->cpe, start, clen);
        res->cpe[clen] = '\0';
    }
}

/* ================================================================== */
/*  SECTION 6: Regex Matching Engine                                  */
/* ================================================================== */

static int try_matches_for_probe(int probe_idx,
                                 const char *banner, size_t banner_len,
                                 char captures[NP_MAX_CAPTURES][NP_CAPTURE_MAX_LEN],
                                 bool *out_is_soft)
{
    if (probe_idx < 0 || probe_idx >= NP_NMAP_PROBE_COUNT)
        return -1;

    const np_nmap_match_range_t *range = &g_nmap_match_range[probe_idx];
    if (range->count == 0)
        return -1;

    int best_soft_match = -1;

    pcre2_match_data *match_data = pcre2_match_data_create(NP_MAX_CAPTURES, NULL);
    if (!match_data)
        return -1;

    for (uint32_t i = 0; i < range->count; i++)
    {
        uint32_t mi = range->start + i;
        if (mi >= (uint32_t)NP_NMAP_MATCH_COUNT)
            break;

        pcre2_code *re = g_compiled_patterns[mi];
        if (!re)
            continue;

        int rc = pcre2_match(
            re,
            (PCRE2_SPTR)banner,
            (PCRE2_SIZE)banner_len,
            0, 0,
            match_data,
            NULL);

        if (rc < 0)
            continue;

        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        uint32_t pair_count = (uint32_t)rc;

        memset(captures, 0, NP_MAX_CAPTURES * NP_CAPTURE_MAX_LEN);

        for (uint32_t g = 0; g < pair_count && g < NP_MAX_CAPTURES; g++)
        {
            PCRE2_SIZE start = ovector[2 * g];
            PCRE2_SIZE end = ovector[2 * g + 1];
            if (start == PCRE2_UNSET || end == PCRE2_UNSET)
                continue;
            size_t clen = (size_t)(end - start);
            if (clen >= NP_CAPTURE_MAX_LEN)
                clen = NP_CAPTURE_MAX_LEN - 1;
            memcpy(captures[g], banner + start, clen);
            captures[g][clen] = '\0';
        }

        const np_nmap_match_t *m = &g_nmap_matches[mi];

        if (!m->is_soft)
        {
            *out_is_soft = false;
            pcre2_match_data_free(match_data);
            return (int)mi;
        }

        if (best_soft_match < 0)
        {
            best_soft_match = (int)mi;
        }
    }

    pcre2_match_data_free(match_data);

    if (best_soft_match >= 0)
    {
        *out_is_soft = true;

        /* Re-run the soft match to re-populate captures */
        pcre2_code *re = g_compiled_patterns[best_soft_match];
        if (re)
        {
            pcre2_match_data *md2 = pcre2_match_data_create(NP_MAX_CAPTURES, NULL);
            if (md2)
            {
                int rc = pcre2_match(re, (PCRE2_SPTR)banner, (PCRE2_SIZE)banner_len,
                                     0, 0, md2, NULL);
                if (rc > 0)
                {
                    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md2);
                    memset(captures, 0, NP_MAX_CAPTURES * NP_CAPTURE_MAX_LEN);
                    for (int g = 0; g < rc && g < NP_MAX_CAPTURES; g++)
                    {
                        PCRE2_SIZE s = ov[2 * g], e = ov[2 * g + 1];
                        if (s == PCRE2_UNSET || e == PCRE2_UNSET)
                            continue;
                        size_t cl = (size_t)(e - s);
                        if (cl >= NP_CAPTURE_MAX_LEN)
                            cl = NP_CAPTURE_MAX_LEN - 1;
                        memcpy(captures[g], banner + s, cl);
                        captures[g][cl] = '\0';
                    }
                }
                pcre2_match_data_free(md2);
            }
        }

        return best_soft_match;
    }

    return -1;
}

/* ================================================================== */
/*  SECTION 7: Single-Port Probe Execution                            */
/* ================================================================== */

static ssize_t execute_probe(const char *ip, uint16_t port,
                             const np_nmap_probe_t *probe,
                             uint32_t timeout_ms,
                             char *buf, size_t bufsz)
{
    uint32_t connect_timeout = timeout_ms;
    if (connect_timeout < 1000)
        connect_timeout = 1000;

    int sock = open_connection(ip, port, connect_timeout);
    if (sock < 0)
        return -1;

    if (probe->send_len > 0 && probe->send_data)
    {
        ssize_t sent = send(sock, probe->send_data, probe->send_len, 0);
        if (sent < 0)
        {
            banner_log("send failed for probe '%s' on port %u: %s",
                       probe->name ? probe->name : "(null)",
                       port, strerror(errno));
            close(sock);
            return -1;
        }
    }

    uint32_t read_timeout = probe->total_wait_ms > 0
                                ? probe->total_wait_ms
                                : timeout_ms;

    if (probe->send_len == 0 && probe->tcp_wrapped_ms > 0)
    {
        read_timeout = probe->tcp_wrapped_ms;
    }

    ssize_t n = read_with_timeout(sock, buf, bufsz, read_timeout);
    close(sock);

    return n;
}
/* ================================================================== */
/*  SECTION 8: Full Port Probe Cycle (with fallback)                  */
/* ================================================================== */

/**
 * Convert an internal np_banner_result_t into the pipeline-compatible
 * np_os_banner_t that lives inside np_os_result_t.
 *
 * np_banner_result_t (os_banner.h):
 *   - probe_idx(int), port(u16), banner[1024], banner_len(u32),
 *     service[128], product[128], version[128], info[128],
 *     hostname[128], os_name[128], device_type[128], cpe[128],
 *     match_idx(int), is_soft_match(bool), confidence(u8)
 *   - sizeof ≈ 2084 bytes
 *
 * np_os_banner_t (netpeek.h):
 *   - port(u16), banner[512], banner_len(u32),
 *     service[32], os_hint[64], os_hint_confidence(int),
 *     product[64], version[64], cpe[128]
 *   - sizeof ≈ 876 bytes
 */
static void banner_result_to_os_banner(const np_banner_result_t *src,
                                       np_os_banner_t *dst)
{
    memset(dst, 0, sizeof(*dst));

    /* ── Port ── */
    dst->port = src->port;

    /* ── Raw banner (truncate 1024 → 512) ── */
    uint32_t copy_len = src->banner_len;
    if (copy_len >= NP_MAX_BANNER_LEN)
        copy_len = NP_MAX_BANNER_LEN - 1;
    memcpy(dst->banner, src->banner, copy_len);
    dst->banner[copy_len] = '\0';
    dst->banner_len = copy_len;

    /* ── Service (128 → 32) ── */
    if (src->service[0])
    {
        snprintf(dst->service, sizeof(dst->service), "%s", src->service);
    }

    /* ── OS hint ← os_name (128 → 64) ── */
    if (src->os_name[0])
    {
        snprintf(dst->os_hint, sizeof(dst->os_hint), "%s", src->os_name);
    }
    dst->os_hint_confidence = (int)src->confidence;

    /* ── Product (128 → 64) ── */
    if (src->product[0])
    {
        snprintf(dst->product, sizeof(dst->product), "%s", src->product);
    }

    /* ── Version (128 → 64) ── */
    if (src->version[0])
    {
        snprintf(dst->version, sizeof(dst->version), "%s", src->version);
    }

    /* ── CPE (128 → 128, same size) ── */
    if (src->cpe[0])
    {
        snprintf(dst->cpe, sizeof(dst->cpe), "%s", src->cpe);
    }
}

/**
 * Probe a single port using the Nmap probe engine.
 * Writes results into a local np_banner_result_t, then converts
 * to np_os_banner_t before storing in result->banners[].
 */
static void probe_port_nmap(const np_target_t *target,
                            uint16_t port,
                            uint32_t timeout_ms,
                            np_os_result_t *result)
{
    if (!target || !result)
        return;

    int probe_indices[NP_MAX_PROBES_PER_PORT];
    int probe_count = find_probes_for_port(
        port,
        NP_MAX_PROBE_RARITY,
        probe_indices,
        NP_MAX_PROBES_PER_PORT);

    if (probe_count == 0)
        return;

    char buf[NP_OS_BANNER_MAX];

    for (int pi = 0; pi < probe_count; pi++)
    {
        int pidx = probe_indices[pi];
        const np_nmap_probe_t *probe = &g_nmap_probes[pidx];

        ssize_t n = execute_probe(target->ip, port, probe,
                                  timeout_ms, buf, sizeof(buf));

        if (n <= 0)
        {
            /* Try fallbacks */
            for (int fi = 0; fi < probe->fallback_count; fi++)
            {
                const char *fname = probe->fallbacks[fi];
                if (!fname || !fname[0])
                    continue;

                for (int k = 0; k < NP_NMAP_PROBE_COUNT; k++)
                {
                    if (g_nmap_probes[k].name &&
                        strcmp(g_nmap_probes[k].name, fname) == 0)
                    {
                        n = execute_probe(target->ip, port,
                                          &g_nmap_probes[k],
                                          timeout_ms, buf, sizeof(buf));
                        if (n > 0)
                            goto GOT_BANNER;
                    }
                }
            }
            continue;
        }

    GOT_BANNER:
        if (n <= 0)
            continue;

        /* ── Boundary check against the PIPELINE array limit ── */
        if (result->banner_count >= NP_OS_MAX_BANNERS)
            break;

        /* ──────────────────────────────────────────────────────
         * Build the result in a LOCAL np_banner_result_t,
         * then convert to np_os_banner_t for the pipeline.
         * This avoids the struct layout mismatch entirely.
         * ────────────────────────────────────────────────────── */
        np_banner_result_t local;
        memset(&local, 0, sizeof(local));

        local.port = port;
        local.probe_idx = pidx;
        local.match_idx = -1;

        /* Safely copy banner */
        size_t copy_len = (size_t)n;
        if (copy_len >= sizeof(local.banner))
            copy_len = sizeof(local.banner) - 1;
        memcpy(local.banner, buf, copy_len);
        local.banner[copy_len] = '\0';
        local.banner_len = (uint32_t)copy_len;

        /* Try match signatures for this probe */
        char captures[NP_MAX_CAPTURES][NP_CAPTURE_MAX_LEN];
        bool is_soft = false;

        int midx = try_matches_for_probe(
            pidx,
            buf, (size_t)n,
            captures,
            &is_soft);

        if (midx >= 0)
        {
            const np_nmap_match_t *m = &g_nmap_matches[midx];

            if (m->service && m->service[0])
                strncpy(local.service, m->service, sizeof(local.service) - 1);

            local.is_soft_match = is_soft;
            local.match_idx = midx;
            local.confidence = is_soft ? 60 : 90;

            /* Apply version-info template */
            expand_version_info(m->version_info_v, captures, &local);

            /* Boost confidence if we got rich data */
            if (local.product[0])
                local.confidence += 3;
            if (local.version[0])
                local.confidence += 3;
            if (local.os_name[0])
                local.confidence += 2;
            if (local.cpe[0])
                local.confidence += 2;
            if (local.confidence > 100)
                local.confidence = 100;
        }

        /* Force NUL termination on all string fields */
        local.banner[sizeof(local.banner) - 1] = '\0';
        local.service[sizeof(local.service) - 1] = '\0';
        local.product[sizeof(local.product) - 1] = '\0';
        local.version[sizeof(local.version) - 1] = '\0';
        local.info[sizeof(local.info) - 1] = '\0';
        local.hostname[sizeof(local.hostname) - 1] = '\0';
        local.os_name[sizeof(local.os_name) - 1] = '\0';
        local.device_type[sizeof(local.device_type) - 1] = '\0';
        local.cpe[sizeof(local.cpe) - 1] = '\0';

        /* ──────────────────────────────────────────────────────
         * CONVERT: np_banner_result_t → np_os_banner_t
         * This is the critical bridge that fixes both bugs:
         *   1. Port now written to correct offset (offset 0)
         *   2. Fields truncated to correct sizes (32/64 bytes)
         * ────────────────────────────────────────────────────── */
        banner_result_to_os_banner(&local,
                                   &result->banners[result->banner_count]);

        /* Log from the local (rich) struct for debug visibility */
        banner_log("  probe_port_nmap: port=%u probe=%d match=%d "
                   "svc='%s' product='%s' ver='%s' os='%s' cpe='%s' "
                   "conf=%u soft=%d",
                   local.port, local.probe_idx, local.match_idx,
                   local.service[0] ? local.service : "(none)",
                   local.product[0] ? local.product : "(none)",
                   local.version[0] ? local.version : "(none)",
                   local.os_name[0] ? local.os_name : "(none)",
                   local.cpe[0] ? local.cpe : "(none)",
                   local.confidence, local.is_soft_match);

        result->banner_count++;
        return; /* first successful banner for this port is enough */
    }
}

/* ================================================================== */
/*  SECTION 9: Public API — np_os_banner_grab                         */
/* ================================================================== */

/*
 * Signature matches os_banner.h:
 *   np_status_t np_os_banner_grab(const np_target_t *target,
 *                                 const uint16_t    *ports,
 *                                 uint32_t           port_count,
 *                                 uint32_t           timeout_ms,
 *                                 const np_proxy_t  *proxy,
 *                                 np_os_result_t    *result);
 */

/* ================================================================
 * np_os_banner_grab — fixed result copy
 * ================================================================ */
np_status_t np_os_banner_grab(const np_target_t *target,
                              const uint16_t *ports,
                              uint32_t port_count,
                              uint32_t timeout_ms,
                              const np_proxy_t *proxy __attribute__((unused)),
                              np_os_result_t *result)
{
    if (!target || !ports || !result)
        return NP_STATUS_ERR;

    if (!g_engine_initialized)
    {
        if (np_banner_engine_init() != 0)
            return NP_STATUS_ERR;
    }

    result->banner_count = 0;

    for (uint32_t pi = 0; pi < port_count &&
                          result->banner_count < NP_OS_MAX_BANNERS;
         pi++)
    {
        uint16_t port = ports[pi];

        /* ── Select probes for this port ── */
        int probe_indices[NP_MAX_PROBES_PER_PORT];
        int probe_count = find_probes_for_port(port, NP_MAX_PROBE_RARITY,
                                               probe_indices,
                                               NP_MAX_PROBES_PER_PORT);

        if (probe_count == 0)
        {
            banner_log("port %u: no probes matched", port);
            continue;
        }

        banner_log("port %u: %d probes selected", port, probe_count);

        /* ──────────────────────────────────────────────────────
         * Per-port strategy:
         *   - Try probes in order (low rarity first).
         *   - On HARD match: store it, stop probing this port.
         *   - On SOFT match: remember it, keep looking for hard.
         *   - No match at all: store ONE banner (the largest
         *     response) so the pipeline can do fallback analysis.
         * ────────────────────────────────────────────────────── */
        np_banner_result_t best_matched;
        memset(&best_matched, 0, sizeof(best_matched));
        best_matched.match_idx = -1;
        bool have_hard_match = false;
        bool have_soft_match = false;

        /* Fallback: remember the largest unmatched response */
        np_banner_result_t best_unmatched;
        memset(&best_unmatched, 0, sizeof(best_unmatched));
        best_unmatched.match_idx = -1;

        for (int pi2 = 0; pi2 < probe_count && !have_hard_match; pi2++)
        {
            int pidx = probe_indices[pi2];
            const np_nmap_probe_t *probe = &g_nmap_probes[pidx];

            /* ── Open connection ── */
            int sock = open_connection(target->ip, port, timeout_ms);
            if (sock < 0)
            {
                banner_log("port %u probe[%s]: connect failed",
                           port, probe->name);
                break; /* No point trying more probes */
            }

            /* ── Send probe & read response ── */
            char recv_buf[NP_BANNER_RECV_BUF_SIZE];
            ssize_t recv_len = -1;

            if (probe->send_len == 0)
            {
                /* NULL probe: wait for server banner */
                recv_len = read_with_timeout(sock, recv_buf,
                                             sizeof(recv_buf), timeout_ms);
            }
            else
            {
                ssize_t sent = send(sock, probe->send_data,
                                    probe->send_len, 0);
                if (sent == (ssize_t)probe->send_len)
                {
                    recv_len = read_with_timeout(sock, recv_buf,
                                                 sizeof(recv_buf), timeout_ms);
                }
            }

            close(sock);

            if (recv_len <= 0)
            {
                banner_log("port %u probe[%s]: no response",
                           port, probe->name);
                continue;
            }

            banner_log("port %u probe[%s]: got %zd bytes",
                       port, probe->name, recv_len);

            /* ── Try matching ── */
            char captures[NP_MAX_CAPTURES][NP_CAPTURE_MAX_LEN];
            bool is_soft = false;

            int match_idx = try_matches_for_probe(
                pidx, recv_buf, (size_t)recv_len,
                captures, &is_soft);

            if (match_idx >= 0)
            {
                /* ── Build matched result ── */
                np_banner_result_t br;
                memset(&br, 0, sizeof(br));
                br.probe_idx = pidx;
                br.port = port;
                br.match_idx = match_idx;
                br.is_soft_match = is_soft;

                size_t copy_len = (size_t)recv_len;
                if (copy_len >= sizeof(br.banner))
                    copy_len = sizeof(br.banner) - 1;
                memcpy(br.banner, recv_buf, copy_len);
                br.banner[copy_len] = '\0';
                br.banner_len = (uint32_t)copy_len;

                const np_nmap_match_t *m = &g_nmap_matches[match_idx];

                if (m->service && m->service[0])
                    strncpy(br.service, m->service, sizeof(br.service) - 1);

                if (m->version_info_v && m->version_info_v[0])
                    expand_version_info(m->version_info_v, captures, &br);

                br.confidence = is_soft ? 50 : 90;

                /* Bonus confidence for rich data */
                if (br.product[0])
                    br.confidence += 3;
                if (br.version[0])
                    br.confidence += 3;
                if (br.os_name[0])
                    br.confidence += 2;
                if (br.cpe[0])
                    br.confidence += 2;
                if (br.confidence > 100)
                    br.confidence = 100;

                banner_log("port %u: MATCHED svc=%s product=%s "
                           "ver=%s os=%s conf=%u soft=%d",
                           port, br.service, br.product,
                           br.version, br.os_name,
                           br.confidence, is_soft);

                if (!is_soft)
                {
                    best_matched = br;
                    have_hard_match = true;
                }
                else if (!have_soft_match)
                {
                    best_matched = br;
                    have_soft_match = true;
                }
                /* If we already have a soft match, keep the first one */
            }
            else
            {
                /* ── Remember largest unmatched response ── */
                if ((size_t)recv_len > best_unmatched.banner_len)
                {
                    memset(&best_unmatched, 0, sizeof(best_unmatched));
                    best_unmatched.probe_idx = pidx;
                    best_unmatched.port = port;
                    best_unmatched.match_idx = -1;
                    best_unmatched.confidence = 0;

                    size_t ulen = (size_t)recv_len;
                    if (ulen >= sizeof(best_unmatched.banner))
                        ulen = sizeof(best_unmatched.banner) - 1;
                    memcpy(best_unmatched.banner, recv_buf, ulen);
                    best_unmatched.banner[ulen] = '\0';
                    best_unmatched.banner_len = (uint32_t)ulen;
                }
            }

        } /* end probe loop */

        /* ──────────────────────────────────────────────────────
         * Pick the best result for this port:
         *   hard match > soft match > unmatched (for fallback)
         * ────────────────────────────────────────────────────── */
        np_banner_result_t *chosen = NULL;

        if (have_hard_match || have_soft_match)
            chosen = &best_matched;
        else if (best_unmatched.banner_len > 0)
            chosen = &best_unmatched;

        if (!chosen)
            continue;

        /* ════════════════════════════════════════════════════════
         * SAFE COPY: np_banner_result_t → np_os_banner_t
         *
         * np_banner_result_t.banner = 1024 bytes
         * np_os_banner_t.banner     =  512 bytes
         *
         * We MUST truncate to avoid overflowing into
         * service/os_hint/product/version/cpe fields.
         * ════════════════════════════════════════════════════════ */
        uint32_t bi = result->banner_count;
        np_os_banner_t *out = &result->banners[bi];
        memset(out, 0, sizeof(*out));

        out->port = chosen->port;

        /* ── SAFE banner copy with truncation ── */
        uint32_t safe_len = chosen->banner_len;
        if (safe_len >= sizeof(out->banner)) /* sizeof = 512 */
            safe_len = (uint32_t)(sizeof(out->banner) - 1);
        memcpy(out->banner, chosen->banner, safe_len);
        out->banner[safe_len] = '\0';
        out->banner_len = safe_len;

        /* ── Service ── */
        if (chosen->service[0])
        {
            strncpy(out->service, chosen->service, sizeof(out->service) - 1);
            out->service[sizeof(out->service) - 1] = '\0';
        }

        /* ── Product ── */
        if (chosen->product[0])
        {
            strncpy(out->product, chosen->product, sizeof(out->product) - 1);
            out->product[sizeof(out->product) - 1] = '\0';
        }

        /* ── Version ── */
        if (chosen->version[0])
        {
            strncpy(out->version, chosen->version, sizeof(out->version) - 1);
            out->version[sizeof(out->version) - 1] = '\0';
        }

        /* ── CPE ── */
        if (chosen->cpe[0])
        {
            strncpy(out->cpe, chosen->cpe, sizeof(out->cpe) - 1);
            out->cpe[sizeof(out->cpe) - 1] = '\0';
        }

        /* ════════════════════════════════════════════════════════
         * OS hint + confidence
         *
         * Two independent concerns:
         *   A) Propagate nmap match confidence (ALWAYS when matched)
         *   B) Derive an OS hint from whatever data we have
         * ════════════════════════════════════════════════════════ */

        /* ── A: ALWAYS propagate confidence for nmap matches ── */
        if (chosen->match_idx >= 0 && chosen->confidence > 0)
        {
            out->os_hint_confidence = (int)chosen->confidence;
        }

        /* ── B: Derive OS hint ── */
        if (chosen->os_name[0])
        {
            /* Direct OS info from version_info "o/" field */
            strncpy(out->os_hint, chosen->os_name,
                    sizeof(out->os_hint) - 1);
            out->os_hint[sizeof(out->os_hint) - 1] = '\0';
        }
        else
        {
            /* Infer OS from product, info, cpe, service fields */
            const char *sources[] = {
                chosen->product, chosen->info, chosen->cpe,
                chosen->service, NULL};

            static const struct
            {
                const char *keyword;
                const char *os_hint;
                int confidence_penalty; /* subtracted from match conf */
            } os_keywords[] = {
                /* ── Explicit OS names (high confidence) ── */
                {"Ubuntu", "Linux/Ubuntu", 0},
                {"Debian", "Linux/Debian", 0},
                {"CentOS", "Linux/CentOS", 0},
                {"Red Hat", "Linux/RHEL", 0},
                {"RHEL", "Linux/RHEL", 0},
                {"Fedora", "Linux/Fedora", 0},
                {"Alpine", "Linux/Alpine", 0},
                {"Windows", "Windows", 0},
                {"Win32", "Windows", 0},
                {"Win64", "Windows", 0},
                {"FreeBSD", "FreeBSD", 0},
                {"OpenBSD", "OpenBSD", 0},
                {"NetBSD", "NetBSD", 0},
                {"macOS", "macOS", 0},
                {"Darwin", "macOS", 0},
                {"Linux", "Linux", 0},
                {"linux", "Linux", 0},

                /* ── Server software → likely OS (lower confidence) ── */
                {"nginx", "Linux", 15},
                {"openresty", "Linux", 15},
                {"OpenResty", "Linux", 15},
                {"sotoon", "Linux", 20},
                {"Sotoon", "Linux", 20},
                {"cloudflare", "Linux", 20},
                {"Cloudflare", "Linux", 20},
                {"Apache", "Linux", 15},
                {"lighttpd", "Linux", 15},
                {"OpenSSH", "Linux", 10},
                {"Postfix", "Linux", 15},
                {"Exim", "Linux", 15},
                {"dovecot", "Linux", 15},
                {"Sendmail", "Linux", 15},
                {"ProFTPD", "Linux", 15},
                {"vsftpd", "Linux", 10},
                {"pure-ftpd", "Linux", 15},
                {"Dropbear", "Linux", 10},
                {"IIS", "Windows", 5},
                {"Microsoft", "Windows", 10},
                {"Kestrel", "Windows", 15},
                {NULL, NULL, 0}};

            for (int s = 0; sources[s] != NULL; s++)
            {
                if (!sources[s][0])
                    continue;
                for (int k = 0; os_keywords[k].keyword; k++)
                {
                    if (strstr(sources[s], os_keywords[k].keyword))
                    {
                        strncpy(out->os_hint, os_keywords[k].os_hint,
                                sizeof(out->os_hint) - 1);
                        out->os_hint[sizeof(out->os_hint) - 1] = '\0';

                        /* Adjust confidence: if we inferred from
                         * software name rather than explicit OS,
                         * reduce confidence accordingly */
                        int penalty = os_keywords[k].confidence_penalty;
                        if (out->os_hint_confidence > penalty)
                            out->os_hint_confidence -= penalty;
                        else if (out->os_hint_confidence == 0)
                            out->os_hint_confidence = 40 - penalty;

                        goto os_hint_done;
                    }
                }
            }
        os_hint_done:;
        }

        result->banner_count++;

    } /* end port loop */

    banner_log("banner_grab complete: %u banners captured",
               result->banner_count);

    return NP_STATUS_OK;
}

/* ================================================================== */
/*  SECTION 10: Legacy API wrapper — np_os_banner_match               */
/* ================================================================== */

np_status_t np_os_banner_match(np_os_result_t *result,
                               const np_os_sigdb_t *db)
{
    (void)db; /* Nmap engine handles matching internally */

    if (!result)
        return NP_STATUS_ERR;

    return NP_STATUS_OK;
}
