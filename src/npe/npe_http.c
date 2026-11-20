/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_http.c — HTTP Client Library Implementation
 * =============================================================================
 *
 *  Implements all functions declared in npe_lib_http.h.
 *  Provides a full HTTP/1.1 client with SSL/TLS, chunked encoding,
 *  redirects, cookies, basic auth, and Lua bindings.
 *
 *  Build requirements:
 *    - OpenSSL (libssl, libcrypto)
 *    - Lua 5.3+ (liblua)
 *    - POSIX (poll, getaddrinfo, clock_gettime)
 *
 *  Compile example (macOS):
 *    cc -std=c11 -O2 -Wall -Wextra \
 *       -I/opt/homebrew/include \
 *       -L/opt/homebrew/lib \
 *       -o npe_http.o -c npe_http.c \
 *       -lssl -lcrypto -llua
 * =============================================================================
 */

/* ── Feature-test macros (before any includes) ─────────────────────────────── */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

/* ── C standard headers ────────────────────────────────────────────────────── */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp on some systems                     */
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
/* ── POSIX / system headers ────────────────────────────────────────────────── */
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include "logger.h"

/* ── OpenSSL headers ───────────────────────────────────────────────────────── */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

/* ── Project header ────────────────────────────────────────────────────────── */
#include "npe_lib_http.h"
#include "logger.h"
#include "npe_http2.h"
#include "npe_http2_adapter.h"

/* ─────────────────────────────────────────────────────────────────────────────
 * SSL Singleton Initialisation Flag
 * ───────────────────────────────────────────────────────────────────────────── */

static int npe_http__ssl_initialised = 0;

static void npe_http__ssl_init_once(void)
{
    if (!npe_http__ssl_initialised)
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        npe_http__ssl_initialised = 1;
    }
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 1 — Utility Helpers
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Monotonic clock in milliseconds ──────────────────────────────────────── */
static double npe_http__time_ms(void)
{
    struct timespec ts;
#if defined(CLOCK_MONOTONIC_RAW)
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
}

/* ── Remaining-timeout helper ─────────────────────────────────────────────── */
static uint32_t npe_http__remaining_ms(double start_ms, uint32_t total_ms)
{
    if (total_ms == 0)
        return 0; /* 0 = unlimited */
    double elapsed = npe_http__time_ms() - start_ms;
    if (elapsed >= (double)total_ms)
        return 1; /* floor to 1 ms, never 0 */
    return (uint32_t)((double)total_ms - elapsed);
}

/* ── Case-insensitive compare (portable) ──────────────────────────────────── */
static int npe_http__strcasecmp(const char *a, const char *b)
{
    return strcasecmp(a, b);
}

/* ── Realloc wrapper (returns NULL on failure, original ptr untouched) ─────  */
static void *npe_http__realloc_safe(void *ptr, size_t new_size)
{
    void *tmp = realloc(ptr, new_size);
    if (!tmp && new_size > 0)
    {
        /* allocation failed — caller must handle NULL */
        return NULL;
    }
    return tmp;
}

/* ── Base64 encoding (for Basic auth) ─────────────────────────────────────── */
static const char npe_http__b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *npe_http__base64_encode(const char *input, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    if (!out)
        return NULL;

    size_t i = 0, j = 0;
    while (i < len)
    {
        uint32_t octet_a = (i < len) ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = (i < len) ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = (i < len) ? (unsigned char)input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = npe_http__b64_table[(triple >> 18) & 0x3F];
        out[j++] = npe_http__b64_table[(triple >> 12) & 0x3F];
        out[j++] = npe_http__b64_table[(triple >> 6) & 0x3F];
        out[j++] = npe_http__b64_table[(triple) & 0x3F];
    }

    /* Apply padding */
    size_t mod = len % 3;
    if (mod == 1)
    {
        out[j - 1] = NPE_HTTP__BASE64_PAD;
        out[j - 2] = NPE_HTTP__BASE64_PAD;
    }
    else if (mod == 2)
    {
        out[j - 1] = NPE_HTTP__BASE64_PAD;
    }

    out[j] = '\0';
    return out;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 2 — Networking Helpers
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Set socket non-blocking ──────────────────────────────────────────────── */
static int npe_http__set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ── Set socket blocking ─────────────────────────────────────────────────── */
static int npe_http__set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/* ── Connection cleanup helper ────────────────────────────────────────────── */
static void npe_http__close_conn(int fd, SSL *ssl, SSL_CTX *ssl_ctx)
{
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl); /* also closes underlying fd */
    }
    else if (fd >= 0)
    {
        close(fd);
    }
    if (ssl_ctx)
    {
        SSL_CTX_free(ssl_ctx);
    }
}

/* ── TCP connect with optional timeout ────────────────────────────────────── */
static int npe_http__connect(const npe_http__parsed_url_t *url,
                             const npe_http_request_opts_t *opts,
                             int *out_fd)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%u", url->port);

    int gai = getaddrinfo(url->host, port_str, &hints, &res);
    if (gai != 0)
    {
        return -1;
    }

    uint32_t connect_timeout = NPE_HTTP__CONNECT_TIMEOUT_MS;
    if (opts && opts->timeout_ms > 0)
        connect_timeout = opts->timeout_ms;

    int fd = -1;
    int last_errno = 0;

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
        {
            last_errno = errno;
            continue;
        }

        /* Set socket options before connect */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

        /* Non-blocking connect for timeout support */
        if (npe_http__set_nonblocking(fd) < 0)
        {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0)
        {
            /* Immediate success */
            npe_http__set_blocking(fd);
            break;
        }

        if (errno != EINPROGRESS && errno != EINTR)
        {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }

        /* Wait for connect with poll() */
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        int pr = poll(&pfd, 1, (int)connect_timeout);
        if (pr < 0)
        {
            /* poll error */
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        if (pr == 0)
        {
            /* timeout */
            last_errno = ETIMEDOUT;
            close(fd);
            fd = -1;
            continue;
        }

        /* Check what poll returned */
        if (!(pfd.revents & POLLOUT))
        {
            /* Not writable, connection failed */
            last_errno = ECONNREFUSED;
            close(fd);
            fd = -1;
            continue;
        }

        /* Check for connect error */
        int so_err = 0;
        socklen_t slen = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) < 0)
        {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }

        if (so_err != 0)
        {
            last_errno = so_err;
            close(fd);
            fd = -1;
            continue;
        }

        /* Success */
        npe_http__set_blocking(fd);
        break;
    }

    freeaddrinfo(res);

    if (fd < 0)
    {
        errno = last_errno;
        return -1;
    }

    *out_fd = fd;
    return 0;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 3 — SSL Helpers
 * ═════════════════════════════════════════════════════════════════════════════*/

static SSL_CTX *npe_http__ssl_ctx_create(bool verify)
{
    npe_http__ssl_init_once();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        return NULL;

    /* Set minimum TLS version to 1.2 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (verify)
    {
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    else
    {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

static SSL *npe_http__ssl_connect(int fd, SSL_CTX *ctx, const char *host)
{
    LOGI("SSL: host='%s' fd=%d", host ? host : "NULL", fd);

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        LOGE("SSL: SSL_new failed");
        return NULL;
    }

    SSL_set_tlsext_host_name(ssl, host);

    if (!SSL_set_fd(ssl, fd))
    {
        LOGE("SSL: SSL_set_fd failed fd=%d errno=%d", fd, errno);
        SSL_free(ssl);
        return NULL;
    }

    int rc = SSL_connect(ssl);
    if (rc != 1)
    {
        LOGE("SSL: SSL_connect failed rc=%d err=%d", rc, SSL_get_error(ssl, rc));
        SSL_free(ssl);
        return NULL;
    }

    LOGI("SSL: handshake OK");
    return ssl;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 4 — Wire I/O
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Send entire buffer through plain or SSL socket ───────────────────────── */
static int npe_http__send_all(int fd, SSL *ssl,
                              const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n;
        if (ssl)
        {
            n = SSL_write(ssl, buf + sent, (int)(len - sent));
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, (int)n);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                    continue;
                return -1;
            }
        }
        else
        {
            n = send(fd, buf + sent, len - sent, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                return -1;
            }
            if (n == 0)
                return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/* ── Receive a single line terminated by \r\n ─────────────────────────────── */
/*    Returns length of line (excluding \r\n), or -1 on error/timeout.
 *    The output buf is NUL-terminated and does NOT include the \r\n.        */
static int npe_http__recv_line(int fd, SSL *ssl,
                               char *buf, size_t buf_size,
                               uint32_t timeout_ms)
{
    size_t pos = 0;
    double start = npe_http__time_ms();

    while (pos + 1 < buf_size)
    {
        /* Check timeout */
        if (timeout_ms > 0)
        {
            double elapsed = npe_http__time_ms() - start;
            if (elapsed >= (double)timeout_ms)
                return -1;

            /* Use poll to wait for data (only for plain sockets;
               SSL may have buffered data) */
            if (!ssl || !SSL_pending(ssl))
            {
                int remain = (int)((double)timeout_ms - elapsed);
                if (remain <= 0)
                    return -1;

                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLIN;
                int pr = poll(&pfd, 1, remain);
                if (pr <= 0)
                    return -1; /* timeout or error */
            }
        }

        /* Read one byte */
        char c;
        ssize_t n;
        if (ssl)
        {
            n = SSL_read(ssl, &c, 1);
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                return -1; /* connection closed or error */
            }
        }
        else
        {
            n = recv(fd, &c, 1, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            if (n == 0)
                return -1; /* connection closed */
        }

        buf[pos++] = c;

        /* Check for \r\n ending */
        if (pos >= 2 && buf[pos - 2] == '\r' && buf[pos - 1] == '\n')
        {
            buf[pos - 2] = '\0';
            return (int)(pos - 2);
        }
    }

    /* Buffer full without finding \r\n */
    buf[pos] = '\0';
    return -1;
}

/* ── Receive exactly `len` bytes ──────────────────────────────────────────── */
static int npe_http__recv_exact(int fd, SSL *ssl,
                                char *buf, size_t len,
                                uint32_t timeout_ms)
{
    size_t received = 0;
    double start = npe_http__time_ms();

    while (received < len)
    {
        /* Check timeout */
        if (timeout_ms > 0)
        {
            double elapsed = npe_http__time_ms() - start;
            if (elapsed >= (double)timeout_ms)
                return -1;

            if (!ssl || !SSL_pending(ssl))
            {
                int remain = (int)((double)timeout_ms - elapsed);
                if (remain <= 0)
                    return -1;

                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLIN;
                int pr = poll(&pfd, 1, remain);
                if (pr <= 0)
                    return -1;
            }
        }

        ssize_t n;
        size_t want = len - received;
        if (want > NPE_HTTP__RECV_BUF_SIZE)
            want = NPE_HTTP__RECV_BUF_SIZE;

        if (ssl)
        {
            n = SSL_read(ssl, buf + received, (int)want);
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                return -1;
            }
        }
        else
        {
            n = recv(fd, buf + received, want, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            if (n == 0)
                return -1; /* connection closed prematurely */
        }
        received += (size_t)n;
    }
    return 0;
}

/* ── Receive all available data until connection close or max_len ─────────── */
/*    Dynamically allocates *out_buf.  Caller must free().
 *    Returns 0 on success (including clean EOF), -1 on hard error.          */
static int npe_http__recv_all_available(int fd, SSL *ssl,
                                        char **out_buf, size_t *out_len,
                                        size_t max_len,
                                        uint32_t timeout_ms)
{
    size_t capacity = NPE_HTTP__INITIAL_BODY_CAP;
    size_t length = 0;
    char *buf = (char *)malloc(capacity);
    if (!buf)
        return -1;

    double start = npe_http__time_ms();

    for (;;)
    {
        /* Timeout check */
        if (timeout_ms > 0)
        {
            double elapsed = npe_http__time_ms() - start;
            if (elapsed >= (double)timeout_ms)
                break; /* treat as done */

            if (!ssl || !SSL_pending(ssl))
            {
                int remain = (int)((double)timeout_ms - elapsed);
                if (remain <= 0)
                    break;

                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLIN;
                int pr = poll(&pfd, 1, remain);
                if (pr < 0)
                {
                    free(buf);
                    return -1;
                }
                if (pr == 0)
                    break; /* timeout — return what we have */
            }
        }

        /* Grow buffer if needed */
        if (length + NPE_HTTP__RECV_BUF_SIZE > capacity)
        {
            size_t new_cap = capacity * 2;
            if (new_cap > max_len)
                new_cap = max_len + 1;
            char *tmp = (char *)npe_http__realloc_safe(buf, new_cap);
            if (!tmp)
            {
                free(buf);
                return -1;
            }
            buf = tmp;
            capacity = new_cap;
        }

        size_t want = capacity - length;
        if (want > NPE_HTTP__RECV_BUF_SIZE)
            want = NPE_HTTP__RECV_BUF_SIZE;
        if (max_len > 0 && length + want > max_len)
            want = max_len - length;
        if (want == 0)
            break; /* max_len reached */

        ssize_t n;
        if (ssl)
        {
            n = SSL_read(ssl, buf + length, (int)want);
            if (n <= 0)
            {
                int err = SSL_get_error(ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                /* SSL_ERROR_ZERO_RETURN = clean shutdown, others = error.
                   Either way, we return what we collected so far.           */
                break;
            }
        }
        else
        {
            n = recv(fd, buf + length, want, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                free(buf);
                return -1;
            }
            if (n == 0)
                break; /* peer closed connection — normal for
                          read-until-close bodies */
        }
        length += (size_t)n;
    }

    /* NUL-terminate for convenience (body might be text) */
    char *final = (char *)npe_http__realloc_safe(buf, length + 1);
    if (!final)
    {
        /* realloc shrink shouldn't fail, but just in case */
        buf[length < capacity ? length : capacity - 1] = '\0';
        *out_buf = buf;
        *out_len = length;
        return 0;
    }
    final[length] = '\0';
    *out_buf = final;
    *out_len = length;
    return 0;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 5 — HTTP Response Parsing
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Parse status line: "HTTP/1.1 200 OK" ─────────────────────────────────── */
/*    Populates resp->status_code and resp->status_line.
 *    Returns 0 on success, -1 on malformed line.                            */
static int npe_http__parse_status_line(const char *line,
                                       npe_http_response_t *resp)
{
    /* Expect: HTTP/x.y SP status_code SP reason_phrase
     * Minimum valid: "HTTP/1.0 200"  (reason may be absent)                 */
    if (strncmp(line, "HTTP/", 5) != 0)
        return -1;

    /* Store entire status line */
    snprintf(resp->status_line, sizeof(resp->status_line), "%s", line);

    /* Advance past "HTTP/x.y" to the space */
    const char *p = line + 5;
    while (*p && *p != ' ')
        p++;
    if (*p != ' ')
        return -1;
    p++; /* skip the space */

    /* Parse status code */
    char *end = NULL;
    long code = strtol(p, &end, 10);
    if (end == p || code < 100 || code > 999)
        return -1;

    resp->status_code = (int)code;
    return 0;
}

/* ── Parse a single header line: "Key: Value" ─────────────────────────────── */
/*    Writes into the provided npe_http_header_t.
 *    Returns 0 on success, -1 on malformed line.                            */
static int npe_http__parse_header_line(const char *line,
                                       npe_http_header_t *hdr)
{
    const char *colon = strchr(line, ':');
    if (!colon)
        return -1;

    /* Key: everything before the colon */
    size_t key_len = (size_t)(colon - line);
    if (key_len == 0 || key_len >= sizeof(hdr->name))
        return -1;

    memcpy(hdr->name, line, key_len);
    hdr->name[key_len] = '\0';

    /* Trim trailing whitespace from key (shouldn't be any, but be safe) */
    while (key_len > 0 && hdr->name[key_len - 1] == ' ')
    {
        hdr->name[--key_len] = '\0';
    }

    /* Value: everything after the colon, skip leading whitespace */
    const char *val = colon + 1;
    while (*val == ' ' || *val == '\t')
        val++;

    snprintf(hdr->value, sizeof(hdr->value), "%s", val);

    /* Trim trailing whitespace from value */
    size_t vlen = strlen(hdr->value);
    while (vlen > 0 && (hdr->value[vlen - 1] == ' ' ||
                        hdr->value[vlen - 1] == '\t' ||
                        hdr->value[vlen - 1] == '\r' ||
                        hdr->value[vlen - 1] == '\n'))
    {
        hdr->value[--vlen] = '\0';
    }

    return 0;
}

/* ── Read all response headers ────────────────────────────────────────────── */
/*    Reads lines until blank line (\r\n\r\n).
 *    Dynamically allocates resp->headers array.
 *    Returns 0 on success, -1 on error.                                     */
static int npe_http__read_headers(int fd, SSL *ssl,
                                  npe_http_response_t *resp,
                                  uint32_t timeout_ms)
{
    char line_buf[NPE_HTTP__LINE_BUF_SIZE];

    /* Read status line first */
    int line_len = npe_http__recv_line(fd, ssl, line_buf,
                                       sizeof(line_buf), timeout_ms);
    if (line_len < 0)
        return -1;

    if (npe_http__parse_status_line(line_buf, resp) < 0)
        return -1;

    /* Allocate initial headers array */
    size_t hdr_cap = NPE_HTTP__INITIAL_HDR_ALLOC;
    resp->headers = (npe_http_header_t *)calloc(hdr_cap,
                                                sizeof(npe_http_header_t));
    if (!resp->headers)
        return -1;
    resp->header_count = 0;

    /* Read header lines */
    for (;;)
    {
        line_len = npe_http__recv_line(fd, ssl, line_buf,
                                       sizeof(line_buf), timeout_ms);
        if (line_len < 0)
            return -1;

        /* Empty line = end of headers */
        if (line_len == 0)
            break;

        /* Grow array if needed */
        if (resp->header_count >= hdr_cap)
        {
            size_t new_cap = hdr_cap * 2;
            npe_http_header_t *tmp = (npe_http_header_t *)
                npe_http__realloc_safe(resp->headers,
                                       new_cap * sizeof(npe_http_header_t));
            if (!tmp)
                return -1;
            /* Zero out new entries */
            memset(tmp + hdr_cap, 0,
                   (new_cap - hdr_cap) * sizeof(npe_http_header_t));
            resp->headers = tmp;
            hdr_cap = new_cap;
        }

        /* Parse header line into next slot */
        npe_http_header_t *h = &resp->headers[resp->header_count];
        if (npe_http__parse_header_line(line_buf, h) == 0)
        {
            resp->header_count++;
        }
        /* Silently skip malformed headers */
    }

    return 0;
}

/* ── Helper: find header value by name (case-insensitive) ─────────────────── */
static const char *npe_http__find_header(const npe_http_response_t *resp,
                                         const char *name)
{
    for (size_t i = 0; i < resp->header_count; i++)
    {
        if (npe_http__strcasecmp(resp->headers[i].name, name) == 0)
            return resp->headers[i].value;
    }
    return NULL;
}

/* ── Extract Set-Cookie headers into resp->cookies ────────────────────────── */
static void npe_http__extract_cookies(npe_http_response_t *resp)
{
    /* First pass: count Set-Cookie headers */
    size_t count = 0;
    for (size_t i = 0; i < resp->header_count; i++)
    {
        if (npe_http__strcasecmp(resp->headers[i].name, "Set-Cookie") == 0)
            count++;
    }

    if (count == 0)
    {
        resp->cookies = NULL;
        resp->cookie_count = 0;
        return;
    }

    resp->cookies = (npe_http_cookie_t *)calloc(count,
                                                sizeof(npe_http_cookie_t));
    if (!resp->cookies)
    {
        resp->cookie_count = 0;
        return;
    }

    /* Second pass: parse each Set-Cookie header */
    size_t ci = 0;
    for (size_t i = 0; i < resp->header_count && ci < count; i++)
    {
        if (npe_http__strcasecmp(resp->headers[i].name, "Set-Cookie") != 0)
            continue;

        const char *val = resp->headers[i].value;
        npe_http_cookie_t *ck = &resp->cookies[ci];

        /* Cookie format: name=value[; attr1; attr2=val; ...] */
        const char *eq = strchr(val, '=');
        const char *semi = strchr(val, ';');

        if (!eq)
            continue; /* malformed */

        /* Cookie name */
        size_t name_len = (size_t)(eq - val);
        if (name_len >= sizeof(ck->name))
            name_len = sizeof(ck->name) - 1;
        memcpy(ck->name, val, name_len);
        ck->name[name_len] = '\0';

        /* Cookie value: from after '=' to ';' or end */
        const char *vstart = eq + 1;
        size_t vlen;
        if (semi)
        {
            vlen = (size_t)(semi - vstart);
        }
        else
        {
            vlen = strlen(vstart);
        }
        if (vlen >= sizeof(ck->value))
            vlen = sizeof(ck->value) - 1;
        memcpy(ck->value, vstart, vlen);
        ck->value[vlen] = '\0';

        /* Parse attributes (domain, path, secure, httponly, expires) */
        ck->secure = false;
        ck->httponly = false;
        ck->domain[0] = '\0';
        ck->path[0] = '\0';
        ck->expires[0] = '\0';

        if (semi)
        {
            const char *attr = semi + 1;
            while (*attr)
            {
                /* Skip whitespace */
                while (*attr == ' ' || *attr == '\t')
                    attr++;
                if (*attr == '\0')
                    break;

                /* Find next semicolon or end */
                const char *next_semi = strchr(attr, ';');
                size_t alen = next_semi ? (size_t)(next_semi - attr)
                                        : strlen(attr);

                /* Check for known attributes */
                if (strncasecmp(attr, "domain=", 7) == 0 && alen > 7)
                {
                    size_t dl = alen - 7;
                    if (dl >= sizeof(ck->domain))
                        dl = sizeof(ck->domain) - 1;
                    memcpy(ck->domain, attr + 7, dl);
                    ck->domain[dl] = '\0';
                }
                else if (strncasecmp(attr, "path=", 5) == 0 && alen > 5)
                {
                    size_t pl = alen - 5;
                    if (pl >= sizeof(ck->path))
                        pl = sizeof(ck->path) - 1;
                    memcpy(ck->path, attr + 5, pl);
                    ck->path[pl] = '\0';
                }
                else if (strncasecmp(attr, "expires=", 8) == 0 && alen > 8)
                {
                    size_t el = alen - 8;
                    if (el >= sizeof(ck->expires))
                        el = sizeof(ck->expires) - 1;
                    memcpy(ck->expires, attr + 8, el);
                    ck->expires[el] = '\0';
                }
                else if (strncasecmp(attr, "secure", 6) == 0)
                {
                    ck->secure = true;
                }
                else if (strncasecmp(attr, "httponly", 8) == 0)
                {
                    ck->httponly = true;
                }

                if (!next_semi)
                    break;
                attr = next_semi + 1;
            }
        }

        ci++;
    }

    resp->cookie_count = ci;
}
/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 6 — Response Body Reading
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Read chunked transfer-encoded body ───────────────────────────────────── */
/*    Dynamically assembles the decoded body.
 *    Returns 0 on success, -1 on error.                                     */
static int npe_http__read_chunked_body(int fd, SSL *ssl,
                                       char **out_buf, size_t *out_len,
                                       size_t max_body,
                                       uint32_t timeout_ms)
{
    size_t capacity = NPE_HTTP__INITIAL_BODY_CAP;
    size_t length = 0;
    char *buf = (char *)malloc(capacity);
    if (!buf)
        return -1;

    char line_buf[NPE_HTTP__LINE_BUF_SIZE];

    for (;;)
    {
        /* Read chunk size line: hex_digits [; extensions] \r\n */
        int ll = npe_http__recv_line(fd, ssl, line_buf,
                                     sizeof(line_buf), timeout_ms);
        if (ll < 0)
        {
            free(buf);
            return -1;
        }

        /* Parse hex chunk size */
        char *end = NULL;
        unsigned long chunk_sz = strtoul(line_buf, &end, 16);
        if (end == line_buf)
        {
            free(buf);
            return -1;
        } /* no hex digits */

        /* Last chunk */
        if (chunk_sz == 0)
            break;

        /* Enforce max body limit */
        if (max_body > 0 && length + chunk_sz > max_body)
        {
            free(buf);
            return -1;
        }

        /* Ensure buffer capacity */
        while (length + chunk_sz + 1 > capacity)
        {
            size_t new_cap = capacity * 2;
            if (new_cap < length + chunk_sz + 1)
                new_cap = length + chunk_sz + 1;
            char *tmp = (char *)npe_http__realloc_safe(buf, new_cap);
            if (!tmp)
            {
                free(buf);
                return -1;
            }
            buf = tmp;
            capacity = new_cap;
        }

        /* Read chunk data */
        if (npe_http__recv_exact(fd, ssl, buf + length,
                                 chunk_sz, timeout_ms) < 0)
        {
            free(buf);
            return -1;
        }
        length += chunk_sz;

        /* Read trailing \r\n after chunk data */
        ll = npe_http__recv_line(fd, ssl, line_buf,
                                 sizeof(line_buf), timeout_ms);
        if (ll < 0)
        {
            free(buf);
            return -1;
        }
        /* line_buf should be empty (just the \r\n that was stripped) */
    }

    /* Read trailer headers (if any) until blank line */
    for (;;)
    {
        int ll = npe_http__recv_line(fd, ssl, line_buf,
                                     sizeof(line_buf), timeout_ms);
        if (ll < 0)
            break; /* tolerate errors in trailers */
        if (ll == 0)
            break; /* blank line = end of trailers */
    }

    /* NUL-terminate */
    char *final = (char *)npe_http__realloc_safe(buf, length + 1);
    if (final)
    {
        buf = final;
    }
    buf[length] = '\0';

    *out_buf = buf;
    *out_len = length;
    return 0;
}

/* ── Read response body according to Transfer-Encoding / Content-Length ──── */
/*    Populates resp->body and resp->body_length.
 *    Returns 0 on success, -1 on error.                                     */
static int npe_http__read_body(int fd, SSL *ssl,
                               npe_http_response_t *resp,
                               size_t max_body,
                               uint32_t timeout_ms)
{
    resp->body = NULL;
    resp->body_len = 0;

    /* 1xx, 204, 304 have no body */
    if (resp->status_code < 200 ||
        resp->status_code == 204 ||
        resp->status_code == 304)
    {
        return 0;
    }

    /* Check Transfer-Encoding: chunked */
    const char *te = npe_http__find_header(resp, "Transfer-Encoding");
    if (te && strstr(te, "chunked"))
    {
        return npe_http__read_chunked_body(fd, ssl,
                                           &resp->body, &resp->body_len,
                                           max_body, timeout_ms);
    }

    /* Check Content-Length */
    const char *cl = npe_http__find_header(resp, "Content-Length");
    if (cl)
    {
        char *end = NULL;
        unsigned long content_len = strtoul(cl, &end, 10);
        if (end == cl)
            return -1;

        if (content_len == 0)
            return 0; /* empty body */

        if (max_body > 0 && content_len > max_body)
            return -1; /* body too large */

        resp->body = (char *)malloc(content_len + 1);
        if (!resp->body)
            return -1;

        if (npe_http__recv_exact(fd, ssl, resp->body,
                                 content_len, timeout_ms) < 0)
        {
            free(resp->body);
            resp->body = NULL;
            return -1;
        }

        resp->body[content_len] = '\0';
        resp->body_len = content_len;
        return 0;
    }

    /* No Content-Length, no chunked: read until connection close */
    size_t limit = max_body > 0 ? max_body : NPE_HTTP__MAX_BODY_DEFAULT;
    return npe_http__recv_all_available(fd, ssl,
                                        &resp->body, &resp->body_len,
                                        limit, timeout_ms);
}

/* ── Decompress gzip/deflate body if Content-Encoding present ─────────────── */
/*    Operates in-place: replaces resp->body and resp->body_length.
 *    If zlib is not available or decompression fails, body is left as-is.   */
#ifdef NPE_HTTP_HAVE_ZLIB
#include <zlib.h>

static int npe_http__decompress_body(npe_http_response_t *resp)
{
    const char *ce = npe_http__find_header(resp, "Content-Encoding");
    if (!ce)
        return 0;

    int is_gzip = (strstr(ce, "gzip") != NULL);
    int is_deflate = (strstr(ce, "deflate") != NULL);
    if (!is_gzip && !is_deflate)
        return 0;

    if (!resp->body || resp->body_length == 0)
        return 0;

    /* Prepare zlib stream */
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    /* windowBits: 15 for deflate, 15+16 for gzip auto-detect */
    int window_bits = is_gzip ? (15 + 16) : 15;
    if (inflateInit2(&zs, window_bits) != Z_OK)
        return -1;

    zs.next_in = (Bytef *)resp->body;
    zs.avail_in = (uInt)resp->body_length;

    /* Estimate output size: start at 4x input */
    size_t out_cap = resp->body_length * 4;
    if (out_cap < 4096)
        out_cap = 4096;
    char *out_buf = (char *)malloc(out_cap);
    if (!out_buf)
    {
        inflateEnd(&zs);
        return -1;
    }

    size_t out_len = 0;
    int ret;
    do
    {
        /* Grow if buffer is full */
        if (out_len >= out_cap)
        {
            size_t new_cap = out_cap * 2;
            char *tmp = (char *)npe_http__realloc_safe(out_buf, new_cap);
            if (!tmp)
            {
                free(out_buf);
                inflateEnd(&zs);
                return -1;
            }
            out_buf = tmp;
            out_cap = new_cap;
        }

        zs.next_out = (Bytef *)(out_buf + out_len);
        zs.avail_out = (uInt)(out_cap - out_len);

        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
        {
            free(out_buf);
            inflateEnd(&zs);
            return -1;
        }

        out_len = out_cap - zs.avail_out;

    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);

    /* NUL-terminate */
    char *final = (char *)npe_http__realloc_safe(out_buf, out_len + 1);
    if (final)
        out_buf = final;
    out_buf[out_len] = '\0';

    /* Replace body */
    free(resp->body);
    resp->body = out_buf;
    resp->body_length = out_len;

    return 0;
}

#else /* no zlib */

static int npe_http__decompress_body(npe_http_response_t *resp)
{
    (void)resp;
    return 0; /* silently leave body compressed */
}

#endif /* NPE_HTTP_HAVE_ZLIB */

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 7 — URL Parsing
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Parse a URL string into components ───────────────────────────────────── */
/*    Supports http:// and https://
 *    Returns 0 on success, -1 on malformed URL.                             */
static int npe_http__parse_url(const char *url, npe_http__parsed_url_t *out)
{
    memset(out, 0, sizeof(*out));

    /* ── Scheme ──────────────────────────────────────────────────────────── */
    const char *p = url;
    if (strncasecmp(p, "https://", 8) == 0)
    {
        out->use_ssl = true;
        out->port = 443;
        snprintf(out->scheme, sizeof(out->scheme), "https");
        p += 8;
    }
    else if (strncasecmp(p, "http://", 7) == 0)
    {
        out->use_ssl = false;
        out->port = 80;
        snprintf(out->scheme, sizeof(out->scheme), "http");
        p += 7;
    }
    else
    {
        return -1; /* unsupported scheme */
    }

    /* ── Host (and optional port) ────────────────────────────────────────── */
    const char *host_start = p;
    const char *slash = strchr(p, '/');
    const char *at_sign = NULL;

    /* Skip over userinfo@ if present (not used, but must not confuse host) */
    for (const char *s = p; s < (slash ? slash : p + strlen(p)); s++)
    {
        if (*s == '@')
        {
            at_sign = s;
            break;
        }
    }
    if (at_sign)
        host_start = at_sign + 1;

    /* Determine host end */
    size_t host_end_len;
    if (slash)
    {
        host_end_len = (size_t)(slash - host_start);
    }
    else
    {
        host_end_len = strlen(host_start);
    }

    /* Temporary buffer for host:port segment */
    char host_port[544];
    if (host_end_len >= sizeof(host_port))
        return -1;
    memcpy(host_port, host_start, host_end_len);
    host_port[host_end_len] = '\0';

    /* Check for port separator — handle IPv6 [addr]:port */
    char *bracket = strchr(host_port, '[');
    char *colon_port = NULL;
    if (bracket)
    {
        /* IPv6 literal */
        char *close = strchr(bracket, ']');
        if (!close)
            return -1;
        /* Host is between brackets */
        size_t hl = (size_t)(close - bracket - 1);
        if (hl == 0 || hl >= sizeof(out->host))
            return -1;
        memcpy(out->host, bracket + 1, hl);
        out->host[hl] = '\0';
        /* Port after ']:'? */
        if (*(close + 1) == ':')
        {
            colon_port = close + 2;
        }
    }
    else
    {
        /* IPv4 or hostname — last colon is port separator */
        char *last_colon = strrchr(host_port, ':');
        if (last_colon)
        {
            *last_colon = '\0';
            colon_port = last_colon + 1;
        }
        snprintf(out->host, sizeof(out->host), "%s", host_port);
    }

    if (colon_port && *colon_port)
    {
        char *end = NULL;
        unsigned long pv = strtoul(colon_port, &end, 10);
        if (end == colon_port || pv == 0 || pv > 65535)
            return -1;
        out->port = (uint16_t)pv;
    }

    /* ── Path ────────────────────────────────────────────────────────────── */
    if (slash)
    {
        snprintf(out->path, sizeof(out->path), "%s", slash);
    }
    else
    {
        snprintf(out->path, sizeof(out->path), "/");
    }

    /* ── Host header value ───────────────────────────────────────────────── */
    bool default_port = (out->use_ssl && out->port == 443) ||
                        (!out->use_ssl && out->port == 80);
    if (default_port)
    {
        snprintf(out->host_header, sizeof(out->host_header),
                 "%s", out->host);
    }
    else
    {
        snprintf(out->host_header, sizeof(out->host_header),
                 "%s:%u", out->host, (unsigned)out->port);
    }

    return 0;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 8 — HTTP Request Building
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Convert method enum to string ────────────────────────────────────────── */
static const char *npe_http__method_str(npe_http_method_t m)
{
    switch (m)
    {
    case NPE_HTTP_GET:
        return "GET";
    case NPE_HTTP_POST:
        return "POST";
    case NPE_HTTP_PUT:
        return "PUT";
    case NPE_HTTP_DELETE:
        return "DELETE";
    case NPE_HTTP_PATCH:
        return "PATCH";
    case NPE_HTTP_HEAD:
        return "HEAD";
    case NPE_HTTP_OPTIONS:
        return "OPTIONS";
    default:
        return "GET";
    }
}

/* ── Build the full HTTP/1.1 request into a dynamically allocated buffer ──── */
/*    Returns allocated string on success, NULL on failure.                   */
static char *npe_http__build_request(const npe_http_request_t *req,
                                     const npe_http__parsed_url_t *url,
                                     size_t *out_len)
{
    /* Estimate buffer size */
    size_t est = 512; /* request line + standard headers */

    /* Custom headers */
    for (size_t i = 0; i < req->header_count; i++)
    {
        est += strlen(req->headers[i].name) + strlen(req->headers[i].value) + 4;
    }

    /* Body */
    if (req->body && req->body_length > 0)
    {
        est += 64; /* Content-Length header */
        est += req->body_length;
    }

    /* Auth */
    if (req->auth_username[0] != '\0')
    {
        est += 512; /* Authorization: Basic ... */
    }

    /* Cookie */
    if (req->cookie_header && req->cookie_header[0] != '\0')
    {
        est += strlen(req->cookie_header) + 16;
    }

    char *buf = (char *)malloc(est);
    if (!buf)
        return NULL;

    int off = 0;
    int remaining = (int)est;

    /* ── Request line ────────────────────────────────────────────────────── */
    off += snprintf(buf + off, (size_t)remaining,
                    "%s %s HTTP/1.1\r\n",
                    npe_http__method_str(req->method),
                    url->path);
    remaining = (int)est - off;

    /* ── Host header ─────────────────────────────────────────────────────── */
    off += snprintf(buf + off, (size_t)remaining,
                    "Host: %s\r\n", url->host_header);
    remaining = (int)est - off;

    /* ── User-Agent ──────────────────────────────────────────────────────── */
    if (req->user_agent[0] != '\0')
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "User-Agent: %s\r\n", req->user_agent);
    }
    else
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "User-Agent: npe_http/1.0\r\n");
    }
    remaining = (int)est - off;

    /* ── Accept-Encoding (request compression if zlib available) ──────── */
#ifdef NPE_HTTP_HAVE_ZLIB
    off += snprintf(buf + off, (size_t)remaining,
                    "Accept-Encoding: gzip, deflate\r\n");
    remaining = (int)est - off;
#endif

    /* ── Connection ──────────────────────────────────────────────────────── */
    off += snprintf(buf + off, (size_t)remaining,
                    "Connection: close\r\n");
    remaining = (int)est - off;

    /* ── Content-Type ────────────────────────────────────────────────────── */
    if (req->content_type[0] != '\0')
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "Content-Type: %s\r\n", req->content_type);
        remaining = (int)est - off;
    }

    /* ── Content-Length ──────────────────────────────────────────────────── */
    if (req->body && req->body_length > 0)
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "Content-Length: %zu\r\n", req->body_length);
        remaining = (int)est - off;
    }

    /* ── Authorization: Basic ────────────────────────────────────────────── */
    if (req->auth_username[0] != '\0')
    {
        char cred[512];
        snprintf(cred, sizeof(cred), "%s:%s",
                 req->auth_username, req->auth_password);

        char *b64 = npe_http__base64_encode(cred, strlen(cred));
        if (b64)
        {
            off += snprintf(buf + off, (size_t)remaining,
                            "Authorization: Basic %s\r\n", b64);
            remaining = (int)est - off;
            free(b64);
        }
    }

    /* ── Bearer token (if no basic auth and bearer_token is set) ─────── */
    if (req->auth_username[0] == '\0' &&
        req->bearer_token[0] != '\0')
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "Authorization: Bearer %s\r\n", req->bearer_token);
        remaining = (int)est - off;
    }

    /* ── Cookie header ───────────────────────────────────────────────────── */
    if (req->cookie_header && req->cookie_header[0] != '\0')
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "Cookie: %s\r\n", req->cookie_header);
        remaining = (int)est - off;
    }

    /* ── Custom headers ──────────────────────────────────────────────────── */
    for (size_t i = 0; i < req->header_count; i++)
    {
        off += snprintf(buf + off, (size_t)remaining,
                        "%s: %s\r\n",
                        req->headers[i].name,
                        req->headers[i].value);
        remaining = (int)est - off;
    }

    /* ── End of headers ──────────────────────────────────────────────────── */
    off += snprintf(buf + off, (size_t)remaining, "\r\n");
    remaining = (int)est - off;

    /* ── Body ────────────────────────────────────────────────────────────── */
    if (req->body && req->body_length > 0)
    {
        if ((size_t)remaining < req->body_length)
        {
            /* Shouldn't happen with our estimate, but be safe */
            size_t new_est = (size_t)off + req->body_length + 1;
            char *tmp = (char *)npe_http__realloc_safe(buf, new_est);
            if (!tmp)
            {
                free(buf);
                return NULL;
            }
            buf = tmp;
            est = new_est;
            remaining = (int)(est - (size_t)off);
        }
        memcpy(buf + off, req->body, req->body_length);
        off += (int)req->body_length;
    }

    buf[off] = '\0';
    if (out_len)
        *out_len = (size_t)off;
    return buf;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 9 — Core Request Engine
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Free all resources held by a response structure ──────────────────────── */
void npe_http_response_free(npe_http_response_t *resp)
{
    if (!resp)
        return;

    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;

    for (size_t i = 0; i < resp->header_count; i++)
    {
        /* header name/value are embedded arrays, nothing to free */
    }
    resp->header_count = 0;

    for (size_t i = 0; i < resp->cookie_count; i++)
    {
        /* cookie fields are embedded arrays, nothing to free */
    }
    resp->cookie_count = 0;

    resp->status_code = 0;
    resp->status_line[0] = '\0';
}

static int
npe_http__perform_h2(const npe_http_request_t *req,
                     const npe_http__parsed_url_t *parsed,
                     int fd, SSL *ssl, SSL_CTX *ctx,
                     npe_http_response_t *resp)
{
    npe_net_socket_t sock = {
        .fd         = fd,
        .ssl_handle = (void *)ssl,
        .timeout_ms = req->timeout_ms,
        .is_http2   = true
    };

    npe_h2_conn_t *conn = npe_h2_conn_create(&sock);
    if (!conn)
        return -1;

    if (npe_h2_conn_handshake(conn) < 0)
    {
        npe_h2_conn_destroy(conn);
        return -1;
    }

    /* Build path */
    char path[1024];
    if (parsed->path[0])
        snprintf(path, sizeof(path), "%s", parsed->path);
    else
        snprintf(path, sizeof(path), "/");

    /* Headers */
    const char *names[16];
    const char *values[16];
    size_t hdr_count = 0;

    names[hdr_count] = "user-agent";
    values[hdr_count++] = "NetPeek";

    if (req->content_type[0])
    {
        names[hdr_count] = "content-type";
        values[hdr_count++] = req->content_type;
    }

    npe_h2_stream_t *stream = NULL;

    int rc = npe_h2_request(
        conn,
        npe_http__method_str(req->method),
        parsed->host,
        path,
        names,
        values,
        hdr_count,
        (const uint8_t *)req->body,
        req->body_length,
        &stream);

    if (rc == 0 && stream)
    {
        rc = npe_h2_await_response(conn, stream);
        if (rc == 0)
            npe_http__h2_stream_to_response(stream, resp);
    }

    npe_h2_conn_destroy(conn);
    return rc;
}

/* ── Perform a single HTTP request (no redirect following) ────────────────── */
static int npe_http__perform_single(const npe_http_request_t *req,
                                    const npe_http__parsed_url_t *url,
                                    npe_http_response_t *resp)
{
    int fd = -1;
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;
    int result = -1;

    memset(resp, 0, sizeof(*resp));

    /* ── DNS Resolve ─────────────────────────────────────────────────────── */
    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)url->port);

    if (getaddrinfo(url->host, port_str, &hints, &ai) != 0 || !ai)
    {
        snprintf(resp->status_line, sizeof(resp->status_line),
                 "DNS resolution failed for %s", url->host);
        resp->status_code = 0;
        goto cleanup;
    }

    /* ── Socket + Connect ────────────────────────────────────────────────── */
    fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd < 0)
    {
        snprintf(resp->status_line, sizeof(resp->status_line),
                 "socket() failed: %s", strerror(errno));
        goto cleanup;
    }

    npe_http_request_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.timeout_ms = req->timeout_ms;
    opts.verify_ssl = req->verify_ssl;

    if (npe_http__connect(url, &opts, &fd) < 0)
    {
        snprintf(resp->status_line, sizeof(resp->status_line),
                 "Connection to %s:%u timed out or failed",
                 url->host, (unsigned)url->port);
        goto cleanup;
    }

    /* ── SSL Handshake (if https) ────────────────────────────────────────── */
    if (url->use_ssl)
    {
        ssl_ctx = npe_http__ssl_ctx_create(req->verify_ssl);
        if (!ssl_ctx)
        {
            snprintf(resp->status_line, sizeof(resp->status_line),
                     "SSL context creation failed");
            goto cleanup;
        }

        ssl = SSL_new(ssl_ctx);
        if (!ssl)
        {
            snprintf(resp->status_line, sizeof(resp->status_line),
                     "SSL_new() failed");
            goto cleanup;
        }

        /* ✅ Enable ALPN for HTTP/2 */
        static const unsigned char alpn_protos[] = {
            2, 'h', '2',
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        SSL_set_alpn_protos(ssl, alpn_protos, sizeof(alpn_protos));

        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, url->host);

        int ssl_ret = SSL_connect(ssl);
        if (ssl_ret != 1)
        {
            int ssl_err = SSL_get_error(ssl, ssl_ret);
            unsigned long err = ERR_get_error();
            char err_buf[256];

            if (err != 0)
                ERR_error_string_n(err, err_buf, sizeof(err_buf));
            else
                snprintf(err_buf, sizeof(err_buf),
                         "SSL_get_error=%d", ssl_err);

            snprintf(resp->status_line, sizeof(resp->status_line),
                     "SSL handshake failed: %s", err_buf);
            goto cleanup;
        }

        /* ── ✅ HTTP/2 PATH ─────────────────────────────────────────────── */
        const unsigned char *alpn_data = NULL;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);
        if (alpn_data && npe_h2_alpn_is_h2((const char *)alpn_data, alpn_len))
        {
            int h2rc = npe_http__perform_h2(
                req,     /* const npe_http_request_t * */
                url,     /* const npe_http__parsed_url_t * */
                fd,      /* socket fd */
                ssl,     /* SSL session */
                ssl_ctx, /* SSL context */
                resp     /* response */
            );

            /* ownership transferred to HTTP/2 layer */
            ssl = NULL;
            ssl_ctx = NULL;
            fd = -1;

            return h2rc;
        }
    }

    /* ── HTTP/1.1 FALLBACK ──────────────────────────────────────────────── */

    /* ── Build & Send Request ────────────────────────────────────────────── */
    {
        size_t req_len = 0;
        char *req_buf = npe_http__build_request(req, url, &req_len);
        if (!req_buf)
        {
            snprintf(resp->status_line, sizeof(resp->status_line),
                     "Failed to build request");
            goto cleanup;
        }

        int send_rc = npe_http__send_all(fd, ssl, req_buf, req_len);
        free(req_buf);
        if (send_rc < 0)
        {
            snprintf(resp->status_line, sizeof(resp->status_line),
                     "Failed to send request");
            goto cleanup;
        }
    }

    /* ── Read Status Line ────────────────────────────────────────────────── */
    {
        char line_buf[NPE_HTTP__LINE_BUF_SIZE];
        int ll = npe_http__recv_line(fd, ssl, line_buf,
                                     sizeof(line_buf),
                                     req->timeout_ms);
        if (ll < 0)
        {
            snprintf(resp->status_line, sizeof(resp->status_line),
                     "Failed to read response status line");
            goto cleanup;
        }

        if (npe_http__parse_status_line(line_buf, resp) < 0)
        {
            snprintf(resp->status_line, sizeof(resp->status_line),
                     "Malformed HTTP status line");
            goto cleanup;
        }
    }

    /* ── Read Response Headers ───────────────────────────────────────────── */
    if (npe_http__read_headers(fd, ssl, resp,
                               req->timeout_ms) < 0)
    {
        snprintf(resp->status_line, sizeof(resp->status_line),
                 "Failed to read response headers");
        resp->status_code = 0;
        goto cleanup;
    }

    npe_http__extract_cookies(resp);

    /* ── Read Response Body ──────────────────────────────────────────────── */
    if (req->method != NPE_HTTP_HEAD)
    {
        npe_http__read_body(fd, ssl, resp,
                            req->max_body_size,
                            req->timeout_ms);
    }

    npe_http__decompress_body(resp);

    result = 0;

cleanup:
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    if (fd >= 0)
        close(fd);
    if (ai)
        freeaddrinfo(ai);

    return result;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 10 — Redirect Following
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Resolve a possibly-relative Location URL ─────────────────────────────── */
static int npe_http__resolve_redirect(const npe_http__parsed_url_t *base,
                                      const char *location,
                                      char *resolved,
                                      size_t resolved_size)
{
    if (!location || !location[0])
        return -1;

    /* Absolute URL */
    if (strncasecmp(location, "http://", 7) == 0 ||
        strncasecmp(location, "https://", 8) == 0)
    {
        snprintf(resolved, resolved_size, "%s", location);
        return 0;
    }

    /* Protocol-relative */
    if (location[0] == '/' && location[1] == '/')
    {
        snprintf(resolved, resolved_size, "%s:%s", base->scheme, location);
        return 0;
    }

    /* Absolute path */
    if (location[0] == '/')
    {
        bool default_port = (base->use_ssl && base->port == 443) ||
                            (!base->use_ssl && base->port == 80);
        if (default_port)
        {
            snprintf(resolved, resolved_size, "%s://%s%s",
                     base->scheme, base->host, location);
        }
        else
        {
            snprintf(resolved, resolved_size, "%s://%s:%u%s",
                     base->scheme, base->host,
                     (unsigned)base->port, location);
        }
        return 0;
    }

    /* Relative path — append to base path directory */
    char base_dir[NPE_HTTP__LINE_BUF_SIZE];
    snprintf(base_dir, sizeof(base_dir), "%s", base->path);
    char *last_slash = strrchr(base_dir, '/');
    if (last_slash)
    {
        *(last_slash + 1) = '\0';
    }
    else
    {
        snprintf(base_dir, sizeof(base_dir), "/");
    }

    bool default_port = (base->use_ssl && base->port == 443) ||
                        (!base->use_ssl && base->port == 80);
    if (default_port)
    {
        snprintf(resolved, resolved_size, "%s://%s%s%s",
                 base->scheme, base->host, base_dir, location);
    }
    else
    {
        snprintf(resolved, resolved_size, "%s://%s:%u%s%s",
                 base->scheme, base->host,
                 (unsigned)base->port, base_dir, location);
    }
    return 0;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 11 — Public API: npe_http_request_perform
 * ═════════════════════════════════════════════════════════════════════════════*/

int npe_http_request_perform(const npe_http_request_t *req,
                             npe_http_response_t *resp)
{
    if (!req || !resp)
        return -1;

    npe_http__ssl_init_once();
    memset(resp, 0, sizeof(*resp));

    uint32_t timeout = req->timeout_ms;
    if (!timeout)
        timeout = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    npe_http_request_t work_req;
    memcpy(&work_req, req, sizeof(work_req));
    work_req.timeout_ms = timeout;

    char current_url[NPE_HTTP_MAX_URL_LENGTH];
    snprintf(current_url, sizeof(current_url), "%s", req->url);

    int max_redirects = req->max_redirects;
    bool follow = req->follow_redirects;

    for (int attempt = 0; attempt <= max_redirects; attempt++)
    {
        npe_http__parsed_url_t parsed;
        if (npe_http__parse_url(current_url, &parsed) < 0)
        {
            snprintf(resp->status_line,
                     sizeof(resp->status_line),
                     "Malformed URL");
            return -1;
        }

        snprintf(work_req.url,
                 sizeof(work_req.url),
                 "%s",
                 current_url);

        if (attempt > 0)
            npe_http_response_free(resp);

        int rc = npe_http__perform_single(&work_req, &parsed, resp);
        if (rc < 0)
            return -1;

        if (!follow)
            break;

        if (resp->status_code >= 300 && resp->status_code <= 308)
        {
            const char *loc = npe_http__find_header(resp, "Location");
            if (!loc)
                break;

            char resolved[NPE_HTTP_MAX_URL_LENGTH];
            if (npe_http__resolve_redirect(&parsed,
                                           loc,
                                           resolved,
                                           sizeof(resolved)) < 0)
                break;

            /* RFC 7231 redirect handling */
            if (resp->status_code == 303 ||
                ((resp->status_code == 301 ||
                  resp->status_code == 302) &&
                 work_req.method == NPE_HTTP_POST))
            {
                work_req.method = NPE_HTTP_GET;
                work_req.body = NULL;
                work_req.body_length = 0;
            }

            snprintf(current_url,
                     sizeof(current_url),
                     "%s",
                     resolved);
            continue;
        }

        break;
    }

    return 0;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 12 — Lua Helpers: Push Response to Lua
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Push a single cookie table onto the Lua stack ────────────────────────── */
static void npe_http__lua_push_cookie(lua_State *L,
                                      const npe_http_cookie_t *c)
{
    lua_newtable(L);

    lua_pushstring(L, c->name);
    lua_setfield(L, -2, "name");

    lua_pushstring(L, c->value);
    lua_setfield(L, -2, "value");

    if (c->domain[0])
    {
        lua_pushstring(L, c->domain);
        lua_setfield(L, -2, "domain");
    }

    if (c->path[0])
    {
        lua_pushstring(L, c->path);
        lua_setfield(L, -2, "path");
    }

    if (c->expires[0])
    {
        lua_pushstring(L, c->expires);
        lua_setfield(L, -2, "expires");
    }

    lua_pushboolean(L, c->secure);
    lua_setfield(L, -2, "secure");

    lua_pushboolean(L, c->httponly);
    lua_setfield(L, -2, "httponly");
}

/* ── Push the full response as a Lua table ────────────────────────────────── */
/*    Stack: pushes one table.                                               */
static void npe_http__lua_push_response(lua_State *L,
                                        const npe_http_response_t *resp)
{
    lua_newtable(L);

    /* status_code */
    lua_pushinteger(L, (lua_Integer)resp->status_code);
    lua_setfield(L, -2, "status_code");

    /* status_line */
    lua_pushstring(L, resp->status_line);
    lua_setfield(L, -2, "status_line");

    /* headers — table of {name, value} pairs AND keyed by lowercase name */
    lua_newtable(L);
    for (size_t i = 0; i < resp->header_count; i++)
    {
        /* Array part: headers[i+1] = {name=..., value=...} */
        lua_newtable(L);
        lua_pushstring(L, resp->headers[i].name);
        lua_setfield(L, -2, "name");
        lua_pushstring(L, resp->headers[i].value);
        lua_setfield(L, -2, "value");
        lua_rawseti(L, -2, (int)(i + 1));

        /* Hash part: headers["content-type"] = value (lowercase key) */
        char lower_name[NPE_HTTP_MAX_HEADER_NAME];
        snprintf(lower_name, sizeof(lower_name), "%s", resp->headers[i].name);
        for (char *p = lower_name; *p; p++)
        {
            if (*p >= 'A' && *p <= 'Z')
                *p += 32;
        }
        lua_pushstring(L, resp->headers[i].value);
        lua_setfield(L, -2, lower_name);
    }
    lua_setfield(L, -2, "headers");

    /* body */
    if (resp->body && resp->body_len > 0)
    {
        lua_pushlstring(L, resp->body, resp->body_len);
    }
    else
    {
        lua_pushstring(L, "");
    }
    lua_setfield(L, -2, "body");

    /* body_length */
    lua_pushinteger(L, (lua_Integer)resp->body_len);
    lua_setfield(L, -2, "body_length");

    /* cookies — array of cookie tables */
    lua_newtable(L);
    for (size_t i = 0; i < resp->cookie_count; i++)
    {
        npe_http__lua_push_cookie(L, &resp->cookies[i]);
        lua_rawseti(L, -2, (int)(i + 1));
    }
    lua_setfield(L, -2, "cookies");
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 13 — Lua Helpers: Read Request Options from Lua Table
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Read a string field from a Lua table at stack index `idx` ────────────── */
static const char *npe_http__lua_optstring(lua_State *L, int idx,
                                           const char *field,
                                           const char *def)
{
    lua_getfield(L, idx, field);
    const char *val = def;
    if (lua_isstring(L, -1))
    {
        val = lua_tostring(L, -1);
    }
    lua_pop(L, 1);
    return val;
}

/* ── Read an integer field from a Lua table ───────────────────────────────── */
static lua_Integer npe_http__lua_optinteger(lua_State *L, int idx,
                                            const char *field,
                                            lua_Integer def)
{
    lua_getfield(L, idx, field);
    lua_Integer val = def;
    if (lua_isnumber(L, -1))
    {
        val = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    return val;
}

/* ── Read a boolean field from a Lua table ────────────────────────────────── */
static bool npe_http__lua_optbool(lua_State *L, int idx,
                                  const char *field, bool def)
{
    lua_getfield(L, idx, field);
    bool val = def;
    if (lua_isboolean(L, -1))
    {
        val = lua_toboolean(L, -1) ? true : false;
    }
    lua_pop(L, 1);
    return val;
}

/* ── Populate npe_http_request_t from a Lua options table at stack idx ──── */
/*    The URL and method are set by the caller; this reads optional fields.  */
static void npe_http__lua_read_options(lua_State *L, int idx,
                                       npe_http_request_t *req)
{
    if (!lua_istable(L, idx))
        return;

    /* timeout (seconds in Lua → milliseconds internal) */
    {
        lua_getfield(L, idx, "timeout");
        if (lua_isnumber(L, -1))
        {
            double t = lua_tonumber(L, -1);
            req->timeout_ms = (uint32_t)(t * 1000.0);
        }
        lua_pop(L, 1);
    }

    /* timeout_ms (direct milliseconds, overrides timeout if set) */
    {
        lua_Integer ms = npe_http__lua_optinteger(L, idx, "timeout_ms", 0);
        if (ms > 0)
            req->timeout_ms = (uint32_t)ms;
    }

    /* headers table: { ["Content-Type"] = "application/json", ... }
     * or array: { {name="...", value="..."}, ... }                          */
    lua_getfield(L, idx, "headers");
    if (lua_istable(L, -1))
    {
        int headers_idx = lua_gettop(L);

        /* Try array style first */
        size_t len = lua_rawlen(L, headers_idx);
        if (len > 0)
        {
            for (size_t i = 1; i <= len && req->header_count < NPE_HTTP_MAX_HEADERS; i++)
            {
                lua_rawgeti(L, headers_idx, (int)i);
                if (lua_istable(L, -1))
                {
                    lua_getfield(L, -1, "name");
                    lua_getfield(L, -2, "value");
                    if (lua_isstring(L, -2) && lua_isstring(L, -1))
                    {
                        size_t hi = req->header_count;
                        snprintf(req->headers[hi].name,
                                 sizeof(req->headers[hi].name),
                                 "%s", lua_tostring(L, -2));
                        snprintf(req->headers[hi].value,
                                 sizeof(req->headers[hi].value),
                                 "%s", lua_tostring(L, -1));
                        req->header_count++;
                    }
                    lua_pop(L, 2); /* name, value */
                }
                lua_pop(L, 1); /* array element */
            }
        }
        else
        {
            /* Hash style: iterate pairs */
            lua_pushnil(L);
            while (lua_next(L, headers_idx) != 0)
            {
                if (lua_isstring(L, -2) && lua_isstring(L, -1) &&
                    req->header_count < NPE_HTTP_MAX_HEADERS)
                {
                    size_t hi = req->header_count;
                    snprintf(req->headers[hi].name,
                             sizeof(req->headers[hi].name),
                             "%s", lua_tostring(L, -2));
                    snprintf(req->headers[hi].value,
                             sizeof(req->headers[hi].value),
                             "%s", lua_tostring(L, -1));
                    req->header_count++;
                }
                lua_pop(L, 1); /* value; keep key for next iteration */
            }
        }
    }
    lua_pop(L, 1); /* headers */

    /* body */
    {
        lua_getfield(L, idx, "body");
        if (lua_isstring(L, -1))
        {
            size_t body_len = 0;
            const char *body = lua_tolstring(L, -1, &body_len);
            req->body = body; /* valid while Lua string lives */
            req->body_length = body_len;
        }
        lua_pop(L, 1);
    }

    /* content_type */
    {
        const char *ct = npe_http__lua_optstring(L, idx, "content_type", NULL);
        if (ct)
            snprintf(req->content_type, sizeof(req->content_type), "%s", ct);
    }

    /* user_agent */
    {
        const char *ua = npe_http__lua_optstring(L, idx, "user_agent", NULL);
        if (ua)
            snprintf(req->user_agent, sizeof(req->user_agent), "%s", ua);
    }

    /* auth_username / auth_password */
    {
        const char *u = npe_http__lua_optstring(L, idx, "auth_username", NULL);
        const char *p = npe_http__lua_optstring(L, idx, "auth_password", NULL);
        if (u)
            snprintf(req->auth_username, sizeof(req->auth_username), "%s", u);
        if (p)
            snprintf(req->auth_password, sizeof(req->auth_password), "%s", p);
    }

    /* bearer_token */
    {
        const char *bt = npe_http__lua_optstring(L, idx, "bearer_token", NULL);
        if (bt)
            snprintf(req->bearer_token, sizeof(req->bearer_token), "%s", bt);
    }

    /* cookie_header (raw Cookie: value) */
    {
        const char *ch = npe_http__lua_optstring(L, idx, "cookie_header", NULL);
        if (ch)
            req->cookie_header = ch;
    }

    /* follow_redirects */
    req->follow_redirects = npe_http__lua_optbool(L, idx,
                                                  "follow_redirects", true);

    /* max_redirects */
    req->max_redirects = (int)npe_http__lua_optinteger(L, idx,
                                                       "max_redirects",
                                                       NPE_HTTP_DEFAULT_MAX_REDIRECTS);

    /* verify_ssl */
    req->verify_ssl = npe_http__lua_optbool(L, idx, "verify_ssl", false);

    /* max_body_size */
    {
        lua_Integer mbs = npe_http__lua_optinteger(L, idx, "max_body_size", 0);
        if (mbs > 0)
            req->max_body_size = (size_t)mbs;
    }
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 14 — Lua-Facing C Functions
 * ═════════════════════════════════════════════════════════════════════════════*/

/* ── Generic request: npe.http.request(method, url [, options]) ───────────── */
static int l_npe_http_request(lua_State *L)
{
    /* Arg 1: method string or integer */
    npe_http_method_t method = NPE_HTTP_GET;
    if (lua_isstring(L, 1))
    {
        const char *ms = lua_tostring(L, 1);
        if (npe_http__strcasecmp(ms, "GET") == 0)
            method = NPE_HTTP_GET;
        else if (npe_http__strcasecmp(ms, "POST") == 0)
            method = NPE_HTTP_POST;
        else if (npe_http__strcasecmp(ms, "PUT") == 0)
            method = NPE_HTTP_PUT;
        else if (npe_http__strcasecmp(ms, "DELETE") == 0)
            method = NPE_HTTP_DELETE;
        else if (npe_http__strcasecmp(ms, "PATCH") == 0)
            method = NPE_HTTP_PATCH;
        else if (npe_http__strcasecmp(ms, "HEAD") == 0)
            method = NPE_HTTP_HEAD;
        else if (npe_http__strcasecmp(ms, "OPTIONS") == 0)
            method = NPE_HTTP_OPTIONS;
        else
            return luaL_error(L, "unknown HTTP method: %s", ms);
    }
    else if (lua_isnumber(L, 1))
    {
        method = (npe_http_method_t)lua_tointeger(L, 1);
    }
    else
    {
        return luaL_argerror(L, 1, "expected method string or integer");
    }

    /* Arg 2: URL string */
    const char *url = luaL_checkstring(L, 2);

    /* Build request struct */
    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = method;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    /* Arg 3: optional options table */
    if (lua_istable(L, 3))
    {
        npe_http__lua_read_options(L, 3, &req);
    }

    /* Execute */
    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);
    /* Debug logging */
    LOGD("DEBUG: rc=%d, status_code=%d, status_line='%s'\n",
         rc, resp.status_code, resp.status_line);
    if (rc < 0 && resp.status_code == 0)
    {
        /* Total failure — return nil, error_message */
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP request failed");
        npe_http_response_free(&resp);
        return 2;
    }

    /* Success — return response table */
    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.get(url [, options]) ───────────────────────────── */
static int l_npe_http_get(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_GET;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    if (lua_istable(L, 2))
        npe_http__lua_read_options(L, 2, &req);

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);
    // لاگ همیشگی برای دیباگ
    LOGE("http.get: rc=%d, status_code=%d, status_line='%s'",
         rc, resp.status_code, resp.status_line);
    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        char err_msg[512];
        snprintf(err_msg, sizeof(err_msg), "HTTP GET failed: rc=%d, status='%s'",
                 rc, resp.status_line[0] ? resp.status_line : "(empty)");
        lua_pushstring(L, err_msg);
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.post(url [, body [, options]]) ─────────────────── */
static int l_npe_http_post(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_POST;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    /* Arg 2: body (string or nil) */
    if (lua_isstring(L, 2))
    {
        size_t body_len = 0;
        req.body = lua_tolstring(L, 2, &body_len);
        req.body_length = body_len;
    }

    /* Arg 3: options table */
    if (lua_istable(L, 3))
        npe_http__lua_read_options(L, 3, &req);

    /* Default content type for POST if body present and none specified */
    if (req.body && req.body_length > 0 && req.content_type[0] == '\0')
    {
        snprintf(req.content_type, sizeof(req.content_type),
                 "application/x-www-form-urlencoded");
    }

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);

    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP POST failed");
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.put(url [, body [, options]]) ──────────────────── */
static int l_npe_http_put(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_PUT;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    if (lua_isstring(L, 2))
    {
        size_t body_len = 0;
        req.body = lua_tolstring(L, 2, &body_len);
        req.body_length = body_len;
    }

    if (lua_istable(L, 3))
        npe_http__lua_read_options(L, 3, &req);

    if (req.body && req.body_length > 0 && req.content_type[0] == '\0')
    {
        snprintf(req.content_type, sizeof(req.content_type),
                 "application/x-www-form-urlencoded");
    }

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);

    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP PUT failed");
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.delete(url [, options]) ────────────────────────── */
static int l_npe_http_delete(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_DELETE;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    if (lua_istable(L, 2))
        npe_http__lua_read_options(L, 2, &req);

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);

    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP DELETE failed");
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.patch(url [, body [, options]]) ────────────────── */
static int l_npe_http_patch(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_PATCH;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    if (lua_isstring(L, 2))
    {
        size_t body_len = 0;
        req.body = lua_tolstring(L, 2, &body_len);
        req.body_length = body_len;
    }

    if (lua_istable(L, 3))
        npe_http__lua_read_options(L, 3, &req);

    if (req.body && req.body_length > 0 && req.content_type[0] == '\0')
    {
        snprintf(req.content_type, sizeof(req.content_type),
                 "application/json");
    }

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);

    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP PATCH failed");
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.head(url [, options]) ──────────────────────────── */
static int l_npe_http_head(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_HEAD;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    if (lua_istable(L, 2))
        npe_http__lua_read_options(L, 2, &req);

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);

    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP HEAD failed");
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── Convenience: npe.http.options(url [, options]) ───────────────────────── */
static int l_npe_http_options(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);

    npe_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = NPE_HTTP_OPTIONS;
    snprintf(req.url, sizeof(req.url), "%s", url);
    req.follow_redirects = true;
    req.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    req.verify_ssl = false;
    req.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;

    if (lua_istable(L, 2))
        npe_http__lua_read_options(L, 2, &req);

    npe_http_response_t resp;
    int rc = npe_http_request_perform(&req, &resp);

    if (rc < 0 && resp.status_code == 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line
                                              : "HTTP OPTIONS failed");
        npe_http_response_free(&resp);
        return 2;
    }

    npe_http__lua_push_response(L, &resp);
    npe_http_response_free(&resp);
    return 1;
}

/* ── URL encode helper: npe.http.url_encode(str) ──────────────────────────── */
static int l_npe_http_url_encode(lua_State *L)
{
    size_t len = 0;
    const char *input = luaL_checklstring(L, 1, &len);

    /* Worst case: every byte becomes %XX → 3x */
    size_t out_cap = len * 3 + 1;
    char *out = (char *)malloc(out_cap);
    if (!out)
        return luaL_error(L, "out of memory");

    size_t oi = 0;
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)input[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~')
        {
            out[oi++] = (char)c;
        }
        else
        {
            snprintf(out + oi, 4, "%%%02X", c);
            oi += 3;
        }
    }
    out[oi] = '\0';

    lua_pushlstring(L, out, oi);
    free(out);
    return 1;
}

/* ── URL decode helper: npe.http.url_decode(str) ──────────────────────────── */
static int l_npe_http_url_decode(lua_State *L)
{
    size_t len = 0;
    const char *input = luaL_checklstring(L, 1, &len);

    char *out = (char *)malloc(len + 1);
    if (!out)
        return luaL_error(L, "out of memory");

    size_t oi = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (input[i] == '%' && i + 2 < len)
        {
            char hex[3] = {input[i + 1], input[i + 2], '\0'};
            char *end = NULL;
            unsigned long val = strtoul(hex, &end, 16);
            if (end == hex + 2)
            {
                out[oi++] = (char)val;
                i += 2;
                continue;
            }
        }
        if (input[i] == '+')
        {
            out[oi++] = ' ';
        }
        else
        {
            out[oi++] = input[i];
        }
    }
    out[oi] = '\0';

    lua_pushlstring(L, out, oi);
    free(out);
    return 1;
}

/* ═════════════════════════════════════════════════════════════════════════════
 * SECTION 15 — Module Registration
 * ═════════════════════════════════════════════════════════════════════════════*/

static const luaL_Reg npe_http_funcs[] = {
    {"request", l_npe_http_request},
    {"get", l_npe_http_get},
    {"post", l_npe_http_post},
    {"put", l_npe_http_put},
    {"delete", l_npe_http_delete},
    {"head", l_npe_http_head},
    {"options", l_npe_http_options},
    {"url_encode", l_npe_http_url_encode},
    {"url_decode", l_npe_http_url_decode},
    {NULL, NULL}};

int luaopen_npe_http(lua_State *L)
{
    luaL_newlib(L, npe_http_funcs);

    /* Method enum constants */
    lua_pushinteger(L, NPE_HTTP_GET);
    lua_setfield(L, -2, "GET");

    lua_pushinteger(L, NPE_HTTP_POST);
    lua_setfield(L, -2, "POST");

    lua_pushinteger(L, NPE_HTTP_PUT);
    lua_setfield(L, -2, "PUT");

    lua_pushinteger(L, NPE_HTTP_DELETE);
    lua_setfield(L, -2, "DELETE");

    lua_pushinteger(L, NPE_HTTP_PATCH);
    lua_setfield(L, -2, "PATCH");

    lua_pushinteger(L, NPE_HTTP_HEAD);
    lua_setfield(L, -2, "HEAD");

    lua_pushinteger(L, NPE_HTTP_OPTIONS);
    lua_setfield(L, -2, "OPTIONS");

    /* Limits exposed for Lua */
    lua_pushinteger(L, NPE_HTTP_MAX_HEADERS);
    lua_setfield(L, -2, "MAX_HEADERS");

    lua_pushinteger(L, NPE_HTTP_MAX_COOKIES);
    lua_setfield(L, -2, "MAX_COOKIES");

    lua_pushinteger(L, NPE_HTTP_DEFAULT_TIMEOUT_MS);
    lua_setfield(L, -2, "DEFAULT_TIMEOUT_MS");

    lua_pushinteger(L, NPE_HTTP_DEFAULT_MAX_REDIRECTS);
    lua_setfield(L, -2, "DEFAULT_MAX_REDIRECTS");

    return 1;
}
