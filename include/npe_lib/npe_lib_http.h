/*
* =============================================================================
*  NetPeek Extension Engine (NPE)
*  npe_lib_http.h — HTTP Client Library
* =============================================================================
*
*  Full-featured HTTP/1.1 client for NPE Lua scripts.
*  Supports GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH methods.
*  Handles chunked transfer encoding, redirects, cookies, and basic/digest
*  authentication.  Can operate over plaintext or SSL/TLS.
*
*  Lua API:
*
*    -- Simple requests
*    local resp = npe.http.get(url [, options])
*    local resp = npe.http.post(url, body [, options])
*    local resp = npe.http.head(url [, options])
*    local resp = npe.http.put(url, body [, options])
*    local resp = npe.http.delete(url [, options])
*    local resp = npe.http.options(url [, options])
*    local resp = npe.http.patch(url, body [, options])
*
*    -- Generic request
*    local resp = npe.http.request(method, url [, options])
*
*    -- Response fields
*    resp.status            -- HTTP status code (integer)
*    resp.status_line       -- Full status line string
*    resp.headers           -- Table of response headers
*    resp.body              -- Response body string
*    resp.content_length    -- Content-Length (or body length)
*    resp.cookies           -- Table of Set-Cookie values
*    resp.redirect_url      -- Final URL after redirects (if any)
*    resp.elapsed_ms        -- Request duration in milliseconds
*    resp.ssl               -- true if HTTPS was used
*
*    -- Options table fields
*    options.headers        -- Table of custom request headers
*    options.timeout_ms     -- Request timeout
*    options.max_redirects  -- Redirect limit (default 5)
*    options.auth           -- { username="...", password="..." }
*    options.cookies        -- Table of cookies to send
*    options.body           -- Request body (alternative to arg)
*    options.content_type   -- Content-Type header shortcut
*    options.user_agent     -- User-Agent header shortcut
*    options.no_body        -- Boolean: discard response body
*    options.raw            -- Boolean: return raw response (no parsing)
*    options.proxy          -- Proxy URL string
*    options.verify_ssl     -- Boolean: verify SSL certificates (default true)
*
*    -- URL utilities
*    local parts = npe.http.parse_url(url)
*    local url   = npe.http.build_url(parts)
*    local enc   = npe.http.url_encode(str)
*    local dec   = npe.http.url_decode(str)
*    local query = npe.http.build_query(table)
*
*    -- Header utilities
*    local val = npe.http.get_header(resp, name)
*    local exists = npe.http.has_header(resp, name)
*
* =============================================================================
*/

#ifndef NPE_LIB_HTTP_H
#define NPE_LIB_HTTP_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
/* ── OpenSSL headers ───────────────────────────────────────────────────────── */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#ifdef __cplusplus
extern "C"
{
#endif

#define NPE_HTTP_MAX_HEADER_NAME 256
#define NPE_HTTP_MAX_COOKIES 64
/* ─────────────────────────────────────────────────────────────────────────────
    * Constants
    * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_HTTP_DEFAULT_TIMEOUT_MS 10000         /* 10 seconds             */
#define NPE_HTTP_DEFAULT_MAX_REDIRECTS 5          /* Redirect follow limit  */
#define NPE_HTTP_MAX_HEADER_SIZE (64 * 1024)      /* 64 KiB header block    */
#define NPE_HTTP_MAX_BODY_SIZE (16 * 1024 * 1024) /* 16 MiB body     */
#define NPE_HTTP_MAX_URL_LENGTH 8192              /* URL string limit       */
#define NPE_HTTP_MAX_HEADERS 128                  /* Max response headers   */
#define NPE_HTTP_DEFAULT_USER_AGENT "NetPeek-NPE/1.0"
#define NPE_HTTP_DEFAULT_HTTP_VERSION "HTTP/1.1"

/* ─────────────────────────────────────────────────────────────────────────────
    * Internal Constants
    * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_HTTP__RECV_BUF_SIZE 4096
#define NPE_HTTP__LINE_BUF_SIZE 8192
#define NPE_HTTP__CONNECT_TIMEOUT_MS 5000
#define NPE_HTTP__BASE64_PAD '='
#define NPE_HTTP__HEADER_VALUE_MAX 4096 /* matches npe_http_header_t.value */
#define NPE_HTTP__INITIAL_BODY_CAP 8192
#define NPE_HTTP__INITIAL_HDR_ALLOC 32
#define NPE_HTTP__CHUNK_LINE_MAX 64
#define NPE_HTTP__MAX_BODY_DEFAULT (100 * 1024 * 1024) /* 100 MB */

/*
    * HTTP methods as an enumeration.
    */
typedef enum npe_http_method
{
    NPE_HTTP_GET = 0,
    NPE_HTTP_POST = 1,
    NPE_HTTP_HEAD = 2,
    NPE_HTTP_PUT = 3,
    NPE_HTTP_DELETE = 4,
    NPE_HTTP_OPTIONS = 5,
    NPE_HTTP_PATCH = 6,
    NPE_HTTP_TRACE = 7,
    NPE_HTTP_CONNECT = 8
} npe_http_method_t;

/* ─────────────────────────────────────────────────────────────────────────────
    * URL Components Structure
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_url_t
    *
    * Parsed components of an HTTP URL.
    */
typedef struct npe_http_url
{
    char scheme[16];    /* "http" or "https"                          */
    char host[256];     /* Hostname or IP                             */
    uint16_t port;      /* Port (default 80/443 if not specified)     */
    char path[4096];    /* Path component (e.g., "/index.html")      */
    char query[2048];   /* Query string (without leading '?')        */
    char fragment[256]; /* Fragment (without leading '#')             */
    char userinfo[256]; /* user:password (if present in URL)          */
    bool is_ssl;        /* true if scheme is https                    */
} npe_http_url_t;

/* ─────────────────────────────────────────────────────────────────────────────
    * Request Header Entry
    * ───────────────────────────────────────────────────────────────────────────── */

typedef struct npe_http_header
{
    char name[256];   /* Header field name                          */
    char value[4096]; /* Header field value                         */
} npe_http_header_t;

typedef struct
{
    char name[256];
    char value[1024];
    char domain[256];
    char path[256];
    char expires[128];
    bool secure;
    bool httponly;
} npe_http_cookie_t;

/* ─────────────────────────────────────────────────────────────────────────────
    * Request Options Structure
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_request_opts_t
    *
    * Configurable options for an HTTP request.
    * Maps 1:1 with the Lua "options" table.
    */
typedef struct npe_http_request_opts
{
    npe_http_header_t *custom_headers; /* Array of custom headers       */
    size_t custom_header_count;        /* Number of custom headers      */

    uint32_t timeout_ms;    /* Request timeout               */
    uint32_t max_redirects; /* Max redirect follows          */

    const char *auth_username; /* Basic/Digest auth username    */
    const char *auth_password; /* Basic/Digest auth password    */

    const char *content_type; /* Content-Type header           */
    const char *user_agent;   /* User-Agent header             */

    const char *body; /* Request body data             */
    size_t body_len;  /* Request body length           */

    const char *proxy; /* Proxy URL (NULL = no proxy)   */

    bool no_body;          /* Skip reading response body    */
    bool raw_response;     /* Return raw bytes              */
    bool verify_ssl;       /* Verify SSL certs (default T)  */
    bool follow_redirects; /* Follow 3xx redirects          */
} npe_http_request_opts_t;

typedef struct
{
    npe_http_method_t method;
    char url[2048];
    char *body;
    size_t body_length;
    char user_agent[256];
    char content_type[128];
    char auth_username[256];
    char auth_password[256];
    char bearer_token[512];
    char *cookie_header;
    npe_http_header_t *headers;
    size_t header_count;
    int timeout_ms;
    int max_redirects;
    size_t max_body_size;
    bool follow_redirects;
    bool verify_ssl;
} npe_http_request_t;


/* HTTP/2-only payload storage (keeps HTTP/1.1 body model unchanged) */
typedef struct npe_http2_response
{
    uint8_t *body;
    size_t length;
    size_t capacity;
    char content_type[64];
    int status_code;
} npe_http2_response_t;

/* ─────────────────────────────────────────────────────────────────────────────
    * Response Structure
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_response_t
    *
    * Complete HTTP response data returned by request functions.
    * Dynamically allocated — caller must free with npe_http_response_free().
    */
typedef struct npe_http_response
{
    int status_code;       /* HTTP status code (200, 404…)  */
    char status_line[256]; /* Full status line              */

    npe_http_header_t *headers; /* Array of response headers     */
    size_t header_count;        /* Number of headers             */

    char *body;      /* Response body (heap alloc)    */
    size_t body_len; /* Body length in bytes          */

    size_t content_length; /* Content-Length (or body_len)  */

    npe_http_cookie_t *cookies;
    size_t cookie_count; /* Number of Set-Cookie headers  */

    char redirect_url[NPE_HTTP_MAX_URL_LENGTH]; /* Final URL  */
    uint32_t redirect_count;                    /* Number of redirects followed  */

    double elapsed_ms; /* Request duration              */
    bool is_ssl;       /* Was HTTPS used?               */

    /* Raw response for debugging */
    char *raw_response;      /* Full raw response (if asked)  */
    size_t raw_response_len; /* Raw response length           */

    /* HTTP/2 payload (used only when negotiated) */
    npe_http2_response_t http2;

} npe_http_response_t;

/* Parsed URL components (stack-allocated, internal use only) */
typedef struct
{
    bool use_ssl;
    char scheme[16];
    char host[512];
    uint16_t port;
    char path[NPE_HTTP__LINE_BUF_SIZE]; /* includes query string */
    char host_header[530];              /* host[:port] for Host header */
} npe_http__parsed_url_t;
/* ─────────────────────────────────────────────────────────────────────────────
    * Lua Module Registration
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * luaopen_npe_http_lib()
    *
    * Lua module opener.  Registers all npe.http functions.
    *
    * @param L   The Lua state.
    * @return    1 (the module table is on the stack).
    */
int luaopen_npe_http_lib(lua_State *L);

/* ─────────────────────────────────────────────────────────────────────────────
    * C-Level API
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_request()
    *
    * Perform an HTTP request.  Core implementation used by all method-specific
    * functions.
    *
    * @param method    HTTP method enum.
    * @param url       Full URL string.
    * @param opts      Request options (NULL for defaults).
    * @param out_resp  On success, populated response struct.
    * @return          0 on success, -1 on error.
    */
int npe_http_request(npe_http_method_t method, const char *url,
                        const npe_http_request_opts_t *opts,
                        npe_http_response_t *out_resp);

/*
    * Convenience wrappers.
    */
int npe_http_get(const char *url, const npe_http_request_opts_t *opts,
                    npe_http_response_t *out_resp);

int npe_http_post(const char *url, const char *body, size_t body_len,
                    const npe_http_request_opts_t *opts,
                    npe_http_response_t *out_resp);

int npe_http_head(const char *url, const npe_http_request_opts_t *opts,
                    npe_http_response_t *out_resp);

int npe_http_put(const char *url, const char *body, size_t body_len,
                    const npe_http_request_opts_t *opts,
                    npe_http_response_t *out_resp);

/* ─────────────────────────────────────────────────────────────────────────────
    * URL Utilities
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_parse_url()
    *
    * Parse a URL string into its components.
    *
    * @param url       The URL string to parse.
    * @param out_url   Pointer to struct to fill.
    * @return          0 on success, -1 on malformed URL.
    */
int npe_http_parse_url(const char *url, npe_http_url_t *out_url);

/*
    * npe_http_build_url()
    *
    * Reconstruct a URL string from components.
    *
    * @param parts     The URL components.
    * @param out_buf   Buffer to write the URL string.
    * @param buf_size  Buffer capacity.
    * @return          Length of the resulting string, -1 on error.
    */
int npe_http_build_url(const npe_http_url_t *parts, char *out_buf,
                        size_t buf_size);

/*
    * npe_http_url_encode()
    *
    * Percent-encode a string for use in URLs.
    *
    * @param input     Raw string.
    * @param out_buf   Buffer for encoded string.
    * @param buf_size  Buffer capacity.
    * @return          Length of encoded string, -1 on error.
    */
int npe_http_url_encode(const char *input, char *out_buf, size_t buf_size);

/*
    * npe_http_url_decode()
    *
    * Decode a percent-encoded URL string.
    *
    * @param input     Encoded string.
    * @param out_buf   Buffer for decoded string.
    * @param buf_size  Buffer capacity.
    * @return          Length of decoded string, -1 on error.
    */
int npe_http_url_decode(const char *input, char *out_buf, size_t buf_size);

/* ─────────────────────────────────────────────────────────────────────────────
    * Header Utilities
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_get_header()
    *
    * Case-insensitive header lookup in a response.
    *
    * @param resp      The response struct.
    * @param name      Header name to find.
    * @return          Pointer to the header value, or NULL if not found.
    */
const char *npe_http_get_header(const npe_http_response_t *resp,
                                const char *name);

/*
    * npe_http_has_header()
    *
    * Check if a header exists in the response (case-insensitive).
    *
    * @param resp  The response struct.
    * @param name  Header name to check.
    * @return      true if present.
    */
bool npe_http_has_header(const npe_http_response_t *resp, const char *name);

/* ─────────────────────────────────────────────────────────────────────────────
    * Response Memory Management
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_response_init()
    *
    * Initialize a response struct to safe defaults (zeroed).
    *
    * @param resp  The response struct to initialize.
    */
void npe_http_response_init(npe_http_response_t *resp);

/*
    * npe_http_response_free()
    *
    * Release all heap-allocated memory inside a response struct.
    * The struct itself is NOT freed (it may be stack-allocated).
    *
    * @param resp  The response struct to clean up.
    */
void npe_lib_http_response_free(npe_http_response_t *resp);

/* ─────────────────────────────────────────────────────────────────────────────
    * Request Options Helpers
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_opts_init()
    *
    * Initialize a request options struct with defaults.
    *
    * @param opts  The options struct to initialize.
    */
void npe_http_opts_init(npe_http_request_opts_t *opts);

/*
    * npe_http_opts_free()
    *
    * Release any heap allocations inside an options struct.
    *
    * @param opts  The options struct to clean up.
    */
void npe_http_opts_free(npe_http_request_opts_t *opts);

/* ─────────────────────────────────────────────────────────────────────────────
    * Method String Conversion
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_method_to_string()
    *
    * Convert an HTTP method enum to its string representation.
    *
    * @param method  The method enum value.
    * @return        Static string like "GET", "POST", etc.
    */
const char *npe_http_method_to_string(npe_http_method_t method);

/*
    * npe_http_method_from_string()
    *
    * Parse an HTTP method string to its enum value.
    *
    * @param str     Method string (case-insensitive).
    * @param out     Pointer to receive the enum value.
    * @return        0 on success, -1 if unrecognized.
    */
int npe_http_method_from_string(const char *str, npe_http_method_t *out);

/* ─────────────────────────────────────────────────────────────────────────────
    * Internal Lua-C Function Bindings
    * ───────────────────────────────────────────────────────────────────────────── */

int npe_http_l_get(lua_State *L);
int npe_http_l_post(lua_State *L);
int npe_http_l_head(lua_State *L);
int npe_http_l_put(lua_State *L);
int npe_http_l_delete(lua_State *L);
int npe_http_l_options(lua_State *L);
int npe_http_l_patch(lua_State *L);
int npe_http_l_request(lua_State *L);
int npe_http_l_parse_url(lua_State *L);
int npe_http_l_build_url(lua_State *L);
int npe_http_l_url_encode(lua_State *L);
int npe_http_l_url_decode(lua_State *L);
int npe_http_l_build_query(lua_State *L);
int npe_http_l_get_header(lua_State *L);
int npe_http_l_has_header(lua_State *L);

/* ─────────────────────────────────────────────────────────────────────────────
    * HTTP Response Push Helper
    * ───────────────────────────────────────────────────────────────────────────── */

/*
    * npe_http_push_response()
    *
    * Convert an npe_http_response_t to a Lua table and push it onto
    * the Lua stack.  This is used by all Lua-facing request functions.
    *
    * @param L     The Lua state.
    * @param resp  The response to convert.
    * @return      1 (one table pushed onto the stack).
    */
int npe_http_push_response(lua_State *L, const npe_http_response_t *resp);

/*
    * npe_http_parse_lua_opts()
    *
    * Parse a Lua options table at the given stack index into a C
    * npe_http_request_opts_t struct.
    *
    * @param L      The Lua state.
    * @param idx    Stack index of the options table.
    * @param opts   Pointer to options struct to fill.
    * @return       0 on success, -1 on error (Lua error raised).
    */
int npe_http_parse_lua_opts(lua_State *L, int idx,
                            npe_http_request_opts_t *opts);

/* ─────────────────────────────────────────────────────────────────────────────
    * Forward Declarations — internal (static) helpers
    * ───────────────────────────────────────────────────────────────────────────── */

/* Utility */
static double npe_http__time_ms(void);
static int npe_http__strcasecmp(const char *a, const char *b);
static void *npe_http__realloc_safe(void *ptr, size_t new_size);
static char *npe_http__base64_encode(const char *input, size_t len);

/* Networking */
static int npe_http__set_nonblocking(int fd);
static int npe_http__set_blocking(int fd);
static int npe_http__connect(const npe_http__parsed_url_t *url,
                                const npe_http_request_opts_t *opts,
                                int *out_fd);

/* SSL */
static SSL_CTX *npe_http__ssl_ctx_create(bool verify);
static SSL *npe_http__ssl_connect(int fd, SSL_CTX *ctx, const char *host);

/* Wire I/O */
static int npe_http__send_all(int fd, SSL *ssl,
                                const char *buf, size_t len);
static int npe_http__recv_line(int fd, SSL *ssl,
                                char *buf, size_t buf_size,
                                uint32_t timeout_ms);
static int npe_http__recv_exact(int fd, SSL *ssl,
                                char *buf, size_t len,
                                uint32_t timeout_ms);
static int npe_http__recv_all_available(int fd, SSL *ssl,
                                        char **out_buf, size_t *out_len,
                                        size_t max_len,
                                        uint32_t timeout_ms);

/* HTTP parsing */
static int npe_http__parse_status_line(const char *line,
                                        npe_http_response_t *resp);
static int npe_http__parse_header_line(const char *line,
                                        npe_http_header_t *hdr);
static int npe_http__read_headers(int fd, SSL *ssl,
                                    npe_http_response_t *resp,
                                    uint32_t timeout_ms);
static void npe_http__extract_cookies(npe_http_response_t *resp);
static int npe_http__read_chunked_body(int fd, SSL *ssl,
                                        char **out_buf, size_t *out_len,
                                        size_t max_body,
                                        uint32_t timeout_ms);
static int npe_http__read_body(int fd, SSL *ssl,
                                npe_http_response_t *resp,
                                size_t max_body,
                                uint32_t timeout_ms);

/* Request building */
static char *npe_http__build_request(const npe_http_request_t *req,
                                        const npe_http__parsed_url_t *url,
                                        size_t *out_len);

/* Redirect */
static bool npe_http__is_redirect(int status_code);
static int npe_http__handle_redirect(const npe_http_response_t *resp,
                                        const npe_http_url_t *current_url,
                                        npe_http_url_t *new_url);

/* Connection cleanup helper */
static void npe_http__close_conn(int fd, SSL *ssl, SSL_CTX *ssl_ctx);

/* Remaining-timeout helper */
static uint32_t npe_http__remaining_ms(double start, uint32_t total);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_HTTP_H */
