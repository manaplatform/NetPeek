/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_lib_ssl.c — SSL/TLS Operations Library Implementation
 * =============================================================================
 */

#include "npe_lib_ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

/* ============================================================================
 * INTERNAL STRUCTURES
 * ============================================================================ */

typedef struct
{
    SSL_CTX *ctx;
    SSL *ssl;
    int socket_fd;
    char hostname[256];
    int port;
    bool connected;
} npe_ssl_connection_t;

/* ============================================================================
 * STATIC GLOBALS
 * ============================================================================ */

static bool g_ssl_initialized = false;
static SSL_CTX *g_ssl_ctx = NULL;

/* ============================================================================
 * INTERNAL HELPER FUNCTIONS
 * ============================================================================ */

static int npe_ssl_init(void)
{
    if (g_ssl_initialized)
    {
        return 0;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx)
    {
        return -1;
    }

    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);

    g_ssl_initialized = true;
    return 0;
}

static void npe_ssl_cleanup(void)
{
    if (g_ssl_ctx)
    {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
    ERR_free_strings();
    EVP_cleanup();
    g_ssl_initialized = false;
}

static int npe_ssl_create_socket(const char *hostname, int port)
{
    struct addrinfo hints, *result;
    int sockfd;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(hostname, port_str, &hints, &result);
    if (status != 0)
    {
        return -1;
    }

    sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd < 0)
    {
        freeaddrinfo(result);
        return -1;
    }

    if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0)
    {
        close(sockfd);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return sockfd;
}

static void npe_ssl_extract_cert_info(X509 *cert, npe_ssl_cert_t *cert_info)
{
    if (!cert || !cert_info)
        return;

    /* Subject */
    const X509_NAME *subject = X509_get_subject_name(cert);
    if (subject)
    {
        X509_NAME_oneline(subject, cert_info->subject, sizeof(cert_info->subject));
    }

    /* Issuer */
    const X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer)
    {
        X509_NAME_oneline(issuer, cert_info->issuer, sizeof(cert_info->issuer));
    }

    /* Serial number */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial)
    {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn)
        {
            char *hex = BN_bn2hex(bn);
            if (hex)
            {
                strncpy(cert_info->serial, hex, sizeof(cert_info->serial) - 1);
                cert_info->serial[sizeof(cert_info->serial) - 1] = '\0';
                OPENSSL_free(hex);
            }
            BN_free(bn);
        }
    }

    /* Validity period */
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    if (not_before)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, not_before);
        BIO_read(bio, cert_info->not_before, sizeof(cert_info->not_before) - 1);
        BIO_free(bio);
    }

    if (not_after)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, not_after);
        BIO_read(bio, cert_info->not_after, sizeof(cert_info->not_after) - 1);
        BIO_free(bio);
    }

    /* Fingerprint SHA256 */
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (X509_digest(cert, EVP_sha256(), md, &md_len))
    {
        char *fp = cert_info->fingerprint_sha256;
        for (unsigned int i = 0; i < md_len; i++)
        {
            sprintf(fp + i * 2, "%02X", md[i]);
        }
    }

    /* Public key info */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey)
    {
        int key_type = EVP_PKEY_id(pkey);
        cert_info->public_key_bits = EVP_PKEY_bits(pkey);

        switch (key_type)
        {
        case EVP_PKEY_RSA:
            strcpy(cert_info->public_key_type, "RSA");
            break;
        case EVP_PKEY_DSA:
            strcpy(cert_info->public_key_type, "DSA");
            break;
        case EVP_PKEY_EC:
            strcpy(cert_info->public_key_type, "EC");
            break;
        default:
            strcpy(cert_info->public_key_type, "Unknown");
            break;
        }
        EVP_PKEY_free(pkey);
    }
}

/* ============================================================================
 * LUA API IMPLEMENTATIONS
 * ============================================================================ */

int npe_lua_ssl_connect(lua_State *L)
{
    const char *hostname = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    int timeout = luaL_optinteger(L, 3, NPE_SSL_DEFAULT_TIMEOUT);

    if (npe_ssl_init() < 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to initialize SSL");
        return 2;
    }

    /* Create socket */
    int sockfd = npe_ssl_create_socket(hostname, port);
    if (sockfd < 0)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "Failed to connect to %s:%d", hostname, port);
        return 2;
    }

    /* Create SSL connection */
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl)
    {
        close(sockfd);
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create SSL structure");
        return 2;
    }

    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, hostname);

    /* Perform SSL handshake */
    int ret = SSL_connect(ssl);
    if (ret <= 0)
    {
        int ssl_err = SSL_get_error(ssl, ret);
        char err_buf[256] = {0};

        if (ssl_err == SSL_ERROR_SYSCALL)
        {
            if (errno != 0)
            {
                snprintf(err_buf, sizeof(err_buf), "System error: %s", strerror(errno));
            }
            else
            {
                snprintf(err_buf, sizeof(err_buf), "Connection closed by peer");
            }
        }
        else
        {
            unsigned long openssl_err = ERR_get_error();
            if (openssl_err != 0)
            {
                ERR_error_string_n(openssl_err, err_buf, sizeof(err_buf));
            }
            else
            {
                snprintf(err_buf, sizeof(err_buf), "SSL error code: %d", ssl_err);
            }
        }

        SSL_free(ssl);
        close(sockfd);
        lua_pushnil(L);
        lua_pushstring(L, err_buf);
        return 2;
    }

    /* Create connection object */
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)lua_newuserdata(L, sizeof(npe_ssl_connection_t));
    conn->ctx = g_ssl_ctx;
    conn->ssl = ssl;
    conn->socket_fd = sockfd;
    strncpy(conn->hostname, hostname, sizeof(conn->hostname) - 1);
    conn->hostname[sizeof(conn->hostname) - 1] = '\0';
    conn->port = port;
    conn->connected = true;

    luaL_getmetatable(L, "npe.ssl.connection");
    lua_setmetatable(L, -2);

    return 1;
}

int npe_lua_ssl_get_cert(lua_State *L)
{
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)luaL_checkudata(L, 1, "npe.ssl.connection");

    if (!conn->connected || !conn->ssl)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Connection not established");
        return 2;
    }

    X509 *cert = SSL_get_peer_certificate(conn->ssl);
    if (!cert)
    {
        lua_pushnil(L);
        lua_pushstring(L, "No peer certificate");
        return 2;
    }

    npe_ssl_cert_t cert_info;
    memset(&cert_info, 0, sizeof(cert_info));
    npe_ssl_extract_cert_info(cert, &cert_info);

    lua_newtable(L);
    lua_pushstring(L, cert_info.subject);
    lua_setfield(L, -2, "subject");

    lua_pushstring(L, cert_info.issuer);
    lua_setfield(L, -2, "issuer");

    lua_pushstring(L, cert_info.serial);
    lua_setfield(L, -2, "serial");

    lua_pushstring(L, cert_info.not_before);
    lua_setfield(L, -2, "not_before");

    lua_pushstring(L, cert_info.not_after);
    lua_setfield(L, -2, "not_after");

    lua_pushstring(L, cert_info.fingerprint_sha256);
    lua_setfield(L, -2, "fingerprint_sha256");

    lua_pushstring(L, cert_info.public_key_type);
    lua_setfield(L, -2, "public_key_type");

    lua_pushinteger(L, cert_info.public_key_bits);
    lua_setfield(L, -2, "public_key_bits");

    X509_free(cert);
    return 1;
}

int npe_lua_ssl_get_cert_chain(lua_State *L)
{
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)luaL_checkudata(L, 1, "npe.ssl.connection");

    if (!conn->connected || !conn->ssl)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Connection not established");
        return 2;
    }

    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(conn->ssl);
    if (!chain)
    {
        lua_pushnil(L);
        lua_pushstring(L, "No certificate chain");
        return 2;
    }

    int chain_len = sk_X509_num(chain);
    lua_newtable(L);

    for (int i = 0; i < chain_len; i++)
    {
        X509 *cert = sk_X509_value(chain, i);
        if (cert)
        {
            npe_ssl_cert_t cert_info;
            memset(&cert_info, 0, sizeof(cert_info));
            npe_ssl_extract_cert_info(cert, &cert_info);

            lua_newtable(L);
            lua_pushstring(L, cert_info.subject);
            lua_setfield(L, -2, "subject");
            lua_pushstring(L, cert_info.issuer);
            lua_setfield(L, -2, "issuer");
            lua_pushstring(L, cert_info.serial);
            lua_setfield(L, -2, "serial");
            lua_pushstring(L, cert_info.fingerprint_sha256);
            lua_setfield(L, -2, "fingerprint_sha256");

            lua_rawseti(L, -2, i + 1);
        }
    }

    return 1;
}

int npe_lua_ssl_get_cipher(lua_State *L)
{
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)luaL_checkudata(L, 1, "npe.ssl.connection");

    if (!conn->connected || !conn->ssl)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Connection not established");
        return 2;
    }

    const char *cipher = SSL_get_cipher(conn->ssl);
    if (!cipher)
    {
        lua_pushnil(L);
        lua_pushstring(L, "No cipher information");
        return 2;
    }

    lua_newtable(L);
    lua_pushstring(L, cipher);
    lua_setfield(L, -2, "name");

    const SSL_CIPHER *cipher_obj = SSL_get_current_cipher(conn->ssl);
    if (cipher_obj)
    {
        lua_pushinteger(L, SSL_CIPHER_get_bits(cipher_obj, NULL));
        lua_setfield(L, -2, "bits");

        lua_pushstring(L, SSL_CIPHER_get_version(cipher_obj));
        lua_setfield(L, -2, "version");
    }

    return 1;
}

int npe_lua_ssl_get_protocol(lua_State *L)
{
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)luaL_checkudata(L, 1, "npe.ssl.connection");

    if (!conn->connected || !conn->ssl)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Connection not established");
        return 2;
    }

    const char *protocol = SSL_get_version(conn->ssl);
    if (!protocol)
    {
        lua_pushnil(L);
        lua_pushstring(L, "No protocol information");
        return 2;
    }

    lua_pushstring(L, protocol);
    return 1;
}

int npe_lua_ssl_enum_ciphers(lua_State *L)
{
    if (npe_ssl_init() < 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to initialize SSL");
        return 2;
    }

    lua_newtable(L);

    STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(g_ssl_ctx);
    if (ciphers)
    {
        int num_ciphers = sk_SSL_CIPHER_num(ciphers);

        for (int i = 0; i < num_ciphers && i < NPE_SSL_MAX_CIPHERS; i++)
        {
            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
            if (cipher)
            {
                lua_newtable(L);

                lua_pushstring(L, SSL_CIPHER_get_name(cipher));
                lua_setfield(L, -2, "name");

                lua_pushinteger(L, SSL_CIPHER_get_bits(cipher, NULL));
                lua_setfield(L, -2, "bits");

                lua_pushstring(L, SSL_CIPHER_get_version(cipher));
                lua_setfield(L, -2, "version");

                lua_rawseti(L, -2, i + 1);
            }
        }
    }

    return 1;
}

int npe_lua_ssl_check_protocol(lua_State *L)
{
    const char *hostname = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    const char *protocol = luaL_optstring(L, 3, "TLSv1.2");

    /* Quick connection test */
    int sockfd = npe_ssl_create_socket(hostname, port);
    if (sockfd < 0)
    {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "Failed to connect to %s:%d", hostname, port);
        return 2;
    }

    close(sockfd);
    lua_pushboolean(L, 1);
    return 1;
}

/* ============================================================================
 * SSL CONNECTION METATABLE METHODS
 * ============================================================================ */

static int npe_ssl_connection_gc(lua_State *L)
{
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)luaL_checkudata(L, 1, "npe.ssl.connection");

    if (conn->ssl)
    {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if (conn->socket_fd >= 0)
    {
        close(conn->socket_fd);
        conn->socket_fd = -1;
    }

    conn->connected = false;
    return 0;
}

static int npe_ssl_connection_tostring(lua_State *L)
{
    npe_ssl_connection_t *conn = (npe_ssl_connection_t *)luaL_checkudata(L, 1, "npe.ssl.connection");
    lua_pushfstring(L, "npe.ssl.connection<%s:%d>", conn->hostname, conn->port);
    return 1;
}

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

static const luaL_Reg ssl_functions[] = {
    {"connect", npe_lua_ssl_connect},
    {"get_cert", npe_lua_ssl_get_cert},
    {"get_cert_chain", npe_lua_ssl_get_cert_chain},
    {"get_cipher", npe_lua_ssl_get_cipher},
    {"get_protocol", npe_lua_ssl_get_protocol},
    {"enum_ciphers", npe_lua_ssl_enum_ciphers},
    {"check_protocol", npe_lua_ssl_check_protocol},
    {NULL, NULL}};

static const luaL_Reg ssl_connection_methods[] = {
    {"__gc", npe_ssl_connection_gc},
    {"__tostring", npe_ssl_connection_tostring},
    {NULL, NULL}};

int npe_lib_ssl_register(lua_State *L)
{
    /* Create ssl connection metatable */
    luaL_newmetatable(L, "npe.ssl.connection");
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, ssl_connection_methods, 0);
    lua_pop(L, 1);

    /* Create ssl module table */
    luaL_newlib(L, ssl_functions);

    /* Add constants */
    lua_pushinteger(L, NPE_SSL_MAX_CERT_LEN);
    lua_setfield(L, -2, "MAX_CERT_LEN");

    lua_pushinteger(L, NPE_SSL_DEFAULT_TIMEOUT);
    lua_setfield(L, -2, "DEFAULT_TIMEOUT");

    return 1;
}
