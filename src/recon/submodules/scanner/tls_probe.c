#include "recon/submodules/scanner/tls_probe.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void copy_capped(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    if (!src)
    {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static bool is_default_tls_port(uint16_t port)
{
    switch (port)
    {
    case 443:
    case 8443:
    case 993:
    case 995:
    case 465:
    case 636:
        return true;
    default:
        return false;
    }
}

static int connect_target(const np_target_t *target, uint16_t port, uint32_t timeout_ms)
{
    int fd = socket(target->is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_storage ss;
    socklen_t slen = 0;
    memset(&ss, 0, sizeof(ss));

    if (target->is_ipv6)
    {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        *s6 = target->addr6;
        s6->sin6_port = htons(port);
        slen = sizeof(*s6);
    }
    else
    {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        *s4 = target->addr4;
        s4->sin_port = htons(port);
        slen = sizeof(*s4);
    }

    if (connect(fd, (struct sockaddr *)&ss, slen) == 0)
        return fd;

    if (errno != EINPROGRESS)
    {
        close(fd);
        return -1;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    if (poll(&pfd, 1, (int)timeout_ms) <= 0)
    {
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0)
    {
        close(fd);
        return -1;
    }

    if (fl >= 0)
        (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    return fd;
}

static void fill_cert_time(char *dst, size_t cap, const ASN1_TIME *tm)
{
    if (!dst || cap == 0)
        return;
    dst[0] = '\0';
    if (!tm)
        return;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return;
    ASN1_TIME_print(bio, tm);
    int n = BIO_read(bio, dst, (int)cap - 1);
    if (n > 0)
        dst[n] = '\0';
    BIO_free(bio);
}

static char tls_grade(const char *proto, const char *cipher)
{
    if (!proto)
        return 'F';
    if (strstr(proto, "TLSv1.3") && cipher && (strstr(cipher, "AES") || strstr(cipher, "CHACHA20")))
        return 'A';
    if (strstr(proto, "TLSv1.2") && cipher && strstr(cipher, "GCM"))
        return 'B';
    if (strstr(proto, "TLSv1.2") && cipher && strstr(cipher, "CBC"))
        return 'C';
    if (strstr(proto, "TLSv1.1"))
        return 'D';
    return 'F';
}

static void collect_cert(np_tls_info_t *out, X509 *cert)
{
    if (!out || !cert)
        return;

    const X509_NAME *subj = X509_get_subject_name(cert);
    const X509_NAME *issuer = X509_get_issuer_name(cert);
    if (subj)
    {
        char buf[256];
        X509_NAME_get_text_by_NID(subj, NID_commonName, buf, sizeof(buf));
        copy_capped(out->cert_subject_cn, sizeof(out->cert_subject_cn), buf);
    }
    if (issuer)
    {
        char buf[256];
        X509_NAME_oneline(issuer, buf, sizeof(buf));
        copy_capped(out->cert_issuer, sizeof(out->cert_issuer), buf);
    }

    fill_cert_time(out->cert_valid_from, sizeof(out->cert_valid_from), X509_get0_notBefore(cert));
    fill_cert_time(out->cert_valid_to, sizeof(out->cert_valid_to), X509_get0_notAfter(cert));

    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (pk)
    {
        out->cert_key_bits = EVP_PKEY_bits(pk);
        EVP_PKEY_free(pk);
    }

    int sig_nid = X509_get_signature_nid(cert);
    copy_capped(out->cert_sig_alg,
                sizeof(out->cert_sig_alg),
                OBJ_nid2ln(sig_nid));

    GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans)
    {
        size_t used = 0;
        int count = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < count; i++)
        {
            const GENERAL_NAME *g = sk_GENERAL_NAME_value(sans, i);
            if (g->type != GEN_DNS)
                continue;

            const unsigned char *s = ASN1_STRING_get0_data(g->d.dNSName);
            int slen = ASN1_STRING_length(g->d.dNSName);
            if (!s || slen <= 0)
                continue;

            if (used > 0 && used + 2 < sizeof(out->cert_san))
            {
                out->cert_san[used++] = ',';
                out->cert_san[used++] = ' ';
            }

            size_t copy_len = (size_t)slen;
            if (copy_len > sizeof(out->cert_san) - used - 1)
                copy_len = sizeof(out->cert_san) - used - 1;
            memcpy(out->cert_san + used, s, copy_len);
            used += copy_len;
            out->cert_san[used] = '\0';
            if (used + 1 >= sizeof(out->cert_san))
                break;
        }
        GENERAL_NAMES_free(sans);
    }
}

np_status_t np_tls_probe_run(np_config_t *cfg)
{
    if (!cfg || !cfg->tls_info)
        return NP_OK;

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NP_ERR_SYSTEM;

    for (uint32_t ti = 0; ti < cfg->target_count; ti++)
    {
        np_target_t *t = &cfg->targets[ti];
        for (uint32_t pi = 0; pi < t->port_count; pi++)
        {
            np_port_result_t *r = &t->results[pi];
            if (r->state != NP_PORT_OPEN && r->state != NP_PORT_OPEN_FILTERED)
                continue;

            bool likely_tls = r->tls_detected || is_default_tls_port(r->port) ||
                              strcasecmp(r->service, "https") == 0 ||
                              strcasecmp(r->service, "ssl") == 0 ||
                              strcasecmp(r->service, "tls") == 0;
            if (!likely_tls)
                continue;

            int fd = connect_target(t, r->port, cfg->timeout_ms);
            if (fd < 0)
                continue;

            SSL *ssl = SSL_new(ctx);
            if (!ssl)
            {
                close(fd);
                continue;
            }

            SSL_set_fd(ssl, fd);
            if (SSL_connect(ssl) != 1)
            {
                SSL_free(ssl);
                close(fd);
                continue;
            }

            r->tls_detected = true;
            r->tls.enabled = true;
            copy_capped(r->tls.protocol, sizeof(r->tls.protocol), SSL_get_version(ssl));

            const SSL_CIPHER *ciph = SSL_get_current_cipher(ssl);
            if (ciph)
                copy_capped(r->tls.cipher, sizeof(r->tls.cipher), SSL_CIPHER_get_name(ciph));

            X509 *cert = SSL_get_peer_certificate(ssl);
            if (cert)
            {
                collect_cert(&r->tls, cert);
                X509_free(cert);
            }

            r->tls.grade = tls_grade(r->tls.protocol, r->tls.cipher);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(fd);
        }
    }

    SSL_CTX_free(ctx);
    return NP_OK;
}

np_status_t np_tls_probe_run_target(np_config_t *cfg, uint32_t target_idx)
{
    if (!cfg || !cfg->tls_info)
        return NP_OK;

    if (target_idx >= cfg->target_count)
        return NP_ERR_ARGS;

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NP_ERR_SYSTEM;

    np_target_t *t = &cfg->targets[target_idx];
    for (uint32_t pi = 0; pi < t->port_count; pi++)
    {
        np_port_result_t *r = &t->results[pi];
        if (r->state != NP_PORT_OPEN && r->state != NP_PORT_OPEN_FILTERED)
            continue;

        bool likely_tls = r->tls_detected || is_default_tls_port(r->port) ||
                          strcasecmp(r->service, "https") == 0 ||
                          strcasecmp(r->service, "ssl") == 0 ||
                          strcasecmp(r->service, "tls") == 0;
        if (!likely_tls)
            continue;

        int fd = connect_target(t, r->port, cfg->timeout_ms);
        if (fd < 0)
            continue;

        SSL *ssl = SSL_new(ctx);
        if (!ssl)
        {
            close(fd);
            continue;
        }

        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1)
        {
            SSL_free(ssl);
            close(fd);
            continue;
        }

        r->tls_detected = true;
        r->tls.enabled = true;
        copy_capped(r->tls.protocol, sizeof(r->tls.protocol), SSL_get_version(ssl));

        const SSL_CIPHER *ciph = SSL_get_current_cipher(ssl);
        if (ciph)
            copy_capped(r->tls.cipher, sizeof(r->tls.cipher), SSL_CIPHER_get_name(ciph));

        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert)
        {
            collect_cert(&r->tls, cert);
            X509_free(cert);
        }

        r->tls.grade = tls_grade(r->tls.protocol, r->tls.cipher);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }

    SSL_CTX_free(ctx);
    return NP_OK;
}
