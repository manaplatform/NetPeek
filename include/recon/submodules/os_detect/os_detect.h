/*
 * NetPeek - OS Detection Module
 * Copyright (c) 2025
 *
 * Combined TCP/IP fingerprinting and banner grabbing
 * with cross-referenced confidence scoring.
 *
 * NOTE: All shared data types (np_os_result_t, np_os_candidate_t,
 *       np_os_match_t, np_os_banner_t, etc.) are defined in
 *       netpeek.h — the single source of truth.
 *       This header only declares OS-detection-specific enums,
 *       config, and the public API.
 */

#ifndef NP_OS_DETECT_H
#define NP_OS_DETECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <signal.h>
#include <stdio.h>

/*
 * netpeek.h provides ALL shared types:
 *   np_os_candidate_t, np_os_match_t, np_os_banner_t,
 *   np_os_result_t, np_target_t, np_proxy_t, np_output_fmt_t,
 *   np_status_t, and all NP_OS_* constants.
 */
#include "netpeek.h"

/*
 * These headers define the REAL (full) versions of
 * np_os_fingerprint_t and np_tcp_probe_result_t,
 * overriding the placeholders in netpeek.h.
 * They must use the same #define guards:
 *   NP_OS_FINGERPRINT_T_DEFINED
 *   NP_TCP_PROBE_RESULT_T_DEFINED
 */
#include "os_fingerprint_score.h"
#include "os_tcp_probes.h"
#include "os_sigload.h"
#include "os_port_discovery.h"

/* ═══════════════════════════════════════════════════════
 *  IP ID behavior (Nmap-style)
 *  (only used inside OS detection engine)
 * ═══════════════════════════════════════════════════════ */

typedef enum {
    IPID_UNKNOWN       = 0,
    IPID_CONSTANT      = 1,
    IPID_INCREMENTAL   = 2,
    IPID_RANDOM        = 3
} np_ipid_behavior_t;

#define NP_IPID_UNKNOWN       0
#define NP_IPID_ZERO          1
#define NP_IPID_INCREMENTAL   2
#define NP_IPID_RANDOM        3

/* ═══════════════════════════════════════════════════════
 *  Confidence thresholds
 * ═══════════════════════════════════════════════════════ */

#define NP_OS_CONFIDENCE_HIGH   80
#define NP_OS_CONFIDENCE_MEDIUM 50
#define NP_OS_CONFIDENCE_LOW    25

/* ═══════════════════════════════════════════════════════
 *  OS detection configuration
 *  (separate from np_config_t — used by standalone
 *   OS detection mode)
 * ═══════════════════════════════════════════════════════ */

typedef struct {
    np_target_t    *targets;
    uint32_t        target_count;

    uint16_t       *probe_ports;
    uint32_t        probe_port_count;

    uint32_t        timeout_ms;
    uint32_t        threads;

    bool            verbose;

    np_proxy_t      proxy;

    np_output_fmt_t output_fmt;
    const char     *output_file;

    bool            do_fingerprint;
    bool            do_banner;

    np_os_result_t *results;
} np_os_config_t;

/* ═══════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════ */

np_status_t np_os_detect_run(
    np_os_config_t *cfg,
    volatile sig_atomic_t *interrupted);

np_status_t np_os_result_alloc(
    np_os_config_t *cfg);

void np_os_result_free(
    np_os_config_t *cfg);

void np_os_result_print(
    const np_os_config_t *cfg);

np_status_t np_os_detect_parse_args(
    int argc,
    char *argv[],
    np_os_config_t *cfg);

void np_os_detect_usage(
    const char *progname);

/* ═══════════════════════════════════════════════════════
 *  Pipeline API
 * ═══════════════════════════════════════════════════════ */

np_status_t np_os_detect_pipeline_run(
    const char *target_ip,
    uint16_t port,
    const np_os_sigdb_t *db,
    np_os_result_t *result);

np_status_t np_os_detect_pipeline_auto_ports(const char *target_ip,
                                             uint16_t port,
                                             const uint16_t *open_ports,
                                             uint32_t open_port_count,
                                             const char *sigdb_path,
                                             np_os_result_t *result);

np_status_t np_os_detect_pipeline_auto(
    const char *target_ip,
    uint16_t port,
    const char *sigfile_path,
    np_os_result_t *result);

np_status_t np_os_detect_quick(
    const char *target_ip,
    uint16_t port,
    char *os_name_out,
    size_t os_name_sz,
    double *confidence_out);

void np_os_detect_result_print(
    FILE *stream,
    const np_os_result_t *result);

void np_os_detect_result_free(
    np_os_result_t *result);

/* ═══════════════════════════════════════════════════════
 *  Low-level helpers used by scan engine
 * ═══════════════════════════════════════════════════════ */

int np_tcp_fingerprint(
    const char *target_ip,
    uint16_t port,
    np_os_fingerprint_t *fp);

int np_grab_banner(
    const char *target_ip,
    uint16_t port,
    np_os_banner_t *banner);

#ifdef __cplusplus
}
#endif

#endif /* NP_OS_DETECT_H */
