/*
 * NetPeek - CLI Network Port Scanner
 * Copyright (c) 2025
 *
 * Core definitions and shared types.
 * *** SINGLE SOURCE OF TRUTH FOR ALL DATA TYPES ***
 */

#ifndef NETPEEK_H
#define NETPEEK_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include "ports.h"
#include "evasion.h"
#include "core/error.h"
#include "os_fingerprint_types.h"
#include "os_tcp_probes.h"
/* ═══════════════════════════════════════════════════════
 *  Global limits
 * ═══════════════════════════════════════════════════════ */

#define NP_MAX_PORTS 65535
#define NP_MAX_TARGETS 4096
#define NP_DEFAULT_THREADS 200
#define NP_DEFAULT_TIMEOUT 2000
#define NP_MAX_HOSTNAME_LEN 253
#define NP_MAX_IP_LEN 64
#define NP_MAX_DNS_SERVERS 4
#define NP_MAX_TRACE_HOPS 32

/* ═══════════════════════════════════════════════════════
 *  OS detection limits & constants
 *  (canonical — os_detect.h must NOT redefine these)
 * ═══════════════════════════════════════════════════════ */

#define NP_OS_NAME_MAX 128
#define NP_OS_NAME_LEN 128
#define NP_OS_FAMILY_MAX 64
#define NP_OS_FAMILY_LEN 32
#define NP_OS_CPE_MAX 128
#define NP_OS_BANNER_MAX 1024
#define NP_MAX_BANNER_LEN 512
#define NP_MAX_OS_HINT 64

#define NP_OS_MAX_MATCHES 8
#define NP_OS_MAX_BANNERS 16
#define NP_OS_MAX_OPEN_PORTS 64
#define NP_OS_MAX_PROBES 16
#define NP_MAX_CANDIDATES 10
#define NP_OS_MAX_CANDIDATES NP_MAX_CANDIDATES /* alias */

/* ═══════════════════════════════════════════════════════
 *  Proxy
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_PROXY_NONE = 0,
    NP_PROXY_SOCKS5,
    NP_PROXY_HTTP_CONNECT
} np_proxy_type_t;

typedef struct
{
    np_proxy_type_t type;
    char host[NP_MAX_HOSTNAME_LEN + 1];
    uint16_t port;
    char username[128];
    char password[128];
    bool has_auth;
} np_proxy_t;

/* ═══════════════════════════════════════════════════════
 *  Port state
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_PORT_UNKNOWN = 0,
    NP_PORT_OPEN,
    NP_PORT_CLOSED,
    NP_PORT_FILTERED,
    NP_PORT_OPEN_FILTERED
} np_port_state_t;

/* ═══════════════════════════════════════════════════════
 *  Scan technique
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_SCAN_TCP_CONNECT = 0,
    NP_SCAN_TCP_SYN,
    NP_SCAN_UDP,
    NP_SCAN_TCP_ACK,
    NP_SCAN_TCP_WINDOW,
    NP_SCAN_TCP_MAIMON,
    NP_SCAN_TCP_NULL,
    NP_SCAN_TCP_FIN,
    NP_SCAN_TCP_XMAS,
    NP_SCAN_TCP_CUSTOM_FLAGS,
    NP_SCAN_IDLE,
    NP_SCAN_SCTP_INIT,
    NP_SCAN_SCTP_COOKIE_ECHO,
    NP_SCAN_IP_PROTOCOL
} np_scan_type_t;

/* ═══════════════════════════════════════════════════════
 *  Output format
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_OUTPUT_PLAIN = 0,
    NP_OUTPUT_JSON,
    NP_OUTPUT_CSV,
    NP_OUTPUT_GREPPABLE,
    NP_OUTPUT_XML,
    NP_OUTPUT_HTML
} np_output_fmt_t;

typedef enum
{
    NP_RECON_STYLE_CLASSIC = 0,
    NP_RECON_STYLE_MODERN,
    NP_RECON_STYLE_COMPACT,
    NP_RECON_STYLE_JSON,
    NP_RECON_STYLE_REPORT
} np_recon_style_t;

/* ═══════════════════════════════════════════════════════
 *  OS detection — prerequisite types
 *  (must come before np_os_result_t)
 * ═══════════════════════════════════════════════════════ */

/* --- OS candidate (used in result + output) --- */
typedef struct np_os_candidate
{
    char os_name[NP_OS_NAME_MAX];
    char os_family[NP_OS_FAMILY_MAX];
    double score; /* 0.0 – 100.0 */
    char cpe[128];
    int int_score; /* integer alias used by some engine code */
} np_os_candidate_t;

/* --- OS match (fingerprint + banner cross-ref) --- */
typedef struct np_os_match
{
    char os_name[NP_OS_NAME_LEN];
    char os_family[NP_OS_FAMILY_LEN];
    char os_vendor[64];
    char os_gen[32];
    char device_type[64];
    char cpe[128];
    uint8_t confidence;
    bool from_fingerprint;
    bool from_banner;
    bool synthetic;
    bool just_guessing;
} np_os_match_t;

/* --- Banner grabbed from a single port --- */
typedef struct np_os_banner
{
    uint16_t port;
    char banner[NP_MAX_BANNER_LEN];
    uint32_t banner_len;
    char service[32];
    char os_hint[NP_MAX_OS_HINT];
    int os_hint_confidence;

    char product[64];
    char version[64];
    char cpe[128];
} np_os_banner_t;

/* --- Family aggregation --- */
typedef struct np_family_score
{
    char family[32];
    uint32_t total_score;
    uint32_t hit_count;
} np_family_score_t;

/*
 * Forward-declare the fingerprint and probe types.
 * Their full definitions live in os_fingerprint_score.h
 * and os_tcp_probes.h respectively — but we only need
 * the names here so np_os_result_t can embed them.
 *
 * If those headers are included BEFORE netpeek.h the
 * full definitions win; if not, these forward decls
 * let the compiler know they exist.
 *
 * NOTE: We cannot embed structs by value with only a
 * forward declaration. So we conditionally typedef
 * placeholder structs that get replaced when the real
 * headers are included.
 */

/* ═══════════════════════════════════════════════════════
 *  OS detection — full result structure (CANONICAL)
 *
 *  Used by:  os_detect engine  (writes all fields)
 *            np_target_t       (embeds it)
 *            output module     (reads display fields)
 * ═══════════════════════════════════════════════════════ */

typedef struct np_os_result
{

    /* ── Best-match identification (final aggregated) ── */
    char best_os[NP_OS_NAME_MAX];
    char best_family[NP_OS_FAMILY_MAX];
    char best_cpe[NP_OS_CPE_MAX];
    double best_confidence; /* 0.0 – 100.0 */
    int hop_distance;

    /* ── All match candidates ────────────────────────── */
    np_os_candidate_t candidates[NP_OS_MAX_CANDIDATES];
    int candidate_count;

    np_os_match_t matches[NP_OS_MAX_MATCHES];
    uint32_t match_count;

    /* ── Captured banners ────────────────────────────── */
    np_os_banner_t banners[NP_OS_MAX_BANNERS];
    uint32_t banner_count;

    /* ── Raw fingerprint from SYN-ACK ────────────────── */
    np_os_fingerprint_t fingerprint;

    /* ── Per-source validity flags ───────────────────── */
    bool fp_valid;
    bool behavior_valid;
    bool banner_valid;

    /* ── Per-source: fingerprint ─────────────────────── */
    char fp_os_name[NP_OS_NAME_LEN];
    uint32_t fp_score;

    /* ── Per-source: behavioral analysis ─────────────── */
    char behavior_os_name[NP_OS_NAME_LEN];
    double behavior_score; /* 0.0 – 1.0 */

    /* ── Per-source: banner grabbing ─────────────────── */
    char banner_os_name[NP_OS_NAME_LEN];
    double banner_confidence; /* 0.0 – 100.0 */

    /* ── Port discovery results ──────────────────────── */
    uint16_t open_ports[NP_OS_MAX_OPEN_PORTS];
    int open_port_count;
    uint16_t port_used; /* port used for FP (0 = none) */

    /* ── TCP probe diagnostics ───────────────────────── */
    int probes_sent;
    int probes_answered;
    int probe_count; /* total TCP probe responses */
    np_tcp_probe_result_t probe_results[NP_OS_MAX_PROBES];

    /* ── Signature match stats ───────────────────────── */
    int sigs_evaluated;
    int sigs_matched;

    /* ── Aggregated classification ───────────────────── */
    char device_type[64];
    char aggregated_device_type[128];
    char aggregated_cpe[256];

    /* ── Pipeline metadata ───────────────────────────── */
    int pipeline_stage_reached; /* last stage completed (1-6) */
    int error_code;             /* 0 = success */
    char error_msg[256];

    /* ── Final confidence (output convenience) ───────── */
    double confidence; /* 0.0 – 100.0 */

    /* ── Passive fingerprint supplemental result ─────── */
    char os_guess_passive[NP_OS_NAME_LEN];
    double passive_confidence; /* 0.0 – 100.0 */
    uint32_t passive_evidence_count;
    bool passive_low_confidence;

} np_os_result_t;

/* ═══════════════════════════════════════════════════════
 *  Single port result
 * ═══════════════════════════════════════════════════════ */

typedef struct
{
    bool enabled;
    char protocol[32];
    char cipher[128];
    char cert_subject_cn[256];
    char cert_san[512];
    char cert_issuer[256];
    char cert_valid_from[64];
    char cert_valid_to[64];
    int cert_key_bits;
    char cert_sig_alg[128];
    char grade;
} np_tls_info_t;

typedef struct
{
    uint16_t port;
    char proto[8];
    np_port_state_t state;
    char service[32];
    char version[128];
    char product[64];
    char cpe[128];
    char os_hint[64];
    uint8_t service_confidence;
    char probe_name[32];
    char service_method[32];
    char reason[64];
    double scan_confidence;
    bool tls_detected;
    np_tls_info_t tls;
    double rtt_ms;
    bool completed;
} np_port_result_t;

/* ═══════════════════════════════════════════════════════
 *  Target descriptor
 * ═══════════════════════════════════════════════════════ */

typedef struct
{
    uint8_t ttl;
    char ip[NP_MAX_IP_LEN];
    double rtt_ms;
    bool timeout;
} np_trace_hop_t;

typedef struct
{
    char hostname[NP_MAX_HOSTNAME_LEN + 1];
    char ip[NP_MAX_IP_LEN];
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    bool is_ipv6;

    np_port_result_t *results;
    uint32_t port_count;

    bool host_up;
    bool host_discovered;
    char host_reason[64];
    double host_rtt_ms;
    np_trace_hop_t trace_hops[NP_MAX_TRACE_HOPS];
    uint8_t trace_hop_count;

    /* OS detection */
    bool os_result_valid;
    np_os_result_t os_result;
} np_target_t;

/* ═══════════════════════════════════════════════════════
 *  Scan mode
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_SCAN_AUTO = 0,
    NP_SCAN_CONNECT,
    NP_SCAN_SYN
} np_scan_mode_t;

typedef enum
{
    NP_HOST_DISCOVERY_DEFAULT = 0,
    NP_HOST_DISCOVERY_SKIP,
    NP_HOST_DISCOVERY_PING_ONLY,
    NP_HOST_DISCOVERY_LIST_ONLY
} np_host_discovery_mode_t;

typedef enum
{
    NP_DNS_AUTO = 0,
    NP_DNS_NEVER,
    NP_DNS_ALWAYS,
    NP_DNS_SYSTEM
} np_dns_mode_t;

typedef enum
{
    NP_TIMING_TEMPLATE_UNSET = 255,
    NP_TIMING_TEMPLATE_0 = 0,
    NP_TIMING_TEMPLATE_1,
    NP_TIMING_TEMPLATE_2,
    NP_TIMING_TEMPLATE_3,
    NP_TIMING_TEMPLATE_4,
    NP_TIMING_TEMPLATE_5
} np_timing_template_t;

typedef enum
{
    NP_ENGINE_LEGACY = 0,
    NP_ENGINE_FULL
} np_engine_mode_t;

typedef enum
{
    NP_UDP_FAST_PATH_AUTO = 0,
    NP_UDP_FAST_PATH_ON,
    NP_UDP_FAST_PATH_OFF
} np_udp_fast_path_mode_t;

typedef enum
{
    NP_AUTH_MODE_PASSIVE = 0,
    NP_AUTH_MODE_SAFE,
    NP_AUTH_MODE_INTRUSIVE
} np_auth_mode_t;

/* ═══════════════════════════════════════════════════════
 *  Global scan configuration
 * ═══════════════════════════════════════════════════════ */

typedef struct
{
    /* Targets */
    np_target_t *targets;
    uint32_t target_count;
    np_port_spec_t ports;

    /* Ports */
    np_port_range_t *port_ranges;
    uint32_t range_count;
    uint16_t *port_list;
    uint32_t port_list_len;

    /* Scan parameters */
    np_scan_type_t scan_type;
    bool scan_type_forced;
    uint8_t tcp_custom_flags;
    uint32_t threads;
    uint32_t timeout_ms;
    int retries;
    bool randomize_ports;
    bool randomize_hosts;
    bool framework_mode;
    np_engine_mode_t engine_mode;
    np_auth_mode_t auth_mode;
    uint32_t full_rx_threads;
    uint32_t full_queue_capacity;
    uint32_t full_max_inflight;
    bool full_enable_host_affinity;

    /* Proxy / Evasion */
    np_proxy_t proxy;
    np_evasion_t evasion;

    /* Output */
    np_output_fmt_t output_fmt;
    const char *output_file;
    const char *recon_output_format;
    const char *recon_subcommand;
    np_recon_style_t recon_style;
    bool recon_style_explicit;
    bool recon_format_explicit;
    bool recon_cli_mode;
    bool recon_no_color;
    bool recon_compact;
    bool recon_summary_only;
    bool recon_verbose_detail;
    bool recon_force_serial;
    uint32_t recon_workers;
    bool suppress_progress;
    bool pretty_output;
    bool show_evidence;
    bool verbose;
    np_log_verbosity_t verbosity;
    bool show_closed;
    bool drop_filtered_states;

    int workers;
    np_scan_mode_t scan_mode;
    bool require_root;
    bool show_reason;
    bool service_version_detect;
    uint8_t version_intensity;
    bool version_trace;
    bool tls_info;
    np_host_discovery_mode_t host_discovery_mode;
    bool host_discovery_done;
    bool probe_icmp_echo;
    bool probe_icmp_timestamp;
    bool probe_icmp_netmask;
    bool probe_tcp_syn;
    bool probe_tcp_ack;
    bool probe_udp;
    bool probe_sctp_init;
    bool probe_ip_proto;
    np_port_spec_t discovery_tcp_syn_ports;
    np_port_spec_t discovery_tcp_ack_ports;
    np_port_spec_t discovery_udp_ports;
    np_port_spec_t discovery_sctp_ports;
    uint8_t discovery_ip_protocols[32];
    uint8_t discovery_ip_protocol_count;
    np_dns_mode_t dns_mode;
    char dns_servers[NP_MAX_DNS_SERVERS][NP_MAX_HOSTNAME_LEN + 1];
    uint8_t dns_server_count;
    bool traceroute_enabled;
    char zombie_host[NP_MAX_HOSTNAME_LEN + 1];
    uint16_t zombie_probe_port;

    /* Rate limiting */
    uint32_t min_rate;
    uint32_t max_rate;
    uint32_t max_retries;

    /* Advanced timing/performance */
    np_timing_template_t timing_template;
    uint32_t min_hostgroup;
    uint32_t max_hostgroup;
    uint32_t min_parallelism;
    uint32_t max_parallelism;
    uint32_t min_rtt_timeout_ms;
    uint32_t max_rtt_timeout_ms;
    uint32_t initial_rtt_timeout_ms;
    uint32_t host_timeout_ms;
    uint32_t scan_delay_us;
    uint32_t max_scan_delay_us;
    np_udp_fast_path_mode_t udp_fast_path_mode;
    uint32_t udp_batch_size;
    uint32_t udp_inflight_per_thread;
    uint32_t udp_min_probe_interval_us;
    bool udp_linux_advanced;

    bool timing_template_explicit;
    bool fast_mode;
    bool udp_batch_size_explicit;
    bool udp_inflight_explicit;
    bool udp_min_probe_interval_explicit;
    bool threads_explicit;
    bool min_rate_explicit;
    bool max_rate_explicit;
    bool max_retries_explicit;
    bool min_hostgroup_explicit;
    bool max_hostgroup_explicit;
    bool min_parallelism_explicit;
    bool max_parallelism_explicit;
    bool min_rtt_timeout_explicit;
    bool max_rtt_timeout_explicit;
    bool initial_rtt_timeout_explicit;
    bool host_timeout_explicit;
    bool scan_delay_explicit;
    bool max_scan_delay_explicit;

    /* OS detection */
    bool os_detect;
    bool allow_partial_os_detect;
    bool osscan_guess;
    bool osscan_limit;
    bool os_builtin_only;
    uint16_t os_target_port;
    const char *os_target_input;
    const char *os_sigfile_path;

    /* Timing */
    struct timespec start_time;

} np_config_t;

/* ═══════════════════════════════════════════════════════
 *  Connection result
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_CONNECT_FAILED = -1,
    NP_CONNECT_IN_PROGRESS = 0,
    NP_CONNECT_IMMEDIATE = 1
} np_connect_rc_t;

/* ═══════════════════════════════════════════════════════
 *  Return codes
 * ═══════════════════════════════════════════════════════ */

typedef enum
{
    NP_STATUS_OK = 0,
    NP_STATUS_ERR = -1,

    NP_ERR_ARGS = -2,
    NP_ERR_RESOLVE = -3,
    NP_ERR_SOCKET = -4,
    NP_ERR_MEMORY = -5,
    NP_ERR_PERMISSION = -6,
    NP_STATUS_ERR_IO = -7,
    NP_ERR_SYSTEM = -8,
    NP_ERR_PRIVILEGE_REQUIRED = -9
} np_status_t;

/* Compatibility aliases */
#define NP_OK NP_STATUS_OK
#define NP_ERR NP_STATUS_ERR

/* ═══════════════════════════════════════════════════════
 *  Lifecycle API
 * ═══════════════════════════════════════════════════════ */

np_config_t *np_config_create(void);
void np_config_destroy(np_config_t *cfg);
const char *np_status_str(np_status_t status);
const char *np_port_state_str(np_port_state_t state);

#endif /* NETPEEK_H */
