#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "cli.h"
#include "logger.h"
#include "args.h"
#include "cli_privilege.h"
#include "recon/recon.h"
#include "recon/output.h"

static volatile sig_atomic_t interrupted = 0;

static bool is_explicit_scan_selector(const char *arg)
{
    if (!arg) return false;

    if (strcmp(arg, "-s") == 0)
        return true;

    if (strncmp(arg, "-s", 2) == 0 && strlen(arg) >= 3)
    {
        char mode = arg[2];
        if (mode == 'S' || mode == 'T' || mode == 'A' || mode == 'W' ||
            mode == 'M' || mode == 'U' || mode == 'N' || mode == 'F' ||
            mode == 'X' || mode == 'I' || mode == 'Y' || mode == 'Z' ||
            mode == 'O')
            return true;
    }

    static const char *long_selectors[] = {
        "--syn", "--connect", "--udp", "--ack", "--window", "--maimon",
        "--null", "--fin", "--xmas", "--scanflags", "--idle",
        "--sctp-init", "--sctp-cookie", "--ip-proto", NULL
    };

    for (const char **flag = long_selectors; *flag; flag++)
    {
        if (strcmp(arg, *flag) == 0)
            return true;
    }

    return false;
}

static void handle_sigint(int sig)
{
    (void)sig;
    interrupted = 1;
}

int cmd_scan(int argc, char **argv)
{
    signal(SIGINT, handle_sigint);

    np_config_t *cfg = np_config_create();
    if (!cfg)
    {
        np_error(NP_ERR_RUNTIME, "[!] Memory allocation failed\n");
        return 1;
    }

    np_logger_init(NP_LOG_WARN, stderr);

    /* ── Default Configuration ──────────────────────────── */
    cfg->scan_mode    = NP_SCAN_AUTO;
    cfg->require_root = false;
    cfg->show_reason  = false;
    cfg->recon_cli_mode = true;

    /*
     * OS detection runs through the os_detect pipeline by default. It needs
     * raw sockets, so np_cli_scan_requires_root() enforces root for it.
     * Use --no-os-detect for an unprivileged recon scan.
     */
    cfg->os_detect    = true;

    /*
     * Build a clean argument array:
     *   1. Strip argv[1] ("scan" subcommand)
     *   2. Pre-parse scan-only flags and consume them
     *   3. Pass only remaining args to np_args_parse
     *
     * This prevents getopt_long from seeing unknown options
     * like --auto, --min-rate etc. which would cause it to
     * error out or corrupt parsing of -t / -p / other flags.
     */

    /* Allocate worst-case (all args kept) */
    char **clean_argv = malloc(sizeof(char *) * ((argc * 2) + 1));
    if (!clean_argv)
    {
        np_error(NP_ERR_RUNTIME, "[!] Memory allocation failed\n");
        np_config_destroy(cfg);
        return 1;
    }

    int clean_argc = 0;

    /* argv[0] = subcommand name ("scan") — always keep */
    clean_argv[clean_argc++] = argv[0];

    /* Walk argv[1..] (argv[0] is already "scan") */
    for (int i = 1; i < argc; i++)
    {
        const char *cur  = argv[i];
        const char *next = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strncmp(cur, "-iL", 3) == 0)
        {
            const char *value = NULL;
            if (cur[3] != '\0')
                value = cur + 3;
            else if (next)
            {
                value = next;
                i++;
            }

            if (!value || value[0] == '\0')
            {
                np_error(NP_ERR_RUNTIME, "[!] -iL requires an input filename\n");
                free(clean_argv);
                np_config_destroy(cfg);
                return 2;
            }

            clean_argv[clean_argc++] = "--input-list";
            clean_argv[clean_argc++] = (char *)value;
            continue;
        }

        if (strncmp(cur, "-iR", 3) == 0)
        {
            const char *value = NULL;
            if (cur[3] != '\0')
                value = cur + 3;
            else if (next)
            {
                value = next;
                i++;
            }

            if (!value || value[0] == '\0')
            {
                np_error(NP_ERR_RUNTIME, "[!] -iR requires a host count\n");
                free(clean_argv);
                np_config_destroy(cfg);
                return 2;
            }

            clean_argv[clean_argc++] = "--random-targets";
            clean_argv[clean_argc++] = (char *)value;
            continue;
        }

        if (strncmp(cur, "-oX", 3) == 0)
        {
            const char *value = NULL;
            if (cur[3] != '\0')
                value = cur + 3;
            else if (next)
            {
                value = next;
                i++;
            }

            if (!value || value[0] == '\0')
            {
                np_error(NP_ERR_RUNTIME, "[!] -oX requires an output filename\n");
                free(clean_argv);
                np_config_destroy(cfg);
                return 2;
            }

            clean_argv[clean_argc++] = "--xml";
            clean_argv[clean_argc++] = (char *)value;
            continue;
        }

        if (is_explicit_scan_selector(cur))
            cfg->scan_type_forced = true;

        if (strncmp(cur, "-s", 2) == 0 && strlen(cur) >= 3)
        {
            switch (cur[2])
            {
            case 'S': cfg->scan_type = NP_SCAN_TCP_SYN; break;
            case 'T': cfg->scan_type = NP_SCAN_TCP_CONNECT; break;
            case 'A': cfg->scan_type = NP_SCAN_TCP_ACK; break;
            case 'W': cfg->scan_type = NP_SCAN_TCP_WINDOW; break;
            case 'M': cfg->scan_type = NP_SCAN_TCP_MAIMON; break;
            case 'U': cfg->scan_type = NP_SCAN_UDP; break;
            case 'N': cfg->scan_type = NP_SCAN_TCP_NULL; break;
            case 'F': cfg->scan_type = NP_SCAN_TCP_FIN; break;
            case 'X': cfg->scan_type = NP_SCAN_TCP_XMAS; break;
            case 'Y': cfg->scan_type = NP_SCAN_SCTP_INIT; break;
            case 'Z': cfg->scan_type = NP_SCAN_SCTP_COOKIE_ECHO; break;
            case 'O': cfg->scan_type = NP_SCAN_IP_PROTOCOL; break;
            case 'I':
                cfg->scan_type = NP_SCAN_IDLE;
                if (next && next[0] != '-')
                {
                    char zombie[NP_MAX_HOSTNAME_LEN + 32];
                    strncpy(zombie, next, sizeof(zombie) - 1);
                    zombie[sizeof(zombie) - 1] = '\0';
                    char *colon = strchr(zombie, ':');
                    if (colon)
                    {
                        *colon = '\0';
                        long p = strtol(colon + 1, NULL, 10);
                        if (p > 0 && p <= 65535)
                            cfg->zombie_probe_port = (uint16_t)p;
                    }
                    strncpy(cfg->zombie_host, zombie, sizeof(cfg->zombie_host) - 1);
                    cfg->zombie_host[sizeof(cfg->zombie_host) - 1] = '\0';
                }
                break;
            default:
                break;
            }
        }

        if (strcmp(cur, "--sctp-init") == 0) cfg->scan_type = NP_SCAN_SCTP_INIT;
        if (strcmp(cur, "--sctp-cookie") == 0) cfg->scan_type = NP_SCAN_SCTP_COOKIE_ECHO;
        if (strcmp(cur, "--ip-proto") == 0) cfg->scan_type = NP_SCAN_IP_PROTOCOL;
        if (strcmp(cur, "--ack") == 0) cfg->scan_type = NP_SCAN_TCP_ACK;
        if (strcmp(cur, "--window") == 0) cfg->scan_type = NP_SCAN_TCP_WINDOW;
        if (strcmp(cur, "--maimon") == 0) cfg->scan_type = NP_SCAN_TCP_MAIMON;
        if (strcmp(cur, "--null") == 0) cfg->scan_type = NP_SCAN_TCP_NULL;
        if (strcmp(cur, "--fin") == 0) cfg->scan_type = NP_SCAN_TCP_FIN;
        if (strcmp(cur, "--xmas") == 0) cfg->scan_type = NP_SCAN_TCP_XMAS;
        if (strcmp(cur, "--udp") == 0) cfg->scan_type = NP_SCAN_UDP;
        if (strcmp(cur, "--connect") == 0) cfg->scan_type = NP_SCAN_TCP_CONNECT;
        if (strcmp(cur, "--syn") == 0) cfg->scan_type = NP_SCAN_TCP_SYN;

        /* ── Pre-parse scan-only flags ── */

        if (strcmp(cur, "--syn") == 0)
        {
            cfg->scan_mode = NP_SCAN_SYN;
            /* --syn IS known by np_args_parse, pass it through */
            clean_argv[clean_argc++] = argv[i];
            continue;
        }

        if (strcmp(cur, "--connect") == 0)
        {
            cfg->scan_mode = NP_SCAN_CONNECT;
            /* --connect IS known by np_args_parse, pass it through */
            clean_argv[clean_argc++] = argv[i];
            continue;
        }

        if (strcmp(cur, "--auto") == 0)
        {
            cfg->scan_mode = NP_SCAN_AUTO;
            /* np_args_parse does NOT know --auto, consume it */
            continue;
        }

        if (strcmp(cur, "--require-root") == 0)
        {
            cfg->require_root = true;
            continue;
        }

        if (strcmp(cur, "--reason") == 0)
        {
            cfg->show_reason = true;
            continue;
        }

        if (strcmp(cur, "--no-os-detect") == 0)
        {
            cfg->os_detect = false;
            continue;
        }

        /* ── Not a scan-only flag — pass through ── */
        clean_argv[clean_argc++] = argv[i];
    }

    clean_argv[clean_argc] = NULL;

    /*
     * Reset getopt global state so np_args_parse starts clean.
     *
     * On macOS/BSD, getopt requires optreset = 1 in addition to
     * optind = 1. On glibc, optind = 0 fully reinitializes.
     */
#if defined(__GLIBC__)
    optind = 0;
#else
    optind = 1;
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    optreset = 1;
#endif

    np_status_t rc = np_args_parse(clean_argc, clean_argv, cfg);
    if (rc != NP_OK)
    {
        np_error(NP_ERR_RUNTIME, "[!] Argument error: %s\n", np_status_str(rc));
        free(clean_argv);
        np_config_destroy(cfg);
        return 2;
    }

    free(clean_argv);

    rc = np_recon_apply_legacy_output_mapping(cfg);
    if (rc != NP_OK)
    {
        np_error(NP_ERR_RUNTIME, "[!] Output mapping failed: %s\n", np_status_str(rc));
        np_config_destroy(cfg);
        return 2;
    }

    if (np_cli_scan_requires_root(cfg) &&
        !np_cli_require_root("Selected scan mode/flags",
                             "Run with sudo, or add --no-os-detect with --connect/-sT for an unprivileged TCP connect scan"))
    {
        np_config_destroy(cfg);
        return 3;
    }

    /* ── Logging ────────────────────────────────────────── */
    np_logger_set_verbose(cfg->verbosity >= NP_LOG_VERBOSE);
    np_logger_set_level((np_log_level_t)cfg->verbosity);

    cfg->recon_subcommand = "scan";

    np_recon_context_t *ctx = np_recon_create(cfg);
    if (!ctx)
    {
        np_config_destroy(cfg);
        return 5;
    }

    if (cfg->host_discovery_mode == NP_HOST_DISCOVERY_LIST_ONLY ||
        cfg->host_discovery_mode == NP_HOST_DISCOVERY_PING_ONLY)
    {
        rc = np_recon_run_discovery(ctx, &interrupted);
        if (rc == NP_OK)
            rc = np_output_stage_run(ctx);
    }
    else
    {
        rc = np_recon_run_report(ctx, &interrupted);
    }

    np_recon_destroy(ctx);

    if (rc != NP_OK)
    {
        if (interrupted)
            np_error(NP_ERR_RUNTIME, "\n[!] Scan interrupted by user\n");
        else
            np_error(NP_ERR_RUNTIME, "[!] Scan failed: %s\n", np_status_str(rc));

        np_config_destroy(cfg);
        return 4;
    }

    np_config_destroy(cfg);
    return 0;
}
