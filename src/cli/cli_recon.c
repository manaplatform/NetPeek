#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "args.h"
#include "cli.h"
#include "cli_privilege.h"
#include "core/error.h"
#include "help.h"
#include "logger.h"
#include "recon/diff.h"
#include "recon/module.h"
#include "recon/output.h"
#include "recon/persist.h"
#include "recon/recon.h"
#include "runtime/stats.h"

static volatile sig_atomic_t g_recon_interrupted = 0;

typedef struct
{
    volatile int running;
    bool enabled;
    const char *subcmd;
    int last_pct;
    pthread_t thread;
} np_recon_progress_state_t;

static double np_recon_ratio(uint64_t done, uint64_t total)
{
    if (total == 0)
        return 1.0;

    double ratio = (double)done / (double)total;
    if (ratio < 0.0)
        ratio = 0.0;
    if (ratio > 1.0)
        ratio = 1.0;
    return ratio;
}

static uint32_t np_recon_stage_weight(np_stage_t stage)
{
    switch (stage)
    {
    case NP_STAGE_DISCOVERY:
        return 10;
    case NP_STAGE_ENUM:
        return 45;
    case NP_STAGE_FINGERPRINT:
        return 30;
    case NP_STAGE_ENRICH:
        return 10;
    case NP_STAGE_REPORT:
        return 5;
    case NP_STAGE_ANALYZE:
    default:
        return 0;
    }
}

static bool np_recon_subcmd_includes_stage(const char *subcmd, np_stage_t stage)
{
    if (!subcmd)
        return false;

    if (strcmp(subcmd, "discover") == 0)
        return stage == NP_STAGE_DISCOVERY;

    if (strcmp(subcmd, "enum") == 0)
        return stage == NP_STAGE_DISCOVERY || stage == NP_STAGE_ENUM;

    if (strcmp(subcmd, "analyze") == 0)
    {
        return stage == NP_STAGE_DISCOVERY ||
               stage == NP_STAGE_ENUM ||
               stage == NP_STAGE_FINGERPRINT ||
               stage == NP_STAGE_ENRICH;
    }

    if (strcmp(subcmd, "run") == 0 || strcmp(subcmd, "report") == 0)
    {
        return stage == NP_STAGE_DISCOVERY ||
               stage == NP_STAGE_ENUM ||
               stage == NP_STAGE_FINGERPRINT ||
               stage == NP_STAGE_ENRICH ||
               stage == NP_STAGE_REPORT;
    }

    return false;
}

static void np_recon_sigint(int sig)
{
    (void)sig;
    g_recon_interrupted = 1;
}

static int np_recon_progress_pct(const np_recon_progress_state_t *state,
                                 const np_stats_snapshot_t *snap)
{
    if (!state || !snap)
        return 0;

    np_module_progress_snapshot_t module_snap;
    np_module_progress_snapshot(&module_snap);

    double weighted_done = 0.0;
    double total_weight = 0.0;

    for (size_t stage_idx = 0; stage_idx < NP_STAGE_COUNT; stage_idx++)
    {
        np_stage_t stage = (np_stage_t)stage_idx;
        if (!np_recon_subcmd_includes_stage(state->subcmd, stage))
            continue;

        uint32_t weight = np_recon_stage_weight(stage);
        if (weight == 0)
            continue;

        double ratio = 0.0;
        if (stage == NP_STAGE_DISCOVERY || stage == NP_STAGE_ENUM)
        {
            if (snap->hosts_total > 0)
                ratio = np_recon_ratio(snap->hosts_completed, snap->hosts_total);
            else if (module_snap.stage_total[stage_idx] > 0)
                ratio = np_recon_ratio(module_snap.stage_completed[stage_idx],
                                       module_snap.stage_total[stage_idx]);
        }
        else if (module_snap.stage_total[stage_idx] > 0)
        {
            ratio = np_recon_ratio(module_snap.stage_completed[stage_idx],
                                   module_snap.stage_total[stage_idx]);
        }

        weighted_done += ratio * (double)weight;
        total_weight += (double)weight;
    }

    if (total_weight <= 0.0)
        return 0;

    int pct = (int)((weighted_done * 100.0) / total_weight);
    if (pct < 0)
        pct = 0;
    if (pct > 100)
        pct = 100;
    return pct;
}

static void np_recon_progress_render(const np_recon_progress_state_t *state,
                                     int pct,
                                     const np_stats_snapshot_t *snap)
{
    if (!state)
        return;

    int filled = pct / 10;
    if (filled > 10)
        filled = 10;

    char bar[64] = {0};
    size_t offset = 0;
    for (int i = 0; i < filled; i++)
        offset += (size_t)snprintf(bar + offset, sizeof(bar) - offset, "▮");
    for (int i = filled; i < 10; i++)
        offset += (size_t)snprintf(bar + offset, sizeof(bar) - offset, "▯");

    const char *subcmd = state->subcmd ? state->subcmd : "recon";
    if (snap && snap->hosts_total > 0)
    {
        fprintf(stderr,
                "\r[%s] [%-30s] %3d%%  Hosts: %llu/%llu",
                subcmd,
                bar,
                pct,
                (unsigned long long)snap->hosts_completed,
                (unsigned long long)snap->hosts_total);
    }
    else
    {
        fprintf(stderr,
                "\r[%s] [%-30s] %3d%%  Hosts: -/-",
                subcmd,
                bar,
                pct);
    }
    fflush(stderr);
}

static void *np_recon_progress_thread(void *arg)
{
    np_recon_progress_state_t *state = (np_recon_progress_state_t *)arg;

    while (state->running)
    {
        np_stats_snapshot_t snap;
        np_stats_snapshot(&snap);

        int pct = np_recon_progress_pct(state, &snap);
        if (pct < state->last_pct)
            pct = state->last_pct;
        else
            state->last_pct = pct;

        np_recon_progress_render(state, pct, &snap);

        usleep(200000);
    }

    return NULL;
}

static void np_recon_progress_start(np_recon_progress_state_t *state,
                                    const char *subcmd)
{
    if (!state)
        return;

    memset(state, 0, sizeof(*state));
    state->subcmd = subcmd;
    state->last_pct = 0;
    state->enabled = isatty(STDERR_FILENO) == 1;
    if (!state->enabled)
        return;

    state->running = 1;
    if (pthread_create(&state->thread, NULL, np_recon_progress_thread, state) != 0)
    {
        state->running = 0;
        state->enabled = false;
    }
}

static void np_recon_progress_stop(np_recon_progress_state_t *state, bool finalize_to_100)
{
    if (!state || !state->enabled)
        return;

    state->running = 0;
    pthread_join(state->thread, NULL);

    if (finalize_to_100)
    {
        np_stats_snapshot_t snap;
        np_stats_snapshot(&snap);
        np_recon_progress_render(state, 100, &snap);
    }

    fputc('\n', stderr);
    fflush(stderr);
}

static uint32_t np_parse_interval_seconds(const char *value)
{
    if (!value || !value[0])
        return 60;

    char *end = NULL;
    unsigned long n = strtoul(value, &end, 10);
    if (n == 0)
        return 60;

    if (!end || *end == '\0' || strcmp(end, "s") == 0)
        return (uint32_t)n;
    if (strcmp(end, "m") == 0)
        return (uint32_t)(n * 60);
    if (strcmp(end, "h") == 0)
        return (uint32_t)(n * 3600);

    return 60;
}

static bool np_parse_u32_value(const char *value,
                               uint32_t min,
                               uint32_t max,
                               uint32_t *out)
{
    if (!value || !out)
        return false;

    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return false;
    if (parsed < (unsigned long)min || parsed > (unsigned long)max)
        return false;

    *out = (uint32_t)parsed;
    return true;
}

static bool np_parse_recon_style(const char *value, np_recon_style_t *out)
{
    if (!value || !out)
        return false;

    if (strcmp(value, "classic") == 0)
        *out = NP_RECON_STYLE_CLASSIC;
    else if (strcmp(value, "modern") == 0)
        *out = NP_RECON_STYLE_MODERN;
    else if (strcmp(value, "compact") == 0)
        *out = NP_RECON_STYLE_COMPACT;
    else if (strcmp(value, "json") == 0)
        *out = NP_RECON_STYLE_JSON;
    else if (strcmp(value, "report") == 0)
        *out = NP_RECON_STYLE_REPORT;
    else
        return false;

    return true;
}

static void np_recon_usage(void)
{
    fprintf(stderr,
            "Usage: netpeek recon <subcommand> [scan-options]\n"
            "Subcommands:\n"
            "  run        full recon pipeline + report\n"
            "  discover   host discovery and persist graph\n"
            "  enum       discover + scan + graph persistence\n"
            "  analyze    full staged pipeline + OS fingerprint\n"
            "  diff       compare two recon JSON outputs\n"
            "  report     pipeline + output report\n"
            "  watch      repeated recon snapshots (--interval 24h)\n"
            "Modes:\n"
            "  --mode passive|safe|intrusive\n"
            "Output:\n"
            "  --style classic|modern|compact|json|report\n"
            "  --no-color --compact --verbose --evidence --summary-only\n"
            "  --recon-serial             Force serial module execution\n"
            "  --recon-workers <n>        Cap recon scheduler workers\n"
            "  --format text|json|md|html|xml|sarif|diff\n"
            "  --output text|json|md|html|xml|sarif|diff  --out <file>  --pretty\n");
}

static bool np_is_recon_pipeline_cmd(const char *subcmd)
{
    if (!subcmd)
        return false;

    return strcmp(subcmd, "run") == 0 ||
           strcmp(subcmd, "discover") == 0 ||
           strcmp(subcmd, "enum") == 0 ||
           strcmp(subcmd, "analyze") == 0 ||
           strcmp(subcmd, "report") == 0;
}

static int np_recon_parse_scan_args(int argc, char **argv, np_config_t *cfg)
{
    if (!cfg)
        return 2;

    cfg->recon_cli_mode = true;
    cfg->suppress_progress = true;

    char **scan_argv = calloc((size_t)argc + 2, sizeof(char *));
    if (!scan_argv)
        return 2;

    int scan_argc = 0;
    scan_argv[scan_argc++] = "scan";
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "--mode") == 0)
        {
            if ((i + 1) >= argc)
            {
                free(scan_argv);
                return 2;
            }

            const char *mode = argv[++i];
            if (strcmp(mode, "passive") == 0)
                cfg->auth_mode = NP_AUTH_MODE_PASSIVE;
            else if (strcmp(mode, "safe") == 0)
                cfg->auth_mode = NP_AUTH_MODE_SAFE;
            else if (strcmp(mode, "intrusive") == 0)
                cfg->auth_mode = NP_AUTH_MODE_INTRUSIVE;
            else
            {
                free(scan_argv);
                return 2;
            }
            continue;
        }

        if (strcmp(argv[i], "--style") == 0)
        {
            if ((i + 1) >= argc)
            {
                free(scan_argv);
                return 2;
            }

            if (!np_parse_recon_style(argv[++i], &cfg->recon_style))
            {
                free(scan_argv);
                return 2;
            }
            cfg->recon_style_explicit = true;
            continue;
        }

        if (strcmp(argv[i], "--output") == 0)
        {
            if ((i + 1) >= argc)
            {
                free(scan_argv);
                return 2;
            }
            cfg->recon_output_format = argv[++i];
            cfg->recon_format_explicit = true;
            continue;
        }

        if (strcmp(argv[i], "--format") == 0)
        {
            if ((i + 1) >= argc)
            {
                free(scan_argv);
                return 2;
            }
            cfg->recon_output_format = argv[++i];
            cfg->recon_format_explicit = true;
            continue;
        }

        if (strcmp(argv[i], "--out") == 0)
        {
            if ((i + 1) >= argc)
            {
                free(scan_argv);
                return 2;
            }
            cfg->output_file = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "--pretty") == 0)
        {
            cfg->pretty_output = true;
            continue;
        }

        if (strcmp(argv[i], "--evidence") == 0)
        {
            cfg->show_evidence = true;
            continue;
        }

        if (strcmp(argv[i], "--compact") == 0)
        {
            cfg->recon_compact = true;
            continue;
        }

        if (strcmp(argv[i], "--summary-only") == 0)
        {
            cfg->recon_summary_only = true;
            continue;
        }

        if (strcmp(argv[i], "--no-color") == 0)
        {
            cfg->recon_no_color = true;
            continue;
        }

        if (strcmp(argv[i], "--verbose") == 0)
        {
            cfg->recon_verbose_detail = true;
            cfg->show_evidence = true;
            scan_argv[scan_argc++] = argv[i];
            continue;
        }

        if (strcmp(argv[i], "--recon-serial") == 0)
        {
            cfg->recon_force_serial = true;
            continue;
        }

        if (strcmp(argv[i], "--recon-workers") == 0)
        {
            if ((i + 1) >= argc)
            {
                free(scan_argv);
                return 2;
            }

            if (!np_parse_u32_value(argv[++i], 1, 100000, &cfg->recon_workers))
            {
                free(scan_argv);
                return 2;
            }
            continue;
        }

        scan_argv[scan_argc++] = argv[i];
    }
    scan_argv[scan_argc] = NULL;

#if defined(__GLIBC__)
    optind = 0;
#else
    optind = 1;
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    optreset = 1;
#endif

    np_status_t rc = np_args_parse(scan_argc, scan_argv, cfg);
    free(scan_argv);

    if (!cfg->recon_output_format &&
        !(cfg->output_file && cfg->output_file[0]) &&
        cfg->recon_style == NP_RECON_STYLE_JSON)
        cfg->recon_output_format = "json";
    else if (!cfg->recon_output_format &&
             !(cfg->output_file && cfg->output_file[0]) &&
             cfg->recon_style == NP_RECON_STYLE_REPORT)
        cfg->recon_output_format = "html";

    return rc == NP_OK ? 0 : 2;
}

static int np_recon_run_once(const char *subcmd, int argc, char **argv)
{
    np_config_t *cfg = np_config_create();
    if (!cfg)
        return 1;

    if (np_recon_parse_scan_args(argc, argv, cfg) != 0)
    {
        np_config_destroy(cfg);
        return 2;
    }

    if (cfg->verbose)
    {
        cfg->recon_verbose_detail = true;
        cfg->show_evidence = true;
    }

    if (strcmp(subcmd, "analyze") == 0)
    {
        cfg->os_detect = true;
        cfg->service_version_detect = true;
    }

    cfg->recon_subcommand = subcmd;

    if (!cfg->recon_style_explicit)
    {
        if (strcmp(subcmd, "run") == 0 || strcmp(subcmd, "report") == 0 || strcmp(subcmd, "analyze") == 0)
            cfg->recon_style = NP_RECON_STYLE_MODERN;
    }

    /*
     * The recon pipeline auto-selects a raw SYN scan when no scan type is
     * forced, which silently yields an empty report without root. Tell the
     * user to re-run with sudo (or force an unprivileged connect scan).
     */
    if (!np_cli_is_effective_root() && np_cli_recon_requires_root(cfg))
    {
        np_error(NP_ERR_OS,
                 "[!] 'recon %s' needs root: the default scan uses raw SYN packets\n",
                 subcmd);
        np_error(NP_ERR_OS,
                 "[!] Re-run with sudo, for example: sudo netpeek recon %s <target>\n",
                 subcmd);
        np_error(NP_ERR_OS,
                 "[!] Or force an unprivileged scan: netpeek recon %s -sT <target>\n",
                 subcmd);
        np_config_destroy(cfg);
        return 3;
    }

    np_logger_set_verbose(cfg->verbosity >= NP_LOG_VERBOSE);
    np_logger_set_level((np_log_level_t)cfg->verbosity);

    np_recon_context_t *ctx = np_recon_create(cfg);
    if (!ctx)
    {
        np_config_destroy(cfg);
        return 1;
    }

    np_recon_progress_state_t progress;
    memset(&progress, 0, sizeof(progress));
    np_module_progress_reset();
    if (!cfg->recon_summary_only)
        np_recon_progress_start(&progress, subcmd);

    const char *home = getenv("HOME");
    if (home && home[0])
    {
        char mod_dir[1024];
        snprintf(mod_dir, sizeof(mod_dir), "%s/.netpeek/modules", home);
        size_t loaded_count = 0;
        (void)np_module_load_dir(ctx, mod_dir, &loaded_count);
    }

    np_status_t rc = np_recon_persist_begin_run(ctx);
    if (rc != NP_OK)
    {
        np_recon_progress_stop(&progress, false);
        np_recon_destroy(ctx);
        np_config_destroy(cfg);
        return 4;
    }

    if (strcmp(subcmd, "discover") == 0)
        rc = np_recon_run_discovery(ctx, &g_recon_interrupted);
    else if (strcmp(subcmd, "enum") == 0)
        rc = np_recon_run_enum(ctx, &g_recon_interrupted);
    else if (strcmp(subcmd, "analyze") == 0)
        rc = np_recon_run_analyze(ctx, &g_recon_interrupted);
    else if (strcmp(subcmd, "run") == 0 || strcmp(subcmd, "report") == 0)
        rc = np_recon_run_report(ctx, &g_recon_interrupted);
    else
        rc = NP_ERR_ARGS;

    np_recon_progress_stop(&progress, rc == NP_OK);

    if (rc == NP_OK && strcmp(subcmd, "report") != 0 && strcmp(subcmd, "run") != 0)
        rc = np_output_stage_run(ctx);

    if (rc == NP_OK)
        rc = np_recon_persist_flush(ctx);

    (void)np_recon_persist_end_run(ctx, rc, np_status_str(rc));

    np_recon_persist_close(ctx);
    np_recon_destroy(ctx);
    np_config_destroy(cfg);

    if (rc != NP_OK)
        return 4;

    return 0;
}

static int np_recon_cmd_diff(int argc, char **argv)
{
    int opt;
    const char *format = NULL;
    const char *out_path = NULL;
    bool no_color = false;

    static struct option long_opts[] = {
        {"json", no_argument, 0, 'j'},
        {"html", required_argument, 0, 1000},
        {"out", required_argument, 0, 1002},
        {"format", required_argument, 0, 1003},
        {"no-color", no_argument, 0, 1001},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

#if defined(__GLIBC__)
    optind = 0;
#else
    optind = 1;
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    optreset = 1;
#endif

    while ((opt = getopt_long(argc, argv, "jh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'j':
            format = "json";
            break;
        case 1000:
            format = "html";
            out_path = optarg;
            break;
        case 1002:
            out_path = optarg;
            break;
        case 1003:
            format = optarg;
            break;
        case 1001:
            no_color = true;
            break;
        case 'h':
            np_help_print_diff_usage("netpeek recon diff", stdout);
            return 0;
        default:
            np_help_print_diff_usage("netpeek recon diff", stderr);
            return 2;
        }
    }

    if (optind + 2 != argc)
    {
        np_help_print_diff_usage("netpeek recon diff", stderr);
        return 2;
    }

    if (!format)
    {
        if (out_path && out_path[0])
            format = np_format_from_extension(out_path);
        else
            format = "text";
    }

    bool use_color = !no_color && isatty(STDOUT_FILENO) == 1;
    return np_recon_diff_run(argv[optind], argv[optind + 1], format, out_path, use_color);
}

int cmd_recon(int argc, char **argv)
{
    signal(SIGINT, np_recon_sigint);
    np_logger_init(NP_LOG_WARN, stderr);

    if (argc < 2)
    {
        np_recon_usage();
        return 2;
    }

    const char *subcmd = argv[1];
    if (strcmp(subcmd, "-h") == 0 || strcmp(subcmd, "--help") == 0)
    {
        np_recon_usage();
        return 0;
    }

    if (strcmp(subcmd, "diff") == 0)
        return np_recon_cmd_diff(argc - 1, &argv[1]);

    if (strcmp(subcmd, "watch") == 0)
    {
        uint32_t interval = 60;
        const char *watch_subcmd = "run";
        int arg_start = 2;

        if (arg_start < argc && np_is_recon_pipeline_cmd(argv[arg_start]))
            watch_subcmd = argv[arg_start++];

        if (arg_start + 1 < argc && strcmp(argv[arg_start], "--interval") == 0)
        {
            interval = np_parse_interval_seconds(argv[arg_start + 1]);
            arg_start += 2;
        }

        uint64_t run_count = 0;
        while (!g_recon_interrupted)
        {
            run_count++;
            if (run_count > 1)
                fprintf(stderr, "\n[recon/watch] starting run #%llu\n", (unsigned long long)run_count);

            int rc = np_recon_run_once(watch_subcmd, argc - arg_start, &argv[arg_start]);
            if (rc != 0)
                return rc;

            if (g_recon_interrupted)
                break;

            for (uint32_t waited = 0; waited < interval; waited++)
            {
                if (g_recon_interrupted)
                    break;
                sleep(1);
            }
        }

        return 130;
    }

    if (!np_is_recon_pipeline_cmd(subcmd))
    {
        np_recon_usage();
        return 2;
    }

    return np_recon_run_once(subcmd, argc - 2, &argv[2]);
}
