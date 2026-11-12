#include "recon/modules/fingerprint_os.h"

#include <stdlib.h>
#include <string.h>

#include "logger.h"
#include "runtime/stats.h"
#include "recon/recon.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "recon/submodules/os_detect/os_pipeline_config.h"
#include "recon/submodules/os_detect/os_sigload.h"
#include "recon/submodules/scanner/scanner_internal.h"

static np_target_t *os_target(np_config_t *cfg)
{
    if (!cfg || cfg->target_count == 0 || !cfg->targets)
        return NULL;

    return &cfg->targets[0];
}

static np_status_t os_fp_run_standalone(np_recon_context_t *ctx)
{
    np_target_t *target = os_target(ctx->cfg);
    if (!target)
        return NP_ERR_ARGS;

    const char *ip = target->ip[0] ? target->ip : target->hostname;
    if (!ip || !ip[0])
        return NP_ERR_ARGS;

    np_os_sigdb_t db;
    np_sigdb_init(&db);

    if (!ctx->cfg->os_builtin_only &&
        ctx->cfg->os_sigfile_path &&
        ctx->cfg->os_sigfile_path[0])
    {
        if (np_sigdb_load(&db, ctx->cfg->os_sigfile_path) != 0)
            LOGW("Failed to load signature file: %s, falling back to builtin", ctx->cfg->os_sigfile_path);
    }

    if (np_sigdb_merge_builtin(&db) != 0)
    {
        np_sigdb_free(&db);
        return NP_ERR_SYSTEM;
    }

    np_os_result_t result;
    memset(&result, 0, sizeof(result));

    uint16_t open_ports[NP_PIPELINE_MAX_OPEN_PORTS];
    uint32_t open_count = 0;
    if (target->port_count > 0 && target->results)
    {
        for (uint32_t i = 0; i < target->port_count && open_count < NP_PIPELINE_MAX_OPEN_PORTS; i++)
        {
            if (target->results[i].state == NP_PORT_OPEN || target->results[i].state == NP_PORT_OPEN_FILTERED)
            {
                open_ports[open_count++] = target->results[i].port;
            }
        }
    }

    np_status_t rc = np_os_detect_pipeline_run_ex(ip,
                                                  ctx->cfg->os_target_port,
                                                  open_count > 0 ? open_ports : NULL,
                                                  open_count,
                                                  0,
                                                  &db,
                                                  ctx->cfg,
                                                  &result);
    np_sigdb_free(&db);
    if (rc != NP_OK)
        return rc;

    if (ctx->cfg->osscan_limit &&
        result.passive_evidence_count == 0 &&
        result.best_confidence == 0)
    {
        return NP_OK;
    }

    if (!ctx->cfg->osscan_guess && result.passive_low_confidence)
        result.os_guess_passive[0] = '\0';

    target->os_result = result;
    target->os_result_valid =
        target->os_result.best_confidence > 0 ||
        target->os_result.os_guess_passive[0] != 0;

    if (result.open_port_count > 0 && target->port_count == 0)
    {
        target->port_count = (uint32_t)result.open_port_count;
        target->results = calloc(target->port_count, sizeof(np_port_result_t));
        if (target->results)
        {
            for (uint32_t i = 0; i < target->port_count; i++)
            {
                np_port_result_t *pr = &target->results[i];
                pr->port = result.open_ports[i];
                pr->state = NP_PORT_OPEN;
                strncpy(pr->proto, "tcp", sizeof(pr->proto) - 1);
                strncpy(pr->reason, "syn-ack", sizeof(pr->reason) - 1);
                np_stats_inc_port_state(NP_PORT_OPEN);
            }
        }
    }

    (void)np_recon_graph_ingest_discovery(ctx);
    if (target->port_count > 0 && ctx->services_seen == 0)
        (void)np_recon_graph_ingest_scan(ctx);

    return np_recon_graph_ingest_os(ctx);
}

static np_status_t os_fp_run(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    if (!ctx->cfg->os_detect)
        return NP_OK;

    if (ctx->cfg->recon_subcommand &&
        strcmp(ctx->cfg->recon_subcommand, "os-detect") == 0)
    {
        return os_fp_run_standalone(ctx);
    }

    np_status_t rc = np_scan_os_detect_run(ctx->cfg, ctx->interrupted);
    if (rc != NP_OK)
        return rc;

    return np_recon_graph_ingest_os(ctx);
}

static const char *g_os_fp_deps[] = {
    "builtin.discovery",
};

np_module_t np_os_fingerprint_module = {
    .name = "os.fingerprint",
    .stage = NP_STAGE_FINGERPRINT,
    .impact = NP_IMPACT_INTRUSIVE,
    .priority = 40,
    .depends_on = g_os_fp_deps,
    .depends_on_count = 1,
    .parallel_safe = true,
    .required = true,
    .init = NULL,
    .run = os_fp_run,
    .cleanup = NULL,
};
