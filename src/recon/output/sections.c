#include "recon/output_sections.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void np_recon_estimate_performance(np_recon_context_t *ctx, np_recon_perf_t *out)
{
    if (!out)
        return;

    memset(out, 0, sizeof(*out));

    out->stages[0].key = "discovery";
    out->stages[0].label = "Discovery";
    out->stages[0].ratio = 0.10;

    out->stages[1].key = "enumeration";
    out->stages[1].label = "Enumeration";
    out->stages[1].ratio = 0.45;

    out->stages[2].key = "fingerprint";
    out->stages[2].label = "Fingerprint";
    out->stages[2].ratio = 0.25;

    out->stages[3].key = "os_detection";
    out->stages[3].label = "OS Detection";
    out->stages[3].ratio = 0.15;

    out->stages[4].key = "report";
    out->stages[4].label = "Report";
    out->stages[4].ratio = 0.05;
    out->stage_count = 5;

    if (!ctx)
        return;

    if (ctx->start_mono_ns > 0)
    {
        uint64_t end_mono_ns = ctx->end_mono_ns;
        if (end_mono_ns == 0)
        {
            struct timespec now;
#if defined(CLOCK_MONOTONIC)
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
                end_mono_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
            else
#endif
                end_mono_ns = ctx->start_mono_ns;
        }

        if (end_mono_ns < ctx->start_mono_ns)
            end_mono_ns = ctx->start_mono_ns;

        out->total_seconds = (double)(end_mono_ns - ctx->start_mono_ns) / 1000000000.0;
    }
    else
    {
        time_t end_ts = ctx->end_ts > 0 ? ctx->end_ts : time(NULL);
        if (end_ts < ctx->start_ts)
            end_ts = ctx->start_ts;

        out->total_seconds = difftime(end_ts, ctx->start_ts);
    }

    if (out->total_seconds < 0.0)
        out->total_seconds = 0.0;

    if (ctx->cfg && !ctx->cfg->os_detect)
    {
        out->stages[2].ratio += out->stages[3].ratio;
        out->stages[3].ratio = 0.0;
    }

    for (uint32_t i = 0; i < out->stage_count; i++)
        out->stages[i].seconds = out->total_seconds * out->stages[i].ratio;
}

bool np_recon_should_show_version(const np_recon_context_t *ctx)
{
    return ctx && ctx->cfg && ctx->cfg->service_version_detect;
}

bool np_recon_should_show_os(const np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return false;

    /* OS detection enabled for this run (e.g. `recon run --os`): show its output. */
    if (ctx->cfg->os_detect)
        return true;

    if (!ctx->cfg->recon_subcommand)
        return false;

    return strcmp(ctx->cfg->recon_subcommand, "analyze") == 0 ||
           strcmp(ctx->cfg->recon_subcommand, "os-detect") == 0;
}

bool np_recon_service_identified(const np_service_view_t *svc)
{
    if (!svc)
        return false;

    if (svc->service && svc->service[0] && strcmp(svc->service, "unknown") != 0)
        return true;
    if (svc->product && svc->product[0])
        return true;
    if (svc->version && svc->version[0])
        return true;

    return false;
}

uint32_t np_recon_count_identified_services(const np_service_view_t *services,
                                            uint32_t count)
{
    uint32_t identified = 0;

    for (uint32_t i = 0; i < count; i++)
    {
        if (np_recon_service_identified(&services[i]))
            identified++;
    }

    return identified;
}

void np_recon_format_elapsed(double seconds, char *buf, size_t len)
{
    if (!buf || len == 0)
        return;

    if (seconds < 1.0)
    {
        snprintf(buf, len, "%.0fms", seconds * 1000.0);
        return;
    }

    if (seconds < 60.0)
    {
        snprintf(buf, len, "%.1fs", seconds);
        return;
    }

    unsigned mm = (unsigned)(seconds / 60.0);
    unsigned ss = (unsigned)seconds % 60u;
    snprintf(buf, len, "%um%02us", mm, ss);
}
