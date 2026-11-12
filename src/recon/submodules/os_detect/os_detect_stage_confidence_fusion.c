/* ============================================================
   stage_confidence_fusion.c — Stage 7: Confidence Fusion
   ============================================================ */

#include "os_pipeline_priv.h"
#include "recon/submodules/os_detect/os_detect_pipeline.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define LOG_STAGE "fusion"

/* ----- Weight configuration for each evidence source ----- */
#define WEIGHT_FINGERPRINT  0.55
#define WEIGHT_BANNER       0.30
#define WEIGHT_BEHAVIOR     0.15

/* ----- Minimum confidence floor to report a result ------- */
#define MIN_CONFIDENCE_THRESHOLD 5.0

/* ----- Agreement bonus when multiple sources concur ------ */
#define AGREEMENT_BONUS      10.0
#define TRIPLE_AGREE_BONUS   18.0

/* ----- Helper: case-insensitive substring check ---------- */
static bool os_names_agree(const char *a, const char *b)
{
    if (!a || !b || !a[0] || !b[0])
        return false;

    /* Derive families and compare */
    char fam_a[NP_OS_FAMILY_LEN] = {0};
    char fam_b[NP_OS_FAMILY_LEN] = {0};

    derive_os_family(a, fam_a, sizeof(fam_a));
    derive_os_family(b, fam_b, sizeof(fam_b));

    if (fam_a[0] && fam_b[0])
        return (strcasecmp(fam_a, fam_b) == 0);

    /* Fallback: direct case-insensitive compare */
    return (strcasecmp(a, b) == 0);
}

/* ----- Clamp a confidence value to [0, 100] -------------- */
static double clamp_confidence(double v)
{
    if (v < 0.0)   return 0.0;
    if (v > 100.0)  return 100.0;
    return v;
}

/* ============================================================
   stage_confidence_fusion
   ============================================================

   Fuses up to three independent evidence channels:
     1. Fingerprint DB match   (fp_valid, fp_score 0-100, candidates[])
     2. Banner analysis        (banner_valid, banner_confidence 0-100)
     3. Behavior heuristic     (behavior_valid, behavior_score 0-100)

   The fusion uses a weighted sum with an agreement bonus when
   multiple sources identify the same OS family.
   ============================================================ */
int stage_confidence_fusion(np_pipeline_ctx_t *ctx)
{
    if (!ctx)
        return -1;

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "Confidence fusion: fp_valid=%d banner_valid=%d behavior_valid=%d",
             ctx->fp_valid, ctx->banner_valid, ctx->behavior_valid);

    /* ---------------------------------------------------------
       Gather each channel's best OS name and raw confidence
       --------------------------------------------------------- */
    const char *fp_os       = NULL;
    double      fp_conf     = 0.0;

    const char *banner_os   = NULL;
    double      banner_conf = 0.0;

    const char *behav_os    = NULL;
    double      behav_conf  = 0.0;

    /* Channel 1: Fingerprint match */
    if (ctx->fp_valid && ctx->candidate_count > 0)
    {
        fp_os   = ctx->candidates[0].os_name;
        fp_conf = (double)ctx->fp_score;

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "  FP channel: os='%s' score=%.1f",
                 fp_os ? fp_os : "(null)", fp_conf);
    }
    else if (ctx->fp_valid && ctx->fp_best_sig)
    {
        fp_os   = ctx->fp_best_sig->os_name;
        fp_conf = (double)ctx->fp_score;

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "  FP channel (sig): os='%s' score=%.1f",
                 fp_os ? fp_os : "(null)", fp_conf);
    }

    /* Channel 2: Banner */
    if (ctx->banner_valid && ctx->banner_os_name[0])
    {
        banner_os   = ctx->banner_os_name;
        banner_conf = ctx->banner_confidence;

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "  Banner channel: os='%s' confidence=%.1f",
                 banner_os, banner_conf);
    }

    /* Channel 3: Behavior */
    if (ctx->behavior_valid && ctx->behavior_os_name && ctx->behavior_os_name[0])
    {
        behav_os   = ctx->behavior_os_name;
        behav_conf = (double)ctx->behavior_score;

        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "  Behavior channel: os='%s' score=%.1f",
                 behav_os, behav_conf);
    }

    /* ---------------------------------------------------------
       Count how many channels produced a result
       --------------------------------------------------------- */
    int active_channels = 0;
    if (fp_os && fp_conf > 0.0)       active_channels++;
    if (banner_os && banner_conf > 0.0) active_channels++;
    if (behav_os && behav_conf > 0.0)  active_channels++;

    pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
             "  Active evidence channels: %d", active_channels);

    /* ---------------------------------------------------------
       If no channels produced anything, attempt TTL fallback
       --------------------------------------------------------- */
    if (active_channels == 0)
    {
        pipe_log(NP_PIPE_LOG_WARN, LOG_STAGE,
                 "No evidence channels produced results; attempting TTL fallback");

        const char *ttl_os = NULL;
        if (ctx->primary_open_port != 0)
        {
            int ttl = get_ttl_from_connect(ctx->target_ip,
                                           ctx->primary_open_port,
                                           2000);
            if (ttl > 0)
                ttl_os = guess_os_from_ttl(ttl);
        }

        if (ttl_os && ttl_os[0])
        {
            strncpy(ctx->final_os_name, ttl_os, NP_OS_NAME_LEN - 1);
            ctx->final_os_name[NP_OS_NAME_LEN - 1] = '\0';
            derive_os_family(ctx->final_os_name,
                             ctx->final_os_family,
                             sizeof(ctx->final_os_family));
            ctx->final_confidence = 15.0; /* low confidence for TTL-only */

            pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
                     "TTL fallback result: %s (%.1f%%)",
                     ctx->final_os_name, ctx->final_confidence);
        }
        else
        {
            strncpy(ctx->final_os_name, "Unknown", NP_OS_NAME_LEN - 1);
            strncpy(ctx->final_os_family, "Unknown", NP_OS_FAMILY_LEN - 1);
            ctx->final_confidence = 0.0;

            pipe_log(NP_PIPE_LOG_WARN, LOG_STAGE,
                     "No OS identification possible");
        }

        goto publish_result;
    }

    /* ---------------------------------------------------------
       Single-channel shortcut: if only one channel fired, use it
       directly (scaled by its weight ratio to avoid over-claiming)
       --------------------------------------------------------- */
    if (active_channels == 1)
    {
        const char *sole_os = NULL;
        double sole_conf    = 0.0;

        if (fp_os && fp_conf > 0.0)
        {
            sole_os   = fp_os;
            sole_conf = fp_conf * 0.85; /* slight penalty for single-source */
        }
        else if (banner_os && banner_conf > 0.0)
        {
            sole_os   = banner_os;
            sole_conf = banner_conf * 0.70;
        }
        else if (behav_os && behav_conf > 0.0)
        {
            sole_os   = behav_os;
            sole_conf = behav_conf * 0.60;
        }

        if (sole_os)
        {
            strncpy(ctx->final_os_name, sole_os, NP_OS_NAME_LEN - 1);
            ctx->final_os_name[NP_OS_NAME_LEN - 1] = '\0';
            derive_os_family(ctx->final_os_name,
                             ctx->final_os_family,
                             sizeof(ctx->final_os_family));
            ctx->final_confidence = clamp_confidence(sole_conf);

            pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                     "Single-channel result: %s (%.2f%%)",
                     ctx->final_os_name, ctx->final_confidence);
        }

        goto publish_result;
    }

    /* ---------------------------------------------------------
       Multi-channel weighted fusion
       --------------------------------------------------------- */
    {
        /*
         * Strategy: compute a weighted confidence for each *candidate OS*.
         * We track up to 3 candidate OS names. For each, accumulate the
         * weighted confidence from every channel that agrees with it.
         */
        typedef struct
        {
            const char *os_name;
            double      weighted_score;
            int         source_count;
            bool        from_fp;
            bool        from_banner;
            bool        from_behav;
        } fusion_candidate_t;

        fusion_candidate_t fcands[3];
        int fcand_count = 0;
        memset(fcands, 0, sizeof(fcands));

        /* Helper macro: find or insert a candidate */
        #define FIND_OR_ADD_CANDIDATE(name)                           \
            ({                                                        \
                int _idx = -1;                                        \
                for (int _i = 0; _i < fcand_count; _i++) {           \
                    if (os_names_agree(fcands[_i].os_name, (name))) { \
                        _idx = _i;                                    \
                        break;                                        \
                    }                                                 \
                }                                                     \
                if (_idx < 0 && fcand_count < 3) {                    \
                    _idx = fcand_count++;                              \
                    fcands[_idx].os_name = (name);                    \
                }                                                     \
                _idx;                                                 \
            })

        /* Accumulate fingerprint */
        if (fp_os && fp_conf > 0.0)
        {
            int idx = FIND_OR_ADD_CANDIDATE(fp_os);
            if (idx >= 0)
            {
                fcands[idx].weighted_score += fp_conf * WEIGHT_FINGERPRINT;
                fcands[idx].source_count++;
                fcands[idx].from_fp = true;
            }
        }

        /* Accumulate banner */
        if (banner_os && banner_conf > 0.0)
        {
            int idx = FIND_OR_ADD_CANDIDATE(banner_os);
            if (idx >= 0)
            {
                fcands[idx].weighted_score += banner_conf * WEIGHT_BANNER;
                fcands[idx].source_count++;
                fcands[idx].from_banner = true;
            }
        }

        /* Accumulate behavior */
        if (behav_os && behav_conf > 0.0)
        {
            int idx = FIND_OR_ADD_CANDIDATE(behav_os);
            if (idx >= 0)
            {
                fcands[idx].weighted_score += behav_conf * WEIGHT_BEHAVIOR;
                fcands[idx].source_count++;
                fcands[idx].from_behav = true;
            }
        }

        #undef FIND_OR_ADD_CANDIDATE

        /* Apply agreement bonuses */
        for (int i = 0; i < fcand_count; i++)
        {
            if (fcands[i].source_count >= 3)
            {
                fcands[i].weighted_score += TRIPLE_AGREE_BONUS;
                pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                         "  Triple agreement bonus for '%s'",
                         fcands[i].os_name);
            }
            else if (fcands[i].source_count >= 2)
            {
                fcands[i].weighted_score += AGREEMENT_BONUS;
                pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                         "  Dual agreement bonus for '%s'",
                         fcands[i].os_name);
            }
        }

        /* Select the best candidate */
        int best_idx = 0;
        for (int i = 1; i < fcand_count; i++)
        {
            if (fcands[i].weighted_score > fcands[best_idx].weighted_score)
                best_idx = i;
        }

        if (fcand_count > 0 && fcands[best_idx].os_name)
        {
            strncpy(ctx->final_os_name,
                    fcands[best_idx].os_name,
                    NP_OS_NAME_LEN - 1);
            ctx->final_os_name[NP_OS_NAME_LEN - 1] = '\0';

            derive_os_family(ctx->final_os_name,
                             ctx->final_os_family,
                             sizeof(ctx->final_os_family));

            ctx->final_confidence =
                clamp_confidence(fcands[best_idx].weighted_score);

            pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                     "  Best fusion candidate: '%s' weighted=%.2f sources=%d",
                     fcands[best_idx].os_name,
                     fcands[best_idx].weighted_score,
                     fcands[best_idx].source_count);

            /* Log runner-ups */
            for (int i = 0; i < fcand_count; i++)
            {
                if (i == best_idx)
                    continue;
                pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                         "  Runner-up: '%s' weighted=%.2f sources=%d",
                         fcands[i].os_name,
                         fcands[i].weighted_score,
                         fcands[i].source_count);
            }
        }
    }

publish_result:

    /* ---------------------------------------------------------
       Apply minimum threshold
       --------------------------------------------------------- */
    if (ctx->final_confidence < MIN_CONFIDENCE_THRESHOLD &&
        strcmp(ctx->final_os_name, "Unknown") != 0)
    {
        pipe_log(NP_PIPE_LOG_DEBUG, LOG_STAGE,
                 "Confidence %.2f%% below threshold %.1f%%, marking Unknown",
                 ctx->final_confidence, MIN_CONFIDENCE_THRESHOLD);

        strncpy(ctx->final_os_name, "Unknown", NP_OS_NAME_LEN - 1);
        strncpy(ctx->final_os_family, "Unknown", NP_OS_FAMILY_LEN - 1);
        ctx->final_confidence = 0.0;
    }

    /* ---------------------------------------------------------
       Publish into os_result
       --------------------------------------------------------- */
    char passive_os[NP_OS_NAME_LEN];
    double passive_conf = ctx->os_result.passive_confidence;
    uint32_t passive_ev = ctx->os_result.passive_evidence_count;
    bool passive_low = ctx->os_result.passive_low_confidence;
    strncpy(passive_os,
            ctx->os_result.os_guess_passive,
            sizeof(passive_os) - 1);
    passive_os[sizeof(passive_os) - 1] = '\0';

    memset(&ctx->os_result, 0, sizeof(ctx->os_result));

    strncpy(ctx->os_result.best_os,
            ctx->final_os_name,
            sizeof(ctx->os_result.best_os) - 1);

    strncpy(ctx->os_result.best_family,
            ctx->final_os_family,
            sizeof(ctx->os_result.best_family) - 1);

    ctx->os_result.best_confidence = ctx->final_confidence;
    if (passive_os[0])
    {
        strncpy(ctx->os_result.os_guess_passive,
                passive_os,
                sizeof(ctx->os_result.os_guess_passive) - 1);
        ctx->os_result.passive_confidence = passive_conf;
        ctx->os_result.passive_evidence_count = passive_ev;
        ctx->os_result.passive_low_confidence = passive_low;
    }

    /* Copy candidates if available */
    if (ctx->candidate_count > 0)
    {
        int n = ctx->candidate_count;
        if (n > NP_MAX_CANDIDATES)
            n = NP_MAX_CANDIDATES;
        memcpy(ctx->os_result.candidates,
               ctx->candidates,
               (size_t)n * sizeof(np_os_match_t));
        ctx->os_result.candidate_count = n;
    }

    /* Preserve port discovery results */
    ctx->os_result.open_port_count = (int)ctx->open_port_count;
    ctx->os_result.port_used = ctx->primary_open_port;
    for (uint32_t i = 0; i < ctx->open_port_count && i < NP_OS_MAX_OPEN_PORTS; i++)
        ctx->os_result.open_ports[i] = ctx->open_ports[i];
    ctx->os_result.probe_count = ctx->probe_response_count;
    ctx->os_result.probes_answered = ctx->probe_response_count;

    pipe_log(NP_PIPE_LOG_INFO, LOG_STAGE,
             "Fusion complete: OS='%s' Family='%s' Confidence=%.2f%%",
             ctx->os_result.best_os,
             ctx->os_result.best_family,
             ctx->os_result.best_confidence);

    return 0;
}
