#include <unistd.h>

#include "cli_privilege.h"
#include "core/error.h"

static bool scan_type_requires_raw(np_scan_type_t scan_type)
{
    switch (scan_type)
    {
    case NP_SCAN_TCP_SYN:
    case NP_SCAN_TCP_ACK:
    case NP_SCAN_TCP_WINDOW:
    case NP_SCAN_TCP_MAIMON:
    case NP_SCAN_TCP_NULL:
    case NP_SCAN_TCP_FIN:
    case NP_SCAN_TCP_XMAS:
    case NP_SCAN_TCP_CUSTOM_FLAGS:
    case NP_SCAN_IDLE:
    case NP_SCAN_SCTP_INIT:
    case NP_SCAN_SCTP_COOKIE_ECHO:
    case NP_SCAN_IP_PROTOCOL:
    case NP_SCAN_UDP:
        return true;
    default:
        return false;
    }
}

bool np_cli_is_effective_root(void)
{
    return geteuid() == 0;
}

bool np_cli_scan_requires_root(const np_config_t *cfg)
{
    if (!cfg)
        return false;

    bool raw_discovery = cfg->probe_icmp_echo || cfg->probe_icmp_timestamp ||
                         cfg->probe_icmp_netmask || cfg->probe_sctp_init ||
                         cfg->probe_ip_proto;

    return cfg->require_root || scan_type_requires_raw(cfg->scan_type) ||
           raw_discovery || cfg->os_detect;
}

/*
 * Recon pipelines run through the staged pipeline, where the scan engine
 * auto-selects a raw SYN scan whenever no scan type has been forced. That
 * requires root; without it the engine silently yields an empty report
 * ("Coverage: 0/0 services identified"). An explicitly forced scan type
 * (for example --connect/-sT) is honoured as-is so unprivileged connect
 * recon keeps working.
 */
bool np_cli_recon_requires_root(const np_config_t *cfg)
{
    if (!cfg)
        return false;

    if (np_cli_scan_requires_root(cfg))
        return true;

    return !cfg->scan_type_forced;
}

bool np_cli_require_root(const char *operation, const char *hint)
{
    if (np_cli_is_effective_root())
        return true;

    np_error(NP_ERR_OS, "[!] This command or flag requires root privilege\n");

    if (operation && operation[0])
        np_error(NP_ERR_OS, "[!] Blocked operation: %s\n", operation);

    if (hint && hint[0])
        np_error(NP_ERR_OS, "[!] %s\n", hint);
    else
        np_error(NP_ERR_OS, "[!] Run with sudo\n");

    return false;
}
