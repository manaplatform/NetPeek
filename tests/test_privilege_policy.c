#include "test.h"
#include "netpeek.h"
#include "cli_privilege.h"

static np_config_t *cfg_new(void)
{
    return np_config_create();
}

NP_TEST(scan_requires_root_default_connect_false)
{
    np_config_t *cfg = cfg_new();
    ASSERT_TRUE(!np_cli_scan_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(scan_requires_root_syn_true)
{
    np_config_t *cfg = cfg_new();
    cfg->scan_type = NP_SCAN_TCP_SYN;
    ASSERT_TRUE(np_cli_scan_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(scan_requires_root_scanflags_true)
{
    np_config_t *cfg = cfg_new();
    cfg->scan_type = NP_SCAN_TCP_CUSTOM_FLAGS;
    ASSERT_TRUE(np_cli_scan_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(scan_requires_root_explicit_flag_true)
{
    np_config_t *cfg = cfg_new();
    cfg->require_root = true;
    ASSERT_TRUE(np_cli_scan_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(scan_requires_root_os_detect_true)
{
    np_config_t *cfg = cfg_new();
    cfg->os_detect = true;
    ASSERT_TRUE(np_cli_scan_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(scan_requires_root_raw_discovery_true)
{
    np_config_t *cfg = cfg_new();
    cfg->probe_icmp_echo = true;
    ASSERT_TRUE(np_cli_scan_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(recon_requires_root_when_scan_type_not_forced)
{
    /* Default recon auto-selects raw SYN, which silently yields an empty
     * report without root, so recon must be guarded. */
    np_config_t *cfg = cfg_new();
    cfg->scan_type_forced = false;
    ASSERT_TRUE(np_cli_recon_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(recon_requires_root_false_for_forced_connect)
{
    np_config_t *cfg = cfg_new();
    cfg->scan_type = NP_SCAN_TCP_CONNECT;
    cfg->scan_type_forced = true;
    ASSERT_TRUE(!np_cli_recon_requires_root(cfg));
    np_config_destroy(cfg);
}

NP_TEST(recon_requires_root_true_for_forced_syn)
{
    np_config_t *cfg = cfg_new();
    cfg->scan_type = NP_SCAN_TCP_SYN;
    cfg->scan_type_forced = true;
    ASSERT_TRUE(np_cli_recon_requires_root(cfg));
    np_config_destroy(cfg);
}

void register_privilege_policy_tests(void)
{
    NP_REGISTER(scan_requires_root_default_connect_false);
    NP_REGISTER(scan_requires_root_syn_true);
    NP_REGISTER(scan_requires_root_scanflags_true);
    NP_REGISTER(scan_requires_root_explicit_flag_true);
    NP_REGISTER(scan_requires_root_os_detect_true);
    NP_REGISTER(scan_requires_root_raw_discovery_true);
    NP_REGISTER(recon_requires_root_when_scan_type_not_forced);
    NP_REGISTER(recon_requires_root_false_for_forced_connect);
    NP_REGISTER(recon_requires_root_true_for_forced_syn);
}
