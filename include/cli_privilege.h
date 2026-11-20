#ifndef NP_CLI_PRIVILEGE_H
#define NP_CLI_PRIVILEGE_H

#include <stdbool.h>
#include "netpeek.h"

bool np_cli_is_effective_root(void);
bool np_cli_scan_requires_root(const np_config_t *cfg);
bool np_cli_recon_requires_root(const np_config_t *cfg);
bool np_cli_require_root(const char *operation, const char *hint);

#endif /* NP_CLI_PRIVILEGE_H */
