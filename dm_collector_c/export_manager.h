#ifndef __DM_COLLECTOR_C_EXPORT_MANAGER_H__
#define __DM_COLLECTOR_C_EXPORT_MANAGER_H__

#include "utils.h"

#include <set>
#include <string>
#include <cstdio>

// Manage the output of logs.
struct ExportManagerState {
    FILE *log_fp;   // Point to the current log.
    std::string filename;
    std::set<int> whitelist;
    double start_timestamp;
    double end_timestamp;
    std::string log_object;
};

// Must be called before usage
void manager_init_state (struct ExportManagerState *pstate);
void manager_change_config (struct ExportManagerState *pstate,
                            const char *new_path, const IdVector &whitelist);
void manager_set_filter(ExportManagerState *pstate, const IdVector &whitelist, double start_timestamp, double end_timestamp);
// Export raw msgs that are in the whitelist
bool manager_export_binary (struct ExportManagerState *pstate, const char *b, size_t length);

#endif // __DM_COLLECTOR_C_EXPORT_MANAGER_H__
