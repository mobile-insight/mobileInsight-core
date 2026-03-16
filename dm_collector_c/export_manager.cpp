/* export_manager.cpp
 * Author: Jiayao Li
 * The ExportManagerState struct imitates LogManagerState in
 * diag_revealer.c . Since they are similar in functionality, hopefully
 * we can merge them in the future.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "consts.h"
#include "export_manager.h"
#include "hdlc.h"
#include "log_packet.h"
#include "log_packet_helper.h"

// A simple but dirty function to retrieve type ID.
// Return -1 if the packet is not recognized
static int
get_log_type(const char *b, size_t length) {
    int type_id = -1;
    if (is_log_packet(b, length) && length >= 8) {
        // 8 = 2 (0x1000) + 2 (len1) + 2 (log_msg_len) + 2 (type_id)
        short t = *((unsigned short *)(b + 6));
        type_id = ((int) t) & 0xFFFF;
    } else if (is_debug_packet(b, length)) {
        type_id = Modem_debug_message;
    }
    return type_id;
}

void
manager_init_state (struct ExportManagerState *pstate) {
    pstate->log_fp = NULL;
    pstate->filename = "";
    pstate->whitelist.clear();
    return;
}

bool
manager_export_binary (struct ExportManagerState *pstate, const char *b, size_t length) {

    int type_id = get_log_type(b, length);
    if (pstate->whitelist.count(type_id) > 0) { // filter

        if (pstate->log_fp != NULL) {
            std::string frame = encode_hdlc_frame(b, (int) length);
            size_t cnt = fwrite(frame.c_str(), sizeof(char), frame.size(), pstate->log_fp);
            (void)cnt;
        }
        return true;
    }
    else
        return false;
}

void
manager_change_config (struct ExportManagerState *pstate,
                        const char *new_path, const IdVector &whitelist) {
    if (pstate->log_fp != NULL && new_path != NULL && pstate->filename != new_path) {   // close old file
        fclose(pstate->log_fp);
        pstate->log_fp = NULL;
        pstate->filename = "";
    }
    if (pstate->log_fp == NULL && new_path != NULL) {   // open new file if necessary
        pstate->log_fp = fopen(new_path, "wb");
        pstate->filename = new_path;
    }
    pstate->whitelist.clear();
    pstate->whitelist.insert(whitelist.begin(), whitelist.end());
}
