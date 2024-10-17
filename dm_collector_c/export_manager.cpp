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
#include <cfloat>
#include <cstring>
#include <iostream>

const double PER_SECOND = 52428800.0;
const double PER_USECOND = 52428800.0 / 1.0e6;
const time_t BASE_TIMESTAMP = 315964800; // Param for parsing raw timestamp into UNIX timestamp

uint64_t
get_timestamp(const char *b, size_t offset) {
    uint64_t timestamp = 0;
    std::memcpy(&timestamp, b + offset, sizeof(uint64_t));
    return timestamp;
}

double
convert_to_unix(uint64_t packet_timestamp) {
    int seconds = int(double(packet_timestamp) / PER_SECOND);
    int useconds = (double(packet_timestamp) / PER_USECOND) - double(seconds) * 1.0e6;
    return BASE_TIMESTAMP + seconds + useconds / 1.0e6;
}

// A simple but dirty function to retrieve type ID and timestamp.
// Return -1 if the packet is not recognized
static int
get_log_type_and_timestamp(const char *b, size_t length, double &packet_timestamp) {
    int type_id = -1;
    unsigned long int timestamp = 0;
    if (is_log_packet(b, length) && length >= 8) {
        // 8 = 2 (0x1000) + 2 (len1) + 2 (log_msg_len) + 2 (type_id)
        short t = *((unsigned short *)(b + 6));
        type_id = ((int) t) & 0xFFFF;

        timestamp = get_timestamp(b, 8);
        packet_timestamp = convert_to_unix(timestamp);

    } else if (is_debug_packet(b, length)) {
        type_id = Modem_debug_message;
        timestamp = get_timestamp(b, 8);
        packet_timestamp = convert_to_unix(timestamp);
    }
    return type_id;
}

void
manager_init_state (struct ExportManagerState *pstate) {
    pstate->log_fp = NULL;
    pstate->filename = "";
    pstate->whitelist.clear();
    pstate->start_timestamp = 0.0;
    pstate->end_timestamp = DBL_MAX;
    pstate->log_object = "";
    return;
}

bool
manager_export_binary (struct ExportManagerState *pstate, const char *b, size_t length) {

    double packet_timestamp = 0.0;
    int type_id = get_log_type_and_timestamp(b, length, packet_timestamp);

    if (pstate->whitelist.count(type_id) > 0 && 
        packet_timestamp >= pstate->start_timestamp &&
        packet_timestamp <= pstate->end_timestamp) { // filter 

        std::string frame = encode_hdlc_frame(b, (int) length);
        pstate->log_object = frame;
        if (pstate->log_fp != NULL) {
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

void 
manager_set_filter(ExportManagerState *pstate, const IdVector &whitelist, double start_timestamp, double end_timestamp) {
    pstate->whitelist.clear();
    pstate->whitelist.insert(whitelist.begin(), whitelist.end());
    pstate->start_timestamp = start_timestamp;
    pstate->end_timestamp = end_timestamp;
}
