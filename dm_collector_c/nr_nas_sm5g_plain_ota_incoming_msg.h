#include "consts.h"
#include "log_packet.h"
#include "log_packet_helper.h"

const Fmt NrNasSm5gPlainOtaMsgFmt[] = {
    {UINT,"Version",           4},
    
};
const Fmt NrNasSm5gPlainOtaMsgFmt_v1[] = {
    {UINT,"Rel_number",        1},
    {UINT,"rel_version_major", 1},
    {UINT,"rel_version_minor", 1},
};
static int
_decode_nr_nas_sm5g_plain_ota_msg(const char* b, int offset, size_t length,
    PyObject* result) {
    int start = offset;
    int pkt_ver = _search_result_int(result, "Version");
    switch (pkt_ver) {
    case 1:
        offset += _decode_by_fmt(NrNasSm5gPlainOtaMsgFmt_v1,
            ARRAY_SIZE(NrNasSm5gPlainOtaMsgFmt_v1, Fmt),
            b, offset, length, result);
        break;
    default:
        printf("(MI)Unknown NR NAS SM5G Plain OTA  version: 0x%x\n", pkt_ver);
        return 0;
    }

    size_t pdu_length = length - offset;
    PyObject* t = Py_BuildValue("(sy#s)",
        "Msg", b + offset, (Py_ssize_t)pdu_length,
        "raw_msg/nas-5gs");
    PyList_Append(result, t);
    Py_DECREF(t);
    return length - start;
}
