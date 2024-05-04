/* log_config.cpp
 * Author: Jiayao Li
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "consts.h"
#include "log_config.h"

#include <algorithm>

int
get_equip_id (int type_id) {
    const int EQUIP_ID_MASK = 0x0000F000;
    return (type_id & EQUIP_ID_MASK) >> 12;
}

int
get_item_id (int type_id) {
    const int ITEM_ID_MASK  = 0x00000FFF;
    return type_id & ITEM_ID_MASK;
}

// Note that all type IDs should have the same equip ID.
BinaryBuffer
encode_log_config (LogConfigOp op, const std::vector<int>& type_ids) {
    BinaryBuffer buf;
    buf.first = NULL;
    buf.second = 0;
    switch (op) {
    case DISABLE:
        buf.second = sizeof(char) * 4 + sizeof(int);
        buf.first = new char[buf.second];
        buf.first[0] = 115;
        buf.first[1] = 0;
        buf.first[2] = 0;
        buf.first[3] = 0;
        *((int *)(buf.first + 4)) = (int) op;
        break;

    case DIAG_BEGIN_1D:
        buf.second = sizeof(char);
        buf.first = new char[buf.second];
        buf.first[0] = 0x1D;
        break;

    case DIAG_BEGIN_00:
        buf.second = sizeof(char);
        buf.first = new char[buf.second];
        buf.first[0] = 0x00;
        break;

    case DIAG_BEGIN_7C:
        buf.second = sizeof(char);
        buf.first = new char[buf.second];
        buf.first[0] = 0x7C;
        break;

    case DIAG_BEGIN_1C:
        buf.second = sizeof(char);
        buf.first = new char[buf.second];
        buf.first[0] = 0x1C;
        break;

    case DIAG_BEGIN_0C:
        buf.second = sizeof(char);
        buf.first = new char[buf.second];
        buf.first[0] = 0x0C;
        break;

    case DIAG_BEGIN_63:
        buf.second = sizeof(char);
        buf.first = new char[buf.second];
        buf.first[0] = 0x63;
        break;

    case DIAG_BEGIN_4B0F0000:
        buf.second = sizeof(char) * 4;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x00000F4B;
        break;

    case DIAG_BEGIN_4B090000:
        buf.second = sizeof(char) * 4;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x0000094B;
        break;

    case DIAG_BEGIN_4B080000:
        buf.second = sizeof(char) * 4;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x0000084B;
        break;

    case DIAG_BEGIN_4B080100:
        buf.second = sizeof(char) * 4;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x0001084B;
        break;

    case DIAG_BEGIN_4B040000:
        buf.second = sizeof(char) * 4;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x0000044B;
        break;

    case DIAG_BEGIN_4B040F00:
        buf.second = sizeof(char) * 4;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x000F044B;
        break;

    case DIAG_END_6000:
        buf.second = sizeof(char) * 2;
        buf.first = new char[buf.second];
        *((int *)(buf.first)) = 0x0060;
        break;


    case SET_MASK:
        {
            int equip_id = -1;
            int highest = -1;
            for (size_t i = 0; i < type_ids.size(); i++) {
                int id = type_ids[i];
                // Haotian: the highest value calculated here may not be proper
                int e = get_equip_id(id);
                if (equip_id == -1) {
                    equip_id = e;
                    highest = std::max(highest, get_item_id(id));
                } else if (equip_id == e) {
                    highest = std::max(highest, get_item_id(id));
                } else {
                    equip_id = -1;
                    break;
                }
            }
            // TODO: Simplify the following code. *highest* indicates the highest item IDs' mask. Setting it to FFF should be able to support all messages
            switch (equip_id) {
                case 0x00000001:    // CDMA, _1xEV, ......
                    highest = 0x00000FD3;
                    break;
                case 0x00000004:    // WCDMA, ......
                    highest = 0x00000920;
                    break;
                case 0x00000007:    // UMTS, ......
                    highest = 0x00000B56;
                    break;
                case 0x0000000b:    // LTE, ......
                    // highest = 0x000001C4;
                    highest = 0x00000FFF;
                    break;
                default:
                    break;
            }
            if (equip_id == -1) {
                ;   // fail to extract an unique equid id
            } else {
                int mask_len = (highest / 8) + 1;
                buf.second = sizeof(char) * 4 + sizeof(int) * 3 + mask_len;
                buf.first = new char[buf.second];
                buf.first[0] = 115; // 0x73
                buf.first[1] = 0;
                buf.first[2] = 0;
                buf.first[3] = 0;
                *((int *)(buf.first + 4)) = (int) op;
                *((int *)(buf.first + 8)) = equip_id;
                *((int *)(buf.first + 12)) = highest + 1;
                char *mask = buf.first + 16;
                for (int i = 0; i < mask_len; i++)
                    mask[i] = 0;
                for (size_t i = 0; i < type_ids.size(); i++) {
                    int id = type_ids[i];
                    int x = get_item_id(id);
                    mask[x / 8] |= 1 << (x % 8);
                }

            }
            break;
        }

    case DEBUG_WCDMA_L1:
        //Yuanjie: enable debugging messages (currently for iCellular only)
        buf.second = 12;
        buf.first = new char[buf.second];
        //Enable WCDMA L1 debug message (for RSCP)
        buf.first[0] = 0x7d;
        buf.first[1] = 0x04;
        buf.first[2] = 0xb9;
        buf.first[3] = 0x0b;
        buf.first[4] = 0xb9;
        buf.first[5] = 0x0b;
        buf.first[6] = 0x00;
        buf.first[7] = 0x00;
        buf.first[8] = 0x04;
        buf.first[9] = 0x00;
        buf.first[10] = 0x00;
        buf.first[11] = 0x00;
        break;

    case DEBUG_LTE_ML1:
        //Yuanjie: enable debugging messages (currently for iCellular only)
        buf.second = 12;
        buf.first = new char[buf.second];
        //Enable LTE ML1 debug message (for RSRP)
        buf.first[0] = 0x7d;
        buf.first[1] = 0x04;
        buf.first[2] = 0x25;
        buf.first[3] = 0x25;
        buf.first[4] = 0x25;
        buf.first[5] = 0x25;
        buf.first[6] = 0x00;
        buf.first[7] = 0x00;
        buf.first[8] = 0x04;
        buf.first[9] = 0x00;
        buf.first[10] = 0x00;
        buf.first[11] = 0x00;

        break;

    case DISABLE_DEBUG:
        buf.second = 8;
        buf.first = new char[buf.second];
        buf.first[0] = 0x7D;
        buf.first[1] = 0x05;
        buf.first[2] = 0x00;
        buf.first[3] = 0x00;
        buf.first[4] = 0x00;
        buf.first[5] = 0x00;
        buf.first[6] = 0x00;
        buf.first[7] = 0x00;
        break;

    case GET_RANGE:
    case GET_MASK:
        // not implemented
        // fall through
    default:
        break;
    }
    return buf;
}
