/* dm_collector_c.cpp
 * Author: Jiayao Li
 * Modified: Yunqi Guo, 2019-11-02 for python3 usage
 * This file defines dm_collector_c, a Python extension module that collects
 * and decodes diagnositic logs from Qualcomm chipsets.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "consts.h"
#include "hdlc.h"
#include "log_config.h"
#include "log_packet.h"
#include "export_manager.h"

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>

#ifdef __ANDROID__
#include <android/log.h>
#define printf(fmt,args...) __android_log_print(ANDROID_LOG_INFO, "python [dm_collector_c]", fmt, ##args);
#endif

#ifndef _WIN32

#include <sys/time.h>

#endif

// NOTE: the following number should be updated every time.
#define DM_COLLECTOR_C_VERSION "1.0.12"

// Global variable to control exportation of raw log
static ExportManagerState g_emanager;

static PyObject *dm_collector_c_disable_logs(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_enable_logs(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_set_filtered_export(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_set_filtered(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_generate_diag_cfg(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_feed_binary(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_reset(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_receive_log_packet(PyObject *self, PyObject *args);

static PyObject *dm_collector_c_set_sampling_rate(PyObject *self, PyObject *args);

static PyMethodDef DmCollectorCMethods[] = {
        {"disable_logs",        dm_collector_c_disable_logs,        METH_VARARGS,
                                                                       "Disable logs for a serial port.\n"
                                                                       "\n"
                                                                       "Args:\n"
                                                                       "    port: a diagnositic serial port.\n"
                                                                       "\n"
                                                                       "Returns:\n"
                                                                       "    Successful or not.\n"
        },
        {"enable_logs",         dm_collector_c_enable_logs,         METH_VARARGS,
                                                                       "Enable logs for a serial port.\n"
                                                                       "\n"
                                                                       "Args:\n"
                                                                       "    port: a diagnositic serial port.\n"
                                                                       "    type_names: a sequence of type names.\n"
                                                                       "\n"
                                                                       "Returns:\n"
                                                                       "    Successful or not.\n"
                                                                       "\n"
                                                                       "Raises\n"
                                                                       "    ValueError: when an unrecognized type name is passed in.\n"
        },
	{"set_sampling_rate",   dm_collector_c_set_sampling_rate,   METH_VARARGS,
		                                                       "Enable target ratio for cross-layer sampling.\n"
								       "Args:\n"
                                                                       "    sampling_rate: the target sampling rate.\n"
								       "    type_names: integer between 0 and 100.\n"
                                                                       "\n"
                                                                       "Returns:\n"
                                                                       "    Successful or not.\n"
                                                                       "\n"
                                                                       "Raises\n"
                                                                       "    ValueError: when an unrecognized sampling rate is passed in.\n"
	},
        {"set_filtered_export", dm_collector_c_set_filtered_export, METH_VARARGS,
                                                                       "Configure this moduel to output a filtered log file.\n"
                                                                       "\n"
                                                                       "Args:\n"
                                                                       "    type_names: a sequence of type names.\n"
                                                                       "\n"
                                                                       "Returns:\n"
                                                                       "    Successful or not.\n"
                                                                       "\n"
                                                                       "Raises\n"
                                                                       "    ValueError: when an unrecognized type name is passed in.\n"
        },
        {"set_filtered",        dm_collector_c_set_filtered,        METH_VARARGS,
                                                                       "Configure this moduel to only decode filtered logs.\n"
                                                                       "\n"
                                                                       "Args:\n"
                                                                       "    type_names: a sequence of type names.\n"
                                                                       "\n"
                                                                       "Returns:\n"
                                                                       "    Successful or not.\n"
                                                                       "\n"
                                                                       "Raises\n"
                                                                       "    ValueError: when an unrecognized type name is passed in.\n"
        },
        {"feed_binary",         dm_collector_c_feed_binary,         METH_VARARGS,
                                                                       "Feed raw packets."},
        {"reset",               dm_collector_c_reset,               METH_VARARGS,
                                                                       "Reset dm_collector."},
        {"generate_diag_cfg",   dm_collector_c_generate_diag_cfg,   METH_VARARGS,
                                                                       "Generate a Diag.cfg file.\n"
                                                                       "\n"
                                                                       "This file can be loaded by diag_mdlog program on Android phones. It\n"
                                                                       "disables all previous log messages, then enables logs specified in\n"
                                                                       "type_names.\n"
                                                                       "\n"
                                                                       "Args:\n"
                                                                       "    file: output Python file object\n"
                                                                       "    type_names: the type of logs you wish to enable.\n"
        },
        {"receive_log_packet",  dm_collector_c_receive_log_packet,  METH_VARARGS,
                                                                       "Extract a log packet from feeded data.\n"
                                                                       "\n"
                                                                       "Args:\n"
                                                                       "    skip_decoding: If set to True, only the header would be decoded.\n"
                                                                       "        Default to False.\n"
                                                                       "    include_timestamp: Return the time when the message is received.\n"
                                                                       "        Default to False.\n"
                                                                       "\n"
                                                                       "Returns:\n"
                                                                       "    If include_timestamp is True, return (decoded, posix_timestamp);\n"
                                                                       "    otherwise only return decoded message.\n"
        },
        {NULL,                  NULL,                               0, NULL}        /* Sentinel */
};

// sort, unique and bucketing
static void
sort_type_ids(IdVector &type_ids, std::vector <IdVector> &out_vectors) {
    sort(type_ids.begin(), type_ids.end());
    IdVector::iterator itr = std::unique(type_ids.begin(), type_ids.end());
    type_ids.resize(std::distance(type_ids.begin(), itr));

    out_vectors.clear();
    int last_equip_id = -1;
    size_t i = 0, j = 0;
    for (j = 0; j < type_ids.size(); j++) {
        if (j != 0 && last_equip_id != get_equip_id(type_ids[j])) {
            out_vectors.push_back(IdVector(type_ids.begin() + i,
                                           type_ids.begin() + j));
            i = j;
        }
        last_equip_id = get_equip_id(type_ids[j]);
    }
    if (i != j) {
        out_vectors.push_back(IdVector(type_ids.begin() + i,
                                       type_ids.begin() + j));
    }
    return;
}

static bool
check_file(PyObject *o) {
    return PyObject_HasAttrString(o, "write");
}

// FIXME: currently it is the same with check_file(), but it should be stricter
static bool
check_serial_port(PyObject *o) {
    return PyObject_HasAttrString(o, "read");
}

static bool
send_msg(PyObject *serial_port, const char *b, int length) {
    std::string frame = encode_hdlc_frame(b, length);
    PyObject *o = PyObject_CallMethod(serial_port,
                                      (char *) "write",
                                      (char *) "y#", frame.c_str(), frame.size());
    Py_DECREF(o);
    return true;
}

#ifndef _WIN32

static double
get_posix_timestamp() {
    struct timeval tv;
    (void) gettimeofday(&tv, NULL);
    return (double) (tv.tv_sec) + (double) (tv.tv_usec) / 1.0e6;
}

#else
static double
get_posix_timestamp () {
    return 0;
}
#endif

// Return: successful or not
static PyObject *
dm_collector_c_disable_logs(PyObject *self, PyObject *args) {
    (void) self;
    IdVector empty;
    BinaryBuffer buf;
    PyObject *serial_port = NULL;
    if (!PyArg_ParseTuple(args, "O", &serial_port)) {
        return NULL;
    }
    Py_INCREF(serial_port);

    // Check arguments
    if (!check_serial_port(serial_port)) {
        PyErr_SetString(PyExc_TypeError, "\'port\' is not a serial port.");
        goto raise_exception;
    }

    buf = encode_log_config(DISABLE, empty);
    if (buf.first == NULL || buf.second == 0) {
        Py_DECREF(serial_port);
        Py_RETURN_FALSE;
    }
    (void) send_msg(serial_port, buf.first, buf.second);
    Py_DECREF(serial_port);
    delete[] buf.first;
    Py_RETURN_TRUE;

    raise_exception:
    Py_DECREF(serial_port);
    return NULL;
}

// Converts type names to a vector of IDs.
// Returns true if all string are successfully converted, or false if wrong name
// is found.
static bool
map_typenames_to_ids(PyObject *type_names, IdVector &type_ids) {
    Py_ssize_t n = PySequence_Length(type_names);

    bool name_error = false;
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PySequence_GetItem(type_names, i);
        if (!PyUnicode_Check(item)) {
            // ignore non-strings
        } else {
            const char *name = PyUnicode_AsUTF8(item);
            int cnt = find_ids(LogPacketTypeID_To_Name,
                               ARRAY_SIZE(LogPacketTypeID_To_Name, ValueName),
                               name, type_ids);
            if (cnt == 0) {
                name_error = true;
            }
        }
        if (item != NULL) {
            Py_DECREF(item);    // Discard reference ownership
        }
        if (name_error) {
            break;
        }
    }
    return !name_error;
}

// A helper function that generated binary code to enable the specified types
// of messages.
// If error occurs, false is returned and PyErr_SetString() will be called.
static bool
generate_log_config_msgs(PyObject *file_or_serial, PyObject *type_names) {

    IdVector type_ids;
    bool success = map_typenames_to_ids(type_names, type_ids);
    if (!success) {
        PyErr_SetString(PyExc_ValueError, "Wrong type name.");
        return false;
    }

    BinaryBuffer buf;
    // Yuanjie: check if Modem_debug_message exists. If so, enable it in slightly different way
    IdVector::iterator debug_ind = type_ids.begin();
    for (; debug_ind != type_ids.end(); debug_ind++) {
        if (*debug_ind == Modem_debug_message) {
            break;
        }
    }
    if (debug_ind != type_ids.end()) {
        //Modem_debug_message should be enabled
        type_ids.erase(debug_ind);

        // Enable LTE ML1 debug
        // buf = encode_log_config(DEBUG_LTE_ML1, type_ids);
        // if (buf.first != NULL && buf.second != 0) {
        //     (void) send_msg(file_or_serial, buf.first, buf.second);
        //     delete [] buf.first;
        // } else {
        //     PyErr_SetString(PyExc_RuntimeError, "Log config msg failed to encode.");
        //     return false;
        // }

        // Enable WCDMA debug
        buf = encode_log_config(DEBUG_WCDMA_L1, type_ids);
        if (buf.first != NULL && buf.second != 0) {
            (void) send_msg(file_or_serial, buf.first, buf.second);
            delete[] buf.first;
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Log config msg failed to encode.");
            return false;
        }

    }

    // send log config messages
    std::vector <IdVector> type_id_vectors;
    sort_type_ids(type_ids, type_id_vectors);
    for (size_t i = 0; i < type_id_vectors.size(); i++) {
        const IdVector &v = type_id_vectors[i];
        buf = encode_log_config(SET_MASK, v);
        if (buf.first != NULL && buf.second != 0) {
            (void) send_msg(file_or_serial, buf.first, buf.second);
            delete[] buf.first;
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Log config msg failed to encode.");
            return false;
        }
    }

    return true;
}

// A helper function that generated binary code of config headers.
// If error occurs, false is returned and PyErr_SetString() will be called.
static bool
generate_log_config_headers(PyObject *file_or_serial, PyObject *type_names) {
    (void) type_names;
    BinaryBuffer buf;
    IdVector empty;
    for (int k = 0; k < 12; k++) {
        switch (k) {
            case 0:
                buf = encode_log_config(DIAG_BEGIN_1D, empty);
                break;
            case 1:
                buf = encode_log_config(DIAG_BEGIN_00, empty);
                break;
            case 2:
                buf = encode_log_config(DIAG_BEGIN_7C, empty);
                break;
            case 3:
                buf = encode_log_config(DIAG_BEGIN_1C, empty);
                break;
            case 4:
                buf = encode_log_config(DIAG_BEGIN_0C, empty);
                break;
            case 5:
                buf = encode_log_config(DIAG_BEGIN_63, empty);
                break;
            case 6:
                buf = encode_log_config(DIAG_BEGIN_4B0F0000, empty);
                break;
            case 7:
                buf = encode_log_config(DIAG_BEGIN_4B090000, empty);
                break;
            case 8:
                buf = encode_log_config(DIAG_BEGIN_4B080000, empty);
                break;
            case 9:
                buf = encode_log_config(DIAG_BEGIN_4B080100, empty);
                break;
            case 10:
                buf = encode_log_config(DIAG_BEGIN_4B040000, empty);
                break;
            case 11:
                buf = encode_log_config(DIAG_BEGIN_4B040F00, empty);
                break;
            default:
                break;
        }
        if (buf.first != NULL && buf.second != 0) {
            (void) send_msg(file_or_serial, buf.first, buf.second);
            delete[] buf.first;
            buf.first = NULL;
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Log config msg failed to encode.");
            return false;
        }
    }
    return true;
}

// A helper function that generated binary code of config ends.
// If error occurs, false is returned and PyErr_SetString() will be called.
static bool
generate_log_config_ends(PyObject *file_or_serial, PyObject *type_names) {
    (void) type_names;
    BinaryBuffer buf;
    IdVector empty;
    buf = encode_log_config(DIAG_END_6000, empty);
    if (buf.first != NULL && buf.second != 0) {
        (void) send_msg(file_or_serial, buf.first, buf.second);
        delete[] buf.first;
        buf.first = NULL;
    } else {
        PyErr_SetString(PyExc_RuntimeError, "Log config msg failed to encode.");
        return false;
    }
    return true;
}

// Return: successful or not
static PyObject *
dm_collector_c_set_sampling_rate(PyObject *self, PyObject *args) {
    (void) self;  
    int c_sampling_rate;
    bool success = false;

    if (!PyArg_ParseTuple(args, "i", &c_sampling_rate)) {
	    return NULL;
    }

    if(c_sampling_rate < 0 || c_sampling_rate > 100){
        PyErr_SetString(PyExc_RuntimeError, "The sampling rate must be between 0 and 100.");
        return NULL;
    }

    success = set_target_sampling_rate(c_sampling_rate);
    if (!success) {
        goto raise_exception;
    }
    Py_RETURN_TRUE;

    raise_exception:
    return NULL;


}


// Return: successful or not
static PyObject *
dm_collector_c_enable_logs(PyObject *self, PyObject *args) {
    (void) self;
    PyObject *serial_port = NULL;
    PyObject *sequence = NULL;
    bool success = false;

    if (!PyArg_ParseTuple(args, "OO", &serial_port, &sequence)) {
        return NULL;
    }
    Py_INCREF(serial_port);
    Py_INCREF(sequence);

    // Check arguments
    if (!check_serial_port(serial_port)) {
        PyErr_SetString(PyExc_TypeError, "\'port\' is not a serial port.");
        goto raise_exception;
    }
    if (!PySequence_Check(sequence)) {
        PyErr_SetString(PyExc_TypeError, "\'type_names\' is not a sequence.");
        goto raise_exception;
    }

    success = generate_log_config_msgs(serial_port, sequence);
    if (!success) {
        goto raise_exception;
    }
    Py_DECREF(sequence);
    Py_DECREF(serial_port);
    Py_RETURN_TRUE;

    raise_exception:
    Py_DECREF(sequence);
    Py_DECREF(serial_port);
    return NULL;
}

// Return: successful or not
static PyObject *
dm_collector_c_set_filtered_export(PyObject *self, PyObject *args) {
    (void) self;
    const char *path;
    PyObject *sequence = NULL;
    IdVector type_ids;
    bool success = false;

    if (!PyArg_ParseTuple(args, "sO", &path, &sequence)) {
        return NULL;
    }
    Py_INCREF(sequence);

    // Check arguments
    if (!PySequence_Check(sequence)) {
        PyErr_SetString(PyExc_TypeError, "\'type_names\' is not a sequence.");
        goto raise_exception;
    }

    success = map_typenames_to_ids(sequence, type_ids);
    if (!success) {
        PyErr_SetString(PyExc_ValueError, "Wrong type name.");
        goto raise_exception;
    }
    Py_DECREF(sequence);

    manager_change_config(&g_emanager, path, type_ids);
    Py_RETURN_TRUE;

    raise_exception:
    Py_DECREF(sequence);
    return NULL;
}

// Return: successful or not
static PyObject *
dm_collector_c_set_filtered(PyObject *self, PyObject *args) {
    (void) self;
    PyObject *sequence = NULL;
    IdVector type_ids;
    bool success = false;

    if (!PyArg_ParseTuple(args, "O", &sequence)) {
        return NULL;
    }
    Py_INCREF(sequence);

    // Check arguments
    if (!PySequence_Check(sequence)) {
        PyErr_SetString(PyExc_TypeError, "\'type_names\' is not a sequence.");
        goto raise_exception;
    }

    success = map_typenames_to_ids(sequence, type_ids);
    if (!success) {
        PyErr_SetString(PyExc_ValueError, "Wrong type name.");
        goto raise_exception;
    }
    Py_DECREF(sequence);

    manager_change_config(&g_emanager, NULL, type_ids);
    Py_RETURN_TRUE;

    raise_exception:
    Py_DECREF(sequence);
    return NULL;
}

// Return: successful or not
static PyObject *
dm_collector_c_generate_diag_cfg(PyObject *self, PyObject *args) {
    (void) self;
    PyObject *file = NULL;
    PyObject *sequence = NULL;
    bool success = false;
    BinaryBuffer buf;
    IdVector empty;

    if (!PyArg_ParseTuple(args, "OO", &file, &sequence)) {
        return NULL;
    }
    Py_INCREF(file);
    Py_INCREF(sequence);

    // Check arguments
    if (!check_file(file)) {
        PyErr_SetString(PyExc_TypeError, "\'file\' is not a file object.");
        goto raise_exception;
    }
    if (!PySequence_Check(sequence)) {
        PyErr_SetString(PyExc_TypeError, "\'type_names\' is not a sequence.");
        goto raise_exception;
    }

    // Config Headers
    success = generate_log_config_headers(file, sequence);
    if (!success) {
        goto raise_exception;
    }

    // Disable previous logs
    for (int k = 0; k < 2; k++) {
        if (k == 0) {   // Disable normal log msgs
            // buf = encode_log_config(DISABLE, empty);
            buf = encode_log_config(DISABLE_DEBUG, empty);
        } else {        // Disable debug msgs
            // buf = encode_log_config(DISABLE_DEBUG, empty);
            buf = encode_log_config(DISABLE, empty);
        }
        if (buf.first != NULL && buf.second != 0) {
            (void) send_msg(file, buf.first, buf.second);
            delete[] buf.first;
            buf.first = NULL;
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Log config msg failed to encode.");
            goto raise_exception;
        }
    }

    success = generate_log_config_msgs(file, sequence);
    if (!success) {
        goto raise_exception;
    }

    // Config End
    success = generate_log_config_ends(file, sequence);
    if (!success) {
        goto raise_exception;
    }

    Py_DECREF(sequence);
    Py_DECREF(file);
    Py_RETURN_TRUE;

    raise_exception:
    Py_DECREF(sequence);
    Py_DECREF(file);
    return NULL;
}

// Return: None
static PyObject *
dm_collector_c_feed_binary(PyObject *self, PyObject *args) {
    (void) self;
    const char *b;
    Py_ssize_t length;
    if (!PyArg_ParseTuple(args, "y#", &b, &length)) {
         printf("dm_collector_c_feed_binary returns NULL\n");
        return NULL;
    }
    feed_binary(b, length);
    Py_RETURN_NONE;
}

static PyObject *
dm_collector_c_reset(PyObject *self, PyObject *args) {
    (void) self;
    (void) args;
    reset_binary();
    Py_RETURN_NONE;
}


// Return: decoded_list or None
static PyObject *
dm_collector_c_receive_log_packet(PyObject *self, PyObject *args) {

    // (void)self;

    std::string frame;
    bool crc_correct = false;
    bool skip_decoding = false, include_timestamp = false;  // default values
    double posix_timestamp = (include_timestamp ? get_posix_timestamp() : -1.0);
    bool success = true;
    PyObject *arg_skip_decoding = NULL;
    PyObject *arg_include_timestamp = NULL;


    if (!PyArg_ParseTuple(args, "|OO:receive_log_packet",
                          &arg_skip_decoding, &arg_include_timestamp))
        Py_RETURN_NONE;
    if (arg_skip_decoding != NULL) {
        Py_INCREF(arg_skip_decoding);
        skip_decoding = (PyObject_IsTrue(arg_skip_decoding) == 1);
        Py_DECREF(arg_skip_decoding);
    }
    if (arg_include_timestamp != NULL) {
        Py_INCREF(arg_include_timestamp);
        include_timestamp = (PyObject_IsTrue(arg_include_timestamp) == 1);
        Py_DECREF(arg_include_timestamp);
    }

    while (success) {
        // Keep reading the buffer in case there are any frames remained.

        success = get_next_frame(frame, crc_correct);
        // printf("success=%d crc_correct=%d is_log_packet=%d\n", success, crc_correct, is_log_packet(frame.c_str(), frame.size()));
        // if (success && crc_correct && is_log_packet(frame.c_str(), frame.size())) {
        //

        if (success && crc_correct) {

            check_frame_format(frame);

            // Check if it is custom packet
            if(is_custom_packet(frame.c_str(), frame.size())) {
                if (skip_decoding) {
                    Py_RETURN_NONE;
                }
                const char *s = frame.c_str();
                PyObject *decoded = decode_custom_packet(s + 2,  // skip first two bytes
                                                      frame.size() - 2);
                if (include_timestamp) {
                    PyObject *ret = Py_BuildValue("(Od)", decoded, posix_timestamp);
                    Py_DECREF(decoded);
                    return ret;
                } else {
                    return decoded;
                }
            }

            if (!manager_export_binary(&g_emanager, frame.c_str(), frame.size()))
                continue;
            if (is_log_packet(frame.c_str(), frame.size())) {
                const char *s = frame.c_str();
                PyObject *decoded = decode_log_packet(s + 2,  // skip first two bytes
                                                      frame.size() - 2,
                                                      skip_decoding);
		if (include_timestamp) {
                    PyObject *ret = Py_BuildValue("(Od)", decoded, posix_timestamp);

		    if(decoded != Py_None)
                      Py_DECREF(decoded);

		    return ret;
                } else {
                    return decoded;
                }

            } else if (is_debug_packet(frame.c_str(), frame.size())) {
                //Yuanjie: the original debug msg does not have header...

                unsigned short n_size = frame.size()+sizeof(char)*14;

                unsigned char tmp[14]={
                    0xFF, 0xFF,
                    0x00, 0x00, 0xeb, 0x1f,
                    0x00, 0x00, 0x73, 0xB7,
                    0xB8, 0x65, 0xDD, 0x00
                };
                // tmp[2]=(char)(n_size);
                *(tmp+2)=n_size;
                *(tmp)=n_size;
                char *s = new char[n_size];
                memmove(s,tmp,sizeof(char)*14);
                memmove(s+sizeof(char)*14,frame.c_str(),frame.size());
                PyObject *decoded = decode_log_packet_modem(s, n_size, skip_decoding);

                // char *s = new char[n_size];
                // memset(s,0,sizeof(char)*n_size);
                // *s = n_size;
                // *(s+2) = n_size;
                // *(s+4) = 0xeb;
                // *(s+5) = 0x1f;
                // memmove(s+sizeof(char)*14,frame.c_str(),frame.size());
                // PyObject *decoded = decode_log_packet(s, n_size, skip_decoding);



                // // The following code does not crash on Android.
                // // But if use s and frame.size(), it crashes
                // const char *s = frame.c_str();
                // PyObject *decoded = decode_log_packet(  s + 2,  // skip first two bytes
                //                                         frame.size() - 2,
                //                                         skip_decoding);

                if (include_timestamp) {
                    PyObject *ret = Py_BuildValue("(Od)", decoded, posix_timestamp);
                    Py_DECREF(decoded);
                    // delete [] s; //Yuanjie: bug for it on Android, but no problem on laptop
                    return ret;
                } else {
                    // delete [] s; //Yuanjie: bug for it on Android, but no problem on laptop
                    return decoded;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }
    }
    Py_RETURN_NONE;
}

// Init the module
PyMODINIT_FUNC
PyInit_dm_collector_c(void) {
    /*
    Yunqi: change the functions for python 3
    */
    //    PyObject *dm_collector_c = Py_InitModule3("dm_collector_c", DmCollectorCMethods,
    //        "collects and decodes diagnositic logs from Qualcomm chipsets.");
    static struct PyModuleDef moduledef = {
            PyModuleDef_HEAD_INIT, "dm_collector_c",
            "collects and decodes diagnositic logs from Qualcomm chipsets.", -1,
            DmCollectorCMethods,
    };
    PyObject *dm_collector_c = PyModule_Create(&moduledef);

    PyObject *log_packet_types;

    // dm_ccllector_c.log_packet_types: stores all supported type names
    if (EXPOSE_INTERNAL_LOGS == 1) {
        //YUANJIE: expose all logs to MobileInsight
        int n_types = ARRAY_SIZE(LogPacketTypeID_To_Name, ValueName);
        log_packet_types = PyTuple_New(n_types);
        for (int i = 0; i < n_types; i++) {
            // There is no leak here, because PyTuple_SetItem steals reference


            // Yuanjie: only expose public logs to py module
            // Refer to consts.h
            // printf("%s\n",LogPacketTypeID_To_Name[i].name);
            PyTuple_SetItem(log_packet_types,
                            i,
                            Py_BuildValue("s", LogPacketTypeID_To_Name[i].name));
        }

    } else {
        //YUANJIE: internal logs are not exposed
        int n_types = 0;
        for (int i = 0; i < (int) ARRAY_SIZE(LogPacketTypeID_To_Name, ValueName); i++) {
            if (LogPacketTypeID_To_Name[i].b_public)
                n_types++;
        }
        log_packet_types = PyTuple_New(n_types);
        int count = 0;
        for (int i = 0; i < (int) ARRAY_SIZE(LogPacketTypeID_To_Name, ValueName); i++) {
            if (LogPacketTypeID_To_Name[i].b_public) {
                // printf("%s\n",LogPacketTypeID_To_Name[i].name);
                PyTuple_SetItem(log_packet_types,
                                count,
                                Py_BuildValue("s", LogPacketTypeID_To_Name[i].name));
                count++;
            }

        }
    }

    PyObject_SetAttrString(dm_collector_c, "log_packet_types", log_packet_types);
    Py_DECREF(log_packet_types);

    // dm_ccllector_c.version: stores the value of DM_COLLECTOR_C_VERSION
    PyObject *pystr = PyUnicode_FromString(DM_COLLECTOR_C_VERSION);
    PyObject_SetAttrString(dm_collector_c, "version", pystr);
    Py_DECREF(pystr);

    manager_init_state(&g_emanager);
    return dm_collector_c;
}
