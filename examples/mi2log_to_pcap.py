#!/usr/bin/env python3
"""
mi2log_to_pcap.py - Convert MobileInsight .mi2log files to Wireshark .pcap files

Uses GSMTAP encapsulation (Ethernet + IPv4 + UDP:4729 + GSMTAP header) so that
ANY standard Wireshark installation can decode the LTE RRC messages natively.

Usage:
    python mi2log_to_pcap.py <input.mi2log> [output.pcap]
"""

import sys
import struct
import xml.etree.ElementTree as ET
from datetime import datetime

# --- PERFORMANCE & CORRECTNESS HACK ---
# MobileInsight's LogAnalyzer automatically passes raw LTE RRC packets to Wireshark 
# (via ws_dissector) to get XML. We want the RAW bytes for GSMTAP.
# Monkey-patching WSDissector skips the slow Wireshark call and preserves exact bytes!
from mobile_insight.monitor.dm_collector.dm_endec.ws_dissector import WSDissector
def raw_dummy_decode(msg_type, b):
    # Store exact raw hex in a fake XML so LogAnalyzer doesn't crash
    return f'<msg><packet><field name="aww.proto" show="{msg_type}"/><field name="lte-rrc.message" value="{b.hex()}"/></packet></msg>'
WSDissector.decode_msg = staticmethod(raw_dummy_decode)
# --------------------------------------

from mobile_insight.analyzer import LogAnalyzer

# PCAP constants
PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1

# GSMTAP constants
GSMTAP_VERSION = 0x02
GSMTAP_HDR_LEN = 4          # in 32-bit words (= 16 bytes)
GSMTAP_TYPE_LTE_RRC = 13

# GSMTAP LTE RRC sub-types (channel mapping based on Wireshark packet-gsmtap.c)
GSMTAP_LTE_RRC_SUB = {
    "DL_CCCH":     0,
    "DL_DCCH":     1,
    "UL_CCCH":     2,
    "UL_DCCH":     3,
    "BCCH_BCH":    4,
    "BCCH_DL_SCH": 5,
    "PCCH":        6,
    "MCCH":        7,
}

# Map AWW proto IDs/names to GSMTAP sub-types
AWW_TO_GSMTAP = {
    "LTE-RRC_PCCH": GSMTAP_LTE_RRC_SUB["PCCH"],
    "LTE-RRC_DL_DCCH": GSMTAP_LTE_RRC_SUB["DL_DCCH"],
    "LTE-RRC_UL_DCCH": GSMTAP_LTE_RRC_SUB["UL_DCCH"],
    "LTE-RRC_BCCH_DL_SCH": GSMTAP_LTE_RRC_SUB["BCCH_DL_SCH"],
    "LTE-RRC_DL_CCCH": GSMTAP_LTE_RRC_SUB["DL_CCCH"],
    "LTE-RRC_UL_CCCH": GSMTAP_LTE_RRC_SUB["UL_CCCH"],
}


def write_pcap_global_header(f):
    f.write(struct.pack('<IHHiIII',
        PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
        0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE_ETHERNET))

def write_pcap_packet(f, ts_sec, ts_usec, data):
    f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
    f.write(data)

def build_gsmtap_header(gsmtap_type, sub_type, arfcn=0, frame_nr=0):
    """Build a 16-byte GSMTAP header."""
    return struct.pack('>BBBBHBBIBBB x',
        GSMTAP_VERSION,    # version
        GSMTAP_HDR_LEN,    # header length in 32-bit words
        gsmtap_type,        # type (LTE_RRC = 13)
        0,                  # timeslot
        arfcn,              # ARFCN
        0,                  # signal_dbm
        0,                  # snr_db
        frame_nr,           # frame number
        sub_type,           # sub_type (channel)
        0,                  # antenna_nr
        0,                  # sub_slot
    )

def build_ethernet_ipv4_udp(payload):
    """Wrap payload in Ethernet + IPv4 + UDP headers for GSMTAP (port 4729)."""
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack('>HHHH', 4729, 4729, udp_len, 0)
    
    ip_total_len = 20 + udp_len
    ip_hdr = struct.pack('>BBHHHBBHII',
        0x45, 0, ip_total_len, 0, 0x4000, 64, 17, 0, 0x7f000001, 0x7f000001)
    
    eth_hdr = struct.pack('>6s6sH',
        b'\x00'*6, b'\x00'*6, 0x0800)
    return eth_hdr + ip_hdr + udp_hdr + payload

def parse_timestamp(ts_str):
    for fmt in ('%Y-%m-%d  %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d  %H:%M:%S'):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            epoch = datetime(1970, 1, 1)
            delta = dt - epoch
            return int(delta.total_seconds()), dt.microsecond
        except ValueError:
            continue
    return 0, 0

def extract_pdu_from_xml(payload_xml):
    """Extract msg_type (AWW name) and raw PDU bytes from our monkey-patched XML."""
    try:
        root = ET.fromstring(payload_xml)
    except ET.ParseError:
        return None, None, 0, 0

    msg_type = None
    pdu_hex = None
    arfcn = 0
    frame_nr = 0

    for pair in root.findall(".//pair"):
        key = pair.get("key")
        if key == "Freq" and pair.text:
            try: arfcn = int(pair.text)
            except: pass
        elif key == "SysFrameNum/SubFrameNum" and pair.text:
            try: frame_nr = int(pair.text)
            except: pass

    # Find the data inside our fake <msg><packet> structure
    for field in root.findall(".//field"):
        if field.get("name") == "aww.proto":
            msg_type = field.get("show")
        elif field.get("name") == "lte-rrc.message":
            pdu_hex = field.get("value")

    if msg_type and pdu_hex:
        try:
            return msg_type, bytes.fromhex(pdu_hex), arfcn, frame_nr
        except ValueError:
            pass
    return None, None, 0, 0


def convert_mi2log_to_pcap(input_path, output_path):
    print(f"Loading {input_path}...")
    def on_done(): pass
    
    # We load standard log analyzer, but because we monkey-patched WSDissector, 
    # it runs instantly and yields the pure raw bytes inside a quick XML wrapper.
    analyzer = LogAnalyzer(on_done)
    analyzer.AnalyzeFile([input_path], analyzer.supported_types)

    if not analyzer.msg_logs:
        print("Error: No messages found.")
        return False

    rrc_msgs = [m for m in analyzer.msg_logs if m.get('TypeID') == 'LTE_RRC_OTA_Packet']
    print(f"Found {len(analyzer.msg_logs)} total messages, {len(rrc_msgs)} LTE_RRC_OTA_Packet messages")

    exported = 0
    skipped = 0

    with open(output_path, 'wb') as f:
        write_pcap_global_header(f)

        for msg in rrc_msgs:
            payload = msg.get('Payload', '')
            timestamp = msg.get('Timestamp', '')

            msg_type, pdu_bytes, arfcn, frame_nr = extract_pdu_from_xml(payload)
            if msg_type is None or pdu_bytes is None:
                skipped += 1
                continue

            gsmtap_sub = AWW_TO_GSMTAP.get(msg_type)
            if gsmtap_sub is None:
                skipped += 1
                continue

            gsmtap_hdr = build_gsmtap_header(GSMTAP_TYPE_LTE_RRC, gsmtap_sub, arfcn, frame_nr)
            gsmtap_pkt = gsmtap_hdr + pdu_bytes
            eth_frame = build_ethernet_ipv4_udp(gsmtap_pkt)

            ts_sec, ts_usec = parse_timestamp(timestamp)
            write_pcap_packet(f, ts_sec, ts_usec, eth_frame)
            exported += 1

    print(f"\nExported {exported} packets to {output_path}")
    if skipped:
        print(f"Skipped {skipped} packets (NB-IoT or unsupported channel)")
    print(f"\nOpen with: wireshark {output_path}")
    return exported > 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.mi2log> [output.pcap]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) >= 3 else input_file.rsplit('.', 1)[0] + '.pcap'
    success = convert_mi2log_to_pcap(input_file, output_file)
    sys.exit(0 if success else 1)
