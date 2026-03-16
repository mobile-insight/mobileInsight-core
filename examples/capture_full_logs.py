#!/usr/bin/env python3
"""
capture_full_logs.py - Capture MobileInsight logs directly from a phone via USB.
This script enables detailed logging including LTE RRC, NAS, and MAC layers.

Usage:
    python capture_full_logs.py <serial_port> <baud_rate> [output_file]
Example:
    python capture_full_logs.py /dev/ttyUSB0 9600 my_capture.mi2log
"""

import sys
import os
from mobile_insight.monitor import OnlineMonitor
from mobile_insight.analyzer import MsgLogger

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python capture_full_logs.py <serial_port> <baud_rate> [output_file]")
        print("Example: python capture_full_logs.py /dev/ttyUSB0 9600 my_capture.mi2log")
        sys.exit(1)

    port = sys.argv[1]
    baud = int(sys.argv[2])
    
    if len(sys.argv) >= 4:
        output_file = sys.argv[3]
    else:
        output_file = "capture_mac_rrc.mi2log"

    print(f"Starting capture on {port} at {baud} baud. Saving to {output_file}...")
    print("Press Ctrl+C to stop recording.")

    # Initialize monitor
    src = OnlineMonitor()
    src.set_serial_port(port)
    src.set_baudrate(baud)
    src.save_log_as(output_file)

    # Enable detailed logs (RRC, NAS, and MAC)
    logs_to_enable = [
        # RRC
        "LTE_RRC_OTA_Packet",
        "LTE_RRC_Serv_Cell_Info",
        "5G_NR_RRC_OTA_Packet",
        "WCDMA_RRC_OTA_Packet",
        
        # NAS
        "LTE_NAS_EMM_OTA_Incoming_Packet",
        "LTE_NAS_EMM_OTA_Outgoing_Packet",
        "LTE_NAS_ESM_OTA_Incoming_Packet",
        "LTE_NAS_ESM_OTA_Outgoing_Packet",
        
        # MAC
        "LTE_MAC_DL_Transport_Block",
        "LTE_MAC_UL_Transport_Block",
        "LTE_MAC_UL_Tx_Statistics",
        "LTE_MAC_UL_Buffer_Status_Internal",
        
        # PHY (optional, disabled by default to save space, uncomment if needed)
        # "LTE_PHY_Connected_Mode_Intra_Freq_Meas",
        # "LTE_PHY_Serv_Cell_Measurement",
    ]

    for log_name in logs_to_enable:
        src.enable_log(log_name)

    # Optional: Dump to screen while capturing (Disable if it slows things down)
    dumper = MsgLogger()
    dumper.set_source(src)
    dumper.set_decoding(MsgLogger.INFO)  # Change to MsgLogger.XML for verbose output

    try:
        src.run()
    except KeyboardInterrupt:
        print(f"\nCapture stopped. Saved to {output_file}")
        sys.exit(0)
