#!/usr/bin/python
# Filename: offline-analysis-filtering.py
import os
import sys
from datetime import datetime

"""
Offline analysis: save the log as a new one with pre-defined filter
"""

# Import MobileInsight modules
from mobile_insight.monitor import OfflineReplayer

if __name__ == "__main__":

    # Initialize a 3G/4G monitor
    src = OfflineReplayer()
    src.set_input_path("./offline_log_example.mi2log")

    # Configure the log to be saved
    start_timestamp = datetime(2020, 11, 16, 9, 49, 0)
    end_timestamp = datetime(2020, 11, 16, 9, 50, 0)
    src.enable_log("LTE_RRC_OTA_Packet", start_timestamp, end_timestamp)
    src.enable_log("LTE_NAS_ESM_OTA_Incoming_Packet")
    src.enable_log("LTE_RRC_Serv_Cell_Info")
    src.enable_log("LTE_RRC_OTA_Packet")
    src.enable_log("WCDMA_RRC_Serv_Cell_Info")
    src.enable_log("WCDMA_RRC_OTA_Packet")

    # Save log as
    src.save_log_as("./filtered_log.mi2log")

    # Start the monitoring
    src.run()
