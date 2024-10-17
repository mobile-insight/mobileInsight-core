#!/usr/bin/python
# Filename: dm_collector.py
"""
dm_collector.py
A monitor for 3G/4G mobile network protocols (RRC/EMM/ESM).

Author: Jiayao Li
"""

__all__ = ["DMCollector"]

from ..monitor import *

import binascii
import os
import optparse
import serial
import sys
import timeit

from .dm_endec import *
# import dm_collector_c
from . import dm_collector_c

class DMCollector(Monitor):
    """
    A monitor for 3G/4G mobile network protocols (RRC/EMM/ESM).
    It currently supports mobile devices with Qualcomm chipsets.
    """

    #: a list containing the currently supported message types.
    SUPPORTED_TYPES = set(dm_collector_c.log_packet_types)

    def __init__(self, prefs={}):
        """
        Configure this class with user preferences.
        This method should be called before any actual decoding.

        :param prefs: configurations for message decoder. Empty by default.
        :type prefs: dictionary
        """
        Monitor.__init__(self)

        self.phy_baudrate = 9600
        self.phy_ser_name = None
        self._prefs = prefs
        self._type_names = []
        # Initialize Wireshark dissector
        DMLogPacket.init(self._prefs)

    def available_log_types(self):
        """
        Return available log types

        :returns: a list of supported message types
        """
        return self.__class__.SUPPORTED_TYPES

    def set_serial_port(self, phy_ser_name):
        """
        Configure the serial port that dumps messages

        :param phy_ser_name: the serial port name (path)
        :type phy_ser_name: string
        """
        self.phy_ser_name = phy_ser_name

    def set_baudrate(self, rate):
        """
        Configure the baudrate of the serial port

        :param rate: the baudrate of the port
        :type rate: int
        """
        self.phy_baudrate = rate

    def enable_log(self, type_name, start_timestamp = None, end_timestamp = None):
        """
        Enable the messages to be monitored.
        Currently DMCollector supports the following logs:

        :param type_name: the message type(s) to be monitored
        :type type_name: string or list

        :except ValueError: unsupported message type encountered
        """
        cls = self.__class__
        if isinstance(type_name, str):
            type_name = [type_name]
        for n in type_name:
            if n not in cls.SUPPORTED_TYPES:
                self.log_warning("Unsupported log message type: %s" % n)
            if n not in self._type_names:
                self._type_names.append(n)
                self.log_info("Enable collection: " + n)

        start_timestamp = start_timestamp.timestamp() if start_timestamp else 0.0
        end_timestamp = end_timestamp.timestamp() if end_timestamp else float('Inf')

        dm_collector_c.set_filtered(self._type_names, start_timestamp, end_timestamp)

    def enable_log_all(self, start_timestamp = None, end_timestamp = None):
        """
        Enable all supported logs
        """
        cls = self.__class__
        self.enable_log(cls.SUPPORTED_TYPES, start_timestamp, end_timestamp)

    def save_log_as(self, path):
        """
        Save the log as a mi2log file (for offline analysis)

        :param path: the file name to be saved
        :type path: string
        :param log_types: a filter of message types to be saved
        :type log_types: list of string
        """
        dm_collector_c.set_filtered_export(path, self._type_names)

    def run(self):
        """
        Start monitoring the mobile network. This is usually the entrance of monitoring and analysis.

        This function does NOT return or raise any exception.
        """
        assert self.phy_ser_name

        print(("PHY COM: %s" % self.phy_ser_name))
        print(("PHY BAUD RATE: %d" % self.phy_baudrate))

        try:
            # Open COM ports
            phy_ser = serial.Serial(self.phy_ser_name,
                                    baudrate=self.phy_baudrate,
                                    timeout=None, rtscts=True, dsrdtr=True)

            # Disable logs
            self.log_debug("Disable logs") 
            dm_collector_c.disable_logs(phy_ser)

            # Enable logs
            self.log_debug("Enable logs")
            dm_collector_c.enable_logs(phy_ser, self._type_names)

            # Read log packets from serial port and decode their contents
            while True:
                s = phy_ser.read(64)
                # s = phy_ser.read(1)
                dm_collector_c.feed_binary(s)

                decoded = dm_collector_c.receive_log_packet(self._skip_decoding,
                                                            True,   # include_timestamp
                                                            )
                if decoded:
                    try:
                        # packet = DMLogPacket(decoded)
                        if not decoded[0]:
                            continue
                        packet = DMLogPacket(decoded[0])
                        type_id = packet.get_type_id()
                        # print d["type_id"], d["timestamp"]
                        # xml = packet.decode_xml()
                        # print xml
                        # print ""
                        # Send event to analyzers
                        event = Event(timeit.default_timer(),
                                      type_id,
                                      packet)
                        self.send(event)
                    except FormatError as e:
                        # skip this packet
                        print(("FormatError: ", e))

        except (KeyboardInterrupt, RuntimeError) as e:
            print(("\n\n%s Detected: Disabling all logs" % type(e).__name__))
            # Disable logs
            dm_collector_c.disable_logs(phy_ser)
            phy_ser.close()
            sys.exit(e)
        except Exception as e:
            sys.exit(e)
