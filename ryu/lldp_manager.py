import os
import sys
import six
import codecs
import struct
import time
import traceback
import calendar
import logging
import pprint

from itertools import compress
from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER, \
    MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.topology.switches import LLDPPacket
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.ofproto import *

class LLDPUtils:

    @staticmethod
    def get_dpid_from_chassis_id(chassis_id):
        "Will be in the format dpid:0000080027c11115, to be converted to decimal of 0000080027c11115"
        dec_value = int(chassis_id[5:], 16)
        # print("get_dpid_from_chassis_id", dec_value)
        return dec_value

    @staticmethod
    def determine_node_name_from_lldp(lldp_host_obj):
        """
            Implement Fallbacks for Node Name determination from the LLDP objects
        :param lldp_host_obj:
        :return: node_name or None if can be determined
        """
        node_name = None
        if lldp_host_obj.host_type == LLDPHost.HOST_TYPE_SWITCH:
            # print("////// FOUND SWITCH AS NODE /////")
            dpid = LLDPUtils.get_dpid_from_chassis_id(lldp_host_obj.chassis_id)
            node_name = "switch:" + str(dpid)
        elif lldp_host_obj.system_name is not None:
            # print("////// FOUND HOST AS NODE /////")
            node_name = lldp_host_obj.system_name
        elif lldp_host_obj.chassis_id is not None:
            node_name = "device:"+str(lldp_host_obj.chassis_id)
        return node_name

    @staticmethod
    def determine_port_name_from_lldp(lldp_host_obj):
        """
            Implement Fallbacks for Port Name determination from the LLDP objects
        :param lldp_host_obj:
        :return: port_name or None if can be determined
        """
        port_name = None
        # the consequences of this simple function caused me physical pain. TODO: refactor entire program and rewrite this.
        if lldp_host_obj.port_description is not None:
            port_name = "port:" + lldp_host_obj.port_description
        elif lldp_host_obj.port_id is not None:
            port_name = (lldp_host_obj.port_id)
        return str(port_name)


class LLDPHost:

    # Host Type
    HOST_TYPE_LLDPD = 0
    HOST_TYPE_SWITCH = 1

    # Port ID Subtypes
    PORT_ID_MAC_ADDRESS = 0
    PORT_ID_NUMBER = 1

    # Chassis ID Subtypes
    CHASSIS_ID_MAC_ADDRESS = 0
    CHASSIS_ID_NAME = 1

    def __init__(self, lldp_tlvs, logger):
        self.logger = logger
        self.host_type = None
        self.chassis_id = None
        self.chassis_id_subtype = None
        self.port_id = None
        self.port_id_subtype = None
        self.system_name = None
        self.system_description = None
        self.port_description = None
        self.management_addresses = []
        for tlv in lldp_tlvs.tlvs:
            if tlv.tlv_type == lldp.LLDP_TLV_CHASSIS_ID:
                # pprint("------LLDP_TLV_CHASSIS_ID-----")
                self.parse_chassis_id(tlv)
            elif tlv.tlv_type == lldp.LLDP_TLV_PORT_ID:
                self.parse_port_id(tlv)
                # pprint("------LLDP_TLV_PORT_ID-----")
            elif tlv.tlv_type == lldp.LLDP_TLV_PORT_DESCRIPTION:
                # pprint("------LLDP_TLV_PORT_DESCRIPTION-----")
                self.port_description = tlv.tlv_info.decode("utf-8")
            elif tlv.tlv_type == lldp.LLDP_TLV_SYSTEM_NAME:
                # pprint("------LLDP_TLV_SYSTEM_NAME-----")
                self.system_name = tlv.tlv_info.decode("utf-8")
            elif tlv.tlv_type == lldp.LLDP_TLV_SYSTEM_DESCRIPTION:
                # pprint("------LLDP_TLV_SYSTEM_DESCRIPTION-----")
                self.system_description = tlv.tlv_info.decode("utf-8")
            elif tlv.tlv_type == lldp.LLDP_TLV_MANAGEMENT_ADDRESS:
                # pprint("------LLDP_TLV_MANAGEMENT_ADDRESS-----")
                self.parse_management_address(tlv)
        self.parse_host_type()
        self.display()

    @staticmethod
    def lldp_parse_new(data):
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = six.next(i)
        assert type(eth_pkt) == ethernet.ethernet
        lldp_pkt = six.next(i)
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()
        return lldp_pkt

    def parse_host_type(self):
        if self.chassis_id is not None and self.chassis_id_subtype == LLDPHost.CHASSIS_ID_NAME and \
                        "dpid:" in self.chassis_id:
            self.host_type = LLDPHost.HOST_TYPE_SWITCH
        else:
            self.host_type = LLDPHost.HOST_TYPE_LLDPD
# TLV type parsers
    def parse_chassis_id(self, tlv_chassis_id):
        if tlv_chassis_id.subtype == lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            chassis_id = tlv_chassis_id.chassis_id.decode('utf-8')
            # pprint(chassis_id)
            self.chassis_id_subtype = LLDPHost.CHASSIS_ID_NAME
            self.chassis_id = chassis_id
        elif tlv_chassis_id.subtype == lldp.ChassisID.SUB_MAC_ADDRESS:
            # pprint(self.parse_mac_address(tlv.chassis_id))
            self.chassis_id_subtype = LLDPHost.CHASSIS_ID_MAC_ADDRESS
            self.chassis_id = self.parse_mac_address(tlv_chassis_id.chassis_id)
            # elif tlv.subtype == lldp.ChassisID.

    def parse_port_id(self, tlv_port_id):
        if tlv_port_id.subtype == lldp.PortID.SUB_PORT_COMPONENT:
            port_id = tlv_port_id.port_id
            if len(port_id) == LLDPPacket.PORT_ID_SIZE:
                (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)
                self.port_id_subtype = LLDPHost.PORT_ID_NUMBER
                self.port_id = src_port_no
        elif tlv_port_id.subtype == lldp.PortID.SUB_MAC_ADDRESS:
            self.port_id_subtype = LLDPHost.PORT_ID_MAC_ADDRESS
            self.port_id = self.parse_mac_address(tlv_port_id.port_id)

    def parse_management_address(self, tlv_management_address):
        if tlv_management_address.addr_subtype == 1:
            # pprint("------IPv4 address----")
            self.management_addresses.append(self.parse_ipv4_address(tlv_management_address.addr))
        elif tlv_management_address.addr_subtype == 2:
            # pprint("---- IPv6 address----")
            self.management_addresses.append(self.parse_ipv6_address(tlv_management_address.addr))
        
# Utilities
    def parse_mac_address(self, hex_string):
        mac_string = codecs.encode(hex_string, 'hex').decode('utf-8')
        new_string = ""
        for i in range(0, len(mac_string)):
            if i != 0 and i % 2 == 0:
                new_string += ':'
            new_string += str(mac_string[i])
        return new_string

    def parse_ipv4_address(self, ip_binary_string):
        ip_hex_string = codecs.encode(ip_binary_string, 'hex')
        self.logger.info(ip_hex_string)
        ip_dec_string = ""
        for i in range(0, 4):
            ip_dec_string += str(int(ip_hex_string[2*i:2*i+2], 16))
            if i != 3:
                ip_dec_string += "."
        return ip_dec_string

    def parse_ipv6_address(self, ip_binary_string):
        ip_hex_string = codecs.encode(ip_binary_string, 'hex').decode('utf-8')
        self.logger.info(ip_hex_string)
        ipv6_string = ""
        for i in range(0, 8):
            ipv6_string += str(ip_hex_string[4 * i:4 * i + 4])
            if i != 7:
                ipv6_string += ":"
        return ipv6_string


    def display(self):
        self.logger.info("==== Printing the LLDP Host details ====")
        self.logger.info(self.chassis_id)
        self.logger.info(self.port_id)
        #self.logger.info(self.port_description)
        #self.logger.info(self.system_name)
        #self.logger.info(self.system_description)
        #self.logger.info(self.management_addresses)
