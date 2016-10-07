import os
import six

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
# from ryu.lib.packet.lldp import *
from pprint import pprint
import codecs
import struct
from unis.models import *
from unis.runtime import Runtime

# from lldp_host_parser import LLDPHost

PATH = os.path.dirname(__file__)

class OSIRISApp(app_manager.RyuApp):
    _CONTEXTS = {
        'switches': switches.Switches
    }
    
    def __init__(self, *args, **kwargs):
        super(OSIRISApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.rt = Runtime("http://localhost:8888")
        
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("**** switch_features_handler *****")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        print("**** switch_enter_handler *****")
        self.check_add_switch(ev.switch, ev.switch.dp)

    def check_add_switch(self, switch, datapath):
        switch_name = "switch:"+str(datapath.id)
        port_object = None
        ports_list = []

        # Nodes
        print("*** PRINT 111***")
        switch_node = self.check_node(switch_name)
        print("*** PRINT 112***")
        if switch_node is None:
            print("*** NEW SWITCH***")
            switch_node = Node({"name": switch_name})
            self.rt.insert(switch_node, commit=True)

        # Ports
        print("*** PRINT 114***")
        for port in switch.ports:
            print("*** PRINT 115***")
            port_object = self.check_port(port.name, switch_node)
            if port_object is None:
                print("****NEW PORT***")
                port_object = Port({"name": port.name.decode("utf-8"), "index": str(port.port_no), "address":
                    {"address": port.hw_addr, "type": "mac"}})
            else:
                print("****OLD PORT***")
                port_object = self.merge_port_diff(port_object, port)
            pprint(port_object.__dict__)
            print("*** PRINT 116***")
            self.rt.insert(port_object, commit=True)
            print("*** PRINT 117***")
            ports_list.append(port_object)
            print("*** PRINT 118***")
        print("*** PRINT 1183***")
        switch_node.ports = ports_list
        # self.rt.insert(switch_node, commit=True)
        print("*** PRINT 1184***")

    def merge_port_diff(self, port_object, port):
        if port_object.name != port.name.decode("utf-8"):
            print("*** ERROR: Port name is different***")
            return None
        if port_object.index != str(port.port_no):
            port_object.index = str(port.port_no)
        if port_object.address.address != port.hw_addr:
            port_object.address.address = port.hw_addr
        return port_object

    def check_port(self, port_name, switch_node):
        for port in switch_node.ports:
            if port.name == port_name:
                return port
        return None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        print("PACKETSSS")
        print(ev.__dict__)
        # print(msg.switch)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        print("********dpid********"+str(dpid))
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info("SupLLDP packet in %s %s %s %s %x", dpid, src, dst, in_port, eth_pkt.ethertype)
            lldp_host_obj = LLDPHost(LLDPPacket.lldp_parse_new(msg.data))
            print("***PACKET****")
            self.check_and_add_node(lldp_host_obj)
            self.create_links(datapath, in_port, lldp_host_obj)
            # print(self.rt.nodes)
            # pprint()

    def check_and_add_node(self, lldp_host_obj):
        pprint("check_and_add_node***")
        pprint(lldp_host_obj.__dict__)
        print("portID:"+lldp_host_obj.port_id)
        node = self.check_node(lldp_host_obj.system_name)
        port_name = lldp_host_obj.port_description
        port_address = lldp_host_obj.port_id
        port_address_type = "mac"
        if node is None:
            print("*** PRINT 1***")
            port = Port({"name": port_name, "address": {"type": port_address_type, "address": port_address}})
            print("*** PRINT 12***")
            self.rt.insert(port, commit=True)
            print("*** PRINT 13***")
            pprint(port.__dict__)
            print("*** PRINT 14***")
            node = Node({"name": lldp_host_obj.system_name,
                         "description": lldp_host_obj.system_description})
            print("*** PRINT 15***")
            node.ports.append(port)
            print("*** PRINT 16***")
            self.rt.insert(node, commit=True)
            print("*** PRINT 3333***")
        else:
            print("*** PRINT 2***")
            port = self.check_port_in_node(node, port_name)
            if port is None:
                port = Port({"name": port_name, "address": {"type": port_address_type, "address": port_address}})
                node.ports.append(port)
        print("*** PRINT 4***")

    def create_links(self, datapath, in_port, lldp_host_obj):
        dpid = datapath.id
        switch_port = None
        host_port = None
        # Find switch Node/ Port Ref

        print("in_port::::::", in_port)
        print("lldp_host_obj.port_description:::::::::", lldp_host_obj.port_description)
        for node in self.rt.nodes:
            if node.name == "switch:"+str(dpid):
                for port in node.ports:
                    if port.index == str(in_port):
                        switch_port = port
                        break
            if node.name == lldp_host_obj.system_name:
                for port in node.ports:
                    if port.name == lldp_host_obj.port_description:
                        host_port = port
                        break

        pprint("======Creating a link between ")
        pprint(switch_port.__dict__)
        pprint(host_port.__dict__)
        if switch_port is not None and host_port is not None:
            link_name = switch_port.id + ":" + host_port.id
            link = self.check_link(link_name)
            if link is None:
                link = Link({"name": link_name, "directed": False, "endpoints":
                    [{"rel": "full", "href": switch_port.selfRef}, {"rel": "full", "href": host_port.selfRef}]})
                self.rt.insert(link, commit=True)

    def check_link(self, link_name):
        for link in self.rt.links:
            if link.name == link_name:
                return link
        return None

    def check_node(self, node_name):
        pprint("Checking NODES")
        for node in self.rt.nodes:
            print(node.name)
            if node.name == node_name:
                print("found")
                return node
        return None

    def check_port_in_node(self, node, port_name):
        for port in node.ports:
            if port.name == port_name:
                return port
        return None

class LLDPHost:

    def __init__(self, lldp_tlvs):
        self.chassis_id = None
        self.port_id = None
        self.system_name = None
        self.system_description = None
        self.port_description = None
        self.management_addresses = []
        for tlv in lldp_tlvs.tlvs:
            if tlv.tlv_type == lldp.LLDP_TLV_CHASSIS_ID:
                pprint("------LLDP_TLV_CHASSIS_ID-----")
                self.parse_chassis_id(tlv)
            elif tlv.tlv_type == lldp.LLDP_TLV_PORT_ID:
                self.parse_port_id(tlv)
                pprint("------LLDP_TLV_PORT_ID-----")
            elif tlv.tlv_type == lldp.LLDP_TLV_TTL:
                pprint("------LLDP_TLV_TTL-----")
            elif tlv.tlv_type == lldp.LLDP_TLV_PORT_DESCRIPTION:
                pprint("------LLDP_TLV_PORT_DESCRIPTION-----")
                self.port_description = tlv.tlv_info.decode("utf-8")
            elif tlv.tlv_type == lldp.LLDP_TLV_SYSTEM_NAME:
                pprint("------LLDP_TLV_SYSTEM_NAME-----")
                self.system_name = tlv.tlv_info.decode("utf-8")
            elif tlv.tlv_type == lldp.LLDP_TLV_SYSTEM_DESCRIPTION:
                pprint("------LLDP_TLV_SYSTEM_DESCRIPTION-----")
                self.system_description = tlv.tlv_info.decode("utf-8")
            elif tlv.tlv_type == lldp.LLDP_TLV_MANAGEMENT_ADDRESS:
                pprint("------LLDP_TLV_MANAGEMENT_ADDRESS-----")
                self.parse_management_address(tlv)
        self.display()

# TLV type parsers
    def parse_chassis_id(self, tlv_chassis_id):
        if tlv_chassis_id.subtype == lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            chassis_id = tlv_chassis_id.chassis_id.decode('utf-8')
            # pprint(chassis_id)
            self.chassis_id = chassis_id
        elif tlv_chassis_id.subtype == lldp.ChassisID.SUB_MAC_ADDRESS:
            # pprint(self.parse_mac_address(tlv.chassis_id))
            self.chassis_id = self.parse_mac_address(tlv_chassis_id.chassis_id)
            # elif tlv.subtype == lldp.ChassisID.

    def parse_port_id(self, tlv_port_id):
        if tlv_port_id.subtype == lldp.PortID.SUB_PORT_COMPONENT:
            port_id = tlv_port_id.port_id
            if len(port_id) == LLDPPacket.PORT_ID_SIZE:
                (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)
                self.port_id = src_port_no
        elif tlv_port_id.subtype == lldp.PortID.SUB_MAC_ADDRESS:
            self.port_id = self.parse_mac_address(tlv_port_id.port_id)

    def parse_management_address(self, tlv_management_address):
        if tlv_management_address.addr_subtype == 1:
            pprint("------IPv4 address----")
            self.management_addresses.append(self.parse_ipv4_address(tlv_management_address.addr))
        elif tlv_management_address.addr_subtype == 2:
            pprint("---- IPv6 address----")
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
        pprint(ip_hex_string)
        ip_dec_string = ""
        for i in range(0, 4):
            ip_dec_string += str(int(ip_hex_string[2*i:2*i+2], 16))
            if i != 3:
                ip_dec_string += "."
        return ip_dec_string

    def parse_ipv6_address(self, ip_binary_string):
        ip_hex_string = codecs.encode(ip_binary_string, 'hex').decode('utf-8')
        pprint(ip_hex_string)
        ipv6_string = ""
        for i in range(0, 8):
            ipv6_string += str(ip_hex_string[4 * i:4 * i + 4])
            if i != 7:
                ipv6_string += ":"
        return ipv6_string


    def display(self):
        pprint("==== Printing the LLDP Host details ====")
        pprint(self.chassis_id)
        pprint(self.port_id)
        pprint(self.system_name)
        pprint(self.system_description)
        pprint(self.management_addresses)

app_manager.require_app('ryu.app.ofctl_rest')
