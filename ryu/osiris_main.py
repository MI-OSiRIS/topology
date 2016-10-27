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

from ryu import cfg
CONF = cfg.CONF


PATH = os.path.dirname(__file__)

class OSIRISApp(app_manager.RyuApp):
    _CONTEXTS = {
        'switches': switches.Switches
    }
    
    def __init__(self, *args, **kwargs):
        super(OSIRISApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        unis_server = CONF['osiris_main']['unis_server']
        self.domain_name = CONF['osiris_main']['domain']
        pprint("Connecting to UNIS Server at "+unis_server)
        pprint("Connecting to Domain: "+self.domain_name)
        self.rt = Runtime("http://"+unis_server)
        self.create_domain()

    def create_domain(self):
        domain_obj = None
        for domain in self.rt.domains:
            if domain.name == self.domain_name:
                domain_obj = domain
                break

        if domain_obj is None:
            domain_obj = Domain({"name": self.domain_name})
            self.rt.insert(domain_obj, commit=True)
        self.domain_obj = domain_obj

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
        switch_node = self.check_node(switch_name)
        if switch_node is None:
            print("*** NEW SWITCH***")
            switch_node = Node({"name": switch_name})
            self.rt.insert(switch_node, commit=True)
            print("*** ADDING TO DOMAIN***")
            self.domain_obj.nodes.append(switch_node)
        # Ports
        for port in switch.ports:
            port_object = self.check_port(port.name, switch_node)
            if port_object is None:
                print("****NEW PORT***")
                port_object = Port({"name": port.name.decode("utf-8"), "index": str(port.port_no), "address":
                    {"address": port.hw_addr, "type": "mac"}})
            else:
                print("****OLD PORT***")
                port_object = self.merge_port_diff(port_object, port)
            self.rt.insert(port_object, commit=True)
            ports_list.append(port_object)
        switch_node.ports = ports_list

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
            self.check_add_node_and_port(lldp_host_obj)
            self.create_links(datapath, in_port, lldp_host_obj)


    def get_dpid_from_chassis_id(self, chassis_id):
        "Will be in the format dpid:0000080027c11115, to be converted to decimal of 0000080027c11115"
        dec_value = int(chassis_id[5:], 16)
        # print("get_dpid_from_chassis_id", dec_value)
        return dec_value

    def check_add_node_and_port(self, lldp_host_obj):
        pprint("**check_add_node_and_port***")
        node = None
        node_name = ""
        port_name = None

        # Node Details
        if lldp_host_obj.host_type == LLDPHost.HOST_TYPE_SWITCH:
            # print("////// FOUND SWITCH AS NODE /////")
            dpid = self.get_dpid_from_chassis_id(lldp_host_obj.chassis_id)
            node_name = "switch:" + str(dpid)
        else:
            # print("////// FOUND HOST AS NODE /////")
            node_name = lldp_host_obj.system_name
        node = self.check_node(node_name)

        # Port details
        # Currently this assumes 1:1 between Nodes and Ports
        if lldp_host_obj.port_description is not None:
            port_name = lldp_host_obj.port_description

        port_address = lldp_host_obj.port_id
        if lldp_host_obj.port_id_subtype == LLDPHost.PORT_ID_MAC_ADDRESS:
            port_address_type = "mac"
        else:
            port_address_type = "number"

        # Create Node and Port object
        if node is None:
            port = None
            if port_address is not None:
                port = Port({"name": port_name, "address": {"type": port_address_type, "address": port_address}})
            else:
                port = Port({"name": port_name})
            self.rt.insert(port, commit=True)
            # self.domain_obj.ports.append(port)
            node = Node({"name": node_name,
                         "description": lldp_host_obj.system_description})
            node.ports.append(port)
            self.rt.insert(node, commit=True)
            print("*** ADDING TO DOMAIN***")
            self.domain_obj.nodes.append(node)
        else:                                                       # Create Port object
            if port_name is not None:                               # In case of LLDP ad from a switch will have no port name
                port = self.check_port_in_node(node, port_name)
                if port is None:
                    port = Port({"name": port_name, "address": {"type": port_address_type, "address": port_address}})
                    node.ports.append(port)

    def create_links(self, datapath, in_port, lldp_host_obj):
        dpid = datapath.id
        switch_port = None
        host_port = None

        # FIND SWITCH NODE
        for node in self.rt.nodes:
            if node.name == "switch:"+str(dpid):
                for port in node.ports:
                    if port.index == str(in_port):
                        switch_port = port
                        break

        # FIND THE OTHER NODE/PORT
        if lldp_host_obj.host_type == LLDPHost.HOST_TYPE_SWITCH:
            dpid = self.get_dpid_from_chassis_id(lldp_host_obj.chassis_id)
            node_name = "switch:" + str(dpid)
            node = self.check_node(node_name)
            host_port = self.find_port(node.ports, port_index=str(lldp_host_obj.port_id))
        else:
            node = self.check_node(lldp_host_obj.system_name)
            host_port = self.find_port(node.ports, port_name=lldp_host_obj.port_description)

        # pprint("///////////switch_port/////////")
        # pprint(switch_port.__dict__)

        # pprint("///////////host_port/////////")
        # pprint(host_port.__dict__)
        # CREATE THE LINK
        pprint("======Creating a link between ")
        pprint(host_port.name)
        pprint("AND")
        pprint("SWITCH:"+str(dpid))
        pprint("====== END LINK CREATE====")

        if switch_port is not None and host_port is not None:
            link_name = switch_port.id + ":" + host_port.id
            link_name_2 = host_port.id + ":" + switch_port.id
            link = self.check_link(link_name)
            if link is None:
                link = self.check_link(link_name_2)

            if link is None:
                link = Link({"name": link_name, "directed": False, "endpoints":
                    [{"rel": "full", "href": switch_port.selfRef}, {"rel": "full", "href": host_port.selfRef}]})
                self.rt.insert(link, commit=True)
                self.domain_obj.links.append(link)

    def find_port(self, ports, port_name=None, port_index=None):
        """
            Returns the first instance of Port Object which matches any condition
        :param ports:
        :param port_name:
        :param port_index:
        :return: Port Object
        """
        for port in ports:
            if port_index is not None and port_index == port.index:
                return port
            if port_name is not None and port_name == port.name:
                return port

    def check_link(self, link_name):
        for link in self.rt.links:
            if link.name == link_name:
                return link
        return None

    def check_node(self, node_name):
        # pprint("Checking NODES")
        for node in self.rt.nodes:
            # print(node.name)
            if node.name == node_name:
                # print("found")
                return node
        return None

    def check_port_in_node(self, node, port_name):
        for port in node.ports:
            if port.name == port_name:
                return port
        return None

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

    def __init__(self, lldp_tlvs):
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
            elif tlv.tlv_type == lldp.LLDP_TLV_TTL:
                pass
                # pprint("------LLDP_TLV_TTL-----")
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
        pprint(self.port_description)
        pprint(self.system_name)
        pprint(self.system_description)
        pprint(self.management_addresses)

app_manager.require_app('ryu.app.ofctl_rest')
