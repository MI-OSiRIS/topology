"""
    This is a RYU application which builds Dynamic Network Topology information from all the Openflow switches connected to this RYU controller.
    The Topology information is automatically pushed to UNIS server using UNISRt.
    The Topology information Nodes, Ports and Links will be part of the Domain name specified.
To RUN:
ryu-manager ./osiris_main.py --default-log-level=1 --install-lldp-flow --observe-links --ofp-tcp-listen-port=<Openflow-port>
--osiris_main-domain <UNIS_DOMAIN_NAME> --osiris_main-unis_server <UNIS_HOST_IP>:<UNIS_HOST_PORT>

Requirements:
* Python3
* UNISRt package installed

"""

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
from ryu.ofproto import *
# from ryu.lib.packet.lldp import *
from pprint import pprint
import codecs
import struct
from unis.models import *
from unis.runtime import Runtime
import traceback
import sys
from ryu import cfg
import time
import threading

CONF = cfg.CONF

#Create OFSwitchNode class
OFSwitchNode = schemaLoader.get_class("http://unis.crest.iu.edu/schema/ext/ofswitch/1/ofswitch#")

PATH = os.path.dirname(__file__)

class OSIRISApp(app_manager.RyuApp):
    _CONTEXTS = {
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(OSIRISApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.CONF.register_opts([
            cfg.StrOpt('osiris_domain', default=''),
            cfg.StrOpt('unis_server', default='')
        ])
        self.domain_name = self.CONF.osiris_domain
        unis_server = self.CONF.unis_server
        self.domain_name = CONF['osiris_main']['domain']
        self.logger.info("Connecting to UNIS Server at "+unis_server)
        self.logger.info("Connecting to Domain: "+self.domain_name)
        self.rt = Runtime("http://"+unis_server, defer_update=True)
        self.create_domain()
        # updates_thread = threading.Thread(target=self.start_updates, args=[10])
        # updates_thread.start()
        # self.start_updates(10)

    def start_updates(self, time_secs):

        self.logger.info("----- UPDATE TIMER SET TO "+str(time_secs)+"s  -------")
        while True:
            time.sleep(time_secs)
            self.logger.info("----- UPDATING UNIS DB -------")
            self.rt.flush()

    def create_domain(self):
        domain_obj = None
        for domain in self.rt.domains:
            if domain.name == self.domain_name:
                domain_obj = domain
                break

        if domain_obj is None:
            self.logger.info("CREATING A NEW DOMAIN")
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
                self.deregister_switch(datapath)

    def deregister_switch(self, datapath):
        self.logger.debug('deregister_switch datapath: %s', datapath.id)
        self.logger.debug(self.check_node('switch:'+str(datapath.id)))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("**** switch_features_handler *****")
        # self.logger.info(ev.msg.version)
        self.logger.info("*****END INFO*******")
        datapath = ev.msg.datapath
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        #
        # self.logger.info("ofproto.OFP_VERSION:: %s" % ofproto.OFP_VERSION)
        # if ofproto.OFP_VERSION == 0x01:
        #     self.logger.info("Version 1.0")
        # elif ofproto.OFP_VERSION == 0x04:
        #     self.logger.info("Version 1.3")
        # else:
        #     self.logger.info("Some version OF")
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        # match = parser.OFPMatch()
        # OFPCML_NO_BUFFER attr not in OF 1.0
        # if hasattr(ofproto, 'OFPCML_NO_BUFFER'):
        #     actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
        #                                   ofproto.OFPCML_NO_BUFFER)]
        # else:
        #     actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow_new(datapath)
        # self.add_flow(datapath, 0, match, actions)

    def send_desc_stats_request(self, datapath):
        self.logger.info("*****Send send_desc_stats_request*****")
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        """
            Retrieves detailed switch info from OF Desc Stats Reply message and pushes into UNIS switch node
        :param ev:
        :return:
        """
        self.logger.info("****desc_stats_reply_handler   ******"+str(ev.msg.datapath.id))
        body = ev.msg.body
        switch_node = self.check_node("switch:"+str(ev.msg.datapath.id))
        if switch_node is not None:
            description_str = ""
            if body.mfr_desc is not None:
                description_str += body.mfr_desc.decode("utf-8") + ","
                switch_node.mfrdesc = body.mfr_desc.decode("utf-8")
            if body.hw_desc is not None:
                description_str += body.hw_desc.decode("utf-8") + ","
                switch_node.hwdesc = body.hw_desc.decode("utf-8")
            if body.sw_desc is not None:
                description_str += body.sw_desc.decode("utf-8") + ","
                switch_node.swdesc = body.sw_desc.decode("utf-8")
            if len(description_str) > 0:
                description_str = description_str[:-1]
            if len(switch_node.description) == 0:
                switch_node.description = description_str

    def add_flow_new(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if ofproto.OFP_VERSION == 0x01:
            self.logger.info("Version 1.0")
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                    match=match, actions=actions)
            datapath.send_msg(mod)
            self.logger.info("Flow configured for 1.0")
        elif ofproto.OFP_VERSION == 0x04:
            self.logger.info("Version 1.3")
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
                                                  ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                        match=match, instructions=inst)
            datapath.send_msg(mod)
            self.logger.info("Flow configured for 1.3")
        else:
            self.logger.info("Some other version of OF")

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
        self.logger.info("**** switch_enter_handler *****")
        self.check_add_switch(ev.switch, ev.switch.dp)
        self.send_desc_stats_request(ev.switch.dp)
        self.logger.info("**** switch_enter_handler done*****")

    def check_add_switch(self, switch, datapath):
        """
            This function adds the switch as a Node into the specified domain into UNIS.
            The node name will be switch:<dp_id>
            Also adds ports of a switch as Port objects with port No as Index and MAC address.
            If a port already exists for a switch in UNIS, it updates the MAC address and Port No, if there are any changes.

        :param switch:
        :param datapath:
        :return:
        """
        switch_name = "switch:"+str(datapath.id)
        port_object = None
        ports_list = []

        self.logger.info("**** Adding the switch *****")
        # Nodes
        switch_node = self.check_node(switch_name)

        if switch_node is None:
            self.logger.info("*** NEW SWITCH***")
            switch_node = OFSwitchNode({"name": switch_name, "datapathid": str(datapath.id)})
            self.rt.insert(switch_node, commit=True)
            self.logger.info("*** ADDING TO DOMAIN***")
            self.domain_obj.nodes.append(switch_node)
        else:
            self.logger.info("FOUND switch_node id: %s" % switch_node.id)
        self.logger.info("**** Adding the ports *****")
        # Ports
        for port in switch.ports:
            # Search by Port Name
            port_object = self.check_port(port.name, switch_node)
            if port_object is None:
                self.logger.info("****NEW PORT***")
                port_object = Port({"name": port.name.decode("utf-8"), "index": str(port.port_no), "address":
                    {"address": port.hw_addr, "type": "mac"}})
                self.domain_obj.ports.append(port_object)
            else:
                self.logger.info("****OLD PORT***")
                port_object = self.merge_port_diff(port_object, port)
            self.rt.insert(port_object, commit=True)
            ports_list.append(port_object)
        switch_node.ports = ports_list

    def merge_port_diff(self, port_object, port):
        if port_object.name != port.name.decode("utf-8"):
            self.logger.info("*** ERROR: Port name is different***")
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
        self.logger.info("********dpid********"+str(dpid))
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info("LLDP packet in %s %s %s %s %x", dpid, src, dst, in_port, eth_pkt.ethertype)
            lldp_host_obj = LLDPHost(LLDPHost.lldp_parse_new(msg.data), self.logger)
            self.logger.info("***PACKET****")

            self.check_add_node_and_port(lldp_host_obj)
            self.create_links(datapath, in_port, lldp_host_obj)


    def get_dpid_from_chassis_id(self, chassis_id):
        "Will be in the format dpid:0000080027c11115, to be converted to decimal of 0000080027c11115"
        dec_value = int(chassis_id[5:], 16)
        # print("get_dpid_from_chassis_id", dec_value)
        return dec_value

    def determine_node_name_from_lldp(self, lldp_host_obj):
        """
            Implement Fallbacks for Node Name determination from the LLDP objects
        :param lldp_host_obj:
        :return: node_name or None if can be determined
        """
        node_name = None
        if lldp_host_obj.host_type == LLDPHost.HOST_TYPE_SWITCH:
            # print("////// FOUND SWITCH AS NODE /////")
            dpid = self.get_dpid_from_chassis_id(lldp_host_obj.chassis_id)
            node_name = "switch:" + str(dpid)
        elif lldp_host_obj.system_name is not None:
            # print("////// FOUND HOST AS NODE /////")
            node_name = lldp_host_obj.system_name
        elif lldp_host_obj.chassis_id is not None:
            node_name = "device:"+str(lldp_host_obj.chassis_id)
        return node_name

    def determine_port_name_from_lldp(self, lldp_host_obj):
        """
            Implement Fallbacks for Port Name determination from the LLDP objects
        :param lldp_host_obj:
        :return: port_name or None if can be determined
        """
        port_name = None
        if lldp_host_obj.port_description is not None:
            port_name = lldp_host_obj.port_description
        elif lldp_host_obj.port_id is not None:
            port_name = "port:"+str(lldp_host_obj.port_id)
        return port_name

    def check_add_node_and_port(self, lldp_host_obj):
        """
            Creates UNIS Nodes and Ports from the LLDPHost information provided.
            Switch Nodes will be created by node_name as switch:<dp-id> and Host Nodes' name will be LLDP System Name.
            As LLDP Advertisement can contain only one Port Information, this function assumes 1:1 relation
            between Host and Ports.

        :param lldp_host_obj:
        :return:
        """
        self.logger.info("**check_add_node_and_port***")
        try:
            # Node Details
            node_name = self.determine_node_name_from_lldp(lldp_host_obj)
            if node_name is None:
                self.logger.error("LLDP Node cannot be added due to insufficient information.")
                return
            node = self.check_node(node_name)

            # Port details
            # Currently this assumes 1:1 between Nodes and Ports
            port_name = self.determine_port_name_from_lldp(lldp_host_obj)
            if port_name is None or lldp_host_obj.port_id is None:
                self.logger.error("LLDP Node's port cannot be added due to insufficient information.")
                return
            port_address = lldp_host_obj.port_id
            if lldp_host_obj.port_id_subtype == LLDPHost.PORT_ID_MAC_ADDRESS:
                port_address_type = "mac"
            else:
                port_address_type = "number"

            # Create Node
            if node is None:
                node = Node({"name": node_name})
                if lldp_host_obj.system_description is not None:
                    self.logger.debug("Updating node description to %s" % lldp_host_obj.system_description)
                    node.description = lldp_host_obj.system_description
                self.rt.insert(node, commit=True)
                self.domain_obj.nodes.append(node)

            # Create Port
            port = self.check_port_in_node(node, port_name)
            if port is None:
                port = Port(
                        {"name": port_name, "address": {"type": port_address_type, "address": str(port_address)}})
                self.rt.insert(port, commit=True)
                node.ports.append(port)
                self.domain_obj.ports.append(port)

            # Create Node and Port object
            # if node is None:
            #     port = None
            #     if port_address is not None:
            #         port = Port({"name": port_name, "address": {"type": port_address_type, "address": port_address}})
            #     else:
            #         port = Port({"name": port_name})
            #     self.rt.insert(port, commit=True)
            #     # self.domain_obj.ports.append(port)
            #     node = Node({"name": node_name})
            #     if lldp_host_obj.system_description is not None:
            #         node.description = lldp_host_obj.system_description
            #     node.ports.append(port)
            #     self.rt.insert(node, commit=True)
            #     print("*** ADDING TO DOMAIN***")
            #     self.domain_obj.nodes.append(node)
            # else:                                                       # Create Port object
            #     if port_name is not None:                               # In case of LLDP ad from a switch will have no port name
            #         port = self.check_port_in_node(node, port_name)
            #         if port is None:
            #             if port_address is not None:
            #                 port = Port(
            #                     {"name": port_name, "address": {"type": port_address_type, "address": port_address}})
            #             else:
            #                 port = Port({"name": port_name})
            #             self.rt.insert(port, commit=True)
            #             node.ports.append(port)
        except:
            self.logger.info("EEEEEEEException in check_add_node_and_port")
            self.logger.info(lldp_host_obj.__dict__)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            self.logger.error(''.join(line for line in lines))

    def create_links(self, datapath, in_port, lldp_host_obj):
        """ A link is always established between a switch node and host node.
            port1 will be switch node's port to which it is getting connected
            port2 will be host node's port
            Link name will be <port1-id>:<port2-id>
            :param datapath: switch datapath details to find the switch node
            :param in_port: switch in_port details to find the switch port
            :param lldp_host_obj: LLDPHost Object to find the host node/port
        """

        dpid = datapath.id
        switch_port = None
        host_port = None

        try:
            # FIND SWITCH NODE
            for node in self.rt.nodes:
                if node.name == "switch:"+str(dpid):
                    self.logger.info("SWITCH NODE NAME:"+node.name)
                    self.logger.info("SWITCH NODE ID:" + node.id)
                    for port in node.ports:
                        if port.index == str(in_port):
                            switch_port = port
                            break

            # FIND THE OTHER NODE/PORT
            node_name = self.determine_node_name_from_lldp(lldp_host_obj)
            node = self.check_node(node_name)
            port_name = self.determine_port_name_from_lldp(lldp_host_obj)
            host_port = self.check_port(port_name, node)

            # host_port = self.find_port(node.ports, port_index=str(lldp_host_obj.port_id))

            # if lldp_host_obj.host_type == LLDPHost.HOST_TYPE_SWITCH:
            #     dpid = self.get_dpid_from_chassis_id(lldp_host_obj.chassis_id)
            #     node_name = "switch:" + str(dpid)
            #     node = self.check_node(node_name)
            #     host_port = self.find_port(node.ports, port_index=str(lldp_host_obj.port_id))
            # else:
            #     node = self.check_node(lldp_host_obj.system_name)
            #     host_port = self.find_port(node.ports, port_name=lldp_host_obj.port_description)

            # pprint("///////////switch_port/////////")
            # pprint(switch_port.__dict__)

            # pprint("///////////host_port/////////")
            # pprint(host_port.__dict__)
            # CREATE THE LINK

            self.logger.info("======Creating a link between ")
            self.logger.info(host_port.name)
            self.logger.info("AND")
            self.logger.info("SWITCH:"+str(dpid))
            self.logger.info(switch_port.name)
            self.logger.info("====== END LINK CREATE====")

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
        except:
            self.logger.info("EEEEEEEException in create_links ---------")
            self.logger.info(lldp_host_obj.__dict__)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            self.logger.error(''.join(line for line in lines))

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
        for link in self.rt.links.where({"name": link_name}):
            # if link.name == link_name:
            return link
        return None

    def check_node(self, node_name):
        # pprint("Checking NODES")
        for node in self.rt.nodes.where({"name": node_name}):
            # print(node.name)
            # if node.name == node_name:
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
        self.logger.info(self.port_description)
        self.logger.info(self.system_name)
        self.logger.info(self.system_description)
        self.logger.info(self.management_addresses)

app_manager.require_app('ryu.app.ofctl_rest')
