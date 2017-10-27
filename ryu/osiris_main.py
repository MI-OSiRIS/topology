"""
    This is a RYU application which builds Dynamic Network Topology
    information from all the Openflow switches connected to this
    RYU controller.
    The Topology information is automatically pushed to UNIS server
    using UNISRt. The topology Nodes, Ports and Links will be part of
    the Domain name specified.

    See http://github.com/MI-OSIRIS/topology for more information.
"""

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
from ryu import cfg
import unis
from unis.models import *
from unis.runtime import Runtime
from unis import logging as ulog
from unis.models.models import UnisList

# turn down various loggers
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("libdlt").setLevel(logging.WARNING)

#Create OFSwitchNode class
OFSwitchNode = schemaLoader.get_class("http://unis.crest.iu.edu/schema/ext/ofswitch/1/ofswitch#")
PATH = os.path.dirname(__file__)

@lldp.lldp.set_tlv_type(lldp.LLDP_TLV_SYSTEM_CAPABILITIES)
class SystemCapabilities(lldp.LLDPBasicTLV):
    # chassis subtype(1) + system cap(2) + enabled cap(2)
    _PACK_STR = '!HH'
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = _PACK_SIZE

    # System Capabilities
    CAP_REPEATER = (1 << 1)             # IETF RFC 2108
    CAP_MAC_BRIDGE = (1 << 2)           # IEEE Std 802.1D
    CAP_WLAN_ACCESS_POINT = (1 << 3)    # IEEE Std 802.11 MIB
    CAP_ROUTER = (1 << 4)               # IETF RFC 1812
    CAP_TELEPHONE = (1 << 5)            # IETF RFC 4293
    CAP_DOCSIS = (1 << 6)               # IETF RFC 4639 and IETF RFC 4546
    CAP_STATION_ONLY = (1 << 7)         # IETF RFC 4293
    CAP_CVLAN = (1 << 8)                # IEEE Std 802.1Q
    CAP_SVLAN = (1 << 9)                # IEEE Std 802.1Q
    CAP_TPMR = (1 << 10)                # IEEE Std 802.1Q

    def __init__(self, buf=None, *args, **kwargs):
        super(SystemCapabilities, self).__init__(buf, *args, **kwargs)
        if buf:
            self.subtype = 0
            (self.system_cap, self.enabled_cap) = \
                struct.unpack(self._PACK_STR, self.tlv_info[:self._PACK_SIZE])
        else:
            self.subtype = kwargs['subtype']
            self.system_cap = kwargs['system_cap']
            self.enabled_cap = kwargs['enabled_cap']
            self.len = self._PACK_SIZE
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def serialize(self):
        return struct.pack('!HBHH',
                           self.typelen, self.subtype,
                           self.system_cap, self.enabled_cap)

class OSIRISApp(app_manager.RyuApp):
    _CONTEXTS = {
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(OSIRISApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.CONF.register_opts([
            cfg.StrOpt('unis_domain', default=''),
            cfg.StrOpt('unis_server', default='http://localhost:8888'),
            cfg.StrOpt('unis_update_interval', default='5'),
        ], group="osiris")
        self.domain_name = self.CONF.osiris.unis_domain
        unis_server = self.CONF.osiris.unis_server
        self.interval_secs = int(self.CONF.osiris.unis_update_interval)
        self.logger.info("----- UPDATE INTERVAL IS %d -------" % self.interval_secs)
        self.logger.info("Connecting to UNIS Server at "+unis_server)
        self.logger.info("Connecting to Domain: "+self.domain_name)
        self.rt = Runtime(unis_server, subscribe=False, defer_update=True)
        #UnisRT debug lines
        #unis.logging.setLevel(unis.logging.DEBUG)
        #unis.logging.doTrace(True)
        ###### end debug lines
        self.create_domain()
        self.update_time_secs = calendar.timegm(time.gmtime())
        # Transient dict of LLDP-discovered Nodes, Ports and Links which are reset every cycle
        self.alive_dict = dict()
        # Persistent dict of Switch Nodes, Ports which are not reset every cycle, modified only on OF events
        self.switches_dict = dict()
        # checks for topologies, if none, create a local topology. TODO: if domain_obj has changed, push a topology that references the new guy.
        print("Making Topology...")
        self.instantiate_local_topology()


####### UNIS Update functions #########
    def send_updates_decorator(func):
        """
            This is a decorator which needs to be called when any event occurs, which basically updates UNIS
            about objects whose ts has to be updated
        :return:
        """
        def func_wrapper(self, *args, **kwargs):
            self.send_updates()
            func(self, *args, **kwargs)
        return func_wrapper

    def send_updates(self):
        if not calendar.timegm(time.gmtime()) >= self.update_time_secs:
            return
        self.logger.info("----- UPDATING UNIS DB -------")
        self.update_time_secs = calendar.timegm(time.gmtime()) + self.interval_secs
        self.send_alive_dict_updates()
        self.send_switches_updates()

    def send_updates_force(self):
        self.logger.info("----- UPDATING UNIS DB -------")
        self.update_time_secs = calendar.timegm(time.gmtime()) + self.interval_secs
        self.send_alive_dict_updates()
        self.send_switches_updates()


    def send_switches_updates(self):
        """
            Updates of Switch Nodes, Ports which are not reset every cycle
        :return:
        """

        self.logger.info("----- send_switches_updates -------")
        for id_ in self.switches_dict:
            print(self.switches_dict[id_].ts)
            self.switches_dict[id_].poke()
        self.logger.info("----- send_switches_updates end -------")


    def send_alive_dict_updates(self):
        """
            Updates of LLDP discovered nodes, ports and links which are reset every cycle
        :return:
        """
        self.logger.info("----- send_alive_dict_updates -------")
        self.logger.info(self.alive_dict)
        for id_ in self.alive_dict:

            # Manually doing what poke does to see what is breaking here...
            obj = self.alive_dict[id_]
            obj.__dict__["ts"] = int(time.time() * 1000000)
            payload = json.dumps({"ts": obj.ts})
            obj._runtime._unis.put(obj.selfRef, payload)
            self.logger.info("----- id_ : %s -------" % id_)

            print("PRINTING ALIVE DICT ITEM")
            print(self.alive_dict[id_].selfRef)
            self.alive_dict[id_].commit()
            #self.alive_dict[id_].poke()
        self.logger.info("----- send_alive_dict_updates done -------")
        # reset
        self.alive_dict = dict()
        self.rt.flush()
        print("FLUSHED")

########### OpenFlow event Handlers #############
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    @send_updates_decorator
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

    @set_ev_cls(event.EventSwitchEnter)
    @send_updates_decorator
    def switch_enter_handler(self, ev):
        self.logger.info("**** switch_enter_handler *****")
        self.check_add_switch(ev.switch, ev.switch.dp)
        self.send_desc_stats_request(ev.switch.dp)
        self.logger.info("**** switch_enter_handler done*****")

    @set_ev_cls(ofp_event.EventOFPPortStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    @send_updates_decorator
    def _port_state_change_handler(self, ev):
        datapath_obj = ev.datapath
        port_number = ev.port_no
        print("PORT NUMBER: %s" % port_number)
        print("EV: %s" % ev)
        print(ev.reason)
        reason = ev.reason
        ofproto = datapath_obj.ofproto
        self.logger.info("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&_port_state_change_handler")
        self.logger.info('_port_state_change_handler sv obj: %s', ev.__dict__)

        switch_name = "switch:"+str(datapath_obj.id)
        switch_node = self.check_node(switch_name)
        self.logger.info('Found switch id %s', switch_node.id)

        # test if the port is in the datapath, if it is not it means it has been deleted
        try:
            port = datapath_obj.ports[port_number]
            print(port)
            port_state = port.state
        except Exception:
            port_state = 0


        if port_state == 0:
            # if port state is 0, track down the deleted port object from current switch using the port_number.
            port_object = self.find_port(switch_node.ports, port_index=str(port_number))
            print(port_object)
            self.logger.info('PORT DELETE')

            # checks node for port on whatever port number EV said was deleted and removes it.
            check = self.check_port_in_node_by_port_number(switch_node, str(port_object.index))
            print("Checking port result: %s" % check)

            if check is not None:
                print("Port Object ID to DELETE: %s" % port_object.id)
                print(self.switches_dict)

                self.switches_dict[switch_node.id].ports.remove(port_object)

                self.switches_dict[switch_node.id].update(force=True)


                self.logger.info('PORT DELETED with %d number and %s id', port_number, port_object.id)
            #if port_object is not None and port_object.id in self.switches_dict:
            #    del self.switches_dict[port_object.id]
            #    self.logger.info('PORT DELETED with %d number and %s id', port_number, port_object.id)
        else:
            self.logger.info('PORT ADD or MODIFY')
            port_object = self.find_port(self.domain_obj.ports, port.name.decode("utf-8"))
            if port_object is not None:
                self.logger.info('PORT Already exists')
                if port_object.id not in self.switches_dict:

                    # NEED TO UPDATE VPORT NUMBER AND INDEX CURRENTLY TO REFLECT CONFIGURATION
                    # TODO: get away from using Index for port number, remnant of previous spaghetti.
                    port_object.address.vport_number = port_number
                    port_object.index = str(port_number)
                    port_object.vport_number = port_number
                    print("ADD - ", port_object)
                    # add found port to switch
                    self.switches_dict[switch_node.id].ports.append(port_object)
                    self.rt.flush()
                    print("PORT SUCCESSFULLY ADDED TO SWITCH IN UNIS")

            else:
                # PORT OBJECT NEEDS AN ID, DOESNT GET ADDED TO SWITCH WITHOUT ONE
                port_object = Port({"name": port.name.decode("utf-8"), "index": str(port.port_no), "address":
                    {"address": port.hw_addr, "type": "mac", "port_type":"vport", "vport_number": port.port_no}})
                self.rt.insert(port_object, commit=True)
                self.domain_obj.ports.append(port_object)
                self.switches_dict[switch_node.id].ports.append(port_object)
                self.logger.info('PORT ADDED with %d port number and %s id', port_number, port_object.id)

        # UPDATE UNIS
        self.rt.flush()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    @send_updates_decorator
    def switch_features_handler(self, ev):
        self.logger.info("**** switch_features_handler *****")
        datapath = ev.msg.datapath
        self.add_default_flow(datapath)


    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        """
            Retrieves detailed switch info from OF Desc Stats Reply message and pushes into UNIS switch node
        :param ev:
        :return:
        """
        print("EVALUATION:", ev)
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @send_updates_decorator
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.logger.info("********dpid********" + str(dpid))
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

            # CREATE NODE and PORT
            self.check_add_node_and_port(lldp_host_obj)
            # CREATE the LINK
            self.create_links(datapath, in_port, lldp_host_obj)

######### INIT helper functions ########
    def instantiate_local_topology(self):
        '''
            Creates a new local topology object in unis that references the local domain only.
            Only occurs if there is no topology inside of it.
        '''
        topo_obj = None
        try:
            topo_obj = self.rt.topologies[0]
            self.logger.info("LOCAL TOPOLOGY FOUND")
        except Exception:
            # only if there is no topology, create a new one.
            if topo_obj == None:
                self.logger.info("NO LOCAL TOPOLOGY FOUND - CREATING NEW LOCAL TOPOLOGY")
                new_topo = Topology({"name":"Local Topology"})
                new_topo.domains.append(self.domain_obj)
                self.rt.insert(new_topo, commit=True)
                self.rt.flush()


        return

    def create_domain(self):
        try:
            domain_obj = next(self.rt.domains.where(lambda x: getattr(x, "name", None) == self.domain_name))
        except StopIteration:
            self.logger.info("CREATING A NEW DOMAIN")
            domain_obj = Domain({"name": self.domain_name})
            self.rt.insert(domain_obj, commit=True)
        self.domain_obj = domain_obj

    def send_desc_stats_request(self, datapath):
        """
            Sends OpenFlow ofp_desc_stats message to get more information about the switch
        :param datapath: Switch Datapath Object
        """
        self.logger.info("*****Send send_desc_stats_request*****")
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def deregister_switch(self, datapath):
        self.logger.debug('deregister_switch datapath: %s', datapath.id)
        self.logger.debug(self.check_node('switch:'+str(datapath.id)))
        switch_object = self.check_node('switch:' + str(datapath.id))

        # Remove the port entries
        for port_obj in switch_object.ports:
            del self.switches_dict[port_obj.id]
        #
        # # Remove the node entry from switches dict
        del self.switches_dict[switch_object.id]

    def add_default_flow(self, datapath):
        """
            Adds Default OF flow to send all LLDP packets to the controller
        :param datapath: Switch datapath Object
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if ofproto.OFP_VERSION == 0x01:
            self.logger.info("Openflow Version 1.0")
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                    match=match, actions=actions)
            datapath.send_msg(mod)
            self.logger.info("Flow configured for 1.0")
        elif ofproto.OFP_VERSION == 0x04:
            self.logger.info("Openflow Version 1.3")
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

######### Main Event processing functions #########
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
            self.logger.info("SWITCH NAME: %s | DATAPATH: %s \n" % (switch_node.name, switch_node.datapathid))
            if datapath.address is not None:
                switch_node.mgmtaddress = datapath.address[0]
            self.rt.insert(switch_node, commit=True)
            self.logger.info("*** ADDING TO DOMAIN***\n")
            self.switches_dict[switch_node.id] = switch_node

            # get the node back out of UNIS after commit so it is treated as a UNIS object.
            switch_node = self.check_node(switch_name)
            self.domain_obj.nodes.append(switch_node)
        else:
            self.logger.info("FOUND switch_node id: %s" % switch_node.id)
        self.switches_dict[switch_node.id] = switch_node

        self.logger.info("**** Adding the ports *****\n")

        # Ports
        for port in switch.ports:

            # Search by Port Name - checks if port is already attached to our node.
            port_object = self.check_port(port.name.decode('utf-8'), switch_node)

            if port_object is None:

                # see if the port is already in UNIS
                port_object = self.find_port(self.domain_obj.ports, port.name.decode("utf-8"), port.port_no)

                # Check to see if port is already in UNIS and then add it to the Switch
                # TODO: check by port MAC address instead of port.name to avoid complications in the future
                if port_object is not None:
                    self.logger.info("\nPORT NAME: %s ALREADY IN UNIS PORT DB BUT NOT IN SWITCH\n" % port_object.name)
                    # Add port to switch now, if this IF statement is validated it means the port
                    # was incorrectly not added to the switch previously and is already in UNIS
                    print("PORT NUMBER: %s" % port.port_no)

                    # updates unis port object with the correct port number. Unfortunately the schema is a string..
                    port_object.index = str(port.port_no)
                    port_object.update(force=True)

                    ports_list.append(port_object)

                    self.logger.info("ADDING PORT TO SWITCH UNIS OBJECT %s \n" % self.domain_obj.name)

                    continue # move on to testing the next port

                self.logger.info("!****NEW PORT***!")
                port_object = self.create_vport_object(port)


                self.logger.info("PORT NAME: %s | PORT NUMBER: %s | ADDRESS: %s \n"
                    % (port_object.name, port_object.index, port_object.address.address))
                self.rt.insert(port_object, commit=True)
                self.domain_obj.ports.append(port_object)

            else:
                self.logger.info("\n****OLD PORT***")

                # The following line is a temporary fix so the merge function works correctly
                port_object = self.find_port(self.domain_obj.ports, port.name.decode("utf-8"), port.port_no)
                port_object = self.merge_port_diff(port_object, port)

            ports_list.append(port_object)

        # update the switch with the new list of ports
        switch_node.ports = ports_list
        print(switch_node.ports)
        print("\nSWITCH NODE UPDATE - \n %s", switch_node)
        print("SWITCH DICT: %s" % self.switches_dict)
        self.switches_dict[switch_node.id].ports = ports_list

        #switch_node.update()
        self.rt.flush()


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
            node_name = LLDPUtils.determine_node_name_from_lldp(lldp_host_obj)
            if node_name is None:
                self.logger.error("LLDP Node cannot be added due to insufficient information.")
                return
            node = self.check_node(node_name)

            # Port details
            # Currently this assumes 1:1 between Nodes and Ports <- 9/8/17 This assumption is the source of all the big problems
            # in Ryu D:
            port_name = LLDPUtils.determine_port_name_from_lldp(lldp_host_obj)
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

            self.alive_dict[node.id] = node
            self.alive_dict[port.id] = port

            self.logger.info("Node id:"+node.id)
            self.logger.info("Port id:" + port.id)
        except:
            self.logger.info("Exception in check_add_node_and_port")
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
            # TODO: note to self, when you refacter this spaghetti, below is an example
            # that can be compressed into a single, readable, line of UnisRT code.
            for node in self.rt.nodes:
                if node.name == "switch:"+str(dpid):
                    self.logger.info("SWITCH NODE NAME:"+node.name)
                    self.logger.info("SWITCH NODE ID:" + node.id)
                    for port in node.ports:
                        if port.index == str(in_port):
                            switch_port = port
                            break

            # FIND THE OTHER NODE/PORT
            node_name = LLDPUtils.determine_node_name_from_lldp(lldp_host_obj)
            node = self.check_node(node_name)
            port_name = LLDPUtils.determine_port_name_from_lldp(lldp_host_obj)
            host_port = self.check_port(port_name, node)
            self.logger.info("======Creating a link =======")

            if switch_port is not None and host_port is not None:
                link_name = switch_port.id + ":" + host_port.id
                link_name_2 = host_port.id + ":" + switch_port.id
                link = self.check_link(link_name)
                if link is None:
                    link = self.check_link(link_name_2)

                print("SWITCH PORT: ", switch_port, " ||||||||||||||||||||||||||||||||||||||||||")
                print("HOST PORT: ", host_port, " ||||||||||||||||||||||||||||||||||||||||||")

                # screw it, it works, will nix the source of the issue when after the demo is working 100%
                if switch_port.selfRef == "" or host_port.selfRef == "":
                    print("BAD PORT, SKIPPING LINK CREATION.")
                    return

                if link is None:
                    link = Link({"name": link_name, "directed": False, "endpoints":[switch_port, host_port]})
                        #[{"rel": "full", "href": switch_port.selfRef}, {"rel": "full", "href": host_port.selfRef}]
                    self.rt.insert(link, commit=True)
                    self.domain_obj.links.append(link)
                self.logger.info("Link id:"+link.id)
                self.alive_dict[link.id] = link
        except:
            self.logger.info("Exception in create_links ---------")
            self.logger.info(lldp_host_obj.__dict__)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            self.logger.error(''.join(line for line in lines))

######## Main Event processing helper functions ##########
    def merge_port_diff(self, port_object, port):
        """
            Merges any changes in the port details with the already existing port object
        :param port_object: Already Existing Port object
        :param port: port entry from the OF message
        :return: port_object: Merged port object
        """
        print(port_object.name, port.name.decode('utf-8'))
        if port_object.name != port.name.decode("utf-8"):
            self.logger.info("*** ERROR: Port name is different***")
            return None
        if port_object.index != str(port.port_no):
            port_object.index = str(port.port_no)
        if port_object.address.address != port.hw_addr:
            port_object.address.address = port.hw_addr
        return port_object

    def check_port(self, port_name, switch_node):
        self.logger.info("CHECKING FOR PORT %s IN SWITCH %s" % (port_name, switch_node.name))
        found = 0
        for port in switch_node.ports:
            # Need to convert port_name to UTF-8 because for some reason port_name gets resolved
            # as a byte string, which will always fail tests against port.name UTF-8 format.
            if port.name == port_name:
                found += 1
        if found == 1:
            return port
        elif found > 1:
            return self.logger.info("PORT %s ALREADY FOUND IN SWITCH", port.name)
        else:
            self.logger.info("PORT %s NOT FOUND IN SWITCH %s" % (port_name, switch_node.name))
        return None

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

    def find_switch(self, switches, port_name=None, port_index=None):
        """
            Returns the first instance of Switch Object which matches any condition
        :param switches:
        :param switch_name:
        :param switch_index:
        :return: Switch Object
        """
        for switch in switches:
            if switch_index is not None and switch_index == switch.index:
                return switch
            if switch_name is not None and switch_name == switch.name:
                return switch

    def check_link(self, link_name):
        for link in self.rt.links.where({"name": link_name}):
            return link
        return None

    def check_node(self, node_name):
        for node in self.rt.nodes.where({"name": node_name}):
            return node
        return None

    def check_port_in_node(self, node, port_name):
        for port in node.ports:
            if port.name == port_name:
                return port
        return None

    def check_port_in_node_by_port_number(self, node, port_number):
        for port in node.ports:
            print(port)
            if port.index == port_number:
                return port
        return None

    def create_vport_object(self, port):
        # Takes a port from RYU and converts it into a unisRT port object to push into the DB.

        port_object = Port({"name": port.name.decode("utf-8"), "index": str(port.port_no), "address":
            {"address": port.hw_addr, "type": "mac"},"port_type":"vport", "vport_number": port.port_no})

        return port_object

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
        if lldp_host_obj.port_description is not None:
            port_name = lldp_host_obj.port_description
        elif lldp_host_obj.port_id is not None:
            port_name = "port:"+str(lldp_host_obj.port_id)
        return port_name


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
        self.logger.info(self.port_description)
        self.logger.info(self.system_name)
        self.logger.info(self.system_description)
        self.logger.info(self.management_addresses)

app_manager.require_app('ryu.app.ofctl_rest')
