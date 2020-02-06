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

from itertools import compress
from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER, \
    MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.topology.switches import LLDPPacket
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.ofproto import *
from ryu import cfg
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib.ovs import vsctl
from ryu.lib.ovs.bridge import OVSBridge
from ryu.app.rest_qos import *
from ryu.app.simple_switch_13 import *
from ryu.app.rest_conf_switch import *
from ryu.services.protocols.ovsdb import api as ovsdb
from ryu.services.protocols.ovsdb import event as ovsdb_event
import unis
from unis.models import *
from unis.runtime import Runtime
import lace
from lace.logging import trace
import pprint
from lldp_manager import LLDPHost, LLDPUtils
import requests

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
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'conf_switch': conf_switch.ConfSwitchSet,
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
            cfg.StrOpt('unis_host', default='http://localhost:8888'),
            cfg.StrOpt('ovsdb_addr', default='"tcp:127.0.0.1:6650"')
        ], group="osiris")
         
        
        self.domain_name = self.CONF.osiris.unis_domain
        unis_server = self.CONF.osiris.unis_server
        self.ovsdb_addr = self.CONF.osiris.ovsdb_addr
        self.unis_server = self.CONF.osiris.unis_server
        self.unis_host = self.CONF.osiris.unis_host
        self.interval_secs = int(self.CONF.osiris.unis_update_interval)
        self.logger.info("----- UPDATE INTERVAL IS %d -------" % self.interval_secs)
        self.logger.info("Connecting to UNIS Server at "+unis_server)
        self.logger.info("Connecting to Domain: "+self.domain_name)

        ## UnisRT debug lines
        #trace.setLevel(lace.logging.DEBUG) 
        self.logger.info("UNIS SERVER: " + str( self.CONF.osiris.unis_server))
        self.rt = Runtime([unis_server], proxy={ 'subscribe':True,'defer_update':True} , name="main_rt")

        print(self.rt.settings['proxy'])
       
        
        self.update_time_secs = calendar.timegm(time.gmtime())
        # Transient dict of LLDP-discovered Nodes, Ports and Links which are reset every cycle
        self.alive_dict = dict()
        # Persistent dict of Switch Nodes, Ports which are not reset every cycle, modified only on OF events
        self.switches_dict = dict()
        # checks for topologies, if none, create a local topology. TODO: if domain_obj has changed, push a topology that references the new guy.
       
        self.logger.info("Checked domain")
        self.create_domain()
        self.logger.info("Making Topology...")
        self.instantiate_local_topology()
        self.logger.info("Attemping to Update Host Topology")
        self.check_update_host_topology()
        self.logger.info('UPDATED HOST TOPOLOGY')
        
        self.logger.info("Created initial RT instance")
        
        
        self.nodelist = {}
        
        
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
            if "Open" in self.switches_dict[id_].description:
                continue # fixes the bug where OpenVSwitch Schema nodes were turning into regular nodes ¯\_(ツ)_/¯ will return to this eventually
            self.switches_dict[id_].touch()
        self.logger.info("----- send_switches_updates end -------")
        print("\n LIST OF NODES SEEN: ", self.nodelist)

        # Torch old rt and reinstantiate, for some reason the rt is getting blown during program
        #self.rt = Runtime(self.unis_server, proxy= {"subscribe":False, "defer_update":True})
    def send_alive_dict_updates(self):
        """
            Updates of LLDP discovered nodes, ports and links which are reset every cycle
        :return:
        """
        self.logger.info("----- send_alive_dict_updates -------")
        self.logger.info(self.alive_dict)
        for id_ in self.alive_dict:

            self.logger.info("----- id_ : %s -------" % id_)
            try:

                print("PRINTING ALIVE DICT ITEM")
                print(self.alive_dict[id_].selfRef)
                if not self.alive_dict[id_].selfRef or self.alive_dict[id_].selfRef == '':
                    print("Adding new resource")
                    self.rt.insert(self.alive_dict[id_])
                    self.alive_dict[id_].commit()
                    #self.alive_dict[id_].update()
                    self.alive_dict[id_].touch()
                else: 
                    print("Updating resource")
                    self.alive_dict[id_].commit()
                    #self.alive_dict[id_].update()
                    self.rt.flush()
                    self.alive_dict[id_].touch()
            except:
                print("Could not update - ", self.alive_dict[id_])
            print("OLD TS: ", self.alive_dict[id_].ts)
            print("POKING", self.alive_dict[id_].selfRef)
            self.alive_dict[id_].touch()
            print("NEW TS: ", self.alive_dict[id_].ts, '\n') 
        
        self.logger.info("----- send_alive_dict_updates done -------")
        # reset
        self.alive_dict = dict()
        self.domain_obj.commit()
        self.logger.info('""""""" DOMAIN NODES INFO """""""' + str(self.domain_obj.nodes.getRuntime()) + " " + str(self.domain_obj._rt_live) + " " + str(self.domain_obj._rt_remote))
        self.logger.info("BEFORE FLUSH -" +  str(self.rt._pending))
        self.rt.flush()
        self.logger.info("********** DOMAIN AFTER NODE ADDED ************" + str(self.domain_obj.to_JSON()))
        self.logger.info('"""""" DOMAIN NODES *******' + str(self.domain_obj.nodes._rt_parent.id))
        print("FLUSHED")

########### OpenFlow event Handlers #############

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    @send_updates_decorator
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                pprint.pprint(ev.__dict__) 
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                self.deregister_switch(datapath)

    @set_ev_cls(event.EventSwitchEnter)
    def get_switch_topo(self, ev):
        
        print("Switch Enter Event: ", ev.switch)
        switch_list = get_switch(self, ev.switch.dp.id)
        print("SWITCH: ", switch_list)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self, None)
        links=[(link.src.dpid,link.dst.dpid,{'src':link.src.to_dict(), 'port_dst':link.dst.to_dict()}) for link in links_list]
        print("DISCOVERY")
        print(switches, links)

    @set_ev_cls(event.EventSwitchEnter)
    @send_updates_decorator
    def switch_enter_handler(self, ev): 
        self.logger.info("**** switch_enter_handler *****")
        hex_dpid = "%016x" % ev.switch.dp.id
        """self.logger.info("**** register QoS *****")
        OVSDB_ADDR = 'tcp:127.0.0.1:6650'
        ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
        command = vsctl.VSCtlCommand(
            'find',
            ('Bridge',
            'datapath_id=%s' % hex_dpid))
        
        ovs_vsctl.run_command([command])
        endpoint = "http://localhost:8081/v1.0/conf/switches/" + hex_dpid + "/ovsdb_addr"  
        print("Attempting to register switch id %016x to QoS service." % ev.switch.dp.id)
        print("Endpoint: ", endpoint)
        # dpids need to be in hex for qos stuff
        
        print('"tcp:127.0.0.1:6650"', self.ovsdb_addr) 

        try:
            res = requests.put(endpoint, data = self.ovsdb_addr )
            print("Requested update to OVSDB with switch id " + hex_dpid + " address " + self.ovsdb_addr)
            print(res)
        except Exception as e:
            print("Registration to address " + self.ovsdb_addr + " failed with: " + e)
        
        """
        
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
            port_object = self.find_port(switch_node.ports, port_index=port_number)
            print("searching for vport num: ", port_number)
            for port in switch_node.ports:
                print("port: ", port.name, " - ", port.properties.vport_number)
            print(port_object)
            self.logger.info('PORT DELETE')

            # checks node for port on whatever port number EV said was deleted and removes it.
            check = self.check_port_in_node_by_name(switch_node, port_object.name)
            print("Checking port result: %s" % check)

            if check is not None:
                print("Port Object ID to DELETE: %s" % port_object.id)
                print(self.switches_dict)

                self.switches_dict[switch_node.id].ports.remove(port_object)

                self.switches_dict[switch_node.id].commit()
                self.rt.flush()

                self.logger.info('PORT DELETED with %d number and %s id', port_number, port_object.id)
            #if port_object is not None and port_object.id in self.switches_dict:
            #    del self.switches_dict[port_object.id]
            #    self.logger.info('PORT DELETED with %d number and %s id', port_number, port_object.id)
        else:
            self.logger.info('PORT ADD or MODIFY')
            port_object = self.find_port(self.domain_obj.ports, port_name = switch_name + ":"+ port.name.decode("utf-8"))
            if port_object is not None:
                self.logger.info('PORT Already exists')
                if port_object.id not in self.switches_dict:

                    # NEED TO UPDATE VPORT NUMBER AND INDEX CURRENTLY TO REFLECT CONFIGURATION
                    # TODO: get away from using Index for port number, remnant of previous spaghetti.
                    port_object.address.vport_number = port_number
                    port_object.index = str(port_number)
                    port_object.properties.vport_number = port_number
                    print("ADD - ", port_object)
                    # add found port to switch
                    self.switches_dict[switch_node.id].ports.append(port_object)
                    self.rt.flush()
                    print("PORT SUCCESSFULLY ADDED TO SWITCH IN UNIS")

            else:
                # PORT OBJECT NEEDS AN ID, DOESNT GET ADDED TO SWITCH WITHOUT ONE
                #port_object = Port({"name": port.name.decode("utf-8"), "index": str(port.port_no), "address":
                #    {"address": port.hw_addr, "type": "mac", "port_type":"vport", "vport_number": port.port_no}})
                port_object = self.create_vport_object(port, switch_name)
                self.rt.insert(port_object, commit=True)
                self.domain_obj.ports.append(port_object)
                self.switches_dict[switch_node.id].ports.append(port_object)
                self.logger.info('NEW PORT ADDED')

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
        print("Packet in Hangler: ", msg)
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
        try:
            in_port = msg.match['in_port']
        except Exception:
            in_port = msg.in_port

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.info("LLDP packet in %s %s %s %s %x", dpid, src, dst, in_port, eth_pkt.ethertype)
            lldp_host_obj = LLDPHost(LLDPHost.lldp_parse_new(msg.data), self.logger)
            # CREATE NODE and PORT
            print("MANAGEMENT ADDRESS", lldp_host_obj.management_addresses)
            self.check_add_node_and_port(lldp_host_obj, in_port=in_port)
            # CREATE the LINK
            try:

                self.create_links(datapath, in_port, lldp_host_obj)
            except:
                print("Count not create Link")
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

    def check_update_host_topology(self):
        '''
            Checks the currect osiris.json esque topology on the host node, and update the
            associated hrefs to match the current switch's domain href.

            Also updates the link in the host that connects the topology to ChicPOP
        '''
        self.logger.info("UNIS HOST: " + str(self.unis_host))
        host_rt = Runtime([self.unis_host], name="remote")      # we are going to update the 'main' topology based on the what is in the configuration file
        topology = host_rt.topologies[0]                   # the first topology instance is the most recent and AFAIK the one we want
        topology_dict = topology.to_JSON()                 # this is how we get around the Runtime essentially sandboxing us, treat JSON as a dict.
        href_list = []                                     # create something to store the hrefs we are about to gather
        for i in range(0, len(topology.domains)):          # iterate with respect to key on each domain, test against that href
                domain_href = topology_dict['domains'][i]['href']
                self.logger.info("Finding HREF" + str(domain_href))
                href_list.append(domain_href)

        match = None                                            # instantiate something to store the href if we hit a match

        def clean_up(topology):
            
            domain_exists = False # once we see a domain once we should remove copies of it.
            self.logger.info("Finishing Up startup, cleaning up topologies.")
            new_domains = []
            for domain in topology.domains:
                try:
                    temp_name = domain.name
                    if temp_name == self.domain_obj.name and domain_exists == False:
                        self.logger.info("Ensured instance of local domain in remote topology")
                        new_domains.append(domain)
                        domain_exists = True
                    elif temp_name == self.domain_obj.name and domain_exists == True:
                        self.logger.info("Found Duplicate of local domain obj in remote topology, deleting..")
                        topology.domains.remove(domain)
                        #self.logger.info(topology.domains.to_JSON())
                    else:
                        new_domains.append(domain)
                except:
                    self.logger.info("Delete Broken Domain")
                    topology.domains.remove(domain)
            topology.domains = new_domains
            topology.commit()
            host_rt.flush()
            return

        for index, href in enumerate(href_list):                                # time to sift through the different unis instances

                unis_href = href.split('8888', 1)[0] + '8888' # regex here?, TODO? 
                self.logger.info("TESTING OUT " + str(unis_href))
                current_rt = Runtime([unis_href], name="current"+str(index))
                try:
                        #most_recent_domain = next(current_rt.domains.where({"name":self.domain_obj.name}))
                        most_recent_domain = current_rt.domains[0]
                        self.logger.info("Comparing " + str(self.domain_obj.name) + " with " + str(most_recent_domain.name))

                        if self.domain_obj.name == most_recent_domain.name:  # KEY: production switches now need to properly set the unis_domain setting in the config file from now on
                                self.logger.info("Found current matching domain in UNIS Host...")
                                match = unis_href
                                topology.domains[index] = most_recent_domain
                                host_rt.flush() # not sure if this is necessary, will experiment
                                self.logger.info("\nDomain: " + str(self.domain_obj.name) + ", updated domain object successfully at " + str( topology.selfRef) + " with href - " + str (href) + "\n")
                                topology.commit()
                                self.logger.info("Flushing change to Host RT " + self.unis_host)
                                host_rt.flush()
                                link = '' 

                                try: # update the link as well

                                    link_name = "link-" + self.domain_obj.name + "-CHIC" # string - 'link-UM-CHIC'
                                    self.logger.info("TESTING AGAINST LINK NAME: " + link_name)
                                    link_map = list(map(lambda link: link.name == link_name, topology.links))
                                    self.logger.info("Link Map - " + str(link_map))
                                    for key, l in enumerate(topology.links):
                                            if link_map[key] == True:
                                                    
                                                    print(link_map[key])
                                                    link = l
                                                    link.endpoints[0] = most_recent_domain
                                                    self.logger.info('Verified the link to this domain.\n')
                                                    
                                                    

                                    if link == '' or topology.links == []: # no link was found, add it to the topology
                                        self.logger.info("No link found for this domain, creating and adding it to host topology...")
                                        new_link = Link({"name": link_name,
                                                        "directed": False,
                                                        "endpoints":
                                                            [most_recent_domain,
                                                            {"href" : "$.domains[?(@.name==\"CHIC PoP\")]", "rel": "full"}]})
                                        topology.links.append(new_link)
                                        host_rt.flush()                                    
                                        self.logger.info("Generated new link to the current domain.\n")

                                except Exception:
                                    print("EXCEPTION")
                                    self.logger.info('Could not update interdomain link.')


                except Exception as e:
                        self.logger.exception("Exception: ")
                        self.logger.info("Domain not found, deleting from topology entry")
                        self.logger.info("Domain index: " + str(index) + " | HREF: " + href)


                        self.logger.info('Trouble Updating Unis Host Topology... Continuing')



        if match is None:                                              # TODO: occurs if no match was found, if so then add it to the topology, not sure if would work correctly in this object though..
                self.logger.info('No match found for: ' + str(self.domain_obj.name) + ', adding domain to host site, '+ str( topology.selfRef))
                # not sure how to go about this since a we are not pushing the remote object to the host but instead 'updating' it.
                new_domain = self.domain_obj
                topology.domains.append(new_domain)
                topology.commit()
                host_rt.flush()
        clean_up(topology)

        return

    def create_domain(self):
        try:

            self.domain_obj = next(self.rt.domains.where(lambda x: getattr(x, "name", None) == self.domain_name))

            self.domain_obj = next(self.rt.domains.where({"name" == self.domain_name}))

        except:
            self.logger.info("CREATING A NEW DOMAIN")
            self.domain_obj = Domain({"name": self.domain_name})
            self.rt.insert(self.domain_obj, commit=True)

            self.rt.flush()
        

        self.domain_obj = self.domain_obj

        logging.info("New domain obj: " + str(self.domain_obj.to_JSON()))

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

        print(switch)
        print("SWITCH: ", switch_name)

        self.logger.info("**** Adding the switch *****")
        # Nodes
        switch_node = self.check_node(switch_name)

        if switch_node is None:
            self.logger.info("*** NEW SWITCH***")
            switch_node = OFSwitchNode({"name": switch_name, "datapathid": str(datapath.id)})
            self.logger.info("SWITCH NAME: %s | DATAPATH: %s \n" % (switch_node.name, switch_node.datapathid))
            if datapath.address is not None:
                switch_node.properties.mgmtaddr = datapath.address[0]
            self.rt.insert(switch_node, commit=True)
            self.logger.info("*** ADDING TO DOMAIN***\n")
            self.switches_dict[switch_node.id] = switch_node

            # get the node back out of UNIS after commit so it is treated as a UNIS object.
            switch_node = self.check_node(switch_name)
            self.domain_obj.nodes.append(switch_node)
            self.rt.flush()
            #self.domain_obj.commit()
        else:
            self.logger.info("FOUND switch_node id: %s" % switch_node.id)
        self.switches_dict[switch_node.id] = switch_node

        self.logger.info("**** Adding the ports *****\n")

        # Ports
        for port in switch.ports:

            # Search by Port Name - checks if port is already attached to our node.
            print("SWITCH NODE NAME: ", switch_node.name)
            print("SWITCH NAME", switch_name)
            port_object = self.check_port(switch_name + ":" + port.name.decode('utf-8'), switch_node)

            if port_object is None:

                # see if the port is already in UNIS
                port_object = self.find_port(self.domain_obj.ports, port_name = switch_name + ":" + port.name.decode("utf-8"), port_index = port.port_no)

                # Check to see if port is already in UNIS and then add it to the Switch
                # TODO: check by port MAC address instead of port.name to avoid complications in the future
                if port_object is not None:
                    self.logger.info("\nPORT NAME: %s ALREADY IN UNIS PORT DB BUT NOT IN SWITCH\n" % port_object.name)
                    # Add port to switch now, if this IF statement is validated it means the port
                    # was incorrectly not added to the switch previously and is already in UNIS
                    print("PORT NUMBER: %s" % port.port_no)

                    print("PORT NAME: ", port_object.name)

                    # updates unis port object with the correct port number. Unfortunately the schema is a string..
                    port_object.index = str(port.port_no)
                    port_object.commit()

                    ports_list.append(port_object)

                    self.logger.info("ADDING PORT TO SWITCH UNIS OBJECT %s \n" % self.domain_obj.name)

                    continue # move on to testing the next port

                self.logger.info("!****NEW PORT***!")
                port_object = self.create_vport_object(port, switch_name)


                self.logger.info("PORT NAME: %s | PORT NUMBER: %s | ADDRESS: %s \n"
                    % (port_object.name, port_object.index, port_object.address.address))
                self.rt.insert(port_object, commit=True)
                self.domain_obj.ports.append(port_object)
                self.domain_obj.commit()
            else:
                self.logger.info("\n****OLD PORT***")

                # The following line is a temporary fix so the merge function works correctly
                port_object = self.find_port(self.domain_obj.ports, switch_name + ":" + port.name.decode("utf-8"), port.port_no)
               	
                port_object = self.merge_port_diff(port_object, port, switch_name)
                
            ports_list.append(port_object)

        # update the switch with the new list of ports
        switch_node.ports = ports_list
        print(switch_node.ports)
        print("\nSWITCH NODE UPDATE - \n %s", switch_node)
        print("SWITCH DICT: %s" % self.switches_dict)
        self.switches_dict[switch_node.id].ports = ports_list
        self.logger.info("**** DOMAIN SNAPSHOT ****" + str(self.domain_obj.to_JSON()))
        #switch_node.update()
        self.rt.flush()


    def check_add_node_and_port(self, lldp_host_obj, in_port=None):
        """
            Creates UNIS Nodes and Ports from the LLDPHost information provided.
            Switch Nodes will be created by node_name as switch:<dp-id> and Host Nodes' name will be LLDP System Name.
            As LLDP Advertisement can contain only one Port Information, this function assumes 1:1 relation
            between Host and Ports. <- this is the fatal flaw :(, trying to fix.

        :param lldp_host_obj:
        :return:
        """
        self.logger.info("**check_add_node_and_port***")
        print("HOST DESCRIPTION: ", lldp_host_obj.system_description)
        try:
            # Node Details
            node_name = LLDPUtils.determine_node_name_from_lldp(lldp_host_obj)
            self.nodelist[node_name] = node_name
            if node_name is None:
                self.logger.error("LLDP Node cannot be added due to insufficient information.")
                return
            node = self.check_node(node_name)
            print("SEARCHING FOR NODE NAME: ", node_name," from LLDP Host")
            print("FOUND NODE: ", node.name) if node else print("NODE NOT FOUND....")

            # Port details
            # Currently this assumes 1:1 between Nodes and Ports <- 9/8/17 This assumption is the source of all the big problems
            # in Ryu D:
            port_name = LLDPUtils.determine_port_name_from_lldp(lldp_host_obj)
            print("LLDP_HOST_OBJ:", lldp_host_obj)
            print("CHECKING FOR PORT NAME (LLDPUTILS): ", port_name)
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

                print("CREATING NEW NODE: ", node_name)
                is_of_instance = "Open" in lldp_host_obj.system_description          # had to be done

                if is_of_instance is not True and lldp_host_obj.system_description is not None:
                    node = Node({"name": node_name})
                    self.logger.debug("Updating node description to %s" % lldp_host_obj.system_description)
                    node.description = lldp_host_obj.system_description
                    try:
                        node.properties.mgmtaddr = lldp_host_obj.management_addresses[0]
                    except Exception:
                        print("Couldnt get IP")
                    self.rt.insert(node, commit=True)
                    self.domain_obj.nodes.append(node)
                    self.logger.info("**** PENDING STATUS *******" + str(self.rt._pending)) 
                    
                    self.rt.flush()

            # check to see if port is already on switch
            port = self.check_port_in_node_by_port_number(node, in_port)

            if port is None:
                # Create Port

                print("Creating Port: ", node_name + ":" + port_name )

                port = Port(
                       {"name": node_name + ":" + port_name, "address": {"type": port_address_type, "address": str(port_address)}, "properties":{}})
                port.properties.type = "vport"

                # this is a step to make port matching somewhat reasonable instead of praying it works...
                port.properties.vport_number = in_port # new optional parameter

                self.rt.insert(port, commit=True)
                node.ports.append(port)
                #node.update(force=True)
                self.domain_obj.ports.append(port)
                
                self.rt.flush() 
                
                print(port.name + " added. ")

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
        try:

            dpid = datapath.id
            switch_port = None
            host_port = None


            # FIND SWITCH NODE, FIND SWITCH PORT
            # TODO: note to self, when you refacter this spaghetti, below is an example
            # that can be compressed into a single, readable, line of UnisRT code.
            print("LOOKING FOR SWITCH: ", "switch:"+str(dpid))
            print("SEARCHING FOR PORT NUM: ", str(in_port), " in ", "switch:"+str(dpid))
            for node in self.rt.nodes:
                if node.name == "switch:"+str(dpid):
                    self.logger.info("SWITCH NODE FOUND - NAME:"+node.name)
                    self.logger.info("SWITCH NODE FOUND - ID:" + node.id)
                    for port in node.ports: 
                        if int(port.properties.vport_number) == in_port:
                            switch_node = node
                            switch_port = port
                            print("PORT MATCH: ", port.name, " on port number - ", port.properties.vport_number)
                            break
            if switch_port == None:
                print("NO SWITCH_PORT FOUND")
                print("In port: ", in_port)

            # FIND THE OTHER NODE/PORT
            node_name = LLDPUtils.determine_node_name_from_lldp(lldp_host_obj)
            print("LLDP UTILS FOUND: ", node_name)
            node = self.check_node(node_name)
            print(node.to_JSON())
            port_name = LLDPUtils.determine_port_name_from_lldp(lldp_host_obj)
            port_number = LLDPUtils.determine_port_name_from_lldp(lldp_host_obj)
            print("SEARCHING " + node_name + " for port " + port_name)
            host_port = self.check_port_in_node(node, port_name)
            #print(host_port)
            if host_port is not None:
                print("HOST PORT FOUND - ", host_port.to_JSON())
            else:
                print("Checking as port number: ", port_number)
                try:
                    host_port = self.check_port_in_node_by_port_number(node, port_name)
                    if host_port is not None:
                        print("Found Host Port: ", host_port.name)
                except Exception:
                    return

            #print("SWITCH PORT: ",switch_port.to_JSON())
            if switch_port is not None and host_port is not None:

                self.logger.info("======Creating a link =======")
                print("CONNECTING THESE PORTS")
                #print(host_port.to_JSON(), switch_port.to_JSON())

                print("HOST PORT NAME - ", host_port.name)
                print("SWITCH PORT NAME - ", switch_port.name)


                link_name = switch_port.id + ":" + host_port.id
                link_name_2 = host_port.id + ":" + switch_port.id
                link = self.check_link(link_name)
                if link is None:
                    link = self.check_link(link_name_2)

                print("LINK SWITCH PORT: ", switch_port.name, " ||||||||||||||||||||||||||||||||||||||||||")
                print("LINK HOST PORT: ", host_port.name, " ||||||||||||||||||||||||||||||||||||||||||")
                
                print("SWITCH PORT SELF REF: ", switch_port.selfRef)
                print("HOST PORT SELF REF: ", host_port.selfRef)
                if switch_port.selfRef == "" or host_port.selfRef == "":
                    print("BAD PORT, SKIPPING LINK CREATION.")
                    return

                if link is None:
                    link = Link({"name": link_name, "directed": False, "endpoints":[switch_port, host_port]})
                        #[{"rel": "full", "href": switch_port.selfRef}, {"rel": "full", "href": host_port.selfRef}]
                    self.rt.insert(link, commit=True)
                    self.domain_obj.links.append(link)
                    self.domain_obj.commit()
                    
                self.logger.info("Link id:"+link.id)
                self.alive_dict[link.id] = link
            else:
                print("BAD PORT, SKIPPING LINK CREATION.")
        except:
            self.logger.info("Exception in create_links ---------")
            self.logger.info(lldp_host_obj.__dict__)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            self.logger.error(''.join(line for line in lines))

######## Main Event processing helper functions ##########

    def merge_port_diff(self, port_object, port, switch_name):
        """
            Merges any changes in the port details with the already existing port object
        :param port_object: Already Existing Port object
        :param port: port entry from the OF message
        :return: port_object: Merged port object
        """
        #print(port_object.name, port.name.decode('utf-8'))
        if port_object.name != switch_name + ':' + port.name.decode("utf-8"):
            self.logger.info("*** ERROR: Port name is different***")
            return None
        if port_object.properties.vport_number != str(port.port_no):
            port_object.properties.vport_number = str(port.port_no)
        if port_object.address.address != port.hw_addr:
            port_object.address.address = port.hw_addr
        return port_object

    def check_port(self, port_name, switch_node):
        found = 0
        self.logger.info("CHECKING FOR PORT %s IN SWITCH %s" % (port_name, switch_node.name))
        for port in switch_node.ports:
            # Need to convert port_name to UTF-8 because for some reason port_name gets resolved
            # as a byte string, which will always fail tests against port.name UTF-8 format.
            if port.name == port_name:
                found += 1

        if found == 1:
            return port
        elif found > 1:
            self.logger.info("PORT %s ALREADY FOUND IN SWITCH", port.name)
            return port
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
            #if port_index is not None and port_index == port.properties.vport_number:
            #    return port
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
            if port.name == (node.name + ":" + port_name):
                return port
        return None

    def check_port_in_node_by_name(self, node, port_name):
        for port in node.ports:
            if port.name == port_name:
                return port
        return None

    def check_port_in_node_by_port_number(self, node, port_number):
        for port in node.ports:
            if port.properties.vport_number == int(port_number):
                return port
        return None

    def check_port_by_mac_address(self, node, mac_address):
        """

            Returns the first instance of Port Object which matches any condition
        :param node:
        :param mac_address:
        :return: UnisRT Port Object

        """
        found = 0
        self.logger.info("CHECKING FOR PORT %s IN SWITCH %s" % (port_name, switch_node.name))
        for port in switch_node.ports:
            if port.address.address == mac_address:
                return port

        self.logger.info("PORT %s NOT FOUND IN SWITCH %s" % (port_name, switch_node.name))
        return None

    def create_vport_object(self, port, switch_name):
        # Takes a port from RYU and converts it into a unisRT port object to push into the DB.

        port_object = Port({"name": switch_name + ":" + port.name.decode("utf-8"), "index": str(port.port_no), "address":
            {"address": port.hw_addr, "type": "mac"}})
        port_object.properties.type = "vport"
        port_object.properties.vport_number = port.port_no
        print("CREATING OBJECT FOR NEW PORT: ", port_object.name)
        # ,"port_type":"vport", "vport_number": port.port_no.decode("utf-8")}

        return port_object

app_manager.require_app('ryu.app.simple_switch_13')
app_manager.require_app('ryu.app.rest_conf_switch')
app_manager.require_app('ryu.app.rest_qos')
app_manager.require_app('ryu.app.ofctl_rest')
