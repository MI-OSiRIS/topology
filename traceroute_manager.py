from scapy.all import *
from unis import Runtime
from unis.models import *
import sys
import traceback

'''
    Simple class for using scapy to do traceroute. Arranges hops into an ordered list of dicts.
'''
class Traceroute:
    def __init__(self, host=None):
        self.host = host
        return

    def trace(self, target):
        # Traceroute with Scapy
        ans, unans = traceroute(target, verbose=False)
        
        hops = [{'ttl':snd.ttl, 'ip':rcv.src} for snd, rcv in ans]

        return hops

class Traceroute_Manager:

    def __init__(self, host_rt=None, remote_rt=None, host_node_name=None):
        # TODO: read in defaults from a config.
        '''if host_rt == None:
            self.host_rt = Runtime("http://iu-ps01.osris.org:8888", name = "host")
        else:
            self.host_rt = host_rt
        '''
        self.host_rt = self._setup_runtime(host_rt)
        print(self.host_rt)
        if remote_rt == None:
            self.remote_rt = Runtime("http://iu-ps01.osris.org:8888", name = "remote")
        else:
            self.host_rt = remote_rt

        if host_node_name == None:
            try:
                # TODO: fix hard code host node
                self.host_node = next(self.host_rt.nodes.where({"name":"switch:647020279235264"}))
            except:
                traceback.print_exc()
                print("Not a valid node name. Exitting..")
                sys.exit(0)
        else:
            try:
                self.host_node = next(self.host_rt.nodes.where({"name":host_node_name}))
            except:
                print("Not a valid node name. Exitting..")
                sys.exit(0)

        self._register_to_topology()
        self.tc = Traceroute()
        

        return

    def _setup_runtime(self, host_rt):
        # Setting up RT sources
        rt = Runtime(host_rt)
        topo_dict = rt.topologies[0].to_JSON()
        hrefs = []
        for item in topo_dict['domains']:
            href = item['href'].split('/domains')[0]
            if href not in hrefs:
                hrefs.append(href)
        print("Href list: ", hrefs)
        return  Runtime(hrefs, name="host")
        
    
    '''
        Visits a UNIS instance to ensure that the Tracerout domain exists,
            if it does not exist, create it and add it to the topology.
    '''
    def _register_to_topology(self):
        
        topology = self.host_rt.topologies[0]
        
        print("Looking for Traceroute Domain") 
        try: 
            self.tc_domain = next(self.host_rt.domains.where({"name":"TracerouteV"}))
            print("Found existing Traceroute domain on UNIS host")
            if self.tc_domain in topology.domains:
                print("Domain already registered, continuing..")
            else:
                print("Traceroute domain not found in topology. Adding it to topology's domains")
                topology.domains.append(self.tc_domain)
        except:
            print("No Traceroute Domain found on UNIS host, creating one..")
            self.tc_domain = Domain({"name":"TracerouteV"})
            self.host_rt.insert(self.tc_domain, commit = True)
            topology.domains.append(self.tc_domain) 
                  
        self.host_rt.flush()

        return
    '''
        @param:pattern:string - string of a node name search pattern you are looking for in each domain.

        The nodes retrieved from this setup phase will be used as targets for traceroute and pathing.
    '''
    def _setup(self, pattern):
        # get the local domain, this is the 'source'
        host_domain = self.host_rt.domains[0]
        
        target_domains = self.remote_rt.topologies[0].domains
        target_nodes   = []
        
        #
        # This mess is to handle when a resource can't be resolved. 
        # Only an issue because we are navigating resources in multiple
        # Runtimes on the fly. 
        #
        for d in range(len(target_domains)):
            try:
                current_domain = target_domains[d]    
            except:
                continue
            for n in range(len(current_domain.nodes)):
                try:
                    current_node = current_domain.nodes[n]
                    if pattern in current_node.name:
                        target_nodes.append(current_node)
                except Exception as e:
                    continue

        return target_nodes

    ''' 
        @param:node:UNISNode

        takes a valid Node retrieved in self._setup method and uses traceroute to get the hops to it.
    '''
    def build_path(self, node):
        
        path_nodes = [self.host_node]

        # attempt to trace the path 
        try:
            hops = self.tc.trace(node.properties.mgmtaddr)
        except Exception as e:
            print("Exception: ", e.__traceback__)
            print("Unable to reach IP address of node: " + node.name + " - " + node.properties.mgmtaddr)
        
        # keep track of hops, for each hop test against UNIS and build accordingly
        last_hop = self.host_node
        for hop in hops:

            path_nodes.append(hop)

            print("Last Hop: " + last_hop.name + " - " + last_hop.properties.mgmtaddr)
            
            print("Searching for next hop in UNIS")
            try:
                
                next_hop = next(self.host_rt.nodes.where(lambda n: n.properties.mgmtaddr == str(hop['ip'])))
                print("NEXT HOP", next_hop)
                next_port = next_hop.ports[0]
                print("Next Hop found in UNIS..")
                try:
                    link = next(self.host_rt.links.where(lambda l: l.name == (last_hop.ports[0].id + ":" + next_port.id)))
                    print("Existing Link found between " + last_hop.name + " and " + next_hop.name)
                except:
                    print("No existing link between " + last_hop.name + " and " + next_hop.name + ", creating new link..")
                    link = Link({"name": (last_hop.ports[0].id + ":" + next_port.id), "directed":False, "endpoints":[last_hop.ports[0], next_port]})
                    self.host_rt.insert(link, commit = True)
                    self.tc_domain.links.append(link) 
                
                print("Added discovered node " + next_hop.name) 
                
                
            except Exception as e:
                traceback.print_exc() 
                print("Node not found for hop " + str(hop["ttl"]) + ", Creating new node")
                next_hop = Node({"name":hop["ip"], "properties":{"mgmtaddr":hop["ip"]}})
                next_port = Port({"name":(hop["ip"] + ":port:" + "TraceRoute"), "address":{"type":"ip", "address":hop["ip"]}})
                
                self.host_rt.insert(next_hop, commit = True)
                self.host_rt.insert(next_port, commit = True)

                next_hop.ports.append(next_port)

                link = Link({"name": (last_hop.ports[0].id + ":" + next_port.id), "directed":False, "endpoints":[last_hop.ports[0], next_port]})
        
                self.host_rt.insert(link, commit=True)
                print("Created Node - " +  next_hop.id)
                print("Created Port - " + next_port.id)
                print("Created Link between " + last_hop.name + " and " + next_hop.name)
                

                self.tc_domain.nodes.append(next_hop)
                self.tc_domain.links.append(link)

            self.host_rt.flush()
            if last_hop.properties.mgmtaddr == next_hop.properties.mgmtaddr:
                return hops
            else:
                last_hop = next_hop

        return

if __name__ == '__main__':
    tcm = Traceroute_Manager(host_rt = "http://iu-ps01.osris.org:8888")
    target_nodes = tcm._setup("virt")
    for node in target_nodes:
        print(node.to_JSON())
        hops = tcm.build_path(node)
        print(hops)
