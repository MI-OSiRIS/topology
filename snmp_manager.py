from easysnmp import Session
from unis import Runtime
from unis.models import *

# Useful OIDS
ip_table_oid = 'ipNetToPhysicalPhysAddress'
arp_ip_mac_oid = '.1.3.6.1.2.1.3.1.1.2' 
running_procs_oid = 'hrSWRunName'

class SNMP_Manager():

    def __init__(self, host, community="aspiringvision", version=2, rt=None):
        self.host = host
        self.community = community
        self.version = version
        self.session = Session(hostname=self.host, community=self.community, version=self.version)
        self.neighbors = []
        
        self.osiris_service_manifest = [
                { 'name': 'snmpd',       'desc': 'SNMP daemon.',                       'unis_name': 'snmp',       'unis_service_type': 'host:snmp'},
                { 'name': 'ryu-manager', 'desc': 'RYU SDN Controller.',                'unis_name': 'ryu',        'unis_service_type': 'nmal:tools:ryu'},
                { 'name': 'lldpd',       'desc': 'LLDP daemon.',                       'unis_name': 'lldp',       'unis_service_type': 'host:lldp'},
                { 'name': 'periscoped',  'desc': 'UNIS network resource database.',    'unis_name': 'periscope',  'unis_service_type': 'ps:tools:periscope'},
                { 'name': 'node',        'desc': 'NodeJS web application.',            'unis_name': 'nodejs',     'unis_service_type': 'host:node'},
                { 'name': 'blippd',      'desc': 'BLIPP performance monitoring tool.', 'unis_name': 'blipp',      'unis_service_type': 'ps:tools:blipp'},
                { 'name': 'ntpd',        'desc': 'Network Time Protocol Daemon',       'unis_name': 'ntp',        'unis_service_type': 'host:ntp'},
                { 'name': 'schedular',   'desc': 'PSchedular Service',                 'unis_name': 'pschedular', 'unis_service_type': 'ps:tools:pschedular'},
                { 'name': 'archiver',    'desc': 'PerfSONAR Esmond Archive utility',   'unis_name': 'esmond',     'unis_service_type': 'ps:tools:esmond'},
                { 'name': 'owampd',      'desc': 'OWAMP web server',                   'unis_name': 'owamp',      'unis_service_type': 'host:owamp'}]


        # TODO: make runtime element from config, hardcode placeholder for now
        if rt is None:
            self.rt = Runtime('http://172.18.0.25:9000')
        else:
            self.rt = rt

    #
    #    SNMP Query Helpers
    #
    ################
    
    '''
        SNMP Query a Host for its IP Routing Table. This OID corresponds to link layer `arp -a` command.
    
        Returns a list of IP/Mac address values styled {'ip': <ip address value>, 'dict':<mac address value>}
    '''
    def get_ip_routes(self, host=None):

        if host is not None:
            self.session = Session(hostname=host, community=self.community, version=self.version)

        ret = self.session.walk(ip_table_oid)
        result = []

        for item in ret:
            mac = self.convert_mac_addr(item.value)
            ip  = self.parse_ip_addr(item.oid_index)
            ip_mac_dict = { 'ip': ip, 'mac': mac}
            result.append(ip_mac_dict)

            self.neighbors.append(ip_mac_dict)
        
        return result

    def get_services_list(self, host=None):

        session = Session(hostname=host, community=self.community, version=self.version)        
        
        try:
            query = session.walk(running_procs_oid)
        except Exception as e: 
            print(e)
            print('SNMP Service Query Failed')
            return

        result = []
        s_name_track = []

        for item in query:
            s = self.service_in_manifest(item.value) 
            if len(s) == 1:
                if s[0]['name'] not in s_name_track:
                    s_name_track.append(s[0]['name'])
                    result.append(s[0])

        return result

    #
    #    Use SNMP information to update resources.
    #
    ##############

    '''
        Takes a dict { ip: <val>, mac: <val>}.

        Generates a new node resource to be added to the topology. Handle link generation.
        Links are based off the mac address
    '''
    def add_discovered_node(self, ip_mac_dict):
        
        ip = ip_mac_dict['ip']
        mac = ip_mac_dict['ip']

        node = Node({
                'name': ip,
                'description': ('Discovered by ' + self.host + ' via SNMP'),
                'properties': {
                        'mgmtaddr': ip
                    }
            })
        
        port = Port({
                    'name': ip + ':' + mac,
                    'address' : {
                            'type':'mac',
                            'address': mac
                        },
                    'properties':{
                            'type':'virtual_link',
                            
                        }
                })

        try:
            node.ports.append(port) 
            node = self.rt.insert(node, commit=True)
            port = self.rt.insert(port, commit=True) 
            self.rt.domains[0].nodes.append(node)
            self.rt.domains[0].ports.append(port)
            self.rt.domains[0].commit()
            self.rt.flush()
        except:
            raise AttributeError("Could not commit Object to Domain")
        return node
    
    '''
        The SNMP query will give the local routing table for a given resource.

        If a node is discovered, ensure there is a valid link for it given the namescheme. 
        If there is no link describing this connection, make one.
    '''
    def test_link(self, test_node):
        
        host_node = self.check_node_exists(ip=self.host)
        
        print("Testing for links between ", host_node.name, " and ", test_node.name) 
       
            
        for host_port in host_node.ports:
            for test_port in test_node.ports:
                test_link_name = host_port.id + ':' + test_port.id
                test_link_name2 = test_port.id + ':' + host_port.id
                for link in self.rt.links:
                    if link.name == test_link_name or link.name == test_link_name2:
                        print("FOUND LINK connecting ", host_node.name, " and ", test_node.name)
                        return link

        print("Could not find link connecting ", host_node.name," and ", test_node.name, " - CREATING LINK.")

        # need to determine specific ports for link generation, TODO
        link = Link({
                'name': host_node.ports[0].id + ':' + test_node.ports[0].id,
                'endpoints': [test_node.ports[0], host_node.ports[0]],
                'directed': False,
                'properties': {
                        'type':'arp',
                    }
            })

        self.rt.insert(link, commit=True)
        self.rt.domains[0].links.append(link)
        self.rt.domains[0].commit()
        self.rt.flush()
        print("New link created.")

        return link

    '''
        Query the currently running services for a given host.

        Test to see if the service exists. If it does, poke the timestamp.
        If it does not, create a new service entry and push it to UNIS.

        If there is a service entry no longer running on the Host set the service to 
        not running.
    '''
    def update_services(self, ip):
        services_list = self.get_services_list(host=ip)
        print("Service List for ", ip, " - ", services_list)
        
        node = self.check_node_exists(ip=ip)
        unis_services = []
        
        if node is not None:
            services = self.rt.services.where({'runningOn':  node, 'status':'ON' })
            
            try:
                for s in services:
                    unis_services.append(s) 
            except:
                print('Could not find any existing UNIS entries for services at host ' + node.name)
 
            # check if service exists in UNIS, if not create one
            for item in services_list:
                 
                matches = list(filter(lambda s: s.name == item['unis_name'], unis_services))
                
                if len(matches) > 0: # if there are matches, touch
                    print("Found existing service for " + item['unis_name'] + " at host " + node.name + ". Updating timestamp.")
                    map(lambda s: s.touch(), matches)
                else:
                    # create new services
                    print('Creating new service for ' + item['unis_name'] + ' at host ' + node.name)
                    service = Service({'name':item['unis_name'], 'runningOn': {'href': node.selfRef, 'rel': 'full'}, 'status':'ON', 'serviceType': item['unis_service_type']})
                    self.rt.insert(service, commit=True)

            self.rt.flush()

        else:
            print('Node not found for ' + ip + ', continuing.')

        return

    '''
       
        apply_snmp_nodes will search through a list of dicts { ip: <val>, mac: <val>} to see if a corresponding node
        exists in UNIS. if the node does not exist it will register the node in UNIS.

        Once all dicts in the supplied list have been processed, query the SNMP query the ip and repeat the function
    
    '''
    def apply_snmp_nodes(self, ip_mac_list):
        
        for i in ip_mac_list:
             
            print('Checking - IP: ', i['ip'], " | Mac: ", i['mac'])
            n = self.check_node_exists(ip = i['ip'], mac = i['mac'])
            
            if n is None:
                print("Node with IP address ", i['ip'], " not found. CREATING NEW NODE resource.")
                n = self.add_discovered_node(i)
            else:
                print("FOUND NODE with IP address ", n.properties.mgmtaddr) 
            
            # see if there is a valid link in UNIS for this node.
            self.test_link(n)

        # find and update service entries in UNIS for this host.
        self.update_services(self.host) 
   
        return
    
    '''
        Main function for learning about the network.
    '''
    def discover(self):
        
        print("BEGIN discovery of base host ", self.host)
        snmp_ip_mac_list = self.get_ip_routes()
        self.apply_snmp_nodes(snmp_ip_mac_list)
    
    def discover_neighbors(self):
        for ip_mac_dict in self.neighbors:
            try:
                
                print("Trying to query ", ip_mac_dict['ip'])
                snmp_q = SNMP_Manager(host=ip_mac_dict['ip'], rt=self.rt)
                snmp_q.discover()

                print("Successful Query of ", ip_mac_dict['ip']) 
            except:
                print("Error querying SNMP for , ", ip_mac_dict["ip"], " - continuing.")
                continue
    #
    #   Helper Functions for processing SNMP Results
    #
    ##########

    def convert_mac_addr(self, mac_str):
        byte_from_string = mac_str.encode()
        return byte_from_string.hex()

    def parse_ip_addr(self, ip_oid):
        ip_addr = '.'.join(ip_oid.split('.')[-4:])
        print(ip_addr)
        return ip_addr

    def service_in_manifest(self, service_string):
        result = list(filter(lambda s: s['name'] == service_string, self.osiris_service_manifest))
        return result

    #
    #   UNIS Integration
    #
    #########

    def check_node_exists(self, ip = None, mac = None):
        if ip is None and mac is None:
            raise ValueError('Function check_node_exists must be given an ip=<ip address> or mac=<mac address> parameter.')
        
        for n in self.rt.nodes:
            if n.properties.mgmtaddr == ip:
                return n
        
        return None

'''
    Local Docker test case.
'''
if __name__ == "__main__":
    snmp = SNMP_Manager('172.18.0.30')
    snmp.discover()
    snmp.discover_neighbors()

    snmp = SNMP_Manager('172.18.0.40')
    snmp.discover()
    snmp.discover_neighbors()
