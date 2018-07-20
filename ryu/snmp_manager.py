from easysnmp import Session
from unis import Runtime
from unis.models import *

# Useful OIDS
ip_table_oid = 'ipNetToPhysicalPhysAddress'
arp_ip_mac_oid = '.1.3.6.1.2.1.3.1.1.2' 

class SNMP_Manager():
    def __init__(self, host, community="aspiringvision", version=2, rt=None):
        self.host = host
        self.community = community
        self.version = version
        self.session = Session(hostname=self.host, community=self.community, version=self.version)
        
        # make runtime element from config, hardcode placeholder for now
        if rt is None:
            self.rt = Runtime('http://periscope:9000')
        else:
            self.rt = rt

    def get_ip_routes(self):

        ret = self.session.walk(ip_table_oid)
        result = []

        for item in ret:
            mac = self.convert_mac_addr(item.value)
            ip  = self.parse_ip_addr(item.oid_index)
            ip_mac_dict = { 'ip': ip, 'mac': mac}
            result.append(ip_mac_dict)
        
        return result

    '''
        One of the 'main' function defs.

        apply_snmp_nodes will search through a list of dicts { ip: <val>, mac: <val>} to see if a corresponding node
        exists in UNIS. if the node does not exist it will register the node in UNIS.

        Once all dicts in the supplied list have been processed, query the SNMP query the ip and repeat the function
    '''
    def apply_snmp_nodes(self, ip_mac_list):
        
        for i in ip_mac_list:
            
            print(i)
            print('IP: ', i['ip'], " | Mac: ", i['mac'])
            n = self.check_node_exists(ip = i['ip'], mac = i['mac'])
            
            if n is None:
                print("Node with IP address ", i['ip'], " not found. Creating new node resource.")


        return
    
    '''
        Main function for learning about the network.
    '''
    def discover(self):
        snmp_ip_mac_list = self.get_ip_routes()
        self.apply_snmp_nodes(snmp_ip_mac_list)

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

    #
    #   UNIS Integration
    #
    #########

    def check_node_exists(self, ip = None, mac = None):
        if ip is None and mac is None:
            raise ValueError('Function check_node_exists must be given an ip=<ip address> or mac=<mac address> parameter.')
        
        for n in self.rt.nodes:
            if n.properties.mgmtaddr == ip or n.mgmtaddress == ip:
                return n
        
        return None

if __name__ == "__main__":
    snmp = SNMP_Manager('172.18.0.30')
    snmp.discover()
