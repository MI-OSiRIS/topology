from easysnmp import Session


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
            self.rt = Runtime('periscope:9000')
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

    def convert_mac_addr(self, mac_str):
        byte_from_string = mac_str.encode()
        return byte_from_string.hex()

    def parse_ip_addr(self, ip_oid):
        ip_addr = '.'.join(ip_oid.split('.')[-4:])
        print(ip_addr)
        return ip_addr

if __name__ == "__main__":
    snmp = SNMP_Manager('172.18.0.30')
    print(snmp.get_ip_routes())
