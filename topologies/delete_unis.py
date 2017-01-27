import requests
import coreapi
import sys

class CleanUnis:
    def __init__(self, host_name_unis, port_number_unis):
        self.unis_uri = "http://" + host_name_unis + ":" + port_number_unis + "/"
        self.clean_all()

    def clean_all(self):
        print("Starting the initial CLEANUP PROCESS")
        self.clean_domains()
        self.clean_topology()
        self.clean_nodes()
        self.delete_ports()
        self.delete_links()

    def clean_topology(self):
        print("Deleting the Topology")
        topology_uri = self.unis_uri + "topologies"
        topology_list = coreapi.get(topology_uri)
        for topo_dict in topology_list:
            print topo_dict['selfRef']
            # requests.delete(node_dict['selfRef'])
            del_uri = topology_uri + "/" + topo_dict['selfRef'].split("/")[4]
            requests.delete(del_uri)

    def clean_domains(self):
        print("Deleting the Domains")
        domains_uri = self.unis_uri + "domains"
        domain_list = coreapi.get(domains_uri)
        for domain_dict in domain_list:
            print domain_dict['selfRef']
            # requests.delete(node_dict['selfRef'])
            del_uri = domains_uri + "/" + domain_dict['selfRef'].split("/")[4]
            requests.delete(del_uri)

    def clean_nodes(self):
        print("Deleting the nodes")
        nodes_uri = self.unis_uri+"nodes"
        nodes_list = coreapi.get(nodes_uri)
        for node_dict in nodes_list:
            print node_dict['selfRef']
            # requests.delete(node_dict['selfRef'])
            del_uri = nodes_uri+"/"+node_dict['selfRef'].split("/")[4]
            requests.delete(del_uri)

    def delete_ports(self):
        print("Deleting the ports")
        ports_uri=self.unis_uri+"ports"
        ports_list = coreapi.get(ports_uri)
        for port_dict in ports_list:
            print port_dict['selfRef']
            del_uri=ports_uri+"/"+port_dict['selfRef'].split("/")[4]
            print("Delete:"+del_uri)
            requests.delete(del_uri)

    def delete_links(self):
        print("Deleting the links")
        links_uri=self.unis_uri+"links"
        links_list = coreapi.get(links_uri)
        for link_dict in links_list:
            print link_dict['selfRef']
            # requests.delete(port_dict['selfRef'])
            del_uri = links_uri+"/"+link_dict['selfRef'].split("/")[4]
            print("Delete:"+del_uri)
            requests.delete(del_uri)

if __name__ == "__main__":
    if len(sys.argv) == 3:
        CleanUnis(sys.argv[1], sys.argv[2])
    else:
        print("Usage: <unis-ip> <unis-port>")
