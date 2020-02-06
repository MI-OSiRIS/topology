from topology import Topology, Node, Port, IntermediateNode
import json
import requests
from requests.auth import HTTPBasicAuth
import coreapi

class SC16:
    SCHEMAS = {
        'networkresources': 'http://unis.crest.iu.edu/schema/20151104/networkresource#',
        'nodes': 'http://unis.crest.iu.edu/schema/20151104/node#',
        'domains': 'http://unis.crest.iu.edu/schema/20151104/domain#',
        'ports': 'http://unis.crest.iu.edu/schema/20151104/port#',
        'links': 'http://unis.crest.iu.edu/schema/20151104/link#',
        'paths': 'http://unis.crest.iu.edu/schema/20151104/path#',
        'networks': 'http://unis.crest.iu.edu/schema/20151104/network#',
        'topologies': 'http://unis.crest.iu.edu/schema/20151104/topology#',
        'services': 'http://unis.crest.iu.edu/schema/20151104/service#',
        'blipp': 'http://unis.crest.iu.edu/schema/20151104/blipp#',
        'metadata': 'http://unis.crest.iu.edu/schema/20151104/metadata#',
        'datum': 'http://unis.crest.iu.edu/schema/20151104/datum#',
        'data': 'http://unis.crest.iu.edu/schema/20151104/data#',
        'ipports': 'http://unis.crest.iu.edu/schema/ext/ipport/1/ipport#'
    }

    domain_list = [
            {'domain_name': 'IU',
             'domain_ref': '',
             'nodes': [
                        {'node_name': 'IU',
                         'node_ref': '',
                        'links': [
                                    {'source': 'IU',
                                    'sink': 'CHIC'
                                    }
                                ]
                         }
                        ]
            }
    ]

    def __init__(self, host_name_unis, port_number_unis):
        self.topology_object = Topology()
        self.unis_uri = "http://" + host_name_unis + ":" + port_number_unis + "/"
        self.clean_all()

    def clean_all(self):
        print("Starting the initial CLEANUP PROCESS")
        self.clean_domains()
        self.clean_topology()
        self.clean_nodes()
        self.delete_ports()
        self.delete_links()
        # self.create_nodes()
        # self.update_node_refs()
        # self.create_domains()
        # self.update_domain_refs()


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
            # requests.delete(port_dict['selfRef'])
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

    def create_domains(self):
        domain_dict_list = []
        domains_uri = self.unis_uri+"domains"
        for domain in self.domain_list:
            domain_dict = dict()
            domain_dict["$schema"] = self.SCHEMAS['domains']
            domain_dict["name"] = domain['domain_name']
            nodes_dict_list = []
            nodes_list = self.get_nodes_from_domain_list(domain['domain_name'])
            for node in nodes_list:
                nodes_dict_list.append({'name': 'IU'})
            domain_dict["nodes"] = nodes_dict_list
            domain_dict_list.append(domain_dict)
        json_data = json.dumps(domain_dict_list)
        print("Domain URI::" + domains_uri)
        print("***** DOMAINS JSON DATA:" + json_data)
        requests.post(domains_uri, data=json_data)

    def get_nodes_from_domain_list(self, domain_name):
        for domain in self.domain_list:
            if domain['domain_name'] == domain_name:
                return domain['nodes']

    def update_domain_refs(self):
        domains_uri = self.unis_uri + "domains"
        domains_list = coreapi.get(domains_uri)
        for domain in domains_list:
            print domain['name']
            print domain['selfRef']
            # node_object = Node(domain['name'])
            self.add_domain_ref_to_list(domain['name'], domain['selfRef'])
            # self.topology_object.add_node(self.getId(check_node['selfRef']), node_object)
            print "\n"

        print(self.domain_list)
        # self.topology_object.display_topology()

    def add_domain_ref_to_list(self, domain_name, domain_ref):
        for domain in self.domain_list:
            if domain['domain_name'] == domain_name:
                domain['domain_ref'] = domain_ref
                return

    def create_nodes(self):
        nodes_uri = self.unis_uri+"nodes"
        nodes = []

        for domain in self.domain_list:
            for node_dict in domain['nodes']:
                node = dict()
                node["$schema"] = self.SCHEMAS['nodes']
                node["name"] = node_dict['node_name']
                # print node_dict['node-id']
                nodes.append(node)
        print "::FINAL JSON::"
        json_data = json.dumps(nodes)
        print("NODE URI::" + nodes_uri)
        print("JSON DATA:" + json_data)
        requests.post(nodes_uri, data=json_data)


    def update_node_refs(self):
        nodes_uri = self.unis_uri+"nodes"
        nodes_list = coreapi.get(nodes_uri)
        for check_node in nodes_list:
            print check_node['name']
            print check_node['selfRef']
            node_object = Node(check_node['name'])
            self.topology_object.add_node(self.getId(check_node['selfRef']), node_object)
            self.add_node_ref_to_domain_list(check_node['selfRef'], check_node['name'])
            print "\n"
        self.topology_object.display_topology()

    def add_node_ref_to_domain_list(self, node_ref, node_name):
        for domain in self.domain_list:
            for node in domain['nodes']:
                if node['node_name'] == node_name:
                    node['node_ref'] = node_ref
                    return

    def getId(self, ref_url):
        """
            http://10.10.0.135:8888/nodes/56f88569e1382308b0b6a2ea will return 56f88569e1382308b0b6a2ea
        :param ref_url:
        :return:
        """
        print("getId::"+ref_url)
        return ref_url.split("/")[4]

    def create_ref_url(self, type, id=None):
        """
            It will build the url from type and id
        :param type: ports or nodes
        :param id:
        :return:
        """
        if id is None:
            return self.unis_uri+type
        return self.unis_uri+type+"/"+id

SC16('10.10.0.135', '8888')