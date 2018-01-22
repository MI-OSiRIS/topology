import os
import unis
from configparser import ConfigParser
from unis.models import *
from unis.runtime import Runtime
import pprint as pp
#from unis import logging as ulog
#from unis.models.models import UnisList

# TODO: check Unis for existing resources before pushing them.

class StaticResourceBuilder:
    '''
        Static Resource Builder generates UnisRT Objects based on the Static Resource file defined in :filepath: parameter.

        The object parses the file to build UnisRT resources and then pushes them to the given runtime in :runtime: parameter.
        Each time StaticResourceBuilder.manifest() is called, the object will build the resources using build() and then create all defined linkages with connect().
    '''

    def __init__(self, filepath, runtime):
        self.filepath = filepath
        self.rt = runtime
        self.parser = ConfigParser()
        self.nodes = []
        self.ports = []
        self.links = []

        try:
            self.parser.read(self.filepath)
        except Exception:
            print("INVALID FILE PATH FOR STATIC RESOURCE INI")
            return

##############################################################################################
    '''
        Main calls for the StaticResourceBuilder.

        Pulls in information from the parsed .ini file and creates temporary UnisRT objects.
    '''

    def build(self):

        for section in self.parser.sections():
            current_section = self.parser[section]
            if current_section['Type'] == "Node":
                self.build_node(current_section)
            elif current_section['Type'] == "Port":
                self.build_port(current_section)
            elif current_section['Type'] == "Link":
                self.build_link(current_section)

    '''
        After building the temp UnisRT objects, go through the resources and put them together based on configuration.
    '''

    def connect(self):
        for node in self.nodes:
            print(node.temp_ports)
            self.connect_ports(node)
        for link in self.links:
            self.connect_links(link)

    def manifest(self):
        self.build()
        self.show_resources()
        self.connect()

##############################################################################################
    '''
        Defined Methods for building resources. For now fields are static and must be given,
            if necessary this could be extended to be more dynamic with optional parameters.
    '''

    def build_node(self, item):
        node = Node()
        node.name = item['Name']
        node.mgmtaddress = item['Address']
        node.description = item['Description']
        node.temp_ports = item['Ports'].split(' ')

        check_node = self.check_node_in_unis(node)

        if check_node == None:
            self.rt.insert(node, commit=True)
            self.nodes.append(node)
            print("NODE NOT FOUND IN UNIS... UPLOADING ENTRY")
        else:
            print("Node ", node.name, "already in UNIS.")
            self.nodes.append(check_node)
            self.nodes[-1].temp_ports = item['Ports'].split(' ')

    def build_port(self, item):
        port = Port()
        port.name = item['Name']
        port.address.type = item['AddressType']
        port.address.address = item['Address']
        port.properties.type = item['PortType']
        port.properties.port_number = item['PortNumber']

        check_port = self.check_port_in_unis(port)

        if check_port == None:
            self.rt.insert(port, commit=True)
            print("PORT NOT FOUND IN UNIS... UPLOADING ENTRY")
        else:
            print("Port ", port.name, "already in UNIS.")
            self.ports.append(check_port)


    def build_link(self, item):
        link = Link()
        link.directed = item['Directed']
        link.temp_host_endpoint = item['HostPort']
        link.temp_dest_endpoint = item['DestPort']
        link.endpoints = []

        self.links.append(link)

##############################################################################################
    '''
        Defined methods for connecting resources defined in the .ini file.
    '''

    def connect_ports(self, node):
        print("TPORTS: ", node.temp_ports)
        for tport in node.temp_ports:
            for port in self.ports:
                print("Checking ", tport, " - ", port.name)
                if port.name == tport:
                    print("Match ", tport)
                    node.ports.append(port)

    def connect_links(self, link):
        for port in self.ports:
            if port.name == link.temp_host_endpoint:
                link.endpoints.source = port
            elif port.name == link.temp_dest_endpoint:
                link.endpoints.destination = port

        if self.check_link_in_unis(link) == None:
            print("UPLOADING LINK ENTRY ")
            self.rt.insert(link, commit=True)

        else:
            print("Link ", link.name, "already in UNIS.")
        return

##############################################################################################
    '''
        Helper functions
    '''

    def check_port_in_unis(self, port):
        port_name = port.name
        print("CHECKING FOR PORT ", port_name)
        for port in self.rt.ports:
            if port.name == port_name:
                return port

        print("PORT NOT FOUND IN UNIS", r_name)
        return None

    def check_node_in_unis(self, node):
        node_name = node.name
        print("CHECKING FOR RESOURCE ", node_name)
        for node in self.rt.nodes:
            if node.name == node_name:
                return node

        print("NODE NOT FOUND IN UNIS", r_name)
        return None

    def check_link_in_unis(self, link):
        link_name = link.name
        print("CHECKING FOR LINK ", link_name)
        for link in self.rt.links:
            if link.name == link_name:
                return item

        print("LINK NOT FOUND IN UNIS", link_name)
        return None


    def show_resources(self):
        pp.pprint(self.nodes)
        pp.pprint(self.ports)
        pp.pprint(self.links)


#############################################################################################
'''
    Main defined for convenient testing. And Usage.
'''
if __name__ == "__main__":
    rt = Runtime('http://msu-ps01.osris.org:8888',
                 subscribe=False, defer_update=True)
    SRB = StaticResourceBuilder('config/static_resources.ini', rt)
    SRB.manifest()
    SRB.show_resources()
