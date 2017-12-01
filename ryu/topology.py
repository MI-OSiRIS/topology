'''
    I dont think this is used at all in the switch. Think I undersand why this is here, but it looks like
    these helper functions were never actually used. 
'''

class Topology():
    def __init__(self):
        self.nodes = dict()
    def add_node(self, node_id, node_object):
        if node_id in self.nodes:
            print("Node Id already exists")
            return
        #Check if node_object is of type Node
        self.nodes[node_id]=node_object

    def display_topology(self):
        print("Printing the topology")
        if len(self.nodes) > 0:
            for node_id in self.nodes.keys():
                print("Node_id::"+node_id)
                self.nodes[node_id].display_node()

    def get_node_id_by_name(self, node_name):
        if len(self.nodes) > 0:
            for node_id in self.nodes.keys():
                if self.nodes[node_id].name == node_name:
                    return node_id
        return None

class Node:

    def __init__(self, node_name):
        self.name = node_name
        self.ports = dict()

    def add_port(self, port_id, port_object):
        if port_id in self.ports:
            print("Port Id already exists")
            return
        #Check if port_object is of type Port
        self.ports[port_id]=port_object

    def get_port_id_by_name(self, port_name):
        for port_id in self.ports:
            if self.ports[port_id].name == port_name:
                return port_id
        return None

    def display_node(self):
        print("Node::Name:"+self.name)
        if len(self.ports) > 0:
            for port_id in self.ports.keys():
                print("Port_id::"+port_id)
                self.ports[port_id].display_port()


class Port:

    def __init__(self, port_name, ip_address):
        self.name = port_name
        self.ip_address = ip_address
        self.link_id = None
        self.connected_to_node_id = None
        self.connected_to_port_id = None

    def add_link(self, link_id, node_id, port_id):
        self.link_id = link_id
        self.connected_to_node_id = node_id
        self.connected_to_port_id = port_id

    def display_port(self):
        print("Port::Name:"+self.name)
        print("Port::ip_address:"+self.ip_address)
        if self.link_id is not None:
            print("Port::link_id:"+self.link_id)
            print("Port::connected_to_node_id:"+self.connected_to_node_id)
            print("Port::connected_to_port_id:"+self.connected_to_port_id)


class IntermediateNode:

    def __init__(self):
        self.inodes = dict()

    def add_inode(self, inode_name):
        if inode_name not in self.inodes:
            # self.inodes.[(self._get_empty_inode_dict(inode_name))
            self.inodes[inode_name] = []

    def _get_empty_inode_dict(self, inode_name):
        node_dict = {inode_name : []}
        return node_dict

    def _get_link_dict(self, intf_name, node_name):
        link_dict = {'intf_name': intf_name,
                     'node_name': node_name}
        return link_dict

    def add_link_to_inode(self, inode_name, intf_name, node_name):
        if inode_name not in self.inodes:
            self.add_inode(inode_name)
        self.inodes[inode_name].append(self._get_link_dict(intf_name, node_name))

    def __print_link(self, link_dict):
        if 'intf_name' in link_dict:
            print("Intf_name"+link_dict['intf_name'])
        if 'node_name' in link_dict:
            print("node_name"+link_dict['node_name'])

    def print_inodes(self):
        for inode_name in self.inodes:
            print("INODE name:"+inode_name)

            for link_dict in self.inodes[inode_name]:
                self.__print_link(link_dict)
