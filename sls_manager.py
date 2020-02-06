import requests 
import json
import pprint
from unis.models import *
from unis import Runtime

class SLS_Manager:
    '''
        Class for interfacing with the perfSONAR Simple Lookup Service.
        Is able to query the global registry and then update UNIS resources.

        self.query(<your query>)
        - the main query for Osiris would be group-communities=OSIRIS.
        - another useful one is group-domain=osris.org

        Refer to API for more complex queries.
    '''
    def __init__(self, rt=None, credentials=None):
        
        self.rt = rt 
        self.global_registry  = "http://ps-west.es.net:8096/lookup/activehosts.json"
        self.default_registry = "http://ps-west.es.net:8090/lookup/records"
        self.default_base_url = "http://ps-west.es.net:8090"
        self.headers = { 'Content-type' : 'application/json' }
        self.credentials = credentials

        return

    #############################################################################################
    #
    #  Request Module abstractions.
    #


    def request(self, method, endpoint, data=None, content=None):
        '''
            Connects to a given endpoint.
        '''

        if content:
            headers = {'Content-type': content}
        else:
            headers = self.headers

        if method == "GET":
            try:
                response = requests.get(endpoint,
                headers = headers)
                
            except requests.exceptions.RequestException as e:
                print("GET Request exception: ", e)
        
        return response
    
    def get(self, endpoint):
        '''
            Request module get abstraction
        '''
        
        try:
            
            response = self.request(method = "GET", 
                                    endpoint = endpoint) 
            
            return response
        
        except Exception as e:
            return print("Error getting endpoint: ", e)
        
        

    def query(self, endpoint):
        '''
            Query SLS for a user defined filter
        '''
        
        response = self.get(self.default_registry + "?" + endpoint)
        return response.json()


    
    #############################################################################################
    #
    #  UNIS Helpers
    #

    def check_node_by_name(self, node_name):
        for node in self.rt.nodes:
            if node.name == node_name:
                print("FOUND NODE: ", node_name)

    def check_node_by_address(self, node_address):
        for node in self.rt.nodes:
            if node.properties.mgmtaddr == node_address:
                print("FOUND NODE: ", node.name)

    def get_host_details(self, urn):
        
        res = self.get(self.default_base_url + "/" + urn)
        
        return res.json()

    def check_service_exists(self, service_data, node):
        '''
            Compares service API response data to a node in UNIS to see if an entry for that service on that node exists.

            service_data is a single service response from the API, not a composite from a query
        '''

        service_name = service_data['service-type'][0]     
        exists = self.rt.services.where(lambda s: (s.name == service_name and s.runningOn.href == node.selfRef)) 
        
        # check if generator is empty, return service if found, None if not found.
        try:
            service = exists.next()
            return service
        except:
            return None
            
    #############################################################################################
    #
    #  UNIS Integration
    #

    def validate_node(self, node_name=None, node_addr=None):
        '''
            Checks to see if a node is in UNIS or not. If there is no entry for a given node, create one.
        '''
        if node_name is not None:
            node = next(self.rt.nodes.where(lambda n: n.name == node_name))
            print("Found Node: ", node.to_JSON())
            
            return node
        
        elif node_addr is not None:
            node = next(self.rt.nodes.where(lambda n: n.properties.mgmtaddr == node_addr))
            print("Found Node: ", node.to_JSON())
            
            return node

        else:
            print("No entry found for ", node_name, " : ", node_address, ". Creating one.")
            
            if not node_name: 
                node_name = "UNKNOWN"
            if not node_addr:
                node_addr = "UNKNOWN"

            node = Node({"name": node_name})
            node.properties.mgmtaddr = node_addr
            self.rt.commit(node)

        return node

    def validate_service(self, entry):
        '''
            Checks for service in UNIS. If it does not exist create it.
        '''
        lookup_urn = entry['service-host'][0]
        
        print(self.default_base_url + '/' + lookup_urn)
        node_response = self.get(self.default_base_url + '/' + lookup_urn).json() 
        host_name = node_response['host-name'][1]
        host_addr = node_response['host-name'][0]
        
        node = self.validate_node(node_name=host_name, node_addr=host_addr)

        if node is not None:
            service = self.check_service_exists(entry, node)
        else:
            print("Could not validate node for service " + self.default_base_url + "/" +  entry['uri'][0])
            return False

        
        if service is not None:
            print("Found a service entry for " + service_data['service-type'][0] + " on node " + node.name)
        else:
            print("Create service entry section")
        
        return service

    def integrate(self, data):
        '''
            Takes a response from the SLS query and checks to see if the service exists on an existing node or not.
        '''
        
        ##
        #  Check 'host' entries
        ##
        hosts = list(filter(lambda x: x['type'][0] == "host", data))
        for entry in hosts:
            
            entry_dict = {}
            
            for n in entry['host-name']:

                if n.endswith('org'):
                    entry_dict['name'] = n
                    print("host node name: ", n)
                else:
                    entry_dict['address'] = n
                
            self.validate_node(node_name = entry_dict['name'],
                               node_addr = entry_dict['address'])
        
        ##
        #  Check service entries
        ##
        services = list(filter(lambda x: x['type'][0] == "service", data))
        for entry in services:

            # ensure service is registered to a known node in UNIS
            known_host = any(list(map(lambda s: entry['service-host'][0] == s['uri'], hosts)))
            
            # if a service is found that does not belong to a known host, add the host as a node into UNIS.
            if not known_host:
                host = self.get(self.default_base_url + '/' + entry['service-host'][0]).json()
                node = self.validate_node(node_name = host[0]['host-name'][1], node_addr = host[0]['host-name'][0])
        
            # handle service.
            self.validate_service(entry)
            

        return

'''
    Test case
'''
if __name__ == "__main__":
    sls = SLS_Manager(rt=Runtime(['http://um-ps01.osris.org:8888', 'http://iu-ps01.osris.org:8888']))
    res = sls.query('group-communities=OSIRIS')
    sls.integrate(res)
    for item in res:
        print(item['type'])
    sls.rt.shutdown()
