import requests
import subprocess

url = "http://dev.crest.iu.edu:8888/topologies"
topo_file = "../SC16_topology/topology.json"
topo_file = open(topo_file, 'r')

headers = {'content-type': 'application/perfsonar+json'}
requests.post(url, headers=headers, data=topo_file)