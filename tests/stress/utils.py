import os
import yaml
import re

TOPO_FILE_FOLDER = '../ansible/vars/'
TOPO_FILENAME_TEMPLATE = 'topo_{}.yml'

SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"

def get_crm_resources(duthost, resource, status):
    return duthost.get_crm_resources().get("main_resources").get(resource).get(status)

def check_queue_status(duthost, queue):
    bgp_neighbors = duthost.show_and_parse(SHOW_BGP_SUMMARY_CMD)
    bgp_neighbor_addr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}")
    for neighbor in bgp_neighbors:
        if bgp_neighbor_addr_regex.match(neighbor["neighbhor"]) and int(neighbor[queue]) != 0 :
            return False
    return True