#!/usr/bin/env python

import yaml
import os
import traceback
from collections import defaultdict
from conn_graph_facts import Parse_Lab_Graph

DOCUMENTATION='''
module: network_graph_facts.py
version_added:  2.0
short_description: Retrive lab switches' information physical connections
Description:
    Retrive lab switches' information and physical connections
    add to Ansible facts
options:
    filename: The lab network graph file
    requred: False

Ansible_facts:
    devices: The devices information
    links: The physical connections of devices

'''

EXAMPLES='''
    - name: network_graph_facts

    return:
          "devices": {
              "str-7260-10": {
                  "ManagementIp": "10.251.0.13/23",
                  "HwSku": "Arista-7260QX-64",
                  "Type": "FanoutLeaf'
              },
              "str-msn2700-01": {
                  "HwSku": "Mellanox-2700",
                  "Type": "DevSonic'
              }
          }
          "links": {
              "str-7260-10": [
                  {
                      "StartPort": "Ethernet0",
                      "EndPort": "Ethernet33",
                      "StartDevice": "str-7260-10",
                      "EndDevice": "str-msn2700-01"
                      "VlanID": "233"
                  },
                  {...}
              ]
          }
'''

LAB_CONNECTION_GRAPH_FILE = 'lab_connection_graph.xml'
LAB_GRAPHFILE_PATH = 'files/'

def main():
    module = AnsibleModule(
        argument_spec=dict(
            filename=dict(required=False),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    try:
        if m_args['filename']:
            filename = m_args['filename']
        else:
            filename = LAB_GRAPHFILE_PATH + LAB_CONNECTION_GRAPH_FILE
        lab_graph = Parse_Lab_Graph(filename)
        lab_graph.parse_graph()

        results = {}
        results['devices'] = lab_graph.devices
        results['links']   = lab_graph.links
        module.exit_json(ansible_facts=results)
    except (IOError, OSError):
        module.fail_json(msg="Can not find lab graph file "+LAB_CONNECTION_GRAPH_FILE)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()