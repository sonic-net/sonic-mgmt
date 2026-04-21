#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on create and delete path trace details between
two different IP addresses and network in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function


__metaclass__ = type
__author__ = ["A Mohamed Rafeek, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: path_trace_workflow_manager
short_description: Resource module for managing PathTrace
  settings in Cisco Catalyst Center
description: |
  This module allows the management of PathTrace settings in Cisco Catalyst Center.
  - It supports creating and deleting PathTrace configurations.
  - This module configures PathTrace settings in Cisco Catalyst Center, including
    source/destination IPs, ports, and protocols.
version_added: '6.31.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: |
      Set to `true` to enable configuration verification on Cisco DNA Center after applying
      the playbook configuration. This ensures that the system validates the configuration
      state after the change is applied.
    type: bool
    default: true
  state:
    description: |
      Specifies the desired state for the configuration. If `merged`, the module will create
      or update the configuration, adding new settings or modifying existing ones. If `deleted`,
      it will remove the specified settings.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: A list containing the details for Path
      Trace configuration.
    type: list
    elements: dict
    required: true
    suboptions:
      source_ip:
        description: |
          The source IP address for the path trace. Either flow_analysis_id or
          both source_ip and dest_ip are required.
        type: str
        required: false
      dest_ip:
        description: |
          The destination IP address for the path trace. Either flow_analysis_id or
          both source_ip and dest_ip are required.
        type: str
        required: false
      source_port:
        description: The source port for the path trace
          (optional).
        type: int
        required: false
      dest_port:
        description: The destination port for the path
          trace (optional).
        type: int
        required: false
      protocol:
        description: The protocol to use for the path
          trace, e.g., TCP, UDP (optional).
        type: str
        choices: ["TCP", "UDP"]
        required: false
      include_stats:
        description: |
          A list of optional statistics (multiple choice) to include in the path trace,
          such as QOS statistics or additional details. Examples: "DEVICE_STATS",
          "INTERFACE_STATS", "QOS_STATS", "PERFORMANCE_STATS", "ACL_TRACE".
          - DEVICE_STATS - Collects hardware-related statistics of network devices
            along the path, including CPU usage, memory, uptime, and interface status.
          - INTERFACE_STATS - Gathers details about interfaces used in the path,
            such as interface type, bandwidth usage, errors, and drops.
          - QOS_STATS - Displays Quality of Service (QoS) settings on interfaces,
            including traffic classification, priority settings, and congestion management.
          - PERFORMANCE_STATS: Provides network performance metrics like latency,
            jitter, and packet loss.
          - ACL_TRACE: Analyzes Access Control List (ACL) rules applied along
            the path to identify blocked traffic or policy mismatches.
        type: list
        elements: str
        required: false
      periodic_refresh:
        description: |
          Boolean value to enable periodic refresh for the path trace.
        type: bool
        required: false
        default: true
      get_last_pathtrace_result:
        description: |
          Boolean value to display the last result again for the path trace.
        type: bool
        required: false
        default: true
      delete_on_completion:
        description: |
          Boolean value indicating whether to delete the path trace after generation.
          This applies only when periodic_refresh is set to false..
        type: bool
        required: false
        default: true
      flow_analysis_id:
        description: |
          The Flow Analysis ID uniquely identifies a specific path trace operation in
          Cisco Catalyst Center. This UUID-format identifier serves multiple purposes
          across different operational states.

          **Creation Context:**
          When creating a new path trace, the API returns a flow_analysis_id in the
          response's "request.id" field. This identifier should be captured using
          Ansible's register functionality for subsequent operations.

          **Retrieval Operations:**
          - If provided, retrieves the specific path trace associated with this ID
          - If omitted, the module searches based on source_ip and dest_ip parameters
          - Provides precise identification when multiple traces exist between the same endpoints

          **Deletion Operations:**
          - When state is 'deleted', this ID enables targeted removal of specific traces
          - If not provided, the module searches for matching traces using source_ip/dest_ip
          - Essential for scenarios where multiple path traces exist with identical endpoints

          **Best Practices:**
          - Always capture flow_analysis_id when creating path traces using register
          - Use flow_analysis_id for precise trace management in automation workflows
          - Preferred over source_ip/dest_ip combination for unique trace identification

          **Format:** UUID string (For example, "99e067de-8776-40d2-9f6a-1e6ab2ef083c")
        type: str
        required: false
requirements:
  - dnacentersdk >= 2.8.6
  - python >= 3.9
notes:
  - SDK Method used are
    path_trace.PathTraceWorkflow.retrieves_all_previous_pathtraces_summary,
    path_trace.PathTraceWorkflow.retrieves_previous_pathtraces_summary,
    path_trace.PathTraceWorkflow.initiate_a_new_pathtrace,
    path_trace.PathTraceWorkflow.delete_pathtrace_by_id,
    - API paths used are GET/dna/intent/api/v1/flow-analysis
    POST/dna/intent/api/v1/flow-analysis GET/dna/intent/api/v1/flow-analysis/{flowAnalysisId}
    DELETE/dna/intent/api/v1/flow-analysis/{flowAnalysisId}
"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create and auto-delete path trace on Cisco
        Catalyst Center
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - source_ip: "204.1.2.3"  # required field
            dest_ip: "204.1.2.4"  # required field
            source_port: 4020  # optional field
            dest_port: 4021  # optional field
            protocol: "TCP"  # optional field
            include_stats:  # optional field
              - DEVICE_STATS
              - INTERFACE_STATS
              - QOS_STATS
              - PERFORMANCE_STATS
              - ACL_TRACE
            periodic_refresh: false  # optional field
            delete_on_completion: true  # optional field
    - name: Delete path trace based on source and destination IP
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: deleted
        config_verify: true
        config:
          - source_ip: "204.1.2.3"  # required field
            dest_ip: "204.1.2.4"  # required field
    - name: Retrieve last path trace
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: merged
        config_verify: true
        config:
          - source_ip: "204.1.2.3"  # required field
            dest_ip: "204.1.2.4"  # required field
            get_last_pathtrace_result: true
    - name: Retrieve path trace based on the flow analysis
        id
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: merged
        config_verify: true
        config:
          # When create a path trace, it returns a flow_analysis_id
          # (the "id" from the "request" section), which should be
          # shown in a register.
          - flow_analysis_id: 99e067de-8776-40d2-9f6a-1e6ab2ef083c
            delete_on_completion: false  # optional field
      register: output_list
    - name: Retrieve and Delete path trace based on
        the required field
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: merged
        config_verify: true
        config:
          - source_ip: "204.1.2.3"  # required field
            dest_ip: "204.1.2.4"  # required field
      register: output_list
    - name: Delete path trace based on registered flow
        analysis id
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: deleted
        config_verify: true
        config:
          - flow_analysis_id: output_list.request.id
    - name: delete path trace based on the flow analysis
        id
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: deleted
        config_verify: true
        config:
          # When create a path trace, it returns a flow_analysis_id
          # (the "id" from the "request" section), which should be
          # shown in a register.
          - flow_analysis_id: 99e067de-8776-40d2-9f6a-1e6ab2ef083c
    - name: Create/Retrieve Path trace for the config
        list.
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: merged
        config_verify: true
        config:
          - source_ip: "204.1.2.3"  # required field
            dest_ip: "204.1.2.4"  # required field
            source_port: 4020  # optional field
            dest_port: 4021  # optional field
            protocol: "TCP"  # optional field
            include_stats:  # optional field
              - DEVICE_STATS
              - INTERFACE_STATS
              - QOS_STATS
              - PERFORMANCE_STATS
              - ACL_TRACE
            periodic_refresh: false  # optional field
            delete_on_completion: true  # optional field
          - source_ip: "204.1.1.2"  # required field
            dest_ip: "204.1.2.4"  # required field
            get_last_pathtrace_result: true  # optional field
            delete_on_completion: true  # optional field
          - flow_analysis_id: 99e067de-8776-40d2-9f6a-1e6ab2ef083c
"""


RETURN = r"""
#Case 1: Successful creation of trace path based on multiple fields
response_1:
  description: A dictionary with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "msg": "Path trace created and verified successfully for '[{'source_ip': '204.1.2.3',
            'dest_ip': '204.1.2.4', 'source_port': 4020, 'dest_port': 4021, 'protocol': 'TCP',
            'periodic_refresh': False, 'include_stats': ['DEVICE-STATS',
            'INTERFACE-STATS', 'QOS-STATS', 'PERFORMANCE-STATS', 'ACL-TRACE'],
            'flow_analysis_id': 'f30d648d-adb7-42ba-88f9-9a9e4c4fca4e'}]'.",
        "response": [
            {
                "lastUpdate": "Fri Feb 21 19:16:46 GMT 2025",
                "networkElementsInfo": [
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "b65f159e-b67d-49d4-92d0-801a0eda6426",
                                "name": "TenGigabitEthernet1/1/7",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
                        "ip": "204.1.2.3",
                        "linkInformationSource": "ISIS",
                        "name": "SJ-BN-9300",
                        "role": "DISTRIBUTION",
                        "type": "Switches and Hubs"
                    },
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "2897a064-9079-4c9c-adf2-3e0b5cf22724",
                                "name": "TenGigabitEthernet1/1/7",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "820bd13a-f565-4778-a320-9ec9f23b4725",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "c98d09f3-b57e-468f-a9a1-65e75249e94f",
                                "name": "TenGigabitEthernet1/1/8",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.1.22",
                        "linkInformationSource": "ISIS",
                        "name": "DC-T-9300",
                        "role": "ACCESS",
                        "type": "Switches and Hubs"
                    },
                    {
                        "id": "0be10e21-34c7-4c76-b217-56327ed1f418",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "f24b433c-8388-453e-a034-fcaf516bc749",
                                "name": "TenGigabitEthernet2/1/8",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.2.4",
                        "name": "NY-BN-9300",
                        "role": "DISTRIBUTION",
                        "type": "Switches and Hubs"
                    }
                ],
                "request": {
                    "controlPath": false,
                    "createTime": 1740165404872,
                    "destIP": "204.1.2.4",
                    "destPort": "4021",
                    "id": "81d8b994-fb62-48dc-aa45-cb3a62d4e4b4",
                    "lastUpdateTime": 1740165406115,
                    "periodicRefresh": false,
                    "protocol": "TCP",
                    "sourceIP": "204.1.2.3",
                    "sourcePort": "4020",
                    "status": "COMPLETED"
                }
            }
        ],
        "status": "success"
    }
#Case 2: Retrieve the path trace based on flow analysis id
response_2:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "msg": "Path trace created and verified successfully for '[{'flow_analysis_id':
            '99e067de-8776-40d2-9f6a-1e6ab2ef083c'}]'.",
        "response": [
            {
                "lastUpdate": "Fri Feb 21 19:21:16 GMT 2025",
                "networkElementsInfo": [
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "b65f159e-b67d-49d4-92d0-801a0eda6426",
                                "name": "TenGigabitEthernet1/1/7",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
                        "ip": "204.1.2.3",
                        "linkInformationSource": "ISIS",
                        "name": "SJ-BN-9300",
                        "role": "DISTRIBUTION",
                        "type": "Switches and Hubs"
                    },
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "2897a064-9079-4c9c-adf2-3e0b5cf22724",
                                "name": "TenGigabitEthernet1/1/7",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "820bd13a-f565-4778-a320-9ec9f23b4725",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "c98d09f3-b57e-468f-a9a1-65e75249e94f",
                                "name": "TenGigabitEthernet1/1/8",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.1.22",
                        "linkInformationSource": "ISIS",
                        "name": "DC-T-9300",
                        "role": "ACCESS",
                        "type": "Switches and Hubs"
                    },
                    {
                        "id": "0be10e21-34c7-4c76-b217-56327ed1f418",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "f24b433c-8388-453e-a034-fcaf516bc749",
                                "name": "TenGigabitEthernet2/1/8",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.2.4",
                        "name": "NY-BN-9300",
                        "role": "DISTRIBUTION",
                        "type": "Switches and Hubs"
                    }
                ],
                "request": {
                    "controlPath": false,
                    "createTime": 1740156374801,
                    "destIP": "204.1.2.4",
                    "destPort": "80",
                    "id": "99e067de-8776-40d2-9f6a-1e6ab2ef083c",
                    "lastUpdateTime": 1740156376055,
                    "periodicRefresh": false,
                    "protocol": "TCP",
                    "sourceIP": "204.1.2.3",
                    "sourcePort": "80",
                    "status": "COMPLETED"
                }
            }
        ],
        "status": "success"
    }
#Case 3: Retrieve the last created path trace based on source and dest IP
response_3:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "msg": "Path trace created and verified successfully for '[{'source_ip': '204.1.1.2',
            'dest_ip': '204.1.2.4', 'get_last_pathtrace_result': True,
            'flow_analysis_id': 'f30d648d-adb7-42ba-88f9-9a9e4c4fca4e'}]'.",
        "response": [
            {
                "lastUpdate": "Fri Feb 21 19:25:52 GMT 2025",
                "networkElementsInfo": [
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "44aafd2d-5822-4ce5-95c5-11909e9425f6",
                                "name": "TenGigabitEthernet1/1/1",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "99b62ead-51d6-4bfc-9b0c-dab087f184e9",
                        "ip": "204.1.1.2",
                        "linkInformationSource": "ISIS",
                        "name": "SJ-EN-9300",
                        "role": "ACCESS",
                        "type": "Switches and Hubs"
                    },
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "b65f159e-b67d-49d4-92d0-801a0eda6426",
                                "name": "TenGigabitEthernet1/1/7",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "0610f80e-09fc-4083-8aaa-7cf318b211de",
                                "name": "TenGigabitEthernet1/1/2",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.2.3",
                        "linkInformationSource": "ISIS",
                        "name": "SJ-BN-9300",
                        "role": "DISTRIBUTION",
                        "type": "Switches and Hubs"
                    },
                    {
                        "egressInterface": {
                            "physicalInterface": {
                                "id": "2897a064-9079-4c9c-adf2-3e0b5cf22724",
                                "name": "TenGigabitEthernet1/1/7",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "id": "820bd13a-f565-4778-a320-9ec9f23b4725",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "c98d09f3-b57e-468f-a9a1-65e75249e94f",
                                "name": "TenGigabitEthernet1/1/8",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.1.22",
                        "linkInformationSource": "ISIS",
                        "name": "DC-T-9300",
                        "role": "ACCESS",
                        "type": "Switches and Hubs"
                    },
                    {
                        "id": "0be10e21-34c7-4c76-b217-56327ed1f418",
                        "ingressInterface": {
                            "physicalInterface": {
                                "id": "f24b433c-8388-453e-a034-fcaf516bc749",
                                "name": "TenGigabitEthernet2/1/8",
                                "usedVlan": "NA",
                                "vrfName": "global"
                            }
                        },
                        "ip": "204.1.2.4",
                        "name": "NY-BN-9300",
                        "role": "DISTRIBUTION",
                        "type": "Switches and Hubs"
                    }
                ],
                "request": {
                    "controlPath": false,
                    "createTime": 1740162201882,
                    "destIP": "204.1.2.4",
                    "id": "3cb51b94-2a50-4a92-b204-13ffdde22ef9",
                    "lastUpdateTime": 1740162203167,
                    "periodicRefresh": false,
                    "sourceIP": "204.1.1.2",
                    "status": "COMPLETED"
                }
            }
        ],
        "status": "success"
    }
#Case 4: Delete path trace based on flow analysis id
response_4:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "msg": "Path trace deleted and verified successfully for '[{'source_ip': '204.1.1.2',
            'dest_ip': '204.1.2.4', 'get_last_pathtrace_result': True}]'.",
        "response":"Path trace deleted and verified successfully for '[{'source_ip': '204.1.1.2',
            'dest_ip': '204.1.2.4', 'get_last_pathtrace_result': True}]'.",
        "status": "success"
    }
#Case 5: Delete path trace based on Source and Destination IP
response_5:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "msg": "Path trace deleted and verified successfully for '[{'flow_analysis_id':
            '99e067de-8776-40d2-9f6a-1e6ab2ef083c'}]'.",
        "response": "Path trace deleted and verified successfully for '[{'flow_analysis_id':
            '99e067de-8776-40d2-9f6a-1e6ab2ef083c'}]'.",
        "status": "success"
    }
"""

import re
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class PathTraceWorkflow(DnacBase):
    """Class containing member attributes for Assurance setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.create_path, self.delete_path, self.not_processed = [], [], []
        self.success_path = []

        self.keymap = dict(
            flow_analysis_id="id",
            source_ip="sourceIP",
            dest_ip="destIP",
            dest_port="destPort",
            source_port="sourcePort",
            periodic_refresh="periodicRefresh",
            INTERFACE_STATS="INTERFACE-STATS",
            QOS_STATS="QOS-STATS",
            DEVICE_STATS="DEVICE-STATS",
            PERFORMANCE_STATS="PERFORMANCE-STATS",
            ACL_TRACE="ACL-TRACE",
        )

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
            - self.msg: A message describing the validation result.
            - self.status: The status of the validation ('success' or 'failed').
            - self.validated_config: If successful, a validated version of the 'config' parameter.
        """

        temp_spec = {
            "source_ip": {"type": "str", "required": False},
            "dest_ip": {"type": "str", "required": False},
            "source_port": {
                "type": "int",
                "range_min": 1,
                "range_max": 65535,
                "required": False,
            },
            "dest_port": {
                "type": "int",
                "range_min": 1,
                "range_max": 65535,
                "required": False,
            },
            "protocol": {"type": "str", "choices": ["TCP", "UDP"], "required": False},
            "periodic_refresh": {"type": "bool", "required": False},
            "include_stats": {"type": "list", "elements": "str", "required": False},
            "get_last_pathtrace_result": {"type": "bool", "required": False},
            "flow_analysis_id": {"type": "str", "required": False},
            "delete_on_completion": {"type": "bool", "required": False}
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Validate configuration against the specification
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        valid_temp = [
            {key: value for key, value in data.items() if value is not None}
            for data in valid_temp
        ]
        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")

        return self

    def input_data_validation(self, config):
        """
        Additional validation to check if the provided input path trace data is correct
        and as per the UI Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing the input path trace details.

        Returns:
            self: Current object with path trace input data.

        Description:
            Iterates through available path trace data and Returns the list of invalid
            data for further action or validation.
        """
        self.log("Starting path trace input validation.", "INFO")

        errormsg = []
        valid_inclusions = (
            "DEVICE_STATS",
            "INTERFACE_STATS",
            "QOS_STATS",
            "PERFORMANCE_STATS",
            "ACL_TRACE",
        )

        for each_path in config:
            self.log("Validating path trace entry: {0}".format(str(each_path)), "DEBUG")
            delete_on_completion = each_path.get("delete_on_completion")
            if delete_on_completion is not None and delete_on_completion not in (
                True,
                False,
            ):
                errormsg.append(
                    "delete_on_completion: Invalid value {0} in playbook. Must be either true or false.".format(
                        delete_on_completion
                    )
                )

            flow_analysis_id = each_path.get("flow_analysis_id")
            if flow_analysis_id:
                if not self.is_valid_uuid_regex(flow_analysis_id):
                    errormsg.append(
                        "flow_analysis_id: Invalid value '{0}'. Must be a valid UUID.".format(
                            flow_analysis_id
                        )
                    )
                break

            source_ip = each_path.get("source_ip")
            if source_ip is None:
                errormsg.append("source_ip: Source IP Address is missing in playbook.")
            elif not (self.is_valid_ipv4(source_ip) or self.is_valid_ipv6(source_ip)):
                errormsg.append(
                    "source_ip: Invalid Source IP Address '{0}' in playbook. Must be a valid IPv4 or IPv6 address".format(
                        source_ip
                    )
                )

            dest_ip = each_path.get("dest_ip")
            if dest_ip is None:
                errormsg.append(
                    "dest_ip: Destination IP Address is missing in playbook."
                )
            elif not (self.is_valid_ipv4(dest_ip) or self.is_valid_ipv6(dest_ip)):
                errormsg.append(
                    "dest_ip: Invalid Destination IP Address '{0}' in playbook. Must be a valid IPv4 or IPv6 address".format(
                        dest_ip
                    )
                )

            source_port = each_path.get("source_port")
            if source_port and source_port not in range(1, 65536):
                errormsg.append(
                    "source_port: Invalid Source Port number '{0}' in playbook. Must be between 1 and 65535.".format(
                        source_port
                    )
                )

            dest_port = each_path.get("dest_port")
            if dest_port and dest_port not in range(1, 65536):
                errormsg.append(
                    "dest_port: Invalid Destination Port number '{0}' in playbook. Must be between 1 and 65535.".format(
                        dest_port
                    )
                )

            protocol = each_path.get("protocol")
            if protocol and protocol not in ("TCP", "UDP"):
                errormsg.append(
                    "protocol: Invalid protocol '{0}'. Must be 'TCP' or 'UDP'.".format(
                        protocol
                    )
                )

            periodic_refresh = each_path.get("periodic_refresh")
            if periodic_refresh is not None and periodic_refresh not in (True, False):
                errormsg.append(
                    "periodic_refresh: Invalid periodic refresh "
                    + "'{0}' in playbook. Must be either true or false.".format(
                        periodic_refresh
                    )
                )

            get_last_pathtrace_result = each_path.get("get_last_pathtrace_result")
            if (
                get_last_pathtrace_result is not None
                and get_last_pathtrace_result not in (True, False)
            ):
                errormsg.append(
                    "get_last_pathtrace_result: Invalid get last pathtrace result "
                    + "'{0}' in playbook. Must be either true or false.".format(
                        get_last_pathtrace_result
                    )
                )

            include_stats = each_path.get("include_stats")
            if include_stats:
                collect_invalid_stats = []
                for each_include in include_stats:
                    if each_include not in valid_inclusions:
                        collect_invalid_stats.append(each_include)

                if collect_invalid_stats:
                    errormsg.append(
                        "include_stats: Invalid value(s) '{0}'. Must be one or more of: {1}.".format(
                            str(collect_invalid_stats), ", ".join(valid_inclusions)
                        )
                    )
        if len(errormsg) > 0:
            self.msg = "Invalid parameters in playbook config: '{0}' ".format(errormsg)
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        self.msg = "Successfully validated config params: {0}".format(str(config))
        self.log(self.msg, "INFO")
        return self

    def is_valid_uuid_regex(self, uuid_string):
        """
        Validates if the given string is a valid UUID (version 1 to 5).

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            uuid_string (str): String contains uuid to check valid uuid.

        Returns:
            bool: Return response as True or False if UUID matched.
        """
        uuid_pattern = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
        return bool(uuid_pattern.match(str(uuid_string)))

    def get_want(self, config):
        """
        Retrieve path trace or delete path trace data from playbook configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing path trace details.

        Returns:
            self: The current instance of the class with updated 'want' attributes.

        Description:
            This function parses the playbook configuration to extract information related to path
            trace. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """
        want = {}
        if config:
            self.log("Validating configuration: {0}".format(str(config)), "DEBUG")
            self.input_data_validation(config).check_return_status()
            want["assurance_pathtrace"] = config
            self.log(
                "Path trace data extracted and stored in 'want': {0}".format(str(want)),
                "INFO",
            )
        else:
            self.log("No configuration provided for path trace data.", "WARNING")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Get the current path trace details for the given config from Cisco Catalyst Center

        Parameters:
            config (dict) - Playbook details containing Path Trace

        Returns:
            self - The current object with path trace flow analysis id and details response.
        """
        self.log("Starting to retrieve path trace details.", "DEBUG")
        self.have["assurance_pathtrace"] = []

        for each_path in config:
            if not each_path.get("flow_analysis_id"):
                self.log(
                    "Missing 'flow_analysis_id' for path: {0}".format(each_path),
                    "WARNING",
                )
                get_trace = self.get_path_trace(each_path)

                if not get_trace:
                    self.msg = (
                        "Unable to get path trace for the flow analysis id: {0}".format(
                            each_path
                        )
                    )
                    self.log(self.msg, "DEBUG")
                else:
                    self.have["assurance_pathtrace"].extend(get_trace)
            else:
                self.log(
                    "Found 'flow_analysis_id' for path: {0}".format(each_path), "DEBUG"
                )

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the system"
        self.status = "success"
        return self

    def get_path_trace(self, config_data):
        """
        Get the path trace for the given playbook data and response with
        flow analysis id.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dict containing input data to get id for path trace.

        Returns:
            list: return the list of flow analysis IDs or None.

        Description:
            This function used to get the flow analysis id from the input config.
        """
        offset_limit = 500
        offset = 1
        payload_data = dict(
            limit=offset_limit, offset=offset, order="DESC", sort_by="createTime"
        )
        for key, value in config_data.items():
            if value is not None and key not in (
                "source_port",
                "dest_port",
                "include_stats",
                "delete_on_completion",
                "get_last_pathtrace_result",
            ):
                mapped_key = self.keymap.get(key, key)
                payload_data[mapped_key] = value

        self.log(
            "Get path trace for parameters: {0}".format(self.pprint(payload_data)),
            "INFO",
        )
        try:
            all_path_trace = []
            while True:
                response = self.dnac._exec(
                    family="path_trace",
                    function="retrieves_all_previous_pathtraces_summary",
                    op_modifies=True,
                    params=payload_data,
                )
                self.log(
                    "Response from retrieves_all_previous_pathtraces_summary API: {0}".format(
                        self.pprint(response)
                    ),
                    "DEBUG",
                )

                if not response or not isinstance(response, dict):
                    self.log(
                        "Unexpected or empty response received from API, "
                        + "expected a non-empty dictionary.",
                        "ERROR",
                    )
                    break

                self.log(
                    "Received the path trace response: {0}".format(
                        self.pprint(response)
                    ),
                    "INFO",
                )
                response_list = response.get("response")

                if not response_list:
                    self.log(
                        "No data received from API (Offset={0}). Exiting pagination.".format(
                            payload_data["offset"]
                        ),
                        "DEBUG",
                    )
                    break

                self.log(
                    "Received {0} path trace(s) from API (Offset={1}).".format(
                        len(response_list), payload_data["offset"]
                    ),
                    "DEBUG",
                )
                all_path_trace.extend(response_list)

                if len(response_list) < offset_limit:
                    self.log(
                        "Received less than limit ({0}) results, assuming last page. Exiting pagination.".format(
                            offset_limit
                        ),
                        "DEBUG",
                    )
                    break

                payload_data[
                    "offset"
                ] += offset_limit  # Increment offset for pagination
                self.log(
                    "Incrementing offset to {0} for next API request.".format(
                        payload_data["offset"]
                    ),
                    "DEBUG",
                )

            if all_path_trace:
                self.log(
                    "Total {0} Path Trace(s) retrieved for the config: '{1}'.".format(
                        len(all_path_trace), str(payload_data)
                    ),
                    "DEBUG",
                )
                return all_path_trace

        except Exception as e:
            self.msg = "An error occurred during get path trace: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def create_path_trace(self, config_data):
        """
        Create the path trace for the given config with source and destination IP.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing input config data from playbook.

        Returns:
            flow_analysis_id (str): Returns string contains flow analysis ID.

        Description:
            This function get the path trace config input data and create the path trace then
            return output as string flow analysis id.
        """
        self.log("Starting the process of creating a path trace.", "INFO")
        payload_data = {}
        for key, value in config_data.items():
            excluded_key = [
                "flow_analysis_id",
                "get_last_pathtrace_result",
                "delete_on_completion",
            ]
            if value is not None and key not in excluded_key:
                mapped_key = self.keymap.get(key, key)
                if key == "include_stats" and isinstance(value, list):
                    api_value = []
                    for each_value in value:
                        api_value.append(self.keymap.get(each_value, each_value))
                    payload_data[mapped_key] = api_value
                else:
                    payload_data[mapped_key] = value

        self.log(
            "Creating path trace with parameters: {0}".format(
                self.pprint(payload_data)
            ),
            "INFO",
        )
        try:
            response = self.dnac._exec(
                family="path_trace",
                function="initiate_a_new_pathtrace",
                op_modifies=True,
                params=payload_data,
            )
            self.log(
                "Response from path trace create API response: {0}".format(response),
                "DEBUG",
            )

            if response and isinstance(response, dict):
                flow_analysis_id = response.get("response", {}).get("flowAnalysisId")
                if flow_analysis_id is not None:
                    self.log(
                        "Received the path trace flow analysis id: {0}".format(
                            flow_analysis_id
                        ),
                        "INFO",
                    )
                    return flow_analysis_id

            self.msg = "Unable to Create the path trace for the config: {0}".format(
                self.pprint(payload_data)
            )
            self.not_processed.append(payload_data)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR", payload_data
            ).check_return_status()
        except Exception as e:
            self.msg = "An error occurred during create path trace: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_path_trace_with_flow_id(self, flow_id):
        """
        Get the path trace for the given flow analysis id and response with
        complete path trace between source and destination IP.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            flow_id (str): A string containing flow analysis id from create path trace.

        Returns:
            dict: A dictionary of path trace details.

        Description:
            This function get the path trace for flow analysis id and return the complete
            path trace from source and destination IPs.
        """
        self.log(
            "Getting path trace flow analysis id: {0}".format(str(flow_id)), "INFO"
        )
        try:
            dnac_api_task_timeout = int(self.payload.get("dnac_api_task_timeout"))
            start_time = time.time()

            while True:
                response = self.dnac._exec(
                    family="path_trace",
                    function="retrieves_previous_pathtrace",
                    params=dict(flow_analysis_id=flow_id),
                )
                self.log(
                    "Response from get path trace API: {0}".format(
                        self.pprint(response)
                    ),
                    "DEBUG",
                )

                if response and isinstance(response, dict):
                    status = (
                        response.get("response", {}).get("request", {}).get("status")
                    )
                    if status == "COMPLETED" or status == "FAILED":
                        self.log(
                            "Received the path trace response: {0}".format(
                                self.pprint(response)
                            ),
                            "INFO",
                        )
                        return response.get("response")

                elapsed_time = time.time() - start_time
                if elapsed_time >= dnac_api_task_timeout:
                    self.msg = "Max timeout of {0} sec has reached for the API 'retrieves_previous_pathtrace' status.".format(
                        dnac_api_task_timeout
                    )
                    self.log(self.msg, "CRITICAL")
                    self.status = "failed"
                    break

                self.log("Waiting for '2' seconds to retry back to API call.", "INFO")
                time.sleep(2)

            self.msg = "Unable to get path trace for the flow analysis id: {0}".format(
                flow_id
            )
            self.not_processed.append(flow_id)
            return None

        except Exception as e:
            self.msg = "An error occurred during get path trace: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.not_processed.append(flow_id)
            return None

    def delete_path_trace(self, flow_id):
        """
        Delete the path trace for the given flow analysis id and return taskid.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            flow_id (str): A string containing flow analysis id to delete path trace.

        Returns:
            dict or none: Return task id details or None.

        Description:
            This function delete the path trace for flow analysis id and return the task id
            details.
        """
        self.log(
            "Deleting path trace flow analysis id: {0}".format(str(flow_id)), "INFO"
        )
        try:
            response = self.dnac._exec(
                family="path_trace",
                function="deletes_pathtrace_by_id",
                params=dict(flow_analysis_id=flow_id),
            )
            self.log(
                "Response from delete path trace API: {0}".format(
                    self.pprint(response)
                ),
                "DEBUG",
            )

            if response and isinstance(response, dict):
                task_id = response.get("response", {}).get("taskId")
                if not task_id:
                    self.msg = "Unable to delete path trace for the flow analysis id: {0}".format(
                        flow_id
                    )
                    self.not_processed.append(self.msg)
                    self.fail_and_exit(self.msg)

                self.log("Received the task id: {0}".format(task_id), "INFO")
                dnac_api_task_timeout = int(self.payload.get("dnac_api_task_timeout"))
                start_time = time.time()

                while True:
                    delete_details = self.get_task_details_by_id(task_id)
                    if delete_details.get("progress"):
                        if delete_details.get("errorCode"):
                            self.msg = "Unable to delete path trace for the flow analysis id: {0}".format(
                                flow_id
                            )
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR", delete_details
                            ).check_return_status()
                        return delete_details

                    elapsed_time = time.time() - start_time
                    if elapsed_time >= dnac_api_task_timeout:
                        self.msg = "Max timeout of {0} sec has reached for the 'Task details' API status.".format(
                            dnac_api_task_timeout
                        )
                        return self.fail_and_exit(self.msg)

                    time.sleep(5)

        except Exception as e:
            self.msg = "An error occurred during delete path trace: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_diff_merged(self, config):
        """
        Create the path trace in Cisco Catalyst Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing path trace information.

        Returns:
            self - The current object Path create response information.
        """
        self.msg = ""
        self.changed = False
        self.status = "failed"
        collect_flow_ids = []

        for each_path in config:
            flow_analysis_id = each_path.get("flow_analysis_id")

            if each_path.get("get_last_pathtrace_result"):
                self.log(
                    "Getting Path trace information for {0}".format(each_path), "INFO"
                )
                get_trace = self.get_path_trace(each_path)
                if get_trace and not flow_analysis_id:
                    flow_analysis_id = get_trace[0].get("id")

            # Create a new path trace if no flow analysis ID exists
            if not flow_analysis_id:
                flow_analysis_id = self.create_path_trace(each_path)
                self.log(
                    "Received flow analysis id {0} for {1}".format(
                        flow_analysis_id, each_path
                    ),
                    "INFO",
                )

            config_response = {"each_config": each_path}
            if flow_analysis_id:
                config_response["flow_analysis_id"] = flow_analysis_id

            collect_flow_ids.append(config_response)

        for each_flow_details in collect_flow_ids:
            each_flow_id = each_flow_details.get("flow_analysis_id")
            each_path = each_flow_details.get("each_config")
            path_trace_created = False

            # Retrieve path trace details if flow analysis id exists
            if each_flow_id:
                path_trace = self.get_path_trace_with_flow_id(each_flow_id)
                if path_trace:
                    path_trace_created = True
                    if path_trace.get("request", {}).get("status") == "COMPLETED":
                        self.log(
                            "Received path trace details for flow id {0}: {1}".format(
                                each_flow_id, path_trace
                            ),
                            "INFO",
                        )
                        self.create_path.append(path_trace)
                    else:
                        self.log(
                            "Received failed path trace details for flow id {0}: {1}".format(
                                each_flow_id, path_trace.get("request")
                            ),
                            "INFO",
                        )
                        self.not_processed.append(path_trace.get("request"))

            # If path trace creation failed, log the error
            if not path_trace_created:
                self.not_processed.append(each_path)
                self.msg = "Unable to find the path trace for flow analysis id: {0}".format(
                    each_flow_id if each_flow_id else "N/A"
                )

        if self.create_path:
            self.msg = "Path trace created successfully for '{0}'.".format(
                str(self.create_path)
            )
            self.changed = True
            self.status = "success"

        if self.not_processed:
            self.msg += " Unable to create the following path '{0}'.".format(
                str(self.not_processed)
            )
            self.log(self.msg, "INFO")
            self.set_operation_result(
                "failed",
                False,
                self.msg,
                "ERROR",
                self.not_processed.extend(self.create_path),
            ).check_return_status()

        self.log(self.msg, "INFO")
        self.set_operation_result(
            self.status, self.changed, self.msg, "INFO", self.create_path
        ).check_return_status()
        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (list of dict) - Playbook details containing path trace.

        Returns:
            self - The current object path trace information.
        """
        self.log(
            "Starting path trace verification for configuration: {0}".format(config),
            "INFO",
        )

        self.msg = ""
        success_path = []
        for each_path in config:
            self.log(
                "Verifying path: {0} with flow_analysis_id: {1}, source_ip: {2}, dest_ip: {3}".format(
                    each_path,
                    each_path.get("flow_analysis_id"),
                    each_path.get("source_ip"),
                    each_path.get("dest_ip"),
                ),
                "DEBUG",
            )
            if not self.create_path:
                continue

            for each_trace in self.create_path:
                trace_source_ip = each_trace.get("request").get("sourceIP")
                trace_dest_ip = each_trace.get("request").get("destIP")
                flow_id = each_trace.get("request").get("id")
                delete_on_completion = each_path.get("delete_on_completion")
                periodic_refresh = each_path.get("periodic_refresh")
                each_path["flow_analysis_id"] = flow_id

                if each_path.get("flow_analysis_id"):
                    if each_path.get("flow_analysis_id") == flow_id:
                        self.log(
                            "Successfully matched path: {0} with flow_analysis_id: {1}".format(
                                each_path, flow_id
                            ),
                            "INFO",
                        )
                        success_path.append(each_path)

                        if delete_on_completion and not periodic_refresh:
                            delete_response = self.delete_path_trace(flow_id)
                            if delete_response:
                                self.log(
                                    "Deleted the path trace for {0}".format(each_trace),
                                    "INFO",
                                )
                        break
                elif trace_source_ip == each_path.get(
                    "source_ip"
                ) and trace_dest_ip == each_path.get("dest_ip"):
                    self.log(
                        "Successfully matched path: {0} with source_ip: {1} and dest_ip: {2}".format(
                            each_path, trace_source_ip, trace_dest_ip
                        ),
                        "INFO",
                    )
                    success_path.append(each_path)

                    if delete_on_completion and not periodic_refresh:
                        delete_response = self.delete_path_trace(flow_id)
                        if delete_response:
                            self.log(
                                "Deleted the path trace for {0}".format(each_trace),
                                "INFO",
                            )
                    break

        if success_path:
            self.msg = "Path trace created and verified successfully for '{0}'.".format(
                success_path
            )
            self.log(self.msg, "INFO")
            self.set_operation_result(
                "success", True, self.msg, "INFO", self.create_path
            ).check_return_status()

        return self

    def get_diff_deleted(self, config):
        """
        Delete path trace based on flow analysis id.

        Parameters:
            config (list of dict) - Playbook details containing path trace information.

        Returns:
            self - The current object with status of path trace deleted.
        """
        self.log(
            "Starting path trace deletion for configuration: {0}".format(config), "INFO"
        )

        for each_path in config:
            self.log(
                "Processing path: {0} with flow_analysis_id: {1}".format(
                    each_path, each_path.get("flow_analysis_id")
                ),
                "DEBUG",
            )
            if not each_path.get("flow_analysis_id"):
                get_trace = self.get_path_trace(each_path)

                if get_trace:
                    flow_ids = []
                    for each_trace in get_trace:
                        delete_response = self.delete_path_trace(each_trace["id"])
                        if delete_response:
                            self.log(
                                "Deleted the path trace for {0}".format(each_trace),
                                "INFO",
                            )
                            flow_ids.append(delete_response)

                    if len(get_trace) == len(flow_ids):
                        self.delete_path.append(each_path)
                    else:
                        self.not_processed.append(each_path)
                        self.log(
                            "Failed to delete all path traces for {0}".format(
                                each_path
                            ),
                            "ERROR",
                        )
            else:
                path_trace = self.get_path_trace_with_flow_id(
                    each_path.get("flow_analysis_id"))
                if not path_trace:
                    self.msg = "Path trace for flow_analysis_id '{0}' already deleted or not found: {1}".format(
                        each_path.get("flow_analysis_id"), self.not_processed)
                    self.log(self.msg, "INFO")
                    self.set_operation_result(
                        "success", False, self.msg, "INFO"
                    ).check_return_status()
                    return self

                delete_response = self.delete_path_trace(
                    each_path.get("flow_analysis_id")
                )
                if delete_response:
                    self.log(
                        "Deleted the path trace for flow analysis id : {0}".format(
                            each_path.get("flow_analysis_id")
                        ),
                        "INFO",
                    )
                    self.delete_path.append(each_path)
                else:
                    self.not_processed.append(each_path)
                    self.log(
                        "Failed to delete path trace for flow_analysis_id: {0}".format(
                            each_path.get("flow_analysis_id")
                        ),
                        "ERROR",
                    )

        if len(self.delete_path) > 0:
            self.msg = "Path trace deleted successfully for '{0}'.".format(
                str(self.delete_path)
            )

        if len(self.not_processed) > 0:
            self.msg = self.msg + "Unable to delete the following path '{0}'.".format(
                str(self.not_processed)
            )

        self.log(self.msg, "INFO")
        if len(self.delete_path) > 0 and (
            len(self.not_processed) > 0 or (len(self.not_processed) == 0)
        ):
            self.set_operation_result(
                "success", True, self.msg, "INFO", self.delete_path
            ).check_return_status()
        elif len(self.delete_path) == 0 and len(self.not_processed) == 0:
            self.msg = "Path trace already deleted for '{0}'.".format(config)
            self.set_operation_result(
                "success", False, self.msg, "INFO", config
            ).check_return_status()
        else:
            self.set_operation_result(
                "failed", False, self.msg, "ERROR", self.not_processed
            ).check_return_status()

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the path trace was deleted

        Parameters:
            config (dict) - Playbook config contains path trace.

        Returns:
            self - Return response as verified that path trace was deleted.
        """
        self.log(
            "Starting path trace deletion verification for config: {0}".format(config),
            "INFO",
        )
        self.get_have(config)
        self.log(
            "Get have function response {0}".format(self.have["assurance_pathtrace"]),
            "INFO",
        )

        if len(self.have["assurance_pathtrace"]) > 0:
            self.msg = "Unable to delete the following path '{0}'.".format(
                self.have["assurance_pathtrace"]
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "Error", self.have["assurance_pathtrace"]
            ).check_return_status()
        else:
            if len(self.delete_path) > 0:
                self.msg = (
                    "Path trace deleted and verified successfully for '{0}'.".format(
                        self.delete_path
                    )
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", True, self.msg, "INFO"
                ).check_return_status()
            else:
                self.msg = "Path trace already deleted for '{0}'.".format(config)
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "success", False, self.msg, "INFO"
                ).check_return_status()

        return self


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": True},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": True},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_path_trace = PathTraceWorkflow(module)
    state = ccc_path_trace.params.get("state")

    if (
        ccc_path_trace.compare_dnac_versions(
            ccc_path_trace.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_path_trace.status = "failed"
        ccc_path_trace.msg = (
            "The specified version '{0}' does not support the path trace workflow feature."
            "Supported version(s) start from '2.3.7.6' onwards.".format(
                ccc_path_trace.get_ccc_version()
            )
        )
        ccc_path_trace.log(ccc_path_trace.msg, "ERROR")
        ccc_path_trace.check_return_status()

    if state not in ccc_path_trace.supported_states:
        ccc_path_trace.status = "invalid"
        ccc_path_trace.msg = "State {0} is invalid".format(state)
        ccc_path_trace.check_return_status()

    ccc_path_trace.validate_input().check_return_status()
    config_verify = ccc_path_trace.params.get("config_verify")

    # for config in ccc_path_trace.validated_config:
    config = ccc_path_trace.validated_config

    if not config:
        ccc_path_trace.msg = "Playbook configuration is missing."
        ccc_path_trace.log(ccc_path_trace.msg, "ERROR")
        ccc_path_trace.fail_and_exit(ccc_path_trace.msg)

    ccc_path_trace.reset_values()
    ccc_path_trace.get_want(config).check_return_status()
    ccc_path_trace.get_have(config).check_return_status()
    ccc_path_trace.get_diff_state_apply[state](config).check_return_status()
    if config_verify:
        ccc_path_trace.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_path_trace.result)


if __name__ == "__main__":
    main()
