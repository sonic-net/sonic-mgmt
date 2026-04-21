#!/usr/bin/python

# Copyright: (c) 2022, Rainer Leber rainerleber@gmail.com>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sap_system_facts

short_description: Gathers SAP facts in a host

version_added: "1.0.0"

description:
    - This facts module gathers SAP system facts about the running instance.

author:
    - Rainer Leber (@rainerleber)

notes:
    - Supports C(check_mode).
'''

EXAMPLES = r'''
- name: Return SAP system ansible_facts
  community.sap_libs.sap_system_facts:
'''

RETURN = r'''
# These are examples of possible return values,
# and in general should use other names for return values.
ansible_facts:
  description: Facts about the running SAP systems.
  returned: always
  type: dict
  contains:
    sap:
      description: Facts about the running SAP systems.
      type: list
      elements: dict
      returned: When SAP system fact is present
      sample: [
        {
            "InstanceType": "NW",
            "NR": "00",
            "SID": "ABC",
            "TYPE": "ASCS"
        },
        {
            "InstanceType": "NW",
            "NR": "01",
            "SID": "ABC",
            "TYPE": "PAS"
        },
        {
            "InstanceType": "HANA",
            "NR": "02",
            "SID": "HDB",
            "TYPE": "HDB"
        },
        {
            "InstanceType": "NW",
            "NR": "80",
            "SID": "WEB",
            "TYPE": "WebDisp"
        }
      ]
'''

from ansible.module_utils.basic import AnsibleModule
import os
import re


def get_all_hana_sid():
    hana_sid = list()
    if os.path.isdir("/hana/shared"):
        # /hana/shared directory exists
        for sid in os.listdir('/hana/shared'):
            if os.path.isdir("/usr/sap/" + sid):
                hana_sid = hana_sid + [sid]
    if hana_sid:
        return hana_sid


def get_all_nw_sid():
    nw_sid = list()
    if os.path.isdir("/sapmnt"):
        # /sapmnt directory exists
        for sid in os.listdir('/sapmnt'):
            if os.path.isdir("/usr/sap/" + sid):
                nw_sid = nw_sid + [sid]
            else:
                # Check to see if /sapmnt/SID/sap_bobj exists
                if os.path.isdir("/sapmnt/" + sid + "/sap_bobj"):
                    # is a bobj system
                    nw_sid = nw_sid + [sid]
    if nw_sid:
        return nw_sid


def get_hana_nr(sids, module):
    hana_list = list()
    for sid in sids:
        for instance in os.listdir('/usr/sap/' + sid):
            if 'HDB' in instance:
                instance_nr = instance[-2:]
                # check if instance number exists
                command = [module.get_bin_path('/usr/sap/hostctrl/exe/sapcontrol', required=True)]
                command.extend(['-nr', instance_nr, '-function', 'GetProcessList'])
                check_instance = module.run_command(command, check_rc=False)
                # sapcontrol returns c(0 - 5) exit codes only c(1) is unavailable
                if check_instance[0] != 1:
                    hana_list.append({'NR': instance_nr, 'SID': sid, 'TYPE': 'HDB', 'InstanceType': 'HANA'})
    return hana_list


def get_nw_nr(sids, module):
    nw_list = list()
    type = ""
    for sid in sids:
        for instance in os.listdir('/usr/sap/' + sid):
            instance_nr = instance[-2:]
            command = [module.get_bin_path('/usr/sap/hostctrl/exe/sapcontrol', required=True)]
            # check if returned instance_nr is a number because sapcontrol returns all if a random string is provided
            if instance_nr.isdigit():
                command.extend(['-nr', instance_nr, '-function', 'GetInstanceProperties'])
                check_instance = module.run_command(command, check_rc=False)
                if check_instance[0] != 1:
                    for line in check_instance[1].splitlines():
                        if re.search('INSTANCE_NAME', line):
                            # convert to list and extract last
                            type_raw = (line.strip('][').split(', '))[-1]
                            # split instance number
                            type = type_raw[:-2]
                            nw_list.append({'NR': instance_nr, 'SID': sid, 'TYPE': get_instance_type(type), 'InstanceType': 'NW'})
    return nw_list


def get_instance_type(raw_type):
    if raw_type[0] == "D":
        # It's a PAS
        type = "PAS"
    elif raw_type[0] == "A":
        # It's an ASCS
        type = "ASCS"
    elif raw_type[0] == "W":
        # It's a Webdisp
        type = "WebDisp"
    elif raw_type[0] == "J":
        # It's a Java
        type = "Java"
    elif raw_type[0] == "S":
        # It's an SCS
        type = "SCS"
    elif raw_type[0] == "E":
        # It's an ERS
        type = "ERS"
    else:
        # Unknown instance type
        type = "XXX"
    return type


def run_module():
    module_args = dict()
    system_result = list()

    result = dict(
        changed=False,
        ansible_facts=dict(),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    hana_sid = get_all_hana_sid()
    if hana_sid:
        system_result = system_result + get_hana_nr(hana_sid, module)

    nw_sid = get_all_nw_sid()
    if nw_sid:
        system_result = system_result + get_nw_nr(nw_sid, module)

    if system_result:
        result['ansible_facts'] = {'sap': system_result}
    else:
        result['ansible_facts']

    if module.check_mode:
        module.exit_json(**result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
