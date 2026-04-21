#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_ip
short_description: This module manages IP provisioning on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkip' and 'rmip' commands.
  - This module can run on all IBM Storage Virtualize systems running on 8.4.2.0 or later.
version_added: "1.8.0"
options:
    state:
        description:
            - Creates (C(present)) or removes (C(absent)) an IP address.
        choices: [ present, absent ]
        required: true
        type: str
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        type: str
        required: true
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize system.
            - To generate a token, use the ibm_svc_auth module.
        type: str
    node:
        description:
            - Specifies the name of the node.
        type: str
        required: true
    port:
        description:
            - Specifies a port ranging from 1 - 16 to which IP shall be assigned.
        type: int
        required: true
    portset:
        description:
            - Specifies the name of the portset object.
        type: str
    ip_address:
        description:
            - Specifies a valid ipv4/ipv6 address.
        type: str
        required: true
    subnet_prefix:
        description:
            - Specifies the prefix of subnet mask.
            - Applies when I(state=present).
        type: int
    gateway:
        description:
            - Specifies the gateway address.
            - Applies when I(state=present).
        type: str
    vlan:
        description:
            - Specifies a vlan id ranging from 1 - 4096.
            - Applies when I(state=present).
        type: int
    shareip:
        description:
            - Specifies the flag when IP is shared between multiple portsets.
            - Applies when I(state=present).
        type: bool
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    log_path:
        description:
            - Path of debug log file.
        type: str
author:
    - Sreshtant Bohidar(@Sreshtant-Bohidar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create IP provisioning
  ibm.storage_virtualize.ibm_svc_manage_ip:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   log_path: /tmp/playbook.debug
   node: node1
   port: 1
   portset: portset0
   ip_address: x.x.x.x
   subnet_prefix: 20
   gateway: x.x.x.x
   vlan: 1
   shareip: true
   state: present
- name: Remove IP provisioning
  ibm.storage_virtualize.ibm_svc_manage_ip:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   log_path: /tmp/playbook.debug
   node: node1
   port: 1
   portset: portset0
   ip_address: x.x.x.x
   state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCIp(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                node=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['present', 'absent']),
                port=dict(type='int', required=True),
                portset=dict(type='str'),
                ip_address=dict(type='str', required=True),
                subnet_prefix=dict(type='int'),
                gateway=dict(type='str'),
                vlan=dict(type='int'),
                shareip=dict(type='bool')
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.node = self.module.params['node']
        self.state = self.module.params['state']
        self.port = self.module.params['port']
        self.ip_address = self.module.params.get('ip_address', False)

        # Optional
        self.portset = self.module.params.get('portset', False)
        self.subnet_prefix = self.module.params.get('subnet_prefix', False)
        self.gateway = self.module.params.get('gateway', False)
        self.vlan = self.module.params.get('vlan', False)
        self.shareip = self.module.params.get('shareip', False)

        # Initialize changed variable
        self.changed = False

        # creating an instance of IBMSVCRestApi
        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        if not self.state:
            self.module.fail_json(msg="The parameter [state] is required.")
        if self.state == 'present':
            required_when_present = {
                'node': self.node,
                'port': self.port,
                'ip_address': self.ip_address,
                'subnet_prefix': self.subnet_prefix
            }
            missing_present = [item for item, value in required_when_present.items() if not value]
            if missing_present:
                self.module.fail_json(msg="The parameter {0} is required when state is present.".format(missing_present))
        if self.state == 'absent':
            required_when_absent = {
                'node': self.node,
                'port': self.port,
                'ip_address': self.ip_address
            }
            not_required_when_absent = {
                'subnet_prefix': self.subnet_prefix,
                'gateway': self.gateway,
                'vlan': self.vlan,
                'shareip': self.shareip
            }
            missing_absent = [item for item, value in required_when_absent.items() if not value]
            if missing_absent:
                self.module.fail_json(msg="The parameter {0} is required when state is absent.".format(missing_absent))
            not_applicable_absent = [item for item, value in not_required_when_absent.items() if value]
            if not_applicable_absent:
                self.module.fail_json(msg="The parameter {0} are not applicable when state is absent.".format(not_applicable_absent))

    def get_ip_info(self):
        all_data = self.restapi.svc_obj_info(cmd='lsip', cmdopts=None, cmdargs=None)
        if self.portset:
            data = list(
                filter(
                    lambda item: item['node_name'] == self.node and
                    item['port_id'] == str(self.port) and
                    item['portset_name'] == self.portset and
                    item['IP_address'] == self.ip_address, all_data
                )
            )
        else:
            data = list(
                filter(
                    lambda item: item['node_name'] == self.node and
                    item['port_id'] == str(self.port) and
                    item['IP_address'] == self.ip_address, all_data
                )
            )
            if len(data) > 1:
                self.module.fail_json(msg="Module could not find the exact IP with [node, port, ip_address]. Please also use [portset].")
        self.log('GET: IP data: %s', data)
        return data

    def create_ip(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'mkip'
        command_options = {
            'node': self.node,
            'port': self.port,
            'ip': self.ip_address,
            'prefix': self.subnet_prefix
        }
        if self.portset:
            command_options['portset'] = self.portset
        if self.gateway:
            command_options['gw'] = self.gateway
        if self.vlan:
            command_options['vlan'] = self.vlan
        if self.shareip:
            command_options['shareip'] = self.shareip
        result = self.restapi.svc_run_command(command, command_options, cmdargs=None)
        self.log("create IP result %s", result)
        if 'message' in result:
            self.changed = True
            self.log("create IP result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create IP [%s]" % self.ip_address)

    def remove_ip(self, ip_address_id):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'rmip'
        command_options = None
        cmdargs = [ip_address_id]
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.changed = True
        self.log("removed IP '%s'", self.ip_address)

    def apply(self):
        msg = None
        self.basic_checks()
        if self.state == 'present':
            self.create_ip()
            msg = "IP address {0} has been created.".format(self.ip_address)
        elif self.state == 'absent':
            ip_data = self.get_ip_info()
            if ip_data:
                self.remove_ip(ip_data[0]['id'])
                msg = "IP address {0} has been removed.".format(self.ip_address)
            else:
                msg = "IP address {0} does not exist.".format(self.ip_address)

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCIp()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
