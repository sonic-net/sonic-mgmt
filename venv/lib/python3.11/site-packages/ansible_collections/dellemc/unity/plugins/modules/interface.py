#!/usr/bin/python
# Copyright: (c) 2022-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing Interfaces on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
module: interface
version_added: '1.4.0'
short_description: Manage Interfaces on Unity storage system
description:
- Managing the Interfaces on the Unity storage system includes adding Interfaces to NAS Server, getting
  details of interface and deleting configured interfaces.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Meenakshi Dembi (@dembim) <ansible.team@dell.com>

options:
  nas_server_name:
    description:
    - Name of the NAS server for which interface will be configured.
    type: str
  nas_server_id:
    description:
    - ID of the NAS server for which interface will be configured.
    type: str
  ethernet_port_name:
    description:
    - Name of the ethernet port.
    type: str
  ethernet_port_id:
    description:
    - ID of the ethernet port.
    type: str
  role:
    description:
    - Indicates whether interface is configured as production or backup.
    choices: [PRODUCTION, BACKUP]
    type: str
  interface_ip:
    description:
    - IP of network interface.
    required: true
    type: str
  netmask:
    description:
    - Netmask of network interface.
    type: str
  prefix_length:
    description:
    - Prefix length is mutually exclusive with I(netmask).
    type: int
  gateway:
    description:
    - Gateway of network interface.
    type: str
  vlan_id:
    description:
    - Vlan id of the interface.
    type: int
  state:
    description:
    - Define whether the interface should exist or not.
    choices: [present, absent]
    required: true
    type: str
notes:
- The I(check_mode) is supported.
- Modify operation for interface is not supported.
'''

EXAMPLES = r'''

- name: Add Interface as Backup to NAS Server
  interface:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    ethernet_port_name: "SP A 4-Port Card Ethernet Port 0"
    role: "BACKUP"
    interface_ip: "xx.xx.xx.xx"
    netmask: "xx.xx.xx.xx"
    gateway: "xx.xx.xx.xx"
    vlan_id: 324
    state: "present"

- name: Add Interface as Production to NAS Server
  interface:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    ethernet_port_name: "SP A 4-Port Card Ethernet Port 0"
    role: "PRODUCTION"
    interface_ip: "xx.xx.xx.xx"
    netmask: "xx.xx.xx.xx"
    gateway: "xx.xx.xx.xx"
    vlan_id: 324
    state: "present"

- name: Get interface details
  interface:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    interface_ip: "xx.xx.xx.xx"
    state: "present"

- name: Delete Interface
  interface:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    interface_ip: "xx.xx.xx.xx"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true
interface_details:
    description: Details of the interface.
    returned: When interface is configured for NAS Server.
    type: dict
    contains:
        existed:
            description: Indicates if interface exists.
            type: bool
        gateway:
            description: Gateway of network interface.
            type: str
        id:
            description: Unique identifier interface.
            type: str
        ip_address:
            description: IP address of interface.
            type: str
        ip_port:
            description: Port on which network interface is configured.
            type: dict
            contains:
                id:
                    description: ID of ip_port.
                    type: str
        ip_protocol_version:
            description: IP protocol version.
            type: str
        is_disabled:
            description: Indicates whether interface is disabled.
            type: bool
        is_preferred:
            description: Indicates whether interface is preferred.
            type: bool
        mac_address:
            description: Mac address of ip_port.
            type: bool
        name:
            description: System configured name of interface.
            type: bool
        nas_server:
            description: Details of NAS server where interface is configured.
            type: dict
            contains:
                id:
                    description: ID of NAS Server.
                    type: str
    sample: {
        "existed": true,
        "gateway": "xx.xx.xx.xx",
        "hash": 8785300560421,
        "health": {
            "UnityHealth": {
                "hash": 8785300565468
            }
        },
        "id": "if_69",
        "ip_address": "10.10.10.10",
        "ip_port": {
            "UnityIpPort": {
                "hash": 8785300565300,
                "id": "spb_ocp_0_eth0"
            }
        },
        "ip_protocol_version": "IpProtocolVersionEnum.IPv4",
        "is_disabled": false,
        "is_preferred": true,
        "mac_address": "0C:48:C6:9F:57:BF",
        "name": "36_APM00213404194",
        "nas_server": {
            "UnityNasServer": {
                "hash": 8785300565417,
                "id": "nas_10"
            }
        },
        "netmask": "10.10.10.10",
        "replication_policy": null,
        "role": "FileInterfaceRoleEnum.PRODUCTION",
        "source_parameters": null,
        "v6_prefix_length": null,
        "vlan_id": 324
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils
import ipaddress
from ipaddress import ip_network

LOG = utils.get_logger('interface')

application_type = "Ansible/1.7.1"


class Interface(object):
    """Class with Interface operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_interface_parameters())

        mutually_exclusive = [['nas_server_name', 'nas_server_id'], ['ethernet_port_id', 'ethernet_port_name'], ['netmask', 'prefix_length']]
        required_one_of = [['nas_server_name', 'nas_server_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=True,
            mutually_exclusive=mutually_exclusive,
            required_one_of=required_one_of
        )
        utils.ensure_required_libs(self.module)

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        LOG.info('Check Mode Flag %s', self.module.check_mode)

    def get_interface_details(self, nas_server_obj):
        """Get interface details.
            :param: nas_server_obj: NAS server object.
            :return: Returns interface details configured on NAS server.
        """

        try:
            nas_server_obj_properties = nas_server_obj._get_properties()
            if nas_server_obj_properties['file_interface']:
                for item in nas_server_obj_properties['file_interface']['UnityFileInterfaceList']:
                    interface_id = self.unity_conn.get_file_interface(_id=item['UnityFileInterface']['id'])
                    if interface_id.ip_address == self.module.params['interface_ip']:
                        return interface_id
            return None
        except Exception as e:
            error_msg = "Getting Interface details failed" \
                        " with error %s" % (str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_nas_server_obj(self, nas_server_name, nas_server_id):
        """Get NAS server ID.
            :param: nas_server_name: The name of NAS server
            :param: nas_server_id: ID of NAS server
            :return: Return NAS server object if exists
        """

        LOG.info("Getting NAS server object")
        try:
            if nas_server_name:
                obj_nas = self.unity_conn.get_nas_server(name=nas_server_name)
                return obj_nas
            elif nas_server_id:
                obj_nas = self.unity_conn.get_nas_server(_id=nas_server_id)
                if obj_nas._get_properties()['existed']:
                    return obj_nas
                else:
                    msg = "NAS server with id %s does not exist" % (nas_server_id)
                    LOG.error(msg)
                    self.module.fail_json(msg=msg)
        except Exception as e:
            msg = "Failed to get details of NAS server with error: %s" % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def add_interface(self, nas_server_obj, ethernet_port_id=None, ethernet_port_name=None, role=None, interface_ip=None,
                      netmask=None, prefix_length=None, gateway=None, vlan_id=None):
        """Adding interface to NAS server.
            :param: nas_server_obj: The NAS server object.
            :param: ethernet_port_id: ID of ethernet port.
            :param: ethernet_port_name: Name of ethernet port.
            :param: role: Role of the interface.
            :param: interface_ip: IP of interface.
            :param: netmask: Netmask for interface.
            :param: prefix_length: Prefix length.
            :param: gateway: Gateway for interface.
            :param: vlan_id: vlan_id for interface.
            :return: Return True if interface is configured successfully.
        """

        LOG.info("Adding interface to NAS Server")
        try:
            nas_server_obj_properties = nas_server_obj._get_properties()
            if nas_server_obj_properties['file_interface']:
                for item in nas_server_obj_properties['file_interface']['UnityFileInterfaceList']:
                    interface_id = self.unity_conn.get_file_interface(_id=item['UnityFileInterface']['id'])
                    if interface_id._get_properties()['ip_address'] == self.module.params['interface_ip']:
                        return False
            if role:
                role_value = get_role_enum(role)
            if ethernet_port_name:
                ethernet_port_info = self.unity_conn.get_ethernet_port(name=ethernet_port_name)
                ethernet_port_id = ethernet_port_info.id
            if not self.module.check_mode:
                utils.UnityFileInterface.create(cli=self.unity_conn._cli, nas_server=nas_server_obj.get_id(), ip_port=ethernet_port_id,
                                                role=role_value, ip=interface_ip, netmask=netmask, v6_prefix_length=prefix_length,
                                                gateway=gateway, vlan_id=vlan_id)
            return True
        except Exception as e:
            msg = "Failed to add interface to NAS Server with error: %s" % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def is_modification_required(self, interface_details):
        """Check if modification is required in existing interface/s configured for NAS Server
            :param: interface_details: Existing interface details
            :return: True if modification is required
        """
        key_list = ['vlan_id', 'gateway', 'netmask']
        for item in key_list:
            if self.module.params[item] and self.module.params[item] != interface_details[item]:
                return True
        return False

    def delete_interface(self, interface_obj):
        """Delete NFS server.
            :param: interface_obj: Interface object.
            :return: Return True if interface is deleted.
        """

        LOG.info("Deleting interface")
        try:
            if not self.module.check_mode:
                interface_obj.delete()
            return True
        except Exception as e:
            msg = "Failed to delete interface with error: %s" % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def validate_input_params(self):
        """Validates input parameters"""
        param_list = ["nas_server_id", "nas_server_name",
                      "ethernet_port_name", "ethernet_port_id", "role",
                      "interface_ip", "netmask", "gateway"]

        for param in param_list:
            msg = "Please provide valid value for: %s" % param
            if self.module.params[param] is not None and \
                    len(self.module.params[param].strip()) == 0:
                errmsg = msg.format(param)
                self.module.fail_json(msg=errmsg)

        if self.module.params['vlan_id'] is not None and \
                (self.module.params['vlan_id'] <= 3 or
                 self.module.params['vlan_id'] >= 4094):
            self.module.fail_json(msg='vlan_id should be in the '
                                      'range of 3 to 4094')

        if self.module.params['interface_ip'] and \
                not is_valid_ip(self.module.params['interface_ip']):
            self.module.fail_json(msg='The value for interface ip is invalid')

        if self.module.params['gateway'] and \
                not is_valid_ip(self.module.params['gateway']):
            self.module.fail_json(msg='The value for gateway is invalid')

        if self.module.params['netmask'] and not \
                utils.is_valid_netmask(self.module.params['netmask']):
            self.module.fail_json(msg='Invalid IPV4 address specified '
                                      'for netmask')

        if self.module.params['interface_ip'] and \
                (get_ip_version(self.module.params['interface_ip']) == 6):
            self.module.fail_json(msg='IPv6 format is not supported')

    def validate_create_params(self):
        """Validates input parameters for adding interface"""
        if self.module.params['role'] is None:
            self.module.fail_json(msg='Role is a mandatory parameter'
                                      ' for adding interface to NAS Server.')
        if self.module.params['ethernet_port_name'] is None and \
                self.module.params['ethernet_port_id'] is None:
            self.module.fail_json(msg='ethernet_port_name/ethernet_port_id '
                                      'is mandatory parameter for adding '
                                      'interface to NAS Server.')

    def perform_module_operation(self):
        """
        Perform different actions on Interface module based on parameters
        passed in the playbook
        """
        nas_server_id = self.module.params['nas_server_id']
        nas_server_name = self.module.params['nas_server_name']
        ethernet_port_name = self.module.params['ethernet_port_name']
        ethernet_port_id = self.module.params['ethernet_port_id']
        role = self.module.params['role']
        interface_ip = self.module.params['interface_ip']
        netmask = self.module.params['netmask']
        prefix_length = self.module.params['prefix_length']
        gateway = self.module.params['gateway']
        vlan_id = self.module.params['vlan_id']
        state = self.module.params['state']

        # result is a dictionary that contains changed status and Interface details
        result = dict(
            changed=False,
            interface_details={}
        )
        modify_flag = False

        self.validate_input_params()

        interface_details = None

        nas_server_obj = self.get_nas_server_obj(nas_server_name, nas_server_id)

        interface_obj = self.get_interface_details(nas_server_obj)

        if interface_obj and state == 'present':
            interface_details = interface_obj._get_properties()
            modify_flag = self.is_modification_required(interface_details)
            if modify_flag:
                self.module.fail_json(msg="Modification of Interfaces for NAS server is not supported through Ansible module")

        if not interface_obj and state == 'present':
            self.validate_create_params()

            result['changed'] = self.add_interface(nas_server_obj, ethernet_port_id, ethernet_port_name, role,
                                                   interface_ip, netmask, prefix_length, gateway, vlan_id)

        if interface_obj and state == 'absent':
            result['changed'] = self.delete_interface(interface_obj)

        if result['changed']:
            nas_server_obj = self.get_nas_server_obj(nas_server_name, nas_server_id)
            interface_obj = self.get_interface_details(nas_server_obj)
            if interface_obj:
                interface_details = interface_obj._get_properties()

        result['interface_details'] = interface_details

        self.module.exit_json(**result)


def get_interface_parameters():
    """This method provide parameters required for the ansible
       Interface module on Unity"""
    return dict(
        nas_server_id=dict(type='str'),
        nas_server_name=dict(type='str'),
        ethernet_port_name=dict(type='str'),
        ethernet_port_id=dict(type='str'),
        role=dict(type='str', choices=['PRODUCTION', 'BACKUP']),
        interface_ip=dict(required=True, type='str'),
        netmask=dict(type='str'),
        prefix_length=dict(type='int'),
        gateway=dict(type='str'),
        vlan_id=dict(type='int'),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def get_role_enum(role):
    """Getting correct enum values for role
        :param: role: Indicates role of interface.
        :return: enum value for role.
    """
    if utils.FileInterfaceRoleEnum[role]:
        role = utils.FileInterfaceRoleEnum[role]
        return role


def is_valid_ip(address):
    """Validating IP address format
        :param: address: IP address to be validated for format.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_ip_version(val):
    """Returns IP address version
        :param: val: IP address to be validated for version.
    """
    try:
        val = u'{0}'.format(val)
        ip = ip_network(val, strict=False)
        return ip.version
    except ValueError:
        return 0


def main():
    """Create Unity Interface object and perform action on it
       based on user input from playbook"""
    obj = Interface()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
