#!/usr/bin/python
# Copyright: (c) 2022-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing CIFS server on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
module: cifsserver
version_added: '1.4.0'
short_description: Manage CIFS server on Unity storage system
description:
- Managing the CIFS server on the Unity storage system includes creating CIFS server, getting CIFS server details
  and deleting CIFS server.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Akash Shendge (@shenda1) <ansible.team@dell.com>

options:
  nas_server_name:
    description:
    - Name of the NAS server on which CIFS server will be hosted.
    type: str
  nas_server_id:
    description:
    - ID of the NAS server on which CIFS server will be hosted.
    type: str
  netbios_name:
    description:
    - The computer name of the SMB server in Windows network.
    type: str
  workgroup:
    description:
    - Standalone SMB server workgroup.
    type: str
  local_password:
    description:
    - Standalone SMB server administrator password.
    type: str
  domain:
    description:
    - The domain name where the SMB server is registered in Active Directory.
    type: str
  domain_username:
    description:
    - Active Directory domain user name.
    type: str
  domain_password:
    description:
    - Active Directory domain password.
    type: str
  cifs_server_name:
    description:
    - The name of the CIFS server.
    type: str
  cifs_server_id:
    description:
    - The ID of the CIFS server.
    type: str
  interfaces:
    description:
    - List of file IP interfaces that service CIFS protocol of SMB server.
    type: list
    elements: str
  unjoin_cifs_server_account:
    description:
    - Keep SMB server account unjoined in Active Directory after deletion.
    - C(false) specifies keep SMB server account joined after deletion.
    - C(true) specifies unjoin SMB server account from Active Directory before deletion.
    type: bool
  state:
    description:
    - Define whether the CIFS server should exist or not.
    choices: [absent, present]
    required: true
    type: str
notes:
- The I(check_mode) is supported.
'''

EXAMPLES = r'''
- name: Create CIFS server belonging to Active Directory
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "test_nas1"
    cifs_server_name: "test_cifs"
    domain: "ad_domain"
    domain_username: "domain_username"
    domain_password: "domain_password"
    state: "present"

- name: Get CIFS server details using CIFS server ID
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    cifs_server_id: "cifs_37"
    state: "present"

- name: Get CIFS server details using NAS server name
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "test_nas1"
    state: "present"

- name: Delete CIFS server
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    cifs_server_id: "cifs_37"
    unjoin_cifs_server_account: true
    domain_username: "domain_username"
    domain_password: "domain_password"
    state: "absent"

- name: Create standalone CIFS server
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    netbios_name: "ANSIBLE_CIFS"
    workgroup: "ansible"
    local_password: "Password123!"
    nas_server_name: "test_nas1"
    state: "present"

- name: Get CIFS server details using netbios name
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    netbios_name: "ANSIBLE_CIFS"
    state: "present"

- name: Delete standalone CIFS server
  cifsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    cifs_server_id: "cifs_40"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

cifs_server_details:
    description: Details of the CIFS server.
    returned: When CIFS server exists
    type: dict
    contains:
        id:
            description: Unique identifier of the CIFS server instance.
            type: str
        name:
            description: User-specified name for the SMB server.
            type: str
        netbios_name:
            description: Computer Name of the SMB server in windows network.
            type: str
        description:
            description: Description of the SMB server.
            type: str
        domain:
            description: Domain name where SMB server is registered in Active Directory.
            type: str
        workgroup:
            description: Windows network workgroup for the SMB server.
            type: str
        is_standalone:
            description: Indicates whether the SMB server is standalone.
            type: bool
        nasServer:
            description: Information about the NAS server in the storage system.
            type: dict
            contains:
                UnityNasServer:
                    description: Information about the NAS server in the storage system.
                    type: dict
                    contains:
                        id:
                            description: Unique identifier of the NAS server instance.
                            type: str
        file_interfaces:
            description: The file interfaces associated with the NAS server.
            type: dict
            contains:
                UnityFileInterfaceList:
                    description: List of file interfaces associated with the NAS server.
                    type: list
                    contains:
                        UnityFileInterface:
                            description: Details of file interface associated with the NAS server.
                            type: dict
                            contains:
                                id:
                                    description: Unique identifier of the file interface.
                                    type: str
        smb_multi_channel_supported:
            description: Indicates whether the SMB 3.0+ multichannel feature is supported.
            type: bool
        smb_protocol_versions:
            description: Supported SMB protocols, such as 1.0, 2.0, 2.1, 3.0, and so on.
            type: list
        smbca_supported:
            description: Indicates whether the SMB server supports continuous availability.
            type: bool
    sample: {
        "description": null,
        "domain": "xxx.xxx.xxx.com",
        "existed": true,
        "file_interfaces": {
            "UnityFileInterfaceList": [
                {
                    "UnityFileInterface": {
                        "hash": -9223363258905013637,
                        "id": "if_43"
                    }
                }
            ]
        },
        "hash": -9223363258905010379,
        "health": {
            "UnityHealth": {
                "hash": 8777949765559
            }
        },
        "id": "cifs_40",
        "is_standalone": false,
        "last_used_organizational_unit": "ou=Computers,ou=Dell NAS servers",
        "name": "ansible_cifs",
        "nas_server": {
            "UnityNasServer": {
                "hash": 8777949765531,
                "id": "nas_18"
            }
        },
        "netbios_name": "ANSIBLE_CIFS",
        "smb_multi_channel_supported": true,
        "smb_protocol_versions": [
            "1.0",
            "2.0",
            "2.1",
            "3.0"
        ],
        "smbca_supported": true,
        "workgroup": null
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell import utils

LOG = utils.get_logger('cifsserver')


application_type = "Ansible/1.7.1"


class CIFSServer(object):
    """Class with CIFS server operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_cifs_server_parameters())

        mutually_exclusive = [['nas_server_name', 'nas_server_id'], ['cifs_server_id', 'cifs_server_name'],
                              ['cifs_server_id', 'netbios_name']]
        required_one_of = [['cifs_server_id', 'cifs_server_name', 'netbios_name', 'nas_server_name', 'nas_server_id']]

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

    def get_details(self, cifs_server_id=None, cifs_server_name=None, netbios_name=None, nas_server_id=None):
        """Get CIFS server details.
            :param: cifs_server_id: The ID of the CIFS server
            :param: cifs_server_name: The name of the CIFS server
            :param: netbios_name: Name of the SMB server in windows network
            :param: nas_server_id: The ID of the NAS server
            :return: Dict containing CIFS server details if exists
        """

        LOG.info("Getting CIFS server details")
        id_or_name = get_id_name(cifs_server_id, cifs_server_name, netbios_name, nas_server_id)

        try:
            if cifs_server_id:
                cifs_server_details = self.unity_conn.get_cifs_server(_id=cifs_server_id)
                return process_response(cifs_server_details)

            if cifs_server_name:
                cifs_server_details = self.unity_conn.get_cifs_server(name=cifs_server_name)
                return process_response(cifs_server_details)

            if netbios_name:
                cifs_server_details = self.unity_conn.get_cifs_server(netbios_name=netbios_name)
                if len(cifs_server_details) > 0:
                    return process_dict(cifs_server_details._get_properties())

            if nas_server_id:
                cifs_server_details = self.unity_conn.get_cifs_server(nas_server=nas_server_id)
                if len(cifs_server_details) > 0:
                    return process_dict(cifs_server_details._get_properties())
            return None
        except utils.HttpError as e:
            if e.http_status == 401:
                msg = "Failed to get CIFS server: %s due to incorrect " \
                      "username/password error: %s" % (id_or_name, str(e))
            else:
                msg = "Failed to get CIFS server: %s with error: %s" % (id_or_name, str(e))
        except utils.UnityResourceNotFoundError:
            msg = "CIFS server with ID %s not found" % cifs_server_id
            LOG.info(msg)
            return None
        except utils.StoropsConnectTimeoutError as e:
            msg = "Failed to get CIFS server: %s with error: %s. Please check unispherehost IP: %s" % (
                id_or_name, str(e), self.module.params['unispherehost'])
        except Exception as e:
            msg = "Failed to get details of CIFS server: %s with error: %s" % (id_or_name, str(e))
        LOG.error(msg)
        self.module.fail_json(msg=msg)

    def get_cifs_server_instance(self, cifs_server_id):
        """Get CIFS server instance.
            :param: cifs_server_id: The ID of the CIFS server
            :return: Return CIFS server instance if exists
        """

        try:
            cifs_server_obj = utils.UnityCifsServer.get(cli=self.unity_conn._cli, _id=cifs_server_id)
            return cifs_server_obj

        except Exception as e:
            error_msg = "Failed to get the CIFS server %s instance" \
                        " with error %s" % (cifs_server_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def delete_cifs_server(self, cifs_server_id, skip_unjoin=None, domain_username=None, domain_password=None):
        """Delete CIFS server.
            :param: cifs_server_id: The ID of the CIFS server
            :param: skip_unjoin: Flag indicating whether to unjoin SMB server account from AD before deletion
            :param: domain_username: The domain username
            :param: domain_password: The domain password
            :return: Return True if CIFS server is deleted
        """

        LOG.info("Deleting CIFS server")
        try:
            if not self.module.check_mode:
                cifs_obj = self.get_cifs_server_instance(cifs_server_id=cifs_server_id)
                cifs_obj.delete(skip_domain_unjoin=skip_unjoin, username=domain_username, password=domain_password)
            return True

        except Exception as e:
            msg = "Failed to delete CIFS server: %s with error: %s" % (cifs_server_id, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_nas_server_id(self, nas_server_name):
        """Get NAS server ID.
            :param: nas_server_name: The name of NAS server
            :return: Return NAS server ID if exists
        """

        LOG.info("Getting NAS server ID")
        try:
            obj_nas = self.unity_conn.get_nas_server(name=nas_server_name)
            return obj_nas.get_id()

        except Exception as e:
            msg = "Failed to get details of NAS server: %s with error: %s" % (nas_server_name, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def is_modify_interfaces(self, cifs_server_details):
        """Check if modification is required in existing interfaces
            :param: cifs_server_details: CIFS server details
            :return: Flag indicating if modification is required
        """

        existing_interfaces = []
        if cifs_server_details['file_interfaces']['UnityFileInterfaceList']:
            for interface in cifs_server_details['file_interfaces']['UnityFileInterfaceList']:
                existing_interfaces.append(interface['UnityFileInterface']['id'])

        for interface in self.module.params['interfaces']:
            if interface not in existing_interfaces:
                return True
        return False

    def is_modification_required(self, cifs_server_details):
        """Check if modification is required in existing CIFS server
            :param: cifs_server_details: CIFS server details
            :return: Flag indicating if modification is required
        """

        LOG.info("Checking if any modification is required")
        param_list = ['netbios_name', 'workgroup']
        for param in param_list:
            if self.module.params[param] is not None and cifs_server_details[param] is not None and \
                    self.module.params[param].upper() != cifs_server_details[param]:
                return True

        # Check for domain
        if self.module.params['domain'] is not None and cifs_server_details['domain'] is not None and \
                self.module.params['domain'] != cifs_server_details['domain']:
            return True

        # Check file interfaces
        if self.module.params['interfaces'] is not None:
            return self.is_modify_interfaces(cifs_server_details)
        return False

    def create_cifs_server(self, nas_server_id, interfaces=None, netbios_name=None, cifs_server_name=None, domain=None,
                           domain_username=None, domain_password=None, workgroup=None, local_password=None):
        """Create CIFS server.
            :param: nas_server_id: The ID of NAS server
            :param: interfaces: List of file interfaces
            :param: netbios_name: Name of the SMB server in windows network
            :param: cifs_server_name: Name of the CIFS server
            :param: domain: The domain name where the SMB server is registered in Active Directory
            :param: domain_username: The domain username
            :param: domain_password: The domain password
            :param: workgroup: Standalone SMB server workgroup
            :param: local_password: Standalone SMB server admin password
            :return: Return True if CIFS server is created
        """

        LOG.info("Creating CIFS server")
        try:
            if not self.module.check_mode:
                utils.UnityCifsServer.create(cli=self.unity_conn._cli, nas_server=nas_server_id, interfaces=interfaces,
                                             netbios_name=netbios_name, name=cifs_server_name, domain=domain,
                                             domain_username=domain_username, domain_password=domain_password,
                                             workgroup=workgroup, local_password=local_password)
            return True
        except Exception as e:
            msg = "Failed to create CIFS server with error: %s" % (str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def validate_params(self):
        """Validate the parameters
        """

        param_list = ['nas_server_id', 'nas_server_name', 'domain', 'cifs_server_id', 'cifs_server_name',
                      'local_password', 'netbios_name', 'workgroup', 'domain_username', 'domain_password']

        msg = "Please provide valid {0}"
        for param in param_list:
            if self.module.params[param] is not None and len(self.module.params[param].strip()) == 0:
                errmsg = msg.format(param)
                self.module.fail_json(msg=errmsg)

    def perform_module_operation(self):
        """
        Perform different actions on CIFS server module based on parameters
        passed in the playbook
        """
        cifs_server_id = self.module.params['cifs_server_id']
        cifs_server_name = self.module.params['cifs_server_name']
        nas_server_id = self.module.params['nas_server_id']
        nas_server_name = self.module.params['nas_server_name']
        netbios_name = self.module.params['netbios_name']
        workgroup = self.module.params['workgroup']
        local_password = self.module.params['local_password']
        domain = self.module.params['domain']
        domain_username = self.module.params['domain_username']
        domain_password = self.module.params['domain_password']
        interfaces = self.module.params['interfaces']
        unjoin_cifs_server_account = self.module.params['unjoin_cifs_server_account']
        state = self.module.params['state']

        # result is a dictionary that contains changed status and CIFS server details
        result = dict(
            changed=False,
            cifs_server_details={}
        )

        # Validate the parameters
        self.validate_params()

        if nas_server_name is not None:
            nas_server_id = self.get_nas_server_id(nas_server_name)

        cifs_server_details = self.get_details(cifs_server_id=cifs_server_id,
                                               cifs_server_name=cifs_server_name,
                                               netbios_name=netbios_name,
                                               nas_server_id=nas_server_id)

        # Check if modification is required
        if cifs_server_details:
            if cifs_server_id is None:
                cifs_server_id = cifs_server_details['id']
            modify_flag = self.is_modification_required(cifs_server_details)
            if modify_flag:
                self.module.fail_json(msg="Modification is not supported through Ansible module")

        if not cifs_server_details and state == 'present':
            if not nas_server_id:
                self.module.fail_json(msg="Please provide nas server id/name to create CIFS server.")

            if any([netbios_name, workgroup, local_password]) and not all([netbios_name, workgroup, local_password]):
                msg = "netbios_name, workgroup and local_password " \
                      "are required to create standalone CIFS server."
                LOG.error(msg)
                self.module.fail_json(msg=msg)

            result['changed'] = self.create_cifs_server(nas_server_id, interfaces, netbios_name,
                                                        cifs_server_name, domain, domain_username, domain_password,
                                                        workgroup, local_password)

        if state == 'absent' and cifs_server_details:
            skip_unjoin = None
            if unjoin_cifs_server_account is not None:
                skip_unjoin = not unjoin_cifs_server_account
            result['changed'] = self.delete_cifs_server(cifs_server_id, skip_unjoin, domain_username,
                                                        domain_password)

        if state == 'present':
            result['cifs_server_details'] = self.get_details(cifs_server_id=cifs_server_id,
                                                             cifs_server_name=cifs_server_name,
                                                             netbios_name=netbios_name,
                                                             nas_server_id=nas_server_id)
            LOG.info("Process Dict: %s", result['cifs_server_details'])
        self.module.exit_json(**result)


def get_id_name(cifs_server_id=None, cifs_server_name=None, netbios_name=None, nas_server_id=None):
    """Get the id_or_name.
        :param: cifs_server_id: The ID of CIFS server
        :param: cifs_server_name: The name of CIFS server
        :param: netbios_name: Name of the SMB server in windows network
        :param: nas_server_id: The ID of NAS server
        :return: Return id_or_name
    """
    if cifs_server_id:
        id_or_name = cifs_server_id
    elif cifs_server_name:
        id_or_name = cifs_server_name
    elif netbios_name:
        id_or_name = netbios_name
    else:
        id_or_name = nas_server_id
    return id_or_name


def process_response(cifs_server_details):
    """Process CIFS server details.
        :param: cifs_server_details: Dict containing CIFS server details
        :return: Processed dict containing CIFS server details
    """
    if cifs_server_details.existed:
        return cifs_server_details._get_properties()


def process_dict(cifs_server_details):
    """Process CIFS server details.
        :param: cifs_server_details: Dict containing CIFS server details
        :return: Processed dict containing CIFS server details
    """
    param_list = ['description', 'domain', 'file_interfaces', 'health', 'id', 'is_standalone', 'name', 'nas_server'
                  'netbios_name', 'smb_multi_channel_supported', 'smb_protocol_versions', 'smbca_supported',
                  'workgroup', 'netbios_name']

    for param in param_list:
        if param in cifs_server_details:
            cifs_server_details[param] = cifs_server_details[param][0]
    return cifs_server_details


def get_cifs_server_parameters():
    """This method provide parameters required for the ansible
       CIFS server module on Unity"""
    return dict(
        cifs_server_id=dict(), cifs_server_name=dict(),
        netbios_name=dict(), workgroup=dict(),
        local_password=dict(no_log=True), domain=dict(),
        domain_username=dict(), domain_password=dict(no_log=True),
        nas_server_name=dict(), nas_server_id=dict(),
        interfaces=dict(type='list', elements='str'),
        unjoin_cifs_server_account=dict(type='bool'),
        state=dict(required=True, type='str', choices=['present', 'absent']),
    )


def main():
    """Create Unity CIFS server object and perform action on it
       based on user input from playbook"""
    obj = CIFSServer()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
