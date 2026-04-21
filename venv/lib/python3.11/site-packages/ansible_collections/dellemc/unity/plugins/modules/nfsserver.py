#!/usr/bin/python
# Copyright: (c) 2022-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt))

"""Ansible module for managing NFS server on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
module: nfsserver
version_added: '1.4.0'
short_description: Manage NFS server on Unity storage system
description:
- Managing the NFS server on the Unity storage system includes creating NFS server, getting NFS server details
  and deleting NFS server attributes.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Meenakshi Dembi (@dembim) <ansible.team@dell.com>

options:
  nas_server_name:
    description:
    - Name of the NAS server on which NFS server will be hosted.
    type: str
  nas_server_id:
    description:
    - ID of the NAS server on which NFS server will be hosted.
    type: str
  nfs_server_id:
    description:
    - ID of the NFS server.
    type: str
  host_name:
    description:
    - Host name of the NFS server.
    type: str
  nfs_v4_enabled:
    description:
    - Indicates whether the NFSv4 is enabled on the NAS server.
    type: bool
  is_secure_enabled:
    description:
    - Indicates whether the secure NFS is enabled.
    type: bool
  kerberos_domain_controller_type:
    description:
    - Type of Kerberos Domain Controller used for secure NFS service.
    choices: [CUSTOM, UNIX, WINDOWS]
    type: str
  kerberos_domain_controller_username:
    description:
    - Kerberos Domain Controller administrator username.
    type: str
  kerberos_domain_controller_password:
    description:
    - Kerberos Domain Controller administrator password.
    type: str
  is_extended_credentials_enabled:
    description:
    - Indicates whether support for more than 16 unix groups in a Unix credential.
    type: bool
  remove_spn_from_kerberos:
    description:
    - Indicates whether to remove the SPN from Kerberos Domain Controller.
    default: true
    type: bool
  state:
    description:
    - Define whether the NFS server should exist or not.
    choices: [absent, present]
    required: true
    type: str
notes:
- The I(check_mode) is supported.
- Modify operation for NFS Server is not supported.
- When I(kerberos_domain_controller_type) is C(UNIX), I(kdc_type) in I(nfs_server_details) output is displayed as C(null).
'''

EXAMPLES = r'''

- name: Create NFS server with kdctype as Windows
  nfsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    host_name: "dummy_nas23"
    is_secure_enabled: true
    kerberos_domain_controller_type: "WINDOWS"
    kerberos_domain_controller_username: "administrator"
    kerberos_domain_controller_password: "Password123!"
    is_extended_credentials_enabled: true
    nfs_v4_enabled: true
    state: "present"

- name: Create NFS server with kdctype as Unix
  nfsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    host_name: "dummy_nas23"
    is_secure_enabled: true
    kerberos_domain_controller_type: "UNIX"
    is_extended_credentials_enabled: true
    nfs_v4_enabled: true
    state: "present"

- name: Get NFS server details
  nfsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    state: "present"

- name: Delete NFS server
  nfsserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    kerberos_domain_controller_username: "administrator"
    kerberos_domain_controller_password: "Password123!"
    unjoin_server_account: false
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true
nfs_server_details:
    description: Details of the NFS server.
    returned: When NFS server exists
    type: dict
    contains:
        credentials_cache_ttl:
            description: Credential cache refresh timeout. Resolution is in minutes. Default value is 15 minutes.
            type: str
        existed:
            description: Indicates if NFS Server exists.
            type: bool
        host_name:
            description: Host name of the NFS server.
            type: str
        id:
            description: Unique identifier of the NFS Server instance.
            type: str
        is_extended_credentials_enabled:
            description: Indicates whether the NFS server supports more than 16 Unix groups in a Unix credential.
            type: bool
        is_secure_enabled:
            description: Indicates whether secure NFS is enabled on the NFS server.
            type: bool
        kdc_type:
            description: Type of Kerberos Domain Controller used for secure NFS service.
            type: str
        nfs_v4_enabled:
            description: Indicates whether NFSv4 is enabled on the NAS server.
            type: bool
        servicee_principal_name:
            description: The Service Principal Name (SPN) for the NFS Server.
            type: str
    sample: {
        "credentials_cache_ttl": "0:15:00",
        "existed": true,
        "file_interfaces": {
            "UnityFileInterfaceList": [
                {
                    "UnityFileInterface": {
                        "hash": 8778980109421,
                        "id": "if_37"
                    }
                }
            ]
        },
        "hash": 8778980109388,
        "host_name": "dummy_nas23.pie.lab.emc.com",
        "id": "nfs_51",
        "is_extended_credentials_enabled": true,
        "is_secure_enabled": true,
        "kdc_type": "KdcTypeEnum.WINDOWS",
        "nas_server": {
            "UnityNasServer": {
                "hash": 8778980109412
            }
        },
        "nfs_v4_enabled": true,
        "servicee_principal_name": null
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('nfsserver')

application_type = "Ansible/1.7.1"


class NFSServer(object):
    """Class with NFS server operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_nfs_server_parameters())

        mutually_exclusive = [['nas_server_name', 'nas_server_id']]
        required_one_of = [['nfs_server_id', 'nas_server_name', 'nas_server_id']]

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

    def get_nfs_server_details(self, nfs_server_id=None, nas_server_id=None):
        """Get NFS server details.
            :param: nfs_server_id: The ID of the NFS server
            :param: nas_server_id: The name of the NAS server
            :return: Dict containing NFS server details if exists
        """
        LOG.info("Getting NFS server details")
        try:
            if nfs_server_id:
                nfs_server_details = self.unity_conn.get_nfs_server(_id=nfs_server_id)
                return nfs_server_details._get_properties()
            elif nas_server_id:
                nfs_server_details = self.unity_conn.get_nfs_server(nas_server=nas_server_id)
                if len(nfs_server_details) > 0:
                    return process_dict(nfs_server_details._get_properties())
                return None
        except utils.HttpError as e:
            if e.http_status == 401:
                msg = 'Incorrect username or password provided.'
                LOG.error(msg)
                self.module.fail_json(msg=msg)
            else:
                err_msg = "Failed to get details of NFS Server" \
                          " with error {0}".format(str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

        except utils.UnityResourceNotFoundError as e:
            err_msg = "Failed to get details of NFS Server" \
                      " with error {0}".format(str(e))
            LOG.error(err_msg)
            return None

    def get_nfs_server_instance(self, nfs_server_id):
        """Get NFS server instance.
            :param: nfs_server_id: The ID of the NFS server
            :return: Return NFS server instance if exists
        """

        try:
            nfs_server_obj = self.unity_conn.get_nfs_server(_id=nfs_server_id)
            return nfs_server_obj
        except Exception as e:
            error_msg = "Failed to get the NFS server %s instance" \
                        " with error %s" % (nfs_server_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def delete_nfs_server(self, nfs_server_id, skip_unjoin=None, domain_username=None, domain_password=None):
        """Delete NFS server.
            :param: nfs_server_id: The ID of the NFS server
            :param: skip_unjoin: Flag indicating whether to unjoin SMB server account from AD before deletion
            :param: domain_username: The domain username
            :param: domain_password: The domain password
            :return: Return True if NFS server is deleted
        """

        LOG.info("Deleting NFS server")
        try:
            if not self.module.check_mode:
                nfs_obj = self.get_nfs_server_instance(nfs_server_id=nfs_server_id)
                nfs_obj.delete(skip_kdc_unjoin=skip_unjoin, username=domain_username, password=domain_password)
            return True
        except Exception as e:
            msg = "Failed to delete NFS server: %s with error: %s" % (nfs_server_id, str(e))
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

    def is_modification_required(self, is_extended_credentials_enabled, nfs_server_details):
        """Check if modification is required in existing NFS server
            :param: is_extended_credentials_enabled: Indicates whether the NFS server supports more than 16 Unix groups in a Unix credential.
            :param: nfs_server_details: NFS server details
            :return: True if modification is required
        """

        LOG.info("Checking if any modification is required")
        # Check for Extend Credential
        if is_extended_credentials_enabled is not None and \
                is_extended_credentials_enabled != nfs_server_details['is_extended_credentials_enabled']:
            return True

    def create_nfs_server(self, nas_server_id, host_name=None, nfs_v4_enabled=None, is_secure_enabled=None,
                          kerberos_domain_controller_type=None, kerberos_domain_controller_username=None,
                          kerberos_domain_controller_password=None, is_extended_credentials_enabled=None):
        """Create NFS server.
            :param: nas_server_id: The ID of NAS server.
            :param: host_name: Name of NFS Server.
            :param: nfs_v4_enabled: Indicates whether the NFSv4 is enabled on the NAS server.
            :param: is_secure_enabled: Indicates whether the secure NFS is enabled.
            :param: kerberos_domain_controller_type: Type of Kerberos Domain Controller used for secure NFS service.
            :param: kerberos_domain_controller_username: Kerberos Domain Controller administrator username.
            :param: kerberos_domain_controller_password: Kerberos Domain Controller administrator password.
            :param: is_extended_credentials_enabled: Indicates whether support for more than 16 unix groups in a Unix credential.
        """

        LOG.info("Creating NFS server")
        try:
            if not self.module.check_mode:
                kdc_enum_type = get_enum_kdctype(kerberos_domain_controller_type)
                if kerberos_domain_controller_type == "UNIX":
                    is_extended_credentials_enabled = None
                    is_secure_enabled = None
                utils.UnityNfsServer.create(cli=self.unity_conn._cli, nas_server=nas_server_id, host_name=host_name,
                                            nfs_v4_enabled=nfs_v4_enabled,
                                            is_secure_enabled=is_secure_enabled, kdc_type=kdc_enum_type,
                                            kdc_username=kerberos_domain_controller_username,
                                            kdc_password=kerberos_domain_controller_password,
                                            is_extended_credentials_enabled=is_extended_credentials_enabled)
            return True
        except Exception as e:
            msg = "Failed to create NFS server with on NAS Server %s with error: %s" % (nas_server_id, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def validate_input_params(self):
        param_list = ["nfs_server_id", "nas_server_id", "nas_server_name", "host_name", "kerberos_domain_controller_username",
                      "kerberos_domain_controller_password"]

        for param in param_list:
            msg = "Please provide valid value for: %s" % param
            if self.module.params[param] is not None and len(self.module.params[param].strip()) == 0:
                errmsg = msg.format(param)
                self.module.fail_json(msg=errmsg)

    def perform_module_operation(self):
        """
        Perform different actions on NFS server module based on parameters
        passed in the playbook
        """
        nfs_server_id = self.module.params['nfs_server_id']
        nas_server_id = self.module.params['nas_server_id']
        nas_server_name = self.module.params['nas_server_name']
        host_name = self.module.params['host_name']
        nfs_v4_enabled = self.module.params['nfs_v4_enabled']
        is_secure_enabled = self.module.params['is_secure_enabled']
        kerberos_domain_controller_type = self.module.params['kerberos_domain_controller_type']
        kerberos_domain_controller_username = self.module.params['kerberos_domain_controller_username']
        kerberos_domain_controller_password = self.module.params['kerberos_domain_controller_password']
        is_extended_credentials_enabled = self.module.params['is_extended_credentials_enabled']
        remove_spn_from_kerberos = self.module.params['remove_spn_from_kerberos']
        state = self.module.params['state']

        # result is a dictionary that contains changed status and NFS server details
        result = dict(
            changed=False,
            nfs_server_details={}
        )

        modify_flag = False

        self.validate_input_params()

        if nas_server_name:
            nas_server_id = self.get_nas_server_id(nas_server_name)

        nfs_server_details = self.get_nfs_server_details(nfs_server_id=nfs_server_id,
                                                         nas_server_id=nas_server_id)

        # Check if modification is required
        if nfs_server_details and state == 'present':
            modify_flag = self.is_modification_required(is_extended_credentials_enabled, nfs_server_details)
            if modify_flag:
                self.module.fail_json(msg="Modification of NFS Server parameters is not supported through Ansible module")

        if not nfs_server_details and state == 'present':
            if not nas_server_id:
                self.module.fail_json(msg="Please provide nas server id/name to create NFS server.")

            result['changed'] = self.create_nfs_server(nas_server_id, host_name, nfs_v4_enabled,
                                                       is_secure_enabled, kerberos_domain_controller_type,
                                                       kerberos_domain_controller_username,
                                                       kerberos_domain_controller_password,
                                                       is_extended_credentials_enabled)

        if state == 'absent' and nfs_server_details:
            skip_unjoin = not remove_spn_from_kerberos
            result['changed'] = self.delete_nfs_server(nfs_server_details["id"], skip_unjoin,
                                                       kerberos_domain_controller_username,
                                                       kerberos_domain_controller_password)

        if state == 'present':
            result['nfs_server_details'] = self.get_nfs_server_details(nfs_server_id=nfs_server_id,
                                                                       nas_server_id=nas_server_id)
        self.module.exit_json(**result)


def get_nfs_server_parameters():
    """This method provide parameters required for the ansible
       NFS server module on Unity"""
    return dict(
        nfs_server_id=dict(type='str'),
        host_name=dict(type='str'),
        nfs_v4_enabled=dict(type='bool'),
        is_secure_enabled=dict(type='bool'),
        kerberos_domain_controller_type=dict(type='str', choices=['UNIX', 'WINDOWS', 'CUSTOM']),
        kerberos_domain_controller_username=dict(type='str'),
        kerberos_domain_controller_password=dict(type='str', no_log=True),
        nas_server_name=dict(type='str'),
        nas_server_id=dict(type='str'),
        is_extended_credentials_enabled=dict(type='bool'),
        remove_spn_from_kerberos=dict(default=True, type='bool'),
        state=dict(required=True, type='str', choices=['present', 'absent']),
    )


def get_enum_kdctype(kerberos_domain_controller_type):
    """Getting correct enum values for kerberos_domain_controller_type
        :param: kerberos_domain_controller_type: Type of Kerberos Domain Controller used for secure NFS service.
        :return: enum value for kerberos_domain_controller_type.
    """

    if utils.KdcTypeEnum[kerberos_domain_controller_type]:
        kerberos_domain_controller_type = utils.KdcTypeEnum[kerberos_domain_controller_type]
        return kerberos_domain_controller_type


def process_dict(nfs_server_details):
    """Process NFS server details.
        :param: nfs_server_details: Dict containing NFS server details
        :return: Processed dict containing NFS server details
    """
    param_list = ['credentials_cache_ttl', 'file_interfaces', 'host_name', 'id', 'kdc_type', 'nas_server', 'is_secure_enabled',
                  'is_extended_credentials_enabled', 'nfs_v4_enabled', 'servicee_principal_name']

    for param in param_list:
        if param in nfs_server_details and param == 'credentials_cache_ttl':
            nfs_server_details[param] = str(nfs_server_details[param][0])
        else:
            nfs_server_details[param] = nfs_server_details[param][0]
    return nfs_server_details


def main():
    """Create Unity NFS server object and perform action on it
       based on user input from playbook"""
    obj = NFSServer()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
