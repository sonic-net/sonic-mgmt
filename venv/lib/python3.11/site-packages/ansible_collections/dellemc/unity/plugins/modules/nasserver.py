#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: nasserver
version_added: '1.1.0'
short_description:  Manage NAS servers on Unity storage system
extends_documentation_fragment:
- dellemc.unity.unity
author:
- P Srinivas Rao (@srinivas-rao5) <ansible.team@dell.com>
description:
- Managing NAS servers on Unity storage system includes get,
  modification to the NAS servers.
options:
  nas_server_id:
    description:
    - The ID of the NAS server.
    - Either I(nas_server_name) or I(nas_server_id) is required to perform the task.
    - The parameters I(nas_server_name) and I(nas_server_id) are mutually exclusive.
    type: str
  nas_server_name:
    description:
    - The Name of the NAS server.
    - Either I(nas_server_name) or I(nas_server_id)  is required to perform the task.
    - The parameters I(nas_server_name) and I(nas_server_id) are mutually exclusive.
    type: str
  nas_server_new_name:
    description:
    - The new name of the NAS server.
    - It can be mentioned during modification of the NAS server.
    type: str
  is_replication_destination:
    description:
    - It specifies whether the NAS server is a replication destination.
    - It can be mentioned during modification of the NAS server.
    type: bool
  is_backup_only:
    description:
    - It specifies whether the NAS server is used as backup only.
    - It can be mentioned during modification of the NAS server.
    type: bool
  is_multiprotocol_enabled:
    description:
    - This parameter indicates whether multiprotocol sharing mode is enabled.
    - It can be mentioned during modification of the NAS server.
    type: bool
  allow_unmapped_user:
    description:
    - This flag is used to mandatorily disable access in case of any user
      mapping failure.
    - If C(true), then enable access in case of any user mapping failure.
    - If C(false), then disable access in case of any user mapping failure.
    - It can be mentioned during modification of the NAS server.
    type: bool
  default_windows_user:
    description:
    - Default windows user name used for granting access in the case of Unix
      to Windows user mapping failure.
    - It can be mentioned during modification of the NAS server.
    type: str
  default_unix_user:
    description:
    - Default Unix user name used for granting access in the case of Windows
      to Unix user mapping failure.
    - It can be mentioned during modification of the NAS server.
    type: str
  enable_windows_to_unix_username_mapping:
    description:
    - This parameter indicates whether a Unix to/from Windows user name
      mapping is enabled.
    - It can be mentioned during modification of the NAS server.
    type: bool
  is_packet_reflect_enabled:
    description:
    - If the packet has to be reflected, then this parameter
      has to be set to C(true).
    - It can be mentioned during modification of the NAS server.
    type: bool
  current_unix_directory_service:
    description:
    - This is the directory service used for querying identity information
      for UNIX (such as UIDs, GIDs, net groups).
    - It can be mentioned during modification of the NAS server.
    type: str
    choices: ["NONE", "NIS", "LOCAL", "LDAP", "LOCAL_THEN_NIS", "LOCAL_THEN_LDAP"]
  replication_params:
    description:
    - Settings required for enabling replication.
    type: dict
    suboptions:
      destination_nas_server_name:
        description:
        - Name of the destination nas server.
        - Default value will be source nas server name prefixed by 'DR_'.
        type: str
      replication_mode:
        description:
        - The replication mode.
        - This is mandatory to enable replication.
        type: str
        choices: ['asynchronous', 'manual']
      rpo:
        description:
        - Maximum time to wait before the system syncs the source and destination LUNs.
        - The I(rpo) option should be specified if the I(replication_mode) is C(asynchronous).
        - The value should be in range of C(5) to C(1440).
        type: int
      replication_type:
        description:
        - Type of replication.
        choices: ['local', 'remote']
        type: str
      remote_system:
        description:
        - Details of remote system to which the replication is being configured.
        - The I(remote_system) option should be specified if the
          I(replication_type) is C(remote).
        type: dict
        suboptions:
          remote_system_host:
            required: true
            description:
            - IP or FQDN for remote Unity unisphere Host.
            type: str
          remote_system_username:
            type: str
            required: true
            description:
            - User name of remote Unity unisphere Host.
          remote_system_password:
            type: str
            required: true
            description:
            - Password of remote Unity unisphere Host.
          remote_system_verifycert:
            type: bool
            default: true
            description:
            - Boolean variable to specify whether or not to validate SSL
              certificate of remote Unity unisphere Host.
            - C(true) - Indicates that the SSL certificate should be verified.
            - C(false) - Indicates that the SSL certificate should not be
              verified.
          remote_system_port:
            description:
            - Port at which remote Unity unisphere is hosted.
            type: int
            default: 443
      destination_pool_name:
        description:
        - Name of pool to allocate destination Luns.
        - Mutually exclusive with I(destination_pool_id).
        type: str
      destination_pool_id:
        description:
        - Id of pool to allocate destination Luns.
        - Mutually exclusive with I(destination_pool_name).
        type: str
      destination_sp:
        description:
        - Storage process of destination nas server
        choices: ['SPA', 'SPB']
        type: str
      is_backup:
        description:
        - Indicates if the destination nas server is backup.
        type: bool
      replication_name:
        description:
        - User defined name for replication session.
        type: str
      new_replication_name:
        description:
        - Replication name to rename the session to.
        type: str
  replication_state:
    description:
    - State of the replication.
    choices: ['enable', 'disable']
    type: str
  replication_reuse_resource:
    description:
    - This parameter indicates if existing NAS Server is to be used for replication.
    type: bool
  state:
    description:
    - Define the state of NAS server on the array.
    - The value present indicates that NAS server should exist on the system after
      the task is executed.
    - In this release deletion of NAS server is not supported. Hence, if state is
      set to C(absent) for any existing NAS server then error will be thrown.
    - For any non-existing NAS server, if state is set to C(absent) then it will return None.
    type: str
    required: true
    choices: ['present', 'absent']

notes:
- The I(check_mode) is not supported.
'''

EXAMPLES = r'''

- name: Get Details of NAS Server
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "{{nas_server_name}}"
    state: "present"

- name: Modify Details of NAS Server
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "{{nas_server_name}}"
    nas_server_new_name: "updated_sample_nas_server"
    is_replication_destination: false
    is_backup_only: false
    is_multiprotocol_enabled: true
    allow_unmapped_user: true
    default_unix_user: "default_unix_sample_user"
    default_windows_user: "default_windows_sample_user"
    enable_windows_to_unix_username_mapping: true
    current_unix_directory_service: "LDAP"
    is_packet_reflect_enabled: true
    state: "present"

- name: Enable replication for NAS Server on Local System
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_id: "nas_10"
    replication_reuse_resource: false
    replication_params:
      replication_name: "test_replication"
      destination_nas_server_name: "destination_nas"
      replication_mode: "asynchronous"
      rpo: 60
      replication_type: "local"
      destination_pool_name: "Pool_Ansible_Neo_DND"
      destination_sp: "SPA"
      is_backup: true
    replication_state: "enable"
    state: "present"

- name: Enable replication for NAS Server on Remote System
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    replication_reuse_resource: false
    replication_params:
      replication_name: "test_replication"
      destination_nas_server_name: "destination_nas"
      replication_mode: "asynchronous"
      rpo: 60
      replication_type: "remote"
      remote_system:
        remote_system_host: '10.10.10.10'
        remote_system_verifycert: false
        remote_system_username: 'test1'
        remote_system_password: 'test1!'
      destination_pool_name: "fastVP_pool"
      destination_sp: "SPA"
      is_backup: true
    replication_state: "enable"
    state: "present"

- name: Enable replication for NAS Server on Remote System in existing NAS Server
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    replication_reuse_resource: true
    replication_params:
      destination_nas_server_name: "destination_nas"
      replication_mode: "asynchronous"
      rpo: 60
      replication_type: "remote"
      replication_name: "test_replication"
      remote_system:
        remote_system_host: '10.10.10.10'
        remote_system_verifycert: false
        remote_system_username: 'test1'
        remote_system_password: 'test1!'
      destination_pool_name: "fastVP_pool"
    replication_state: "enable"
    state: "present"

- name: Modify replication on the nasserver
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    replication_params:
      replication_name: "test_repl"
      new_replication_name: "test_repl_updated"
      replication_mode: "asynchronous"
      rpo: 50
    replication_state: "enable"
    state: "present"

- name: Disable replication on the nasserver
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    replication_state: "disable"
    state: "present"

- name: Disable replication by specifying replication_name on the nasserver
  nasserver:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    nas_server_name: "dummy_nas"
    replication_params:
      replication_name: "test_replication"
    replication_state: "disable"
    state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true
nas_server_details:
    description: The NAS server details.
    type: dict
    returned: When NAS server exists.
    contains:
        name:
            description: Name of the NAS server.
            type: str
        id:
            description: ID of the NAS server.
            type: str
        allow_unmapped_user:
            description: Enable/disable access status in case of any user
                         mapping failure.
            type: bool
        current_unix_directory_service:
            description: Directory service used for querying identity
                         information for UNIX (such as UIDs, GIDs, net groups).
            type: str
        default_unix_user:
            description: Default Unix user name used for granting access
                         in the case of Windows to Unix user mapping failure.
            type: str
        default_windows_user:
            description: Default windows user name used for granting
                         access in the case of Unix to Windows user mapping
                         failure.
            type: str
        is_backup_only:
            description: Whether the NAS server is used as backup only.
            type: bool
        is_multi_protocol_enabled:
            description: Indicates whether multiprotocol sharing mode is
                         enabled.
            type: bool
        is_packet_reflect_enabled:
            description: If the packet reflect has to be enabled.
            type: bool
        is_replication_destination:
            description: If the NAS server is a replication destination
                         then true.
            type: bool
        is_windows_to_unix_username_mapping_enabled:
            description: Indicates whether a Unix to/from Windows user name
                         mapping is enabled.
            type: bool
    sample: {
        "allow_unmapped_user": null,
        "cifs_server": {
            "UnityCifsServerList": [
                {
                    "UnityCifsServer": {
                        "hash": 8761756885270,
                        "id": "cifs_34"
                    }
                }
            ]
        },
        "current_sp": {
            "UnityStorageProcessor": {
                "hash": 8761756885273,
                "id": "spb"
            }
        },
        "current_unix_directory_service": "NasServerUnixDirectoryServiceEnum.NIS",
        "default_unix_user": null,
        "default_windows_user": null,
        "existed": true,
        "file_dns_server": {
            "UnityFileDnsServer": {
                "hash": 8761756885441,
                "id": "dns_12"
            }
        },
        "file_interface": {
            "UnityFileInterfaceList": [
                {
                    "UnityFileInterface": {
                        "hash": 8761756889908,
                        "id": "if_37"
                    }
                }
            ]
        },
        "filesystems": null,
        "hash": 8761757005084,
        "health": {
            "UnityHealth": {
                "hash": 8761756867588
            }
        },
        "home_sp": {
            "UnityStorageProcessor": {
                "hash": 8761756867618,
                "id": "spb"
            }
        },
        "id": "nas_10",
        "is_backup_only": false,
        "is_multi_protocol_enabled": false,
        "is_packet_reflect_enabled": false,
        "is_replication_destination": false,
        "is_replication_enabled": true,
        "is_windows_to_unix_username_mapping_enabled": null,
        "name": "dummy_nas",
        "pool": {
            "UnityPool": {
                "hash": 8761756885360,
                "id": "pool_7"
            }
        },
        "preferred_interface_settings": {
            "UnityPreferredInterfaceSettings": {
                "hash": 8761756885438,
                "id": "preferred_if_10"
            }
        },
        "replication_type": "ReplicationTypeEnum.REMOTE",
        "size_allocated": 3489660928,
        "tenant": null,
        "virus_checker": {
            "UnityVirusChecker": {
                "hash": 8761756885426,
                "id": "cava_10"
            }
        }
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils
LOG = utils.get_logger('nasserver')

application_type = "Ansible/1.7.1"


class NASServer(object):
    """Class with NAS Server operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_nasserver_parameters())

        # initialize the ansible module
        mut_ex_args = [['nas_server_name', 'nas_server_id']]
        required_one_of = [['nas_server_name', 'nas_server_id']]

        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mut_ex_args,
            required_one_of=required_one_of
        )
        utils.ensure_required_libs(self.module)

        # result is a dictionary that contains changed status and
        # nas server details
        self.result = {"changed": False,
                       'nas_server_details': {}}

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        self.nas_server_conn_obj = utils.nas_server.UnityNasServer(
            self.unity_conn)
        LOG.info('Connection established with the Unity Array')

    def get_current_uds_enum(self, current_uds):
        """
        Get the enum of the Offline Availability parameter.
        :param current_uds: Current Unix Directory Service string
        :return: current_uds enum
        """
        if current_uds in \
                utils.NasServerUnixDirectoryServiceEnum.__members__:
            return utils.NasServerUnixDirectoryServiceEnum[current_uds]
        else:
            error_msg = "Invalid value {0} for Current Unix Directory" \
                        " Service provided".format(current_uds)
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_nas_server(self, nas_server_name, nas_server_id):
        """
        Get the NAS Server Object using NAME/ID of the NAS Server.
        :param nas_server_name: Name of the NAS Server
        :param nas_server_id: ID of the NAS Server
        :return: NAS Server object.
        """
        nas_server = nas_server_name if nas_server_name else nas_server_id
        try:
            obj_nas = self.unity_conn.get_nas_server(_id=nas_server_id,
                                                     name=nas_server_name)
            if nas_server_id and obj_nas and not obj_nas.existed:
                #  if obj_nas is not None and existed is observed as False,
                #  then None will be returned.
                LOG.error("NAS Server object does not exist"
                          " with ID: %s ", nas_server_id)
                return None
            return obj_nas
        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = "Incorrect username or password , {0}".format(
                    e.message)
                self.module.fail_json(msg=cred_err)
            else:
                err_msg = "Failed to get details of NAS Server" \
                          " {0} with error {1}".format(nas_server, str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

        except utils.UnityResourceNotFoundError as e:
            err_msg = "Failed to get details of NAS Server" \
                      " {0} with error {1}".format(nas_server, str(e))
            LOG.error(err_msg)
            return None

        except Exception as e:
            nas_server = nas_server_name if nas_server_name \
                else nas_server_id
            err_msg = "Failed to get nas server details {0} with" \
                      " error {1}".format(nas_server, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def to_update(self, nas_server_obj, current_uds):
        LOG.info("Checking Whether the parameters are modified or not.")

        # Checking all parameters individually because the nas obj return
        # names are different compared to ansible parameter names.

        # Current Unix Directory Service
        if current_uds is not None and \
                current_uds != nas_server_obj.current_unix_directory_service:
            return True

        # Rename NAS Server
        if self.module.params['nas_server_new_name'] is not None and \
                self.module.params['nas_server_new_name'] != \
                nas_server_obj.name:
            return True

        # Is Replication Destination
        if self.module.params["is_replication_destination"] is not None and \
                (nas_server_obj.is_replication_destination is None or
                 self.module.params["is_replication_destination"] !=
                 nas_server_obj.is_replication_destination):
            return True

        # Is Multiprotocol Enabled
        if self.module.params["is_multiprotocol_enabled"] is not None and \
                (nas_server_obj.is_multi_protocol_enabled is None or
                 self.module.params["is_multiprotocol_enabled"] !=
                 nas_server_obj.is_multi_protocol_enabled):
            return True

        # Is Back Up Enabled
        if self.module.params["is_backup_only"] is not None and \
                (nas_server_obj.is_backup_only is None or
                 self.module.params["is_backup_only"] !=
                 nas_server_obj.is_backup_only):
            return True

        # Is Packet Reflect Enabled
        if self.module.params["is_packet_reflect_enabled"] is not None and \
                (nas_server_obj.is_packet_reflect_enabled is None or
                 self.module.params["is_packet_reflect_enabled"] !=
                 nas_server_obj.is_packet_reflect_enabled):
            return True

        # Allow Unmapped User
        if self.module.params["allow_unmapped_user"] is not None and \
                (nas_server_obj.allow_unmapped_user is None or
                 self.module.params["allow_unmapped_user"] !=
                 nas_server_obj.allow_unmapped_user):
            return True

        # Enable Windows To Unix User Mapping Flag
        nas_win_flag = \
            nas_server_obj.is_windows_to_unix_username_mapping_enabled
        input_win_flag = \
            self.module.params["enable_windows_to_unix_username_mapping"]
        if input_win_flag is not None and \
                (nas_win_flag is None or nas_win_flag != input_win_flag):
            return True

        # Default Windows User
        if self.module.params["default_windows_user"] is not None and \
                (nas_server_obj.default_windows_user is None or
                 self.module.params["default_windows_user"] !=
                 nas_server_obj.default_windows_user):
            return True

        # Default Unix User
        if self.module.params["default_unix_user"] is not None and \
                (nas_server_obj.default_unix_user is None or
                 self.module.params["default_unix_user"] !=
                 nas_server_obj.default_unix_user):
            return True

        return False

    def update_nas_server(self, nas_server_obj, new_name=None,
                          default_unix_user=None, default_windows_user=None,
                          is_rep_dest=None, is_multiprotocol_enabled=None,
                          allow_unmapped_user=None, is_backup_only=None,
                          is_packet_reflect_enabled=None, current_uds=None,
                          enable_win_to_unix_name_map=None):
        """
        The Details of the NAS Server will be updated in the function.
        """
        try:
            nas_server_obj.modify(
                name=new_name,
                is_replication_destination=is_rep_dest,
                is_backup_only=is_backup_only,
                is_multi_protocol_enabled=is_multiprotocol_enabled,
                default_unix_user=default_unix_user,
                default_windows_user=default_windows_user,
                allow_unmapped_user=allow_unmapped_user,
                is_packet_reflect_enabled=is_packet_reflect_enabled,
                enable_windows_to_unix_username=enable_win_to_unix_name_map,
                current_unix_directory_service=current_uds)

        except Exception as e:
            error_msg = "Failed to Update parameters of NAS Server" \
                        " %s with error %s" % (nas_server_obj.name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def modify_replication_session(self, nas_server_obj, repl_session, replication_params):
        """ Modify the replication session
            :param: nas_server_obj: NAS server object
            :param: repl_session: Replication session to be modified
            :param: replication_params: Module input params
            :return: True if modification is successful
        """
        try:
            LOG.info("Modifying replication session of nas server %s", nas_server_obj.name)
            modify_payload = {}
            if replication_params['replication_mode'] and \
                    replication_params['replication_mode'] == 'manual':
                rpo = -1
            elif replication_params['rpo']:
                rpo = replication_params['rpo']
            name = repl_session.name
            if replication_params['new_replication_name'] and \
                    name != replication_params['new_replication_name']:
                name = replication_params['new_replication_name']

            if repl_session.name != name:
                modify_payload['name'] = name
            if ((replication_params['replication_mode'] or replication_params['rpo']) and
                    repl_session.max_time_out_of_sync != rpo):
                modify_payload['max_time_out_of_sync'] = rpo

            if modify_payload:
                repl_session.modify(**modify_payload)
                return True

            return False
        except Exception as e:
            errormsg = "Modifying replication session failed with error %s", e
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def enable_replication(self, nas_server_obj, replication, replication_reuse_resource):
        """ Enable replication on NAS Server
            :param: nas_server_obj: NAS Server object.
            :param: replication: Dict which has all the replication parameter values.
            :return: True if replication is enabled else False.
        """
        try:
            # Validate replication params
            self.validate_nas_server_replication_params(replication)
            self.update_replication_params(replication, replication_reuse_resource)

            repl_session = \
                self.get_replication_session_on_filter(nas_server_obj, replication, "modify")
            if repl_session:
                return self.modify_replication_session(nas_server_obj, repl_session, replication)

            self.validate_create_replication_params(replication)
            replication_args_list = get_replication_args_list(replication)

            # Get remote system
            if 'replication_type' in replication and replication['replication_type'] == 'remote':
                self.get_remote_system(replication, replication_args_list)

                # Form parameters when replication_reuse_resource is False
                if not replication_reuse_resource:
                    update_replication_arg_list(replication, replication_args_list, nas_server_obj)
                    nas_server_obj.replicate_with_dst_resource_provisioning(**replication_args_list)
                else:
                    replication_args_list['dst_nas_server_id'] = replication['destination_nas_server_id']
                    nas_server_obj.replicate(**replication_args_list)
                return True

            if 'replication_type' in replication and replication['replication_type'] == 'local':
                update_replication_arg_list(replication, replication_args_list, nas_server_obj)
                nas_server_obj.replicate_with_dst_resource_provisioning(**replication_args_list)
                return True

        except Exception as e:
            errormsg = "Enabling replication to the nas server %s failed " \
                       "with error %s" % (nas_server_obj.name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def disable_replication(self, obj_nas, replication_params):
        """ Remove replication from the nas server
            :param: replication_params: Module input params
            :param: obj_nas: NAS Server object
            :return: True if disabling replication is successful
        """
        try:
            LOG.info(("Disabling replication on the nas server %s", obj_nas.name))
            if replication_params:
                self.update_replication_params(replication_params, False)
            repl_session = \
                self.get_replication_session_on_filter(obj_nas, replication_params, "delete")
            if repl_session:
                repl_session.delete()
                return True
            return False
        except Exception as e:
            errormsg = "Disabling replication on the nas server %s failed " \
                       "with error %s" % (obj_nas.name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_replication_session_on_filter(self, obj_nas, replication_params, action):
        """ Retrieves replication session on nas server
            :param: obj_nas: NAS server object
            :param: replication_params: Module input params
            :param: action: Specifies action as modify or delete
            :return: Replication session based on filter
        """
        if replication_params and replication_params['remote_system']:
            repl_session = \
                self.get_replication_session(obj_nas, filter_key="remote_system_name",
                                             replication_params=replication_params)
        elif replication_params and replication_params['replication_name']:
            repl_session = \
                self.get_replication_session(obj_nas, filter_key="name",
                                             name=replication_params['replication_name'])
        else:
            repl_session = self.get_replication_session(obj_nas, action=action)
            if repl_session and action and replication_params and \
                    replication_params['replication_type'] == 'local' and \
                    repl_session.remote_system.name != self.unity_conn.name:
                return None
        return repl_session

    def get_replication_session(self, obj_nas, filter_key=None, replication_params=None, name=None, action=None):
        """ Retrieves the replication sessions configured for the nas server
            :param: obj_nas: NAS server object
            :param: filter_key: Key to filter replication sessions
            :param: replication_params: Module input params
            :param: name: Replication session name
            :param: action: Specifies modify or delete action on replication session
            :return: Replication session details
        """
        try:
            repl_session = self.unity_conn.get_replication_session(src_resource_id=obj_nas.id)
            if not filter_key and repl_session:
                if len(repl_session) > 1:
                    if action:
                        error_msg = 'There are multiple replication sessions for the nas server.'\
                                    ' Please specify replication_name in replication_params to %s.' % action
                        self.module.fail_json(msg=error_msg)
                    return repl_session
                return repl_session[0]
            for session in repl_session:
                if filter_key == 'remote_system_name' and \
                        session.remote_system.name == replication_params['remote_system_name']:
                    return session
                if filter_key == 'name' and session.name == name:
                    return session
            return None
        except Exception as e:
            errormsg = "Retrieving replication session on the nas server failed " \
                       "with error %s", str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_remote_system(self, replication, replication_args_list):
        remote_system_name = replication['remote_system_name']
        remote_system_list = self.unity_conn.get_remote_system()
        for remote_system in remote_system_list:
            if remote_system.name == remote_system_name:
                replication_args_list['remote_system'] = remote_system
                break
        if 'remote_system' not in replication_args_list.keys():
            errormsg = "Remote system %s is not found" % (remote_system_name)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def update_replication_params(self, replication, replication_reuse_resource):
        """ Update replication dict with remote system information
            :param: replication: Dict which has all the replication parameter values
            :return: Updated replication Dict
        """
        try:
            if 'replication_type' in replication and replication['replication_type'] == 'remote':
                connection_params = {
                    'unispherehost': replication['remote_system']['remote_system_host'],
                    'username': replication['remote_system']['remote_system_username'],
                    'password': replication['remote_system']['remote_system_password'],
                    'validate_certs': replication['remote_system']['remote_system_verifycert'],
                    'port': replication['remote_system']['remote_system_port']
                }
                remote_system_conn = utils.get_unity_unisphere_connection(
                    connection_params, application_type)
                replication['remote_system_name'] = remote_system_conn.name
                if replication['destination_pool_name'] is not None:
                    pool_object = remote_system_conn.get_pool(name=replication['destination_pool_name'])
                    replication['destination_pool_id'] = pool_object.id
                if replication['destination_nas_server_name'] is not None and replication_reuse_resource:
                    nas_object = remote_system_conn.get_nas_server(name=replication['destination_nas_server_name'])
                    replication['destination_nas_server_id'] = nas_object.id
            else:
                replication['remote_system_name'] = self.unity_conn.name
                if replication['destination_pool_name'] is not None:
                    pool_object = self.unity_conn.get_pool(name=replication['destination_pool_name'])
                    replication['destination_pool_id'] = pool_object.id
        except Exception as e:
            errormsg = "Updating replication params failed with error %s" % str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_rpo(self, replication):
        if 'replication_mode' in replication and replication['replication_mode'] == 'asynchronous' \
                and replication['rpo'] is None:
            errormsg = "rpo is required together with 'asynchronous' replication_mode."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        if (replication['rpo'] and (replication['rpo'] < 5 or replication['rpo'] > 1440)) \
                and (replication['replication_mode'] and replication['replication_mode'] != 'manual' or
                     not replication['replication_mode'] and replication['rpo'] != -1):
            errormsg = "rpo value should be in range of 5 to 1440"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_nas_server_replication_params(self, replication):
        """ Validate NAS server replication params
            :param: replication: Dict which has all the replication parameter values
        """

        # Valdiate replication
        if replication is None:
            errormsg = "Please specify replication_params to enable replication."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)
        else:
            # validate destination pool info
            if replication['destination_pool_id'] is not None and replication['destination_pool_name'] is not None:
                errormsg = "'destination_pool_id' and 'destination_pool_name' is mutually exclusive."
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

            # Validate replication mode
            self.validate_rpo(replication)
            # Validate replication type
            if replication['replication_type'] == 'remote' and replication['remote_system'] is None:
                errormsg = "Remote_system is required together with 'remote' replication_type"
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

            # Validate destination NAS server name
            if 'destination_nas_name' in replication and replication['destination_nas_name'] is not None:
                dst_nas_server_name_length = len(replication['destination_nas_name'])
                if dst_nas_server_name_length == 0 or dst_nas_server_name_length > 95:
                    errormsg = "destination_nas_name value should be in range of 1 to 95"
                    LOG.error(errormsg)
                    self.module.fail_json(msg=errormsg)

    def validate_create_replication_params(self, replication):
        ''' Validate replication params '''
        if replication['destination_pool_id'] is None and replication['destination_pool_name'] is None:
            errormsg = "Either 'destination_pool_id' or 'destination_pool_name' is required."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        keys = ['replication_mode', 'replication_type']
        for key in keys:
            if replication[key] is None:
                errormsg = "Please specify %s to enable replication." % key
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

    def perform_module_operation(self):
        """
        Perform different actions on NAS Server based on user parameters
        chosen in playbook
        """
        state = self.module.params['state']
        nas_server_name = self.module.params['nas_server_name']
        nas_server_id = self.module.params['nas_server_id']
        nas_server_new_name = self.module.params['nas_server_new_name']
        default_unix_user = self.module.params['default_unix_user']
        default_windows_user = self.module.params['default_windows_user']

        is_replication_destination = \
            self.module.params['is_replication_destination']
        is_multiprotocol_enabled = \
            self.module.params['is_multiprotocol_enabled']
        allow_unmapped_user = self.module.params['allow_unmapped_user']
        enable_windows_to_unix_username_mapping = \
            self.module.params['enable_windows_to_unix_username_mapping']

        is_backup_only = self.module.params['is_backup_only']
        is_packet_reflect_enabled = \
            self.module.params['is_packet_reflect_enabled']

        current_uds = self.module.params['current_unix_directory_service']
        replication = self.module.params['replication_params']
        replication_state = self.module.params['replication_state']
        replication_reuse_resource = self.module.params['replication_reuse_resource']
        # Get the enum for the corresponding offline_availability
        if current_uds:
            current_uds = \
                self.get_current_uds_enum(current_uds)

        changed = False

        if replication and replication_state is None:
            self.module.fail_json(msg="Please specify replication_state along with replication_params")

        '''
        Get details of NAS Server.
        '''
        nas_server_obj = None
        if nas_server_name or nas_server_id:
            nas_server_obj = self.get_nas_server(nas_server_name,
                                                 nas_server_id)

        # As creation is not supported and if NAS Server does not exist
        # along with state as present, then error will be thrown.
        if not nas_server_obj and state == "present":
            msg = "NAS Server Resource not found. Please enter a valid " \
                  "Name/ID to get or modify the parameters of nas server."
            LOG.error(msg)
            self.module.fail_json(msg=msg)

        '''
            Update the parameters of NAS Server
        '''
        if nas_server_obj and state == "present":
            update_flag = self.to_update(nas_server_obj, current_uds)
            if update_flag:
                self.update_nas_server(
                    nas_server_obj, nas_server_new_name, default_unix_user,
                    default_windows_user, is_replication_destination,
                    is_multiprotocol_enabled, allow_unmapped_user,
                    is_backup_only, is_packet_reflect_enabled,
                    current_uds, enable_windows_to_unix_username_mapping)
                changed = True

        # As deletion is not supported and if NAS Server exists along with
        # state as absent, then error will be thrown.
        if nas_server_obj and state == 'absent':
            self.module.fail_json(msg="Deletion of NAS Server is "
                                      "currently not supported.")

        if state == 'present' and nas_server_obj and replication_state is not None:
            if replication_state == 'enable':
                changed = self.enable_replication(nas_server_obj, replication, replication_reuse_resource)
            else:
                changed = self.disable_replication(nas_server_obj, replication)

        '''
            Update the changed state and NAS Server details
        '''
        nas_server_details = None
        if nas_server_obj:
            nas_server_details = self.get_nas_server(
                None, nas_server_obj.id)._get_properties()

        self.result["changed"] = changed
        self.result["nas_server_details"] = nas_server_details
        self.module.exit_json(**self.result)


def get_nasserver_parameters():
    """
    This method provides parameters required for the ansible NAS Server
    modules on Unity
    """

    return dict(
        nas_server_name=dict(), nas_server_id=dict(),
        nas_server_new_name=dict(),
        default_unix_user=dict(),
        default_windows_user=dict(),
        current_unix_directory_service=dict(
            choices=["NIS", "LDAP", "LOCAL_THEN_NIS",
                     "LOCAL_THEN_LDAP", "NONE", "LOCAL"]),
        is_replication_destination=dict(type='bool'),
        is_backup_only=dict(type='bool'),
        is_multiprotocol_enabled=dict(type='bool'),
        allow_unmapped_user=dict(type='bool'),
        enable_windows_to_unix_username_mapping=dict(type='bool'),
        is_packet_reflect_enabled=dict(type='bool'),
        replication_params=dict(type='dict', options=dict(
            destination_nas_server_name=dict(type='str'),
            replication_mode=dict(type='str', choices=['asynchronous', 'manual']),
            rpo=dict(type='int'),
            replication_type=dict(type='str', choices=['local', 'remote']),
            remote_system=dict(type='dict',
                               options=dict(
                                    remote_system_host=dict(type='str', required=True, no_log=True),
                                    remote_system_verifycert=dict(type='bool', required=False,
                                                                  default=True),
                                    remote_system_username=dict(type='str', required=True),
                                    remote_system_password=dict(type='str', required=True, no_log=True),
                                    remote_system_port=dict(type='int', required=False, default=443, no_log=True)
                               )),
            destination_pool_name=dict(type='str'),
            destination_pool_id=dict(type='str'),
            destination_sp=dict(type='str', choices=['SPA', 'SPB']),
            is_backup=dict(type='bool'),
            replication_name=dict(type='str'),
            new_replication_name=dict(type='str')
        )),
        replication_reuse_resource=dict(type='bool'),
        replication_state=dict(type='str', choices=['enable', 'disable']),
        state=dict(required=True, choices=['present', 'absent'], type='str')
    )


def get_sp_enum(destination_sp):
    """Getting correct enum values for Storage Processor
            :param: destination_sp: Storage Processor to be used in Destination NAS Server.
            :return: enum value for Storage Processor.
        """
    if utils.NodeEnum[destination_sp]:
        destination_sp_enum = utils.NodeEnum[destination_sp]
        return destination_sp_enum


def get_replication_args_list(replication_params):
    """Returns the replication args for payload"""
    replication_args_list = {}

    if replication_params['replication_name']:
        replication_args_list['replication_name'] = replication_params['replication_name']
    if 'replication_mode' in replication_params and \
            replication_params['replication_mode'] == 'asynchronous':
        replication_args_list['max_time_out_of_sync'] = replication_params['rpo']
    else:
        replication_args_list['max_time_out_of_sync'] = -1

    return replication_args_list


def update_replication_arg_list(replication, replication_args_list, nas_server_obj):
    """ Update replication arg list
        :param: replication: Dict which has all the replication parameter values
        :param: replication_args_list: the existing list which should be updated
        :param: nas_server_obj: NAS Server object on which replication is to be enabled
        :return: Updated replication_args_list
    """
    if 'destination_sp' in replication and replication['destination_sp']:
        dst_sp_enum = get_sp_enum(replication['destination_sp'])
        replication_args_list['dst_sp'] = dst_sp_enum

    replication_args_list['dst_pool_id'] = replication['destination_pool_id']

    if 'is_backup' in replication and replication['is_backup']:
        replication_args_list['is_backup_only'] = replication['is_backup']

    if replication['replication_type'] == 'local':
        replication_args_list['dst_nas_server_name'] = "DR_" + nas_server_obj.name
        if 'destination_nas_server_name' in replication and replication['destination_nas_server_name'] is not None:
            replication_args_list['dst_nas_server_name'] = replication['destination_nas_server_name']
    else:
        if replication['destination_nas_server_name'] is None:
            replication_args_list['dst_nas_server_name'] = nas_server_obj.name


def main():
    """ Create Unity NAS Server object and perform action on it
        based on user input from playbook"""
    obj = NASServer()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
