#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2025 IBM CORPORATION
# Author(s): Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ibm_sv_manage_flashsystem_grid
short_description: This module manages flashsystem-grid operations on IBM Storage Virtualize family storage systems
description:
    - Ansible interface to manage flashsystem-grid operations.
version_added: "2.7.0"
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize storage system.
        required: true
        type: str
    domain:
        description:
            - Domain for the Storage Virtualize storage system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize storage system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize storage system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize storage system.
            - To generate a token, use the ibm_svc_auth module.
        type: str
    name:
        description:
            - Specifies the name of the flashsystem-grid.
        type: str
    action:
        description:
            - Specifies action to be run.
        choices: [ join, accept, remove ]
        type: str
    target_cluster_name:
        description:
            - The FQDN name or IP of the flashsystem-grid coordinator (in case of join action)
              or member cluster (in case of accept or remove action).
        type: str
    truststore:
        description:
            - Specifies the truststore name to be used for join or accept.
        type: str
    state:
        description:
            - Specify as C(present) to create, and to update, and C(absent) to remove a flashsystem-grid.
        choices: [ 'present', 'absent' ]
        required: true
        type: str
    log_path:
        description:
            - Path of debug log file.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool

author:
    - Sumit Kumar Gupta (@sumitguptaibm)
notes:
    - This module supports C(check_mode).
    - This module requires root-certificate exchange between coordinator and member as a pre-requisite for join/accept.
    - If user tries to create flashsystem grid on a cluster that is already part of a flashsystem-grid or a flashsystem
      grid member tries to join another flashsystem-grid, the module will fail with error "CMMVC1265E The command failed
      as this system is already a member of a Flash Grid".
    - If a flashsystem grid coordinator tries to join another flashsystem grid, the module will fail with error
      "CMMVC6036E This system is flashsystem grid coordinator".
'''

EXAMPLES = r'''
- name: Create flashsystem-grid fg0 (this cluster becomes flashsystem-grid owner, also called coordinator)
  ibm.storage_virtualize.ibm_sv_manage_flashsystem_grid:
   clustername: "{{ clustername }}"
   username: "{{ username }}"
   password: "{{ password }}"
   domain: "{{ domain }}"
   name: "fg0"
   state: present
   log_path: /tmp/playbook.debug
- name: Send a join request from requestor to a flashsystem-grid owner
  ibm.storage_virtualize.ibm_sv_manage_flashsystem_grid:
   clustername: "{{ requestor_ip }}"
   username: "{{ requestor_username }}"
   password: "{{ requestor_password }}"
   log_path: /tmp/playbook.debug
   target_cluster_name: "{{ flashsystemgrid_owner_ip_or_fqdn }}"
   truststore: "{{ flashsystemgrid_owner_truststore }}"
   action: join
   state: present
- name: Accept incoming join request
  ibm.storage_virtualize.ibm_sv_manage_flashsystem_grid:
   clustername: "{{ flashsystemgrid_owner_ip }}"
   username: "{{ flashsystemgrid_owner_username }}"
   password: "{{ flashsystemgrid_owner_password }}"
   log_path: /tmp/playbook.debug
   target_cluster_name: "{{ requestor_member_ip_or_fqdn }}"
   truststore: "{{ requestor_truststore }}"
   action: accept
   state: present
- name: Remove a member from flashsystem-grid
  ibm.storage_virtualize.ibm_sv_manage_flashsystem_grid:
   clustername: "{{ flashsystemgrid_owner_ip }}"
   username: "{{ flashsystemgrid_owner_username }}"
   password: "{{ flashsystemgrid_owner_password }}"
   target_cluster_name: "{{ requestor_ip }}"
   log_path: /tmp/playbook.debug
   action: remove
   state: present
- name: Delete flashsystem-grid fg0
  ibm.storage_virtualize.ibm_sv_manage_flashsystem_grid:
   clustername: "{{ flashsystemgrid_owner_ip }}"
   username: "{{ flashsystemgrid_owner_username }}"
   password: "{{ flashsystemgrid_owner_password }}"
   log_path: /tmp/playbook.debug
   state: absent
'''

RETURN = r'''#'''

from traceback import format_exc
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (IBMSVCRestApi,
                                                                                           svc_argument_spec,
                                                                                           get_logger)


class IBMSVFlashsystemGridMgmt(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(type='str'),
                action=dict(type='str', choices=['join', 'accept', 'remove']),
                target_cluster_name=dict(type='str'),
                truststore=dict(type='str'),
                state=dict(type='str', choices=['present', 'absent'], required=True)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        # Required parameter
        self.state = self.module.params['state']
        self.clustername = self.module.params['clustername']

        # Optional parameters
        self.name = self.module.params.get('name')
        self.action = self.module.params.get('action')
        self.target_cluster_name = self.module.params.get('target_cluster_name')
        self.truststore = self.module.params.get('truststore')
        self.log_path = self.module.params['log_path']

        self.basic_checks()

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        # Dynamic variables
        self.changed = False
        self.msg = ''

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=self.log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        if self.state == 'present':
            if self.name:
                # name is to be used only during creating grid, so it is mutually-exclusive with other params below
                if self.action or self.target_cluster_name:
                    self.module.fail_json(
                        msg='Parameter name is mutually exclusive with action and target_cluster_name'
                    )

            # join, accept and remove require both action and target_cluster_name params together
            if bool(self.action) != bool(self.target_cluster_name):
                self.module.fail_json(
                    msg='action and target_cluster_name must be provided together'
                )
            if bool(self.action in ['join', 'accept']) != bool(self.truststore):
                self.module.fail_json(
                    msg='action ({0}) must be provided with truststore.'.format(self.action)
                )

        if self.state == 'absent':
            invalids = ('action', 'target_cluster_name', 'truststore', 'name')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var)))

            if invalid_exists:
                self.module.fail_json(
                    msg='Invalid parameter(s) for state=absent: {0}'.format(invalid_exists)
                )

    def get_fg_info(self, entity=None):
        '''
        Get relevant info from flashsystem-grid based on entity
        '''
        if entity == 'members':
            cmd = 'lsflashgridmembers'
        elif entity == 'partitions':
            cmd = 'lsflashgridpartition'
        elif entity == 'systems':
            cmd = 'lsflashgridsystem'
        else:
            cmd = 'lsflashgrid'

        fg_info = self.restapi.svc_obj_info(cmd, cmdopts=None, cmdargs=None)
        return fg_info

    def get_cluster_role(self, fg_member_data=None, cluster_name=None):
        '''
        : param self: The instance of the class
        : param fg_member_data: The flashsystem-grid data
        : return: The cluster role ("coordinator" or "member" or None)
        '''
        cluster_role = None
        if cluster_name is None:
            # Check self role
            cluster_role = fg_member_data[0].get("role", "")

        # Check target cluster role
        for rec in fg_member_data:
            if rec.get("member_address") == cluster_name:
                cluster_role = rec.get("role", "")
                break
        return cluster_role

    def fg_create_validation(self):
        if not self.name:
            self.module.fail_json(msg="Parameter (name) is required to create a flashgrid")

    def manage_flashsystem_grid(self, action=None):
        cmd = "manageflashgrid"
        cmdopts = {}
        if action == 'create':
            # Create FlashsystemGrid
            self.fg_create_validation()
            cmdopts['create'] = True
            cmdopts['name'] = self.name
            self.msg = "Created flashsystem-grid ({0}) successfully".format(self.name)

        elif action == 'join':
            # Member's join request
            cmdopts['join'] = True
            cmdopts['truststore'] = self.truststore
            cmdopts['ip'] = self.target_cluster_name
            self.msg = "Sent a join request to flashsystem-grid owner ({0}) successfully".format(self.target_cluster_name)

        elif action == 'accept':
            # Accept a pending join request
            cmdopts['accept'] = True
            cmdopts['truststore'] = self.truststore
            cmdopts['ip'] = self.target_cluster_name
            self.msg = "Accepted flashsystem-grid join request from ({0}) successfully".format(self.target_cluster_name)

        elif action == 'remove':
            # Remove a member
            cmdopts['remove'] = self.target_cluster_name
            self.msg = "Removed flashsystem-grid member ({0}) successfully".format(self.target_cluster_name)

        elif action == 'delete':
            # Delete flashsystem-grid
            cmdopts['leave'] = True
            self.msg = "Deleted flashsystem-grid successfully"
        else:
            self.module.fail_json(msg="Invalid action: {0}".format(action))

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.module.exit_json(changed=True, msg=self.msg)

    def apply(self):
        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'
            self.module.exit_json(changed=False, msg=self.msg)

        fg_member_data = self.get_fg_info('members')
        self.log("Flashgrid Member: %s", fg_member_data)
        if self.state == "present":
            if not self.action:
                # User is trying to create the flashsystem-grid
                fg_data = self.get_fg_info()
                self.log("Flashgrid Data: %s", fg_data)
                if fg_member_data:
                    self_role = self.get_cluster_role(fg_member_data)
                    if self_role == "coordinator" and self.name == fg_data.get("flash_grid_name"):
                        self.module.exit_json(changed=False, msg="Flashsystem grid ({0}) already exists.".format(self.name))
                    elif self_role == "member" or self.name != fg_data.get("flash_grid_name"):
                        self.module.fail_json(msg="CMMVC1265E The command failed as this system is already a member of a Flash Grid.")
                else:
                    # Create flashsystem-grid
                    self.manage_flashsystem_grid(action="create")
            else:
                self_role = None
                target_cluster_role = None
                # In case, current cluster and/or target cluster are part of flashgrid, get their roles
                if fg_member_data:
                    self_role = self.get_cluster_role(fg_member_data)
                    target_cluster_role = self.get_cluster_role(fg_member_data, self.target_cluster_name)

                # Check self.action and check whether it is idempotency
                # or a case where member and coordinator are already part of different flashsystem grids

                if self.action == "join":
                    if target_cluster_role == "coordinator" and self_role == "member":
                        self.module.exit_json(changed=False,
                                              msg="({0}) is already member of flashsystem grid with coordinator ({1})"
                                              .format(self.clustername, self.target_cluster_name))

                    elif self_role == "coordinator":
                        self.module.fail_json(msg="CMMVC6036E This system is flashsystem grid coordinator")

                    elif self_role == "member":
                        # This cluster is part of some other flashsystem grid
                        self.module.fail_json(msg="CMMVC1265E The command failed as this system is already a member of a flashsystem grid.")

                elif self.action == "accept":
                    if self_role == "coordinator" and target_cluster_role == "member":
                        self.module.exit_json(changed=False,
                                              msg="({0}) is already member of flashsystem grid with coordinator ({1})"
                                              .format(self.target_cluster_name, self.clustername))

                elif self.action == "remove":
                    # Run on coordinator node
                    if target_cluster_role != "member":
                        self.module.exit_json(changed=False, msg="({0}) is not a flashsystem grid member."
                                              .format(self.target_cluster_name))

                # All checks done. Execute the desired action (join/accept/remove) now
                self.manage_flashsystem_grid(action=self.action)

        else:  # state==absent, user is trying to delete the flashsystemgrid.
            if fg_member_data:
                rc = self.manage_flashsystem_grid(action="delete")
            self.msg = "Flashsystem grid does not exist."
        self.module.exit_json(changed=self.changed, msg=self.msg)


def main():
    v = IBMSVFlashsystemGridMgmt()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
