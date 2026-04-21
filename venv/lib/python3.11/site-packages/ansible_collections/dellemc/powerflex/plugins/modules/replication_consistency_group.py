#!/usr/bin/python

# Copyright: (c) 2022, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing replication consistency groups on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: replication_consistency_group
version_added: '1.5.0'
short_description: Manage replication consistency groups on Dell PowerFlex
description:
- Managing replication consistency groups on PowerFlex storage system includes
  getting details, creating, modifying, creating snapshots, pause, resume, freeze, unfreeze,
  activate, failover, reverse, restore, sync, switchover,
  inactivate and deleting a replication consistency group.
author:
- Trisha Datta (@Trisha-Datta) <ansible.team@dell.com>
- Jennifer John (@Jennifer-John) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  rcg_name:
    description:
    - The name of the replication consistency group.
    - It is unique across the PowerFlex array.
    - Mutually exclusive with I(rcg_id).
    type: str
  rcg_id:
    description:
    - The ID of the replication consistency group.
    - Mutually exclusive with I(rcg_name).
    type: str
  create_snapshot:
    description:
    - Whether to create the snapshot of the replication consistency group.
    type: bool
  rpo:
    description:
    - Desired RPO in seconds.
    type: int
  protection_domain_id:
    description:
    - Protection domain id.
    - Mutually exclusive with I(protection_domain_name).
    type: str
  protection_domain_name:
    description:
    - Protection domain name.
    - Mutually exclusive with I(protection_domain_id).
    type: str
  activity_mode:
    description:
    - Activity mode of RCG.
    - This parameter is supported for version 3.6 and above.
    choices: ['Active', 'Inactive']
    type: str
  pause:
    description:
    - Pause or resume the RCG.
    - This parameter is deprecated. Use rcg_state instead.
    type: bool
  rcg_state:
    description:
    - Specify an action for RCG.
    - Failover the RCG.
    - Reverse the RCG.
    - Restore the RCG.
    - Switchover the RCG.
    - Pause or resume the RCG.
    - Freeze or unfreeze the RCG.
    - Synchronize the RCG.
    choices: ['failover', 'reverse', 'restore',
              'switchover', 'sync', 'pause',
              'resume', 'freeze', 'unfreeze']
    type: str
  force:
    description:
    - Force switchover the RCG.
    type: bool
  freeze:
    description:
    - Freeze or unfreeze the RCG.
    - This parameter is deprecated. Use rcg_state instead.
    type: bool
  pause_mode:
    description:
    - Pause mode.
    - It is required if pause is set as true.
    choices: ['StopDataTransfer', 'OnlyTrackChanges']
    type: str
  target_volume_access_mode:
    description:
    - Target volume access mode.
    choices: ['ReadOnly', 'NoAccess']
    type: str
  is_consistent:
    description:
    - Consistency of RCG.
    type: bool
  new_rcg_name:
    description:
    - Name of RCG to rename to.
    type: str
  remote_peer:
    description:
    - Remote peer system.
    type: dict
    suboptions:
      hostname:
        required: true
        description:
        - IP or FQDN of the remote peer gateway host.
        type: str
        aliases:
            - gateway_host
      username:
        type: str
        required: true
        description:
        - The username of the remote peer gateway host.
      password:
        type: str
        required: true
        description:
        - The password of the remote peer gateway host.
      validate_certs:
        type: bool
        default: true
        aliases:
            - verifycert
        description:
        - Boolean variable to specify whether or not to validate SSL
          certificate.
        - C(true) - Indicates that the SSL certificate should be verified.
        - C(false) - Indicates that the SSL certificate should not be verified.
      port:
        description:
        - Port number through which communication happens with remote peer
          gateway host.
        type: int
        default: 443
      timeout:
        description:
        - Time after which connection will get terminated.
        - It is to be mentioned in seconds.
        type: int
        default: 120
      protection_domain_id:
        description:
        - Remote protection domain id.
        - Mutually exclusive with I(protection_domain_name).
        type: str
      protection_domain_name:
        description:
        - Remote protection domain name.
        - Mutually exclusive with I(protection_domain_id).
        type: str
  state:
    description:
    - State of the replication consistency group.
    choices: ['present', 'absent']
    default: present
    type: str
notes:
- The I(check_mode) is supported.
- Idempotency is not supported for create snapshot operation.
- There is a delay in reflection of final state of RCG after few update operations on RCG.
- In 3.6 and above, the replication consistency group will return back to consistent mode on changing to inconsistent mode
  if consistence barrier arrives. Hence idempotency on setting to inconsistent mode will return changed as true.
'''

EXAMPLES = r'''

- name: Get RCG details
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "{{rcg_name}}"

- name: Create a snapshot of the RCG
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_id: "{{rcg_id}}"
    create_snapshot: true
    state: "present"

- name: Create a replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rpo: 60
    protection_domain_name: "domain1"
    activity_mode: "active"
    remote_peer:
      hostname: "{{hostname}}"
      username: "{{username}}"
      password: "{{password}}"
      validate_certs: "{{validate_certs}}"
      port: "{{port}}"
      protection_domain_name: "domain1"

- name: Modify replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rpo: 60
    target_volume_access_mode: "ReadOnly"
    activity_mode: "Inactive"
    is_consistent: true

- name: Rename replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    new_rcg_name: "rcg_test_rename"

- name: Pause replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "pause"
    pause_mode: "StopDataTransfer"

- name: Resume replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "resume"

- name: Freeze replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "freeze"

- name: UnFreeze replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "unfreeze"

- name: Failover replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "failover"

- name: Reverse replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "reverse"

- name: Restore replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "restore"

- name: Switchover replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "switchover"

- name: Synchronize replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    rcg_state: "sync"

- name: Delete replication consistency group
  dellemc.powerflex.replication_consistency_group:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "rcg_test"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
replication_consistency_group_details:
    description: Details of the replication consistency group.
    returned: When replication consistency group exists
    type: dict
    contains:
        id:
            description: The ID of the replication consistency group.
            type: str
        name:
            description: The name of the replication consistency group.
            type: str
        protectionDomainId:
            description: The Protection Domain ID of the replication consistency group.
            type: str
        peerMdmId:
            description: The ID of the peer MDM of the replication consistency group.
            type: str
        remoteId:
            description: The ID of the remote replication consistency group.
            type: str
        remoteMdmId:
            description: The ID of the remote MDM of the replication consistency group.
            type: str
        currConsistMode:
            description: The current consistency mode of the replication consistency group.
            type: str
        freezeState:
            description: The freeze state of the replication consistency group.
            type: str
        lifetimeState:
            description: The Lifetime state of the replication consistency group.
            type: str
        pauseMode:
            description: The Lifetime state of the replication consistency group.
            type: str
        snapCreationInProgress:
            description: Whether the process of snapshot creation of the replication consistency group is in progress or not.
            type: bool
        lastSnapGroupId:
            description: ID of the last snapshot of the replication consistency group.
            type: str
        lastSnapCreationRc:
            description: The return code of the last snapshot of the replication consistency group.
            type: int
        targetVolumeAccessMode:
            description: The access mode of the target volume of the replication consistency group.
            type: str
        remoteProtectionDomainId:
            description: The ID of the remote Protection Domain.
            type: str
        remoteProtectionDomainName:
            description: The Name of the remote Protection Domain.
            type: str
        failoverType:
            description: The type of failover of the replication consistency group.
            type: str
        failoverState:
            description: The state of failover of the replication consistency group.
            type: str
        activeLocal:
            description: Whether the local replication consistency group is active.
            type: bool
        activeRemote:
            description: Whether the remote replication consistency group is active
            type: bool
        abstractState:
            description: The abstract state of the replication consistency group.
            type: str
        localActivityState:
            description: The state of activity of the local replication consistency group.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication consistency group..
            type: str
        inactiveReason:
            description: The reason for the inactivity of the replication consistency group.
            type: int
        rpoInSeconds:
            description: The RPO value of the replication consistency group in seconds.
            type: int
        replicationDirection:
            description: The direction of the replication of the replication consistency group.
            type: str
        disasterRecoveryState:
            description: The state of disaster recovery of the local replication consistency group.
            type: str
        remoteDisasterRecoveryState:
            description: The state of disaster recovery of the remote replication consistency group.
            type: str
        error:
            description: The error code of the replication consistency group.
            type: int
        type:
            description: The type of the replication consistency group.
            type: str
    sample: {
        "protectionDomainId": "b969400500000000",
        "peerMdmId": "6c3d94f600000000",
        "remoteId": "2130961a00000000",
        "remoteMdmId": "0e7a082862fedf0f",
        "currConsistMode": "Consistent",
        "freezeState": "Unfrozen",
        "lifetimeState": "Normal",
        "pauseMode": "None",
        "snapCreationInProgress": false,
        "lastSnapGroupId": "e58280b300000001",
        "lastSnapCreationRc": "SUCCESS",
        "targetVolumeAccessMode": "NoAccess",
        "remoteProtectionDomainId": "4eeb304600000000",
        "remoteProtectionDomainName": "domain1",
        "failoverType": "None",
        "failoverState": "None",
        "activeLocal": true,
        "activeRemote": true,
        "abstractState": "Ok",
        "localActivityState": "Active",
        "remoteActivityState": "Active",
        "inactiveReason": 11,
        "rpoInSeconds": 30,
        "replicationDirection": "LocalToRemote",
        "disasterRecoveryState": "None",
        "remoteDisasterRecoveryState": "None",
        "error": 65,
        "name": "test_rcg",
        "type": "User",
        "id": "aadc17d500000000"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('replication_consistency_group')


class PowerFlexReplicationConsistencyGroup(object):
    """Class with replication consistency group operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_replication_consistency_group_parameters())

        mut_ex_args = [['rcg_name', 'rcg_id'], ['protection_domain_id', 'protection_domain_name']]

        required_one_of_args = [['rcg_name', 'rcg_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=True,
            mutually_exclusive=mut_ex_args,
            required_one_of=required_one_of_args)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_rcg(self, rcg_name=None, rcg_id=None):
        """Get rcg details
            :param rcg_name: Name of the RCG
            :param rcg_id: ID of the RCG
            :return: RCG details
        """
        name_or_id = rcg_id if rcg_id else rcg_name
        try:
            rcg_details = None
            if rcg_id:
                rcg_details = self.powerflex_conn.replication_consistency_group.get(
                    filter_fields={'id': rcg_id})

            if rcg_name:
                rcg_details = self.powerflex_conn.replication_consistency_group.get(
                    filter_fields={'name': rcg_name})

            if rcg_details:
                rcg_details[0]['statistics'] = \
                    self.powerflex_conn.replication_consistency_group.get_statistics(rcg_details[0]['id'])
                rcg_details[0].pop('links', None)
                self.append_protection_domain_name(rcg_details[0])
                return rcg_details[0]

        except Exception as e:
            errormsg = "Failed to get the replication consistency group {0} with" \
                       " error {1}".format(name_or_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_rcg_snapshot(self, rcg_id):
        """Create RCG snapshot
            :param rcg_id: Unique identifier of the RCG.
            :return: Boolean indicating if create snapshot operation is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.create_snapshot(
                    rcg_id=rcg_id)
            return True

        except Exception as e:
            errormsg = "Create RCG snapshot for RCG with id {0} operation failed with " \
                       "error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_rcg(self, rcg_params):
        """Create RCG"""
        try:
            resp = None
            # Get remote system details
            self.remote_powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params['remote_peer'])
            LOG.info("Got the remote peer connection object instance")
            protection_domain_id = rcg_params['protection_domain_id']
            if rcg_params['protection_domain_name']:
                protection_domain_id = \
                    self.get_protection_domain(self.powerflex_conn, rcg_params['protection_domain_name'])['id']

            remote_protection_domain_id = rcg_params['remote_peer']['protection_domain_id']
            if rcg_params['remote_peer']['protection_domain_name']:
                remote_protection_domain_id = \
                    self.get_protection_domain(self.remote_powerflex_conn,
                                               rcg_params['remote_peer']['protection_domain_name'])['id']

            if not self.module.check_mode:
                resp = self.powerflex_conn.replication_consistency_group.create(
                    rpo=rcg_params['rpo'],
                    protection_domain_id=protection_domain_id,
                    remote_protection_domain_id=remote_protection_domain_id,
                    destination_system_id=self.remote_powerflex_conn.system.get()[0]['id'],
                    name=rcg_params['rcg_name'],
                    activity_mode=rcg_params['activity_mode'])
            return True, resp

        except Exception as e:
            errormsg = "Create replication consistency group failed with error {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_rpo(self, rcg_id, rpo):
        """Modify rpo
            :param rcg_id: Unique identifier of the RCG.
            :param rpo: rpo value in seconds
            :return: Boolean indicates if modify rpo is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.modify_rpo(
                    rcg_id, rpo)
            return True

        except Exception as e:
            errormsg = "Modify rpo for replication consistency group {0} failed with " \
                       "error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_target_volume_access_mode(self, rcg_id, target_volume_access_mode):
        """Modify target volume access mode
            :param rcg_id: Unique identifier of the RCG.
            :param target_volume_access_mode: Target volume access mode.
            :return: Boolean indicates if modify operation is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.modify_target_volume_access_mode(
                    rcg_id, target_volume_access_mode)
            return True

        except Exception as e:
            errormsg = "Modify target volume access mode for replication consistency group {0} failed with " \
                       "error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_activity_mode(self, rcg_id, rcg_details, activity_mode):
        """Modify activity mode
            :param rcg_id: Unique identifier of the RCG.
            :param rcg_details: RCG details.
            :param activity_mode: RCG activity mode.
            :return: Boolean indicates if modify operation is successful
        """
        try:
            if activity_mode == 'Active' and rcg_details['localActivityState'].lower() == 'inactive':
                if not self.module.check_mode:
                    self.powerflex_conn.replication_consistency_group.activate(rcg_id)
                return True
            elif activity_mode == 'Inactive' and rcg_details['localActivityState'].lower() == 'active':
                if not self.module.check_mode:
                    rcg_details = self.powerflex_conn.replication_consistency_group.inactivate(rcg_id)
                return True
        except Exception as e:
            errormsg = "Modify activity_mode for replication consistency group {0} failed with " \
                       "error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def pause_or_resume_rcg(self, rcg_id, rcg_details, pause, pause_mode=None):
        """Perform specified rcg action
            :param rcg_id: Unique identifier of the RCG.
            :param rcg_details: RCG details.
            :param pause: Pause or resume RCG.
            :param pause_mode: Specifies the pause mode if pause is True.
            :return: Boolean indicates if RCG action is successful
        """
        if pause and rcg_details['pauseMode'] == 'None':
            if not pause_mode:
                self.module.fail_json(msg="Specify pause_mode to perform pause on replication consistency group.")
            return self.pause(rcg_id, pause_mode)

        if not pause and (rcg_details['pauseMode'] != 'None' or rcg_details['failoverType'] in ['Failover', 'Switchover']):
            return self.resume(rcg_id)

    def freeze_or_unfreeze_rcg(self, rcg_id, rcg_details, freeze):
        """Perform specified RCG action
            :param rcg_id: Unique identifier of the RCG.
            :param rcg_details: RCG details.
            :param freeze: Freeze or unfreeze RCG.
            :return: Boolean indicates if RCG action is successful
        """
        if freeze and rcg_details['freezeState'].lower() == 'unfrozen':
            return self.freeze(rcg_id)

        if not freeze and rcg_details['freezeState'].lower() == 'frozen':
            return self.unfreeze(rcg_id)

    def freeze(self, rcg_id):
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.freeze(rcg_id)
            return True
        except Exception as e:
            errormsg = "Freeze replication consistency group {0} failed with error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def unfreeze(self, rcg_id):
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.unfreeze(rcg_id)
            return True
        except Exception as e:
            errormsg = "Unfreeze replication consistency group {0} failed with error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def pause(self, rcg_id, pause_mode):
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.pause(rcg_id, pause_mode)
            return True
        except Exception as e:
            errormsg = "Pause replication consistency group {0} failed with error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def resume(self, rcg_id):
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.resume(rcg_id)
            return True
        except Exception as e:
            errormsg = "Resume replication consistency group {0} failed with error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def failover(self, rcg_id):
        """Perform failover
            :param rcg_id: Unique identifier of the RCG.
            :return: Boolean indicates if RCG failover is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.failover(rcg_id)
            return True
        except Exception as e:
            errormsg = f"Failover replication consistency group {rcg_id} failed with error {e}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def reverse(self, rcg_id):
        """Perform reverse
            :param rcg_id: Unique identifier of the RCG.
            :return: Boolean indicates if RCG reverse is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.reverse(rcg_id)
            return True
        except Exception as e:
            errormsg = f"Reverse replication consistency group {rcg_id} failed with error {e}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def restore(self, rcg_id):
        """Perform restore
            :param rcg_id: Unique identifier of the RCG.
            :return: Boolean indicates if RCG restore is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.restore(rcg_id)
            return True
        except Exception as e:
            errormsg = f"Restore replication consistency group {rcg_id} failed with error {e}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def switchover(self, rcg_id, force):
        """Perform switchover
            :param rcg_id: Unique identifier of the RCG.
            :param force: Force switchover.
            :return: Boolean indicates if RCG switchover is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.switchover(rcg_id, force)
            return True
        except Exception as e:
            errormsg = f"Switchover replication consistency group {rcg_id} failed with error {e}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def perform_rcg_action(self, rcg_id, rcg_details):
        """Perform failover, reverse, restore or switchover
            :param rcg_id: Unique identifier of the RCG.
            :param rcg_details: RCG details.
            :return: Boolean indicates if RCG action is successful
        """
        rcg_state = self.module.params['rcg_state']
        force = self.module.params['force']

        if rcg_state == 'failover' and rcg_details['failoverType'] != 'Failover':
            return self.failover(rcg_id)

        if rcg_state == 'switchover' and rcg_details['failoverType'] != 'Switchover':
            return self.switchover(rcg_id, force)

        if rcg_state == 'reverse' and rcg_details['failoverType']:
            return self.reverse(rcg_id)

        if rcg_state == 'restore' and rcg_details['failoverType'] != 'None':
            return self.restore(rcg_id)

    def sync(self, rcg_id):
        """Perform sync
            :param rcg_id: Unique identifier of the RCG.
            :return: Boolean indicates if RCG sync is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.sync(rcg_id)
            return True
        except Exception as e:
            errormsg = f"Synchronization of replication consistency group {rcg_id} failed with error {e}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def set_consistency(self, rcg_id, rcg_details, is_consistent):
        """Set rcg to specified mode
            :param rcg_id: Unique identifier of the RCG.
            :param rcg_details: RCG details.
            :param is_consistent: RCG consistency.
            :return: Boolean indicates if set consistency is successful
        """
        try:
            if is_consistent and rcg_details['currConsistMode'].lower() not in ('consistent', 'consistentpending'):
                if not self.module.check_mode:
                    self.powerflex_conn.replication_consistency_group.set_as_consistent(rcg_id)
                return True
            elif not is_consistent and rcg_details['currConsistMode'].lower() not in ('inconsistent', 'inconsistentpending'):
                if not self.module.check_mode:
                    self.powerflex_conn.replication_consistency_group.set_as_inconsistent(rcg_id)
                return True
        except Exception as e:
            errormsg = "Modifying consistency of replication consistency group failed with error {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def rename_rcg(self, rcg_id, rcg_details, new_name):
        """Rename rcg
            :param rcg_id: Unique identifier of the RCG.
            :param rcg_details: RCG details
            :param new_name: RCG name to rename to.
            :return: Boolean indicates if rename is successful
        """
        try:
            if rcg_details['name'] != new_name:
                if not self.module.check_mode:
                    self.powerflex_conn.replication_consistency_group.rename_rcg(rcg_id, new_name)
                return True
        except Exception as e:
            errormsg = "Renaming replication consistency group to {0} failed with error {1}".format(new_name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_rcg(self, rcg_id):
        """Delete RCG
            :param rcg_id: Unique identifier of the RCG.
            :return: Boolean indicates if delete RCG operation is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_consistency_group.delete(
                    rcg_id=rcg_id)
            return True

        except Exception as e:
            errormsg = "Delete replication consistency group {0} failed with " \
                       "error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_protection_domain(self, conn, protection_domain_name=None, protection_domain_id=None):
        """
        Get protection domain details
        :param conn: local or remote connection
        :param protection_domain_name: Name of the protection domain
        :param protection_domain_id: ID of the protection domain
        :return: Protection domain id if exists
        :rtype: str
        """
        name_or_id = protection_domain_id if protection_domain_id \
            else protection_domain_name
        try:
            pd_details = []
            if protection_domain_id:
                pd_details = conn.protection_domain.get(
                    filter_fields={'id': protection_domain_id})

            if protection_domain_name:
                pd_details = conn.protection_domain.get(
                    filter_fields={'name': protection_domain_name})

            if len(pd_details) == 0:
                error_msg = "Unable to find the protection domain with " \
                            "'%s'." % name_or_id
                self.module.fail_json(msg=error_msg)

            return pd_details[0]
        except Exception as e:
            error_msg = "Failed to get the protection domain '%s' with " \
                        "error '%s'" % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_create(self, rcg_params):
        """Validate create RCG params"""
        params = ['create_snapshot', 'new_rcg_name']
        for param in params:
            if rcg_params[param] is not None:
                self.module.fail_json(msg="%s cannot be specified while creating replication consistency group" % param)
        if not rcg_params['rpo']:
            self.module.fail_json(msg='Enter rpo to create replication consistency group')
        if not rcg_params['remote_peer']:
            self.module.fail_json(msg='Enter remote_peer to create replication consistency group')
        if not rcg_params['protection_domain_id'] and not rcg_params['protection_domain_name']:
            self.module.fail_json(msg='Enter protection_domain_name or protection_domain_id to create replication consistency group')
        if (not rcg_params['remote_peer']['protection_domain_id'] and not rcg_params['remote_peer']['protection_domain_name']) or \
                (rcg_params['remote_peer']['protection_domain_id'] is not None and
                 rcg_params['remote_peer']['protection_domain_name'] is not None):
            self.module.fail_json(msg='Enter remote protection_domain_name or protection_domain_id to create replication consistency group')

    def get_pause_and_freeze_value(self):
        """
        Get Pause and Freeze values
        :return: Boolean for pause and freeze
        :rtype: (bool,bool)
        """
        rcg_state = self.module.params['rcg_state']
        pause = self.module.params['pause']
        freeze = self.module.params['freeze']

        if pause is not None:
            self.module.deprecate(
                msg="Use 'rcg_state' param instead of 'pause'",
                version="3.0.0",
                collection_name="dellemc.powerflex"
            )

        if freeze is not None:
            self.module.deprecate(
                msg="Use 'rcg_state' param instead of 'freeze'",
                version="3.0.0",
                collection_name="dellemc.powerflex"
            )

        if rcg_state == 'pause':
            pause = True
        if rcg_state == 'resume':
            pause = False
        if rcg_state == 'freeze':
            freeze = True
        if rcg_state == 'unfreeze':
            freeze = False

        if self.module.params['pause_mode'] and not pause:
            self.module.fail_json(msg="Specify rcg_state as 'pause' to pause replication consistency group")

        return pause, freeze

    def modify_rcg(self, rcg_id, rcg_details):
        rcg_state = self.module.params['rcg_state']
        create_snapshot = self.module.params['create_snapshot']
        rpo = self.module.params['rpo']
        target_volume_access_mode = self.module.params['target_volume_access_mode']
        is_consistent = self.module.params['is_consistent']
        activity_mode = self.module.params['activity_mode']
        new_rcg_name = self.module.params['new_rcg_name']

        pause, freeze = self.get_pause_and_freeze_value()

        changed = self.create_snap(rcg_id, create_snapshot)

        rpo_changed = self.rpo_mod(rcg_id, rcg_details, rpo)

        if target_volume_access_mode and \
                rcg_details['targetVolumeAccessMode'] != target_volume_access_mode:
            changed = \
                self.modify_target_volume_access_mode(
                    rcg_id, target_volume_access_mode)
        if activity_mode and \
                self.modify_activity_mode(rcg_id, rcg_details, activity_mode):
            changed = True
            rcg_details = self.get_rcg(rcg_id=rcg_details['id'])
        if pause is not None and \
                self.pause_or_resume_rcg(rcg_id, rcg_details, pause, self.module.params['pause_mode']):
            changed = True
        if freeze is not None and \
                self.freeze_or_unfreeze_rcg(rcg_id, rcg_details, freeze):
            changed = True
        if is_consistent is not None and \
                self.set_consistency(rcg_id, rcg_details, is_consistent):
            changed = True
        if new_rcg_name and self.rename_rcg(rcg_id, rcg_details, new_rcg_name):
            changed = True
        if rcg_state == 'sync' and self.sync(rcg_id):
            changed = True

        rcg_action_status = self.perform_rcg_action(rcg_id, rcg_details)

        return rpo_changed or changed or rcg_action_status

    def rpo_mod(self, rcg_id, rcg_details, rpo):
        changed = False
        if rpo and rcg_details['rpoInSeconds'] and \
                rpo != rcg_details['rpoInSeconds']:
            changed = self.modify_rpo(rcg_id, rpo)
        return changed

    def create_snap(self, rcg_id, create_snapshot):
        changed = False
        if create_snapshot is True:
            changed = self.create_rcg_snapshot(rcg_id)
        return changed

    def validate_input(self, rcg_params):
        try:
            api_version = self.powerflex_conn.system.get()[0]['mdmCluster']['master']['versionInfo']
            if rcg_params['activity_mode'] is not None and utils.is_version_less_than_3_6(api_version):
                self.module.fail_json(msg='activity_mode is supported only from version 3.6 and above')
            params = ['rcg_name', 'new_rcg_name']
            for param in params:
                if rcg_params[param] and utils.is_invalid_name(rcg_params[param]):
                    self.module.fail_json(msg='Enter a valid %s' % param)
        except Exception as e:
            error_msg = "Validating input parameters failed with " \
                        "error '%s'" % (str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def append_protection_domain_name(self, rcg_details):
        try:
            # Append protection domain name
            if 'protectionDomainId' in rcg_details \
                    and rcg_details['protectionDomainId']:
                pd_details = self.get_protection_domain(
                    conn=self.powerflex_conn,
                    protection_domain_id=rcg_details['protectionDomainId'])
                rcg_details['protectionDomainName'] = pd_details['name']
        except Exception as e:
            error_msg = "Updating replication consistency group details with protection domain name failed with " \
                        "error '%s'" % (str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on replication consistency group based on parameters passed in
        the playbook
        """
        self.validate_input(self.module.params)
        rcg_name = self.module.params['rcg_name']
        new_rcg_name = self.module.params['new_rcg_name']
        rcg_id = self.module.params['rcg_id']
        state = self.module.params['state']

        # result is a dictionary to contain end state and RCG details
        changed = False
        result = dict(
            changed=False,
            replication_consistency_group_details=[]
        )
        # get RCG details
        rcg_details = self.get_rcg(rcg_name, rcg_id)
        if rcg_details:
            result['replication_consistency_group_details'] = rcg_details
            rcg_id = rcg_details['id']
        msg = "Fetched the RCG details {0}".format(str(rcg_details))
        LOG.info(msg)

        # perform create
        if state == "present":
            if not rcg_details:
                self.validate_create(self.module.params)
                changed, rcg_details = self.create_rcg(self.module.params)
                if rcg_details:
                    rcg_id = rcg_details['id']

            if rcg_details and self.modify_rcg(rcg_id, rcg_details):
                changed = True

        if state == "absent" and rcg_details:
            changed = self.delete_rcg(rcg_id=rcg_details['id'])

        # Returning the RCG details
        if changed:
            result['replication_consistency_group_details'] = \
                self.get_rcg(new_rcg_name or rcg_name, rcg_id)
        result['changed'] = changed
        self.module.exit_json(**result)


def get_powerflex_replication_consistency_group_parameters():
    """This method provide parameter required for the replication_consistency_group
    module on PowerFlex"""
    return dict(
        rcg_name=dict(), rcg_id=dict(),
        create_snapshot=dict(type='bool'),
        rpo=dict(type='int'), protection_domain_id=dict(),
        protection_domain_name=dict(), new_rcg_name=dict(),
        activity_mode=dict(choices=['Active', 'Inactive']),
        pause=dict(type='bool', removed_in_version='3.0.0', removed_from_collection='dellemc.powerflex'),
        freeze=dict(type='bool', removed_in_version='3.0.0', removed_from_collection='dellemc.powerflex'),
        force=dict(type='bool'),
        rcg_state=dict(choices=['failover', 'reverse',
                                'restore', 'switchover',
                                'sync', 'pause', 'resume',
                                'freeze', 'unfreeze']),
        pause_mode=dict(choices=['StopDataTransfer', 'OnlyTrackChanges']),
        target_volume_access_mode=dict(choices=['ReadOnly', 'NoAccess']),
        is_consistent=dict(type='bool'),
        remote_peer=dict(type='dict',
                         options=dict(hostname=dict(type='str', aliases=['gateway_host'], required=True),
                                      username=dict(type='str', required=True),
                                      password=dict(type='str', required=True, no_log=True),
                                      validate_certs=dict(type='bool', aliases=['verifycert'], default=True),
                                      port=dict(type='int', default=443),
                                      timeout=dict(type='int', default=120),
                                      protection_domain_id=dict(),
                                      protection_domain_name=dict())),
        state=dict(default='present', type='str', choices=['present', 'absent'])
    )


def main():
    """ Create PowerFlex Replication Consistency Group object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexReplicationConsistencyGroup()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
