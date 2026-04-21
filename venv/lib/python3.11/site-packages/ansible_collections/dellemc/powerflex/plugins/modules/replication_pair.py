#!/usr/bin/python

# Copyright: (c) 2024, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing replication pairs on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: replication_pair
version_added: '1.6.0'
short_description: Manage replication pairs on Dell PowerFlex
description:
- Managing replication pairs on PowerFlex storage system includes
  getting details, creating, pause, resume initial copy and deleting a replication pair.
author:
- Jennifer John (@Jennifer-John) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  pair_id:
    description:
    - The ID of the replication pair.
    - Mutually exclusive with I(pair_name).
    type: str
  pair_name:
    description:
    - The name of the replication pair.
    - Mutually exclusive with I(pair_id).
    type: str
  rcg_name:
    description:
    - The name of the replication consistency group.
    - Mutually exclusive with I(rcg_id).
    type: str
  rcg_id:
    description:
    - The ID of the replication consistency group.
    - Mutually exclusive with I(rcg_name).
    type: str
  pause:
    description:
    - Pause or resume the initial copy of replication pair.
    type: bool
  pairs:
    description:
    - List of replication pairs to add to rcg.
    type: list
    elements: dict
    suboptions:
      source_volume_id:
        description:
        - Source volume ID.
        - Mutually exclusive with I(source_volume_name).
        type: str
      source_volume_name:
        description:
        - Source volume name.
        - Mutually exclusive with I(source_volume_id).
        type: str
      target_volume_id:
        description:
        - Target volume ID.
        - Mutually exclusive with I(target_volume_name).
        type: str
      target_volume_name:
        description:
        - Target volume name.
        - If specified, I(remote_peer) details should also be specified.
        - Mutually exclusive with I(target_volume_id).
        type: str
      copy_type:
        description:
        - Copy type.
        choices: ['Identical', 'OnlineCopy', 'OnlineHashCopy', 'OfflineCopy']
        type: str
        required: true
      name:
        description:
        - Name of replication pair.
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
  state:
    description:
    - State of the replication pair.
    choices: ['present', 'absent']
    default: present
    type: str
notes:
- The I(check_mode) is supported.
- In 4.0 the creation of replication pair fails when I(copy_type) is specified as C(OfflineCopy).
'''

EXAMPLES = r'''
- name: Get replication pair details
  dellemc.powerflex.replication_pair:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    pair_id: "123"

- name: Create a replication pair
  dellemc.powerflex.replication_pair:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "test_rcg"
    pairs:
      - source_volume_id: "002"
        target_volume_id: "001"
        copy_type: "OnlineCopy"
        name: "pair1"

- name: Create a replication pair with target volume name
  dellemc.powerflex.replication_pair:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    rcg_name: "test_rcg"
    pairs:
      - source_volume_name: "src_vol"
        target_volume_name: "dest_vol"
        copy_type: "OnlineCopy"
        name: "pair1"
    remote_peer:
      hostname: "{{hostname}}"
      username: "{{username}}"
      password: "{{password}}"
      validate_certs: "{{validate_certs}}"
      port: "{{port}}"

- name: Pause replication pair
  dellemc.powerflex.replication_pair:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    pair_name: "pair1"
    pause: true

- name: Resume replication pair
  dellemc.powerflex.replication_pair:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    pair_name: "pair1"
    pause: false

- name: Delete replication pair
  dellemc.powerflex.replication_pair:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    pair_name: "pair1"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
replication_pair_details:
    description: Details of the replication pair.
    returned: When replication pair exists
    type: dict
    contains:
        id:
            description: The ID of the replication pair.
            type: str
        name:
            description: The name of the replication pair.
            type: str
        remoteId:
            description: The ID of the remote replication pair.
            type: str
        localVolumeId:
            description: The ID of the local volume.
            type: str
        localVolumeName:
            description: The name of the local volume.
            type: str
        replicationConsistencyGroupId:
            description: The ID of the replication consistency group.
            type: str
        copyType:
            description: The copy type of the replication pair.
            type: str
        initialCopyState:
            description: The inital copy state of the replication pair.
            type: str
        localActivityState:
            description: The state of activity of the local replication pair.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication pair.
            type: str
        initialCopyPriority:
            description: Initial copy priority.
            type: int
        lifetimeState:
            description: Lifetime state of replication pair.
            type: int
        peerSystemName:
            description: Peer system name.
            type: int
        remoteCapacityInMB:
            description: Remote Capacity in MB.
            type: int
        userRequestedPauseTransmitInitCopy:
            description: Value of user requested pause transmit initial copy.
            type: int
        remoteVolumeId:
            description: Remote Volume ID.
            type: int
        remoteVolumeName:
            description: Remote Volume Name.
            type: int
    sample: {
        "copyType": "OnlineCopy",
        "id": "23aa0bc900000001",
        "initialCopyPriority": -1,
        "initialCopyState": "Done",
        "lifetimeState": "Normal",
        "localActivityState": "RplEnabled",
        "localVolumeId": "e2bc1fab00000008",
        "localVolumeName": "vol1",
        "name": null,
        "peerSystemName": null,
        "remoteActivityState": "RplEnabled",
        "remoteCapacityInMB": 8192,
        "remoteId": "a058446700000001",
        "remoteVolumeId": "1cda7af20000000d",
        "remoteVolumeName": "vol",
        "replicationConsistencyGroupId": "e2ce036b00000002",
        "userRequestedPauseTransmitInitCopy": false
    }
rcg_replication_pairs:
    description: Details of the replication pairs of rcg.
    returned: When rcg exists
    type: list
    contains:
        id:
            description: The ID of the replication pair.
            type: str
        name:
            description: The name of the replication pair.
            type: str
        remoteId:
            description: The ID of the remote replication pair.
            type: str
        localVolumeId:
            description: The ID of the local volume.
            type: str
        localVolumeName:
            description: The name of the local volume.
            type: str
        replicationConsistencyGroupId:
            description: The ID of the replication consistency group.
            type: str
        copyType:
            description: The copy type of the replication pair.
            type: str
        initialCopyState:
            description: The inital copy state of the replication pair.
            type: str
        localActivityState:
            description: The state of activity of the local replication pair.
            type: str
        remoteActivityState:
            description: The state of activity of the remote replication pair.
            type: str
        initialCopyPriority:
            description: Initial copy priority.
            type: int
        lifetimeState:
            description: Lifetime state of replication pair.
            type: int
        peerSystemName:
            description: Peer system name.
            type: int
        remoteCapacityInMB:
            description: Remote Capacity in MB.
            type: int
        userRequestedPauseTransmitInitCopy:
            description: Value of user requested pause transmit initial copy.
            type: int
        remoteVolumeId:
            description: Remote Volume ID.
            type: int
        remoteVolumeName:
            description: Remote Volume Name.
            type: int
    sample: [{
        "copyType": "OnlineCopy",
        "id": "23aa0bc900000001",
        "initialCopyPriority": -1,
        "initialCopyState": "Done",
        "lifetimeState": "Normal",
        "localActivityState": "RplEnabled",
        "localVolumeId": "e2bc1fab00000008",
        "localVolumeName": "vol1",
        "name": null,
        "peerSystemName": null,
        "remoteActivityState": "RplEnabled",
        "remoteCapacityInMB": 8192,
        "remoteId": "a058446700000001",
        "remoteVolumeId": "1cda7af20000000d",
        "remoteVolumeName": "vol",
        "replicationConsistencyGroupId": "e2ce036b00000002",
        "userRequestedPauseTransmitInitCopy": false
    }]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('replication_pair')


class PowerFlexReplicationPair(object):
    """Class with replication pair operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_replication_pair_parameters())

        mut_ex_args = [['rcg_name', 'rcg_id'], ['pair_id', 'pair_name']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=True,
            mutually_exclusive=mut_ex_args)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_replication_pair(self, pair_name=None, pair_id=None):
        """Get replication pair details
            :param pair_name: Name of the replication pair
            :param pair_id: ID of the replication pair
            :return: Replication pair details
        """
        name_or_id = pair_id if pair_id else pair_name
        try:
            pair_details = []
            if pair_id:
                pair_details = self.powerflex_conn.replication_pair.get(
                    filter_fields={'id': pair_id})

            if pair_name:
                pair_details = self.powerflex_conn.replication_pair.get(
                    filter_fields={'name': pair_name})

            if pair_details:
                pair_details[0].pop('links', None)
                pair_details[0]['localVolumeName'] = self.get_volume(pair_details[0]['localVolumeId'], filter_by_name=False)[0]['name']
                pair_details[0]['statistics'] = \
                    self.powerflex_conn.replication_pair.get_statistics(pair_details[0]['id'])
                return pair_details[0]
            return pair_details
        except Exception as e:
            errormsg = "Failed to get the replication pair {0} with" \
                       " error {1}".format(name_or_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_volume(self, vol_name_or_id, filter_by_name=True, is_remote=False):
        """Get volume details
            :param vol_name: ID or name of the volume
            :param filter_by_name: If filter details by name or id
            :param is_remote: Specifies if source or target volume
            :return: Details of volume if exist.
        """
        try:
            volume_details = []
            filter_field = {'id': vol_name_or_id}
            if filter_by_name:
                filter_field = {'name': vol_name_or_id}
            if is_remote:
                self.remote_powerflex_conn = utils.get_powerflex_gateway_host_connection(
                    self.module.params['remote_peer'])
                volume_details = self.remote_powerflex_conn.volume.get(
                    filter_fields=filter_field)
            else:
                volume_details = self.powerflex_conn.volume.get(
                    filter_fields=filter_field)

            if not volume_details:
                vol_type = 'Target' if is_remote else 'Source'
                self.module.fail_json("%s volume %s does not exist" % (vol_type, vol_name_or_id))
            return volume_details
        except Exception as e:
            errormsg = "Failed to retrieve volume {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_rcg(self, rcg_name=None, rcg_id=None):
        """Get rcg details
            :param rcg_name: Name of the rcg
            :param rcg_id: ID of the rcg
            :return: RCG details
        """
        name_or_id = rcg_id if rcg_id else rcg_name
        try:
            rcg_details = {}
            if rcg_id:
                rcg_details = self.powerflex_conn.replication_consistency_group.get(
                    filter_fields={'id': rcg_id})

            if rcg_name:
                rcg_details = self.powerflex_conn.replication_consistency_group.get(
                    filter_fields={'name': rcg_name})

            if not rcg_details:
                self.module.fail_json("RCG %s does not exist" % rcg_name)

            return rcg_details[0]
        except Exception as e:
            errormsg = "Failed to get the replication consistency group {0} with" \
                       " error {1}".format(name_or_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_rcg_replication_pairs(self, rcg_id):
        """Get rcg replication pair details
            :param rcg_id: ID of the rcg
            :return: RCG replication pair details
        """
        try:
            rcg_pairs = self.powerflex_conn.replication_consistency_group.get_replication_pairs(rcg_id)
            for rcg_pair in rcg_pairs:
                rcg_pair.pop('links', None)
                rcg_pair['localVolumeName'] = self.get_volume(rcg_pair['localVolumeId'], filter_by_name=False)[0]['name']
                rcg_pair['replicationConsistencyGroupName'] = self.get_rcg(rcg_id=rcg_pair['replicationConsistencyGroupId'])['name']
            return rcg_pairs
        except Exception as e:
            errormsg = "Failed to get the replication pairs for replication consistency group {0} with" \
                       " error {1}".format(rcg_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_replication_pairs(self, rcg_id, rcg_pairs, input_pairs):
        """Create replication pairs"""
        try:
            for pair in input_pairs:
                if pair['source_volume_name'] is not None:
                    pair['source_volume_id'] = self.get_volume(pair['source_volume_name'])[0]['id']
                if pair['target_volume_name'] is not None:
                    pair['target_volume_id'] = self.get_volume(pair['target_volume_name'], is_remote=True)[0]['id']
            pairs = find_non_existing_pairs(rcg_pairs, input_pairs)
            if not pairs:
                return False
            if not self.module.check_mode:
                for pair in pairs:
                    self.powerflex_conn.replication_pair.add(
                        source_vol_id=pair['source_volume_id'],
                        dest_vol_id=pair['target_volume_id'],
                        rcg_id=rcg_id,
                        copy_type=pair['copy_type'],
                        name=pair['name'])
            return True
        except Exception as e:
            errormsg = "Create replication pairs failed with error {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def pause(self, pair_id):
        """Pause replication pair
            :param pair_id: ID of the replication pair
            :return: True if paused
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_pair.pause(pair_id)
            return True
        except Exception as e:
            errormsg = "Pause replication pair {0} failed with error {1}".format(pair_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def resume(self, pair_id):
        """Resume replication pair
            :param pair_id: ID of the replication pair
            :return: True if resumed
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_pair.resume(pair_id)
            return True
        except Exception as e:
            errormsg = "Resume replication pair {0} failed with error {1}".format(pair_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_pair(self, pair_id):
        """Delete replication pair
            :param pair_id: Replication pair id.
            :return: Boolean indicates if delete pair operation is successful
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.replication_pair.remove(pair_id)
            return True

        except Exception as e:
            errormsg = "Delete replication pair {0} failed with " \
                       "error {1}".format(pair_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_input(self, params):
        if params['pairs'] is not None:
            self.validate_pairs(params)
            if not params['rcg_id'] and not params['rcg_name']:
                self.module.fail_json(msg="Specify either rcg_id or rcg_name to create replication pair")
        self.validate_pause(params)

    def validate_pairs(self, params):
        for pair in params['pairs']:
            if pair['source_volume_id'] and pair['source_volume_name']:
                self.module.fail_json(msg='Specify either source_volume_id or source_volume_name')
            if pair['target_volume_id'] and pair['target_volume_name']:
                self.module.fail_json(msg='Specify either target_volume_id or target_volume_name')
            if pair['target_volume_name'] and params['remote_peer'] is None:
                self.module.fail_json(msg='Specify remote_peer with target_volume_name')

    def validate_pause(self, params):
        if params['pause'] is not None and (not params['pair_id'] and not params['pair_name']):
            self.module.fail_json(msg='Specify either pair_id or pair_name to perform pause or resume of initial copy')

    def validate_pause_or_resume(self, pause, replication_pair_details, pair_id):
        if not replication_pair_details:
            self.module.fail_json(msg="Specify a valid pair_name or pair_id to perform pause or resume")
        return self.perform_pause_or_resume(pause, replication_pair_details, pair_id)

    def perform_pause_or_resume(self, pause, replication_pair_details, pair_id):
        changed = False
        if pause and replication_pair_details['initialCopyState'] not in ('Paused', 'Done'):
            changed = self.pause(pair_id)
        elif not pause and replication_pair_details['initialCopyState'] == 'Paused':
            changed = self.resume(pair_id)
        return changed

    def perform_module_operation(self):
        """
        Perform different actions on replication pair based on parameters passed in
        the playbook
        """
        self.validate_input(self.module.params)
        rcg_name = self.module.params['rcg_name']
        rcg_id = self.module.params['rcg_id']
        pair_name = self.module.params['pair_name']
        pair_id = self.module.params['pair_id']
        pairs = self.module.params['pairs']
        pause = self.module.params['pause']
        state = self.module.params['state']

        changed = False
        result = dict(
            changed=False,
            replication_pair_details=[],
            rcg_replication_pairs=[]
        )

        if pair_id or pair_name:
            result['replication_pair_details'] = self.get_replication_pair(pair_name, pair_id)
            if result['replication_pair_details']:
                pair_id = result['replication_pair_details']['id']
        if pairs:
            rcg_id = self.get_rcg(rcg_name, rcg_id)['id']
            result['rcg_replication_pairs'] = self.get_rcg_replication_pairs(rcg_id)
            changed = self.create_replication_pairs(rcg_id, result['rcg_replication_pairs'], pairs)
            if changed:
                result['rcg_replication_pairs'] = self.get_rcg_replication_pairs(rcg_id)
        if pause is not None:
            changed = self.validate_pause_or_resume(pause, result['replication_pair_details'], pair_id)
        if state == 'absent' and result['replication_pair_details']:
            changed = self.delete_pair(pair_id)
        if changed and (pair_id or pair_name):
            result['replication_pair_details'] = self.get_replication_pair(pair_name, pair_id)
        result['changed'] = changed
        self.module.exit_json(**result)


def find_non_existing_pairs(rcg_pairs, input_pairs):
    for pair in rcg_pairs:
        for input_pair in list(input_pairs):
            if input_pair['source_volume_id'] == pair['localVolumeId'] and \
                    input_pair['target_volume_id'] == pair['remoteVolumeId']:
                input_pairs.remove(input_pair)
    return input_pairs


def get_powerflex_replication_pair_parameters():
    """This method provide parameter required for the replication_consistency_group
    module on PowerFlex"""
    return dict(pair_id=dict(), pair_name=dict(), pause=dict(type='bool'),
                state=dict(choices=['absent', 'present'], default='present'), rcg_id=dict(), rcg_name=dict(),
                remote_peer=dict(type='dict',
                                 options=dict(hostname=dict(type='str', aliases=['gateway_host'], required=True),
                                              username=dict(type='str', required=True),
                                              password=dict(type='str', required=True, no_log=True),
                                              validate_certs=dict(type='bool', aliases=['verifycert'], default=True),
                                              port=dict(type='int', default=443),
                                              timeout=dict(type='int', default=120))),
                pairs=dict(
                type='list', elements='dict',
                options=dict(source_volume_name=dict(),
                             source_volume_id=dict(),
                             target_volume_name=dict(),
                             target_volume_id=dict(),
                             copy_type=dict(required=True, choices=['Identical', 'OnlineCopy', 'OnlineHashCopy', 'OfflineCopy']),
                             name=dict(),)
                ))


def main():
    """ Create PowerFlex Replication Consistency Group object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexReplicationPair()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
