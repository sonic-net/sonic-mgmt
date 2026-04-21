#!/usr/bin/python

# Copyright: (c) 2023-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing snapshot policies on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: snapshot_policy
version_added: '1.7.0'
short_description: Manage snapshot policies on Dell PowerFlex
description:
- Managing snapshot policies on PowerFlex storage system includes
  creating, getting details, modifying attributes, adding a source volume,
  removing a source volume and deleting a snapshot policy.
author:
- Trisha Datta (@trisha-dell) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  snapshot_policy_name:
    description:
    - The name of the snapshot policy.
    - It is unique across the PowerFlex array.
    - Mutually exclusive with I(snapshot_policy_id).
    type: str
  snapshot_policy_id:
    description:
    - The unique identifier of the snapshot policy.
    - Except create operation, all other operations can be performed
      using I(snapshot_policy_id).
    - Mutually exclusive with I(snapshot_policy_name).
    type: str
  auto_snapshot_creation_cadence:
    description:
    - The auto snapshot creation cadence of the snapshot policy.
    type: dict
    suboptions:
      time:
        description:
        - The time between creation of two snapshots.
        type: int
      unit:
        description:
        - The unit of the auto snapshot creation cadence.
        type: str
        choices: ["Minute", "Hour", "Day", "Week"]
        default: "Minute"
  num_of_retained_snapshots_per_level:
    description:
    - Number of retained snapshots per level.
    type: list
    elements: int
  new_name:
    description:
    - New name of the snapshot policy.
    type: str
  access_mode:
    description:
    - Access mode of the snapshot policy.
    choices: ['READ_WRITE', 'READ_ONLY']
    type: str
  secure_snapshots:
    description:
    - Whether to secure snapshots or not.
    - Used only in the create operation.
    type: bool
  source_volume:
    description:
    - The source volume details to be added or removed.
    type: list
    elements: dict
    suboptions:
      id:
        description:
        - The unique identifier of the source volume
          to be added or removed.
        - Mutually exclusive with I(name).
        type: str
      name:
        description:
        - The name of the source volume to be added or removed.
        - Mutually exclusive with I(id).
        type: str
      auto_snap_removal_action:
        description:
        - Ways to handle the snapshots created by the policy (auto snapshots).
        - Must be provided when I(state) is set to C('absent').
        choices: ['Remove', 'Detach']
        type: str
      detach_locked_auto_snapshots:
        description:
        - Whether to detach the locked auto snapshots during removal of source volume.
        type: bool
      state:
        description:
        - The state of the source volume.
        - When C(present), source volume will be added to the snapshot policy.
        - When C(absent), source volume will be removed from the snapshot policy.
        type: str
        choices: ['present', 'absent']
        default: 'present'
  pause:
    description:
    - Whether to pause or resume the snapshot policy.
    type: bool
  state:
    description:
    - State of the snapshot policy.
    choices: ['present', 'absent']
    default: 'present'
    type: str
notes:
  - The I(check_mode) is supported.
'''

EXAMPLES = r'''
- name: Create a snapshot policy
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "snapshot_policy_name_1"
    access_mode: "READ_WRITE"
    secure_snapshots: false
    auto_snapshot_creation_cadence:
      time: 1
      unit: "Hour"
    num_of_retained_snapshots_per_level:
      - 20
    state: "present"

- name: Get snapshot policy details using name
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "snapshot_policy_name_1"

- name: Get snapshot policy details using id
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_id: "snapshot_policy_id_1"

- name: Modify a snapshot policy
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "snapshot_policy_name_1"
    auto_snapshot_creation_cadence:
      time: 2
      unit: "Hour"
    num_of_retained_snapshots_per_level:
      - 40

- name: Rename a snapshot policy
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "snapshot_policy_name_1"
    new_name: "snapshot_policy_name_1_new"

- name: Add source volume
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "snapshot_policy_name_1"
    source_volume:
      - name: "source_volume_name_1"
      - id: "source_volume_id_2"
        state: "present"

- name: Remove source volume
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "{{snapshot_policy_name}}"
    source_volume:
      - name: "source_volume_name_1"
        auto_snap_removal_action: 'Remove'
        state: "absent"
      - id: "source_volume_id_2"
        auto_snap_removal_action: 'Remove'
        detach_locked_auto_snapshots: true
        state: "absent"

- name: Pause a snapshot policy
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "{{snapshot_policy_name}}"
    pause: true

- name: Resume a snapshot policy
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "{{snapshot_policy_name}}"
    pause: false

- name: Delete a snapshot policy
  dellemc.powerflex.snapshot_policy:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_policy_name: "snapshot_policy_name"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
snapshot_policy_details:
    description: Details of the snapshot policy.
    returned: When snapshot policy exists
    type: dict
    contains:
        autoSnapshotCreationCadenceInMin:
            description: The snapshot rule of the snapshot policy.
            type: int
        id:
            description: The ID of the snapshot policy.
            type: str
        lastAutoSnapshotCreationFailureReason:
            description: The reason for the failure of last auto snapshot creation .
            type: str
        name:
            description: Name of the snapshot policy.
            type: str
        lastAutoSnapshotFailureInFirstLevel:
            description: Whether the last auto snapshot in first level failed.
            type: bool
        maxVTreeAutoSnapshots:
            description: Maximum number of VTree auto snapshots.
            type: int
        nextAutoSnapshotCreationTime:
            description: The time of creation of the next auto snapshot.
            type: int
        numOfAutoSnapshots:
            description: Number of auto snapshots.
            type: int
        numOfCreationFailures:
            description: Number of creation failures.
            type: int
        numOfExpiredButLockedSnapshots:
            description: Number of expired but locked snapshots.
            type: int
        numOfLockedSnapshots:
            description: Number of locked snapshots.
            type: int
        numOfRetainedSnapshotsPerLevel:
            description: Number of snapshots retained per level
            type: list
        numOfSourceVolumes:
            description: Number of source volumes.
            type: int
        secureSnapshots:
            description: Whether the snapshots are secured.
            type: bool
        snapshotAccessMode:
            description: Access mode of the snapshots.
            type: str
        snapshotPolicyState:
            description: State of the snapshot policy.
            type: str
        systemId:
            description: Unique identifier of the PowerFlex system.
            type: str
        timeOfLastAutoSnapshot:
            description: Time of the last auto snapshot creation.
            type: str
        timeOfLastAutoSnapshotCreationFailure:
            description: Time of the failure of the last auto snapshot creation.
            type: str
        statistics:
            description: Statistics details of the snapshot policy.
            type: dict
            contains:
                autoSnapshotVolIds:
                    description: Volume Ids of all the auto snapshots.
                    type: list
                expiredButLockedSnapshotsIds:
                    description: Ids of expired but locked snapshots.
                    type: list
                numOfAutoSnapshots:
                    description: Number of auto snapshots.
                    type: int
                numOfExpiredButLockedSnapshots:
                    description: Number of expired but locked snapshots.
                    type: int
                numOfSrcVols:
                    description: Number of source volumes.
                    type: int
                srcVolIds:
                    description: Ids of the source volumes.
                    type: list

    sample: {
        "autoSnapshotCreationCadenceInMin": 120,
        "id": "15ae842800000004",
        "lastAutoSnapshotCreationFailureReason": "NR",
        "lastAutoSnapshotFailureInFirstLevel": false,
        "links": [
            {
                "href": "/api/instances/SnapshotPolicy::15ae842800000004",
                "rel": "self"
            },
            {
                "href": "/api/instances/SnapshotPolicy::15ae842800000004/relationships/Statistics",
                "rel": "/api/SnapshotPolicy/relationship/Statistics"
            },
            {
                "href": "/api/instances/SnapshotPolicy::15ae842800000004/relationships/SourceVolume",
                "rel": "/api/SnapshotPolicy/relationship/SourceVolume"
            },
            {
                "href": "/api/instances/SnapshotPolicy::15ae842800000004/relationships/AutoSnapshotVolume",
                "rel": "/api/SnapshotPolicy/relationship/AutoSnapshotVolume"
            },
            {
                "href": "/api/instances/System::0e7a082862fedf0f",
                "rel": "/api/parent/relationship/systemId"
            }
        ],
        "maxVTreeAutoSnapshots": 40,
        "name": "Sample_snapshot_policy_1",
        "nextAutoSnapshotCreationTime": 1683709201,
        "numOfAutoSnapshots": 0,
        "numOfCreationFailures": 0,
        "numOfExpiredButLockedSnapshots": 0,
        "numOfLockedSnapshots": 0,
        "numOfRetainedSnapshotsPerLevel": [
            40
        ],
        "numOfSourceVolumes": 0,
        "secureSnapshots": false,
        "snapshotAccessMode": "ReadWrite",
        "snapshotPolicyState": "Active",
        "statistics": {
            "autoSnapshotVolIds": [],
            "expiredButLockedSnapshotsIds": [],
            "numOfAutoSnapshots": 0,
            "numOfExpiredButLockedSnapshots": 0,
            "numOfSrcVols": 0,
            "srcVolIds": []
        },
        "systemId": "0e7a082862fedf0f",
        "timeOfLastAutoSnapshot": 0,
        "timeOfLastAutoSnapshotCreationFailure": 0
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('snapshot_policy')


class PowerFlexSnapshotPolicy(object):
    """Class with snapshot policies operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_snapshot_policy_parameters())

        mut_ex_args = [['snapshot_policy_name', 'snapshot_policy_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=True,
            mutually_exclusive=mut_ex_args)

        utils.ensure_required_libs(self.module)

        self.result = dict(
            changed=False,
            snapshot_policy_details={}
        )

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_snapshot_policy(self, snap_pol_id=None, snap_pol_name=None):
        """Get snapshot policy details
            :param snap_pol_name: Name of the snapshot policy.
            :param snap_pol_id: ID of the snapshot policy.
            :return: snapshot policy details
        """
        try:
            snap_pol_details = None
            if snap_pol_id:
                snap_pol_details = self.powerflex_conn.snapshot_policy.get(
                    filter_fields={'id': snap_pol_id})

            if snap_pol_name:
                snap_pol_details = self.powerflex_conn.snapshot_policy.get(
                    filter_fields={'name': snap_pol_name})

            if not snap_pol_details:
                msg = "Unable to find the snapshot policy."
                LOG.info(msg)
                return None

            # Append statistics
            statistics = self.powerflex_conn.snapshot_policy.get_statistics(snap_pol_details[0]['id'])
            snap_pol_details[0]['statistics'] = statistics if statistics else {}
            return snap_pol_details[0]

        except Exception as e:
            errormsg = f'Failed to get the snapshot policy with error {str(e)}'
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_snapshot_policy(self, auto_snapshot_creation_cadence_in_min, num_of_retained_snapshots_per_level,
                               access_mode, secure_snapshots, snapshot_policy_name=None):
        """Create snapshot_policy
            :param auto_snapshot_creation_cadence_in_min: The auto snapshot creation cadence of the snapshot policy.
            :param num_of_retained_snapshots_per_level: Number of retained snapshots per level.
            :param access_mode: Access mode of the snapshot policy.
            :param secure_snapshots: Whether to secure snapshots or not.
            :param snapshot_policy_name: Name of the snapshot policy.
            :return: Id of the snapshot policy, if created.
        """
        try:
            if not self.module.check_mode:
                policy_id = self.powerflex_conn.snapshot_policy.create(
                    auto_snap_creation_cadence_in_min=auto_snapshot_creation_cadence_in_min,
                    retained_snaps_per_level=num_of_retained_snapshots_per_level, name=snapshot_policy_name,
                    snapshot_access_mode=access_mode, secure_snapshots=secure_snapshots)
                return policy_id

        except Exception as e:
            errormsg = f'Creation of snapshot policy failed with error {str(e)}'
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_snapshot_policy(self, snap_pol_id):
        """Delete snapshot policy
            :param snap_pol_id: The unique identifier of the snapshot policy.
            :return: Details of the snapshot policy.
        """

        try:
            if not self.module.check_mode:
                self.powerflex_conn.snapshot_policy.delete(snap_pol_id)
            return self.get_snapshot_policy(snap_pol_id=snap_pol_id)

        except Exception as e:
            errormsg = (f'Deletion of snapshot policy {snap_pol_id} '
                        f'failed with error {str(e)}')
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_volume(self, vol_name=None, vol_id=None):
        """Get volume details
            :param vol_name: Name of the volume
            :param vol_id: ID of the volume
            :return: Details of volume if exist.
        """

        id_or_name = vol_id if vol_id else vol_name

        try:
            if vol_name:
                volume_details = self.powerflex_conn.volume.get(
                    filter_fields={'name': vol_name})
            else:
                volume_details = self.powerflex_conn.volume.get(
                    filter_fields={'id': vol_id})

            if len(volume_details) == 0:
                error_msg = f"Volume with identifier {id_or_name} not found"
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            # Append snapshot policy name and id
            if volume_details[0]['snplIdOfSourceVolume'] is not None:
                snap_policy_id = volume_details[0]['snplIdOfSourceVolume']
                volume_details[0]['snapshotPolicyId'] = snap_policy_id
                volume_details[0]['snapshotPolicyName'] = \
                    self.get_snapshot_policy(snap_policy_id)['name']

            return volume_details[0]

        except Exception as e:
            error_msg = (f"Failed to get the volume {id_or_name}"
                         f" with error {str(e)}")
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def manage_source_volume(self, snap_pol_details, vol_details, source_volume_element):
        """Adding or removing a source volume
            :param snap_pol_details: Details of the snapshot policy details.
            :param vol_details: Details of the volume.
            :param source_volume_element: The index of the source volume in the
                                          list of volumes to be added/removed.
            :return: Boolean indicating whether volume is added/removed.
        """
        try:
            if self.module.params['source_volume'][source_volume_element]['state'] == 'present' and \
                    vol_details['snplIdOfSourceVolume'] != snap_pol_details['id']:
                if not self.module.check_mode:
                    snap_pol_details = self.powerflex_conn.snapshot_policy.add_source_volume(
                        snapshot_policy_id=snap_pol_details['id'],
                        volume_id=vol_details['id'])
                    LOG.info("Source volume successfully added")
                return True

            elif self.module.params['source_volume'][source_volume_element]['state'] == 'absent' and \
                    vol_details['snplIdOfSourceVolume'] == snap_pol_details['id']:
                if not self.module.check_mode:
                    snap_pol_details = self.powerflex_conn.snapshot_policy.remove_source_volume(
                        snapshot_policy_id=snap_pol_details['id'],
                        volume_id=vol_details['id'],
                        auto_snap_removal_action=self.module.params['source_volume'][source_volume_element]['auto_snap_removal_action'],
                        detach_locked_auto_snaps=self.module.params['source_volume'][source_volume_element]['detach_locked_auto_snapshots'])
                    LOG.info("Source volume successfully removed")
                return True

        except Exception as e:
            error_msg = f"Failed to manage the source volume {vol_details['id']} with error {str(e)}"
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def pause_snapshot_policy(self, snap_pol_details):
        """Pausing or resuming a snapshot policy.
            :param snap_pol_details: Details of the snapshot policy details.
            :return: Boolean indicating whether snapshot policy is paused/removed or not.
        """
        try:
            if self.module.params['pause'] and \
                    snap_pol_details['snapshotPolicyState'] != "Paused":
                if not self.module.check_mode:
                    self.powerflex_conn.snapshot_policy.pause(
                        snapshot_policy_id=snap_pol_details['id'])
                    LOG.info("Snapshot policy successfully paused.")
                return True

            elif not self.module.params['pause'] and \
                    snap_pol_details['snapshotPolicyState'] == "Paused":
                if not self.module.check_mode:
                    self.powerflex_conn.snapshot_policy.resume(
                        snapshot_policy_id=snap_pol_details['id'])
                    LOG.info("Snapshot policy successfully resumed.")
                return True

        except Exception as e:
            error_msg = f"Failed to pause/resume {snap_pol_details['id']} with error {str(e)}"
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def to_modify(self, snap_pol_details, auto_snapshot_creation_cadence_in_min, num_of_retained_snapshots_per_level, new_name):
        """Whether to modify the snapshot policy or not
        :param snap_pol_details: Details of the snapshot policy.
        :param auto_snapshot_creation_cadence_in_min: Snapshot rule of the policy.
        :param num_of_retained_snapshots_per_level: Retention rule of the policy.
        :param new_name: The new name of the snapshot policy.
        :return: Dictionary containing the attributes of
         snapshot policy which are to be updated
        """
        modify_dict = {}

        if self.module_params['auto_snapshot_creation_cadence'] is not None and \
                snap_pol_details['autoSnapshotCreationCadenceInMin'] != auto_snapshot_creation_cadence_in_min:
            modify_dict['auto_snapshot_creation_cadence_in_min'] = auto_snapshot_creation_cadence_in_min

        if num_of_retained_snapshots_per_level is not None and \
                snap_pol_details['numOfRetainedSnapshotsPerLevel'] != num_of_retained_snapshots_per_level:
            modify_dict['num_of_retained_snapshots_per_level'] = num_of_retained_snapshots_per_level

        if new_name is not None:
            if len(new_name.strip()) == 0:
                self.module.fail_json(
                    msg="Provide valid volume name.")
            if new_name != snap_pol_details['name']:
                modify_dict['new_name'] = new_name

        return modify_dict

    def modify_snapshot_policy(self, snap_pol_details, modify_dict):
        """
        Modify the snapshot policy attributes
        :param snap_pol_details: Details of the snapshot policy
        :param modify_dict: Dictionary containing the attributes of
         snapshot policy which are to be updated
        :return: True, if the operation is successful
        """
        try:
            msg = (f"Dictionary containing attributes which are to be"
                   f" updated is {str(modify_dict)}.")
            LOG.info(msg)
            if not self.module.check_mode:
                if 'new_name' in modify_dict:
                    self.powerflex_conn.snapshot_policy.rename(snap_pol_details['id'],
                                                               modify_dict['new_name'])
                    msg = (f"The name of the volume is updated"
                           f" to {modify_dict['new_name']} sucessfully.")
                    LOG.info(msg)

                if 'auto_snapshot_creation_cadence_in_min' in modify_dict and \
                        'num_of_retained_snapshots_per_level' not in modify_dict:
                    self.powerflex_conn.snapshot_policy.modify(
                        snapshot_policy_id=snap_pol_details['id'],
                        auto_snap_creation_cadence_in_min=modify_dict['auto_snapshot_creation_cadence_in_min'],
                        retained_snaps_per_level=snap_pol_details['numOfRetainedSnapshotsPerLevel'])
                    msg = f"The snapshot rule is updated to {modify_dict['auto_snapshot_creation_cadence_in_min']}"
                    LOG.info(msg)

                elif 'auto_snapshot_creation_cadence_in_min' not in modify_dict and 'num_of_retained_snapshots_per_level' in modify_dict:
                    self.powerflex_conn.snapshot_policy.modify(
                        snapshot_policy_id=snap_pol_details['id'],
                        auto_snap_creation_cadence_in_min=snap_pol_details['autoSnapshotCreationCadenceInMin'],
                        retained_snaps_per_level=modify_dict['num_of_retained_snapshots_per_level'])
                    msg = f"The retention rule is updated to {modify_dict['num_of_retained_snapshots_per_level']}"
                    LOG.info(msg)

                elif 'auto_snapshot_creation_cadence_in_min' in modify_dict and 'num_of_retained_snapshots_per_level' in modify_dict:
                    self.powerflex_conn.snapshot_policy.modify(
                        snapshot_policy_id=snap_pol_details['id'],
                        auto_snap_creation_cadence_in_min=modify_dict['auto_snapshot_creation_cadence_in_min'],
                        retained_snaps_per_level=modify_dict['num_of_retained_snapshots_per_level'])
                    msg = (f"The snapshot rule is updated to {modify_dict['auto_snapshot_creation_cadence_in_min']}"
                           f" and the retention rule is updated to {modify_dict['num_of_retained_snapshots_per_level']}")
                    LOG.info(msg)

            return True

        except Exception as e:
            err_msg = (f"Failed to update the snapshot policy {snap_pol_details['id']}"
                       f" with error {str(e)}")
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)


def get_access_mode(access_mode):
    """
    :param access_mode: Access mode of the snapshot policy
    :return: The enum for the access mode
    """

    access_mode_dict = {
        "READ_WRITE": "ReadWrite",
        "READ_ONLY": "ReadOnly"
    }
    return access_mode_dict.get(access_mode)


def get_powerflex_snapshot_policy_parameters():
    """This method provide parameter required for the snapshot
    policy module on PowerFlex"""
    return dict(
        snapshot_policy_name=dict(), snapshot_policy_id=dict(),
        new_name=dict(),
        access_mode=dict(choices=['READ_WRITE', 'READ_ONLY']),
        secure_snapshots=dict(type='bool'),
        auto_snapshot_creation_cadence=dict(type='dict', options=dict(
            time=dict(type='int'),
            unit=dict(choices=['Minute', 'Hour', 'Day', 'Week'],
                      default='Minute'))),
        num_of_retained_snapshots_per_level=dict(type='list', elements='int'),
        source_volume=dict(type='list', elements='dict', options=dict(
            id=dict(), name=dict(),
            auto_snap_removal_action=dict(choices=['Remove', 'Detach']),
            detach_locked_auto_snapshots=dict(type='bool'),
            state=dict(default='present', choices=['present', 'absent']))),
        pause=dict(type='bool'),
        state=dict(default='present', choices=['present', 'absent'])
    )


class SnapshotPolicyCreateHandler():
    def handle(self, con_object, con_params, snapshot_policy_details, access_mode, auto_snapshot_creation_cadence_in_min):
        if con_params['state'] == 'present' and not snapshot_policy_details:
            if con_params['snapshot_policy_id']:
                con_object.module.fail_json(msg="Creation of snapshot "
                                                "policy is allowed "
                                                "using snapshot_policy_name only, "
                                                "snapshot_policy_id given.")

            snap_pol_id = con_object.create_snapshot_policy(snapshot_policy_name=con_params['snapshot_policy_name'],
                                                            access_mode=access_mode,
                                                            secure_snapshots=con_params['secure_snapshots'],
                                                            auto_snapshot_creation_cadence_in_min=auto_snapshot_creation_cadence_in_min,
                                                            num_of_retained_snapshots_per_level=con_params['num_of_retained_snapshots_per_level'])
            con_object.result['changed'] = True
            if snap_pol_id:
                snapshot_policy_details = con_object.get_snapshot_policy(snap_pol_name=con_params['snapshot_policy_name'],
                                                                         snap_pol_id=con_params['snapshot_policy_id'])

                msg = (f"snapshot policy created successfully, fetched "
                       f"snapshot_policy details {str(snapshot_policy_details)}")
                LOG.info(msg)

        SnapshotPolicyModifyHandler().handle(con_object, con_params, snapshot_policy_details,
                                             auto_snapshot_creation_cadence_in_min)


class SnapshotPolicyModifyHandler():
    def handle(self, con_object, con_params, snapshot_policy_details, auto_snapshot_creation_cadence_in_min):
        modify_dict = {}
        if con_params['state'] == 'present' and snapshot_policy_details:
            modify_dict = con_object.to_modify(
                snap_pol_details=snapshot_policy_details, new_name=con_params['new_name'],
                auto_snapshot_creation_cadence_in_min=auto_snapshot_creation_cadence_in_min,
                num_of_retained_snapshots_per_level=con_params['num_of_retained_snapshots_per_level'])
            msg = (f"Parameters to be modified are as"
                   f" follows: {str(modify_dict)}")
            LOG.info(msg)
        if modify_dict and con_params['state'] == 'present':
            con_object.result['changed'] = con_object.modify_snapshot_policy(snap_pol_details=snapshot_policy_details,
                                                                             modify_dict=modify_dict)
            snapshot_policy_details = con_object.get_snapshot_policy(snap_pol_id=snapshot_policy_details.get("id"))
        SnapshotPolicySourceVolumeHandler().handle(con_object, con_params, snapshot_policy_details)


class SnapshotPolicySourceVolumeHandler():
    def handle(self, con_object, con_params, snapshot_policy_details):
        if snapshot_policy_details and con_params['state'] == 'present' and con_params['source_volume'] is not None:
            for source_volume_element in range(len(con_params['source_volume'])):
                if not (con_params['source_volume'][source_volume_element]['id'] or
                        con_params['source_volume'][source_volume_element]['name']):
                    con_object.module.fail_json(
                        msg="Either id or name of source volume needs to be "
                            "passed with state of source volume")

                elif con_params['source_volume'][source_volume_element]['id'] and \
                        con_params['source_volume'][source_volume_element]['name']:
                    con_object.module.fail_json(
                        msg="id and name of source volume are mutually exclusive")

                elif con_params['source_volume'][source_volume_element]['id'] or \
                        con_params['source_volume'][source_volume_element]['name']:
                    volume_details = con_object.get_volume(vol_id=con_params['source_volume'][source_volume_element]['id'],
                                                           vol_name=con_params['source_volume'][source_volume_element]['name'])
                    con_object.result['changed'] = con_object.manage_source_volume(snap_pol_details=snapshot_policy_details,
                                                                                   vol_details=volume_details,
                                                                                   source_volume_element=source_volume_element)
                    snapshot_policy_details = con_object.get_snapshot_policy(snap_pol_name=con_params['snapshot_policy_name'],
                                                                             snap_pol_id=con_params['snapshot_policy_id'])

        SnapshotPolicyPauseHandler().handle(con_object, con_params, snapshot_policy_details)


class SnapshotPolicyPauseHandler():
    def handle(self, con_object, con_params, snapshot_policy_details):
        if con_params["state"] == "present" and con_params["pause"] is not None:
            con_object.result['changed'] = \
                con_object.pause_snapshot_policy(snap_pol_details=snapshot_policy_details)
            snapshot_policy_details = \
                con_object.get_snapshot_policy(snap_pol_name=con_params['snapshot_policy_name'],
                                               snap_pol_id=con_params['snapshot_policy_id'])
        SnapshotPolicyDeleteHandler().handle(con_object, con_params, snapshot_policy_details)


class SnapshotPolicyDeleteHandler():
    def handle(self, con_object, con_params, snapshot_policy_details):
        if con_params['state'] == 'absent' and snapshot_policy_details:
            snapshot_policy_details = con_object.delete_snapshot_policy(
                snap_pol_id=snapshot_policy_details.get("id"))
            con_object.result['changed'] = True
        SnapshotPolicyExitHandler().handle(con_object, snapshot_policy_details)


class SnapshotPolicyExitHandler():
    def handle(self, con_object, snapshot_policy_details):
        con_object.result['snapshot_policy_details'] = snapshot_policy_details
        con_object.module.exit_json(**con_object.result)


class SnapshotPolicyHandler():
    def handle(self, con_object, con_params):
        access_mode = get_access_mode(con_params['access_mode'])
        snapshot_policy_details = con_object.get_snapshot_policy(snap_pol_name=con_params['snapshot_policy_name'],
                                                                 snap_pol_id=con_params['snapshot_policy_id'])
        auto_snapshot_creation_cadence_in_min = None
        if snapshot_policy_details:
            auto_snapshot_creation_cadence_in_min = snapshot_policy_details['autoSnapshotCreationCadenceInMin']
        msg = f"Fetched the snapshot policy details {str(snapshot_policy_details)}"
        LOG.info(msg)
        if con_params['auto_snapshot_creation_cadence'] is not None:
            auto_snapshot_creation_cadence_in_min = utils.get_time_minutes(time=con_params['auto_snapshot_creation_cadence']['time'],
                                                                           time_unit=con_params['auto_snapshot_creation_cadence']['unit'])
        SnapshotPolicyCreateHandler().handle(con_object, con_params, snapshot_policy_details,
                                             access_mode, auto_snapshot_creation_cadence_in_min)


def main():
    """ Create PowerFlex snapshot policy object and perform action on it
        based on user input from playbook"""
    obj = PowerFlexSnapshotPolicy()
    SnapshotPolicyHandler().handle(obj, obj.module.params)


if __name__ == '__main__':
    main()
