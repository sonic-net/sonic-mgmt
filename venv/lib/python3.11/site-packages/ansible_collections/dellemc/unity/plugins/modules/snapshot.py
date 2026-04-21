#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing Snapshots on Unity"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: snapshot
short_description: Manage snapshots on the Unity storage system
description:
- Managing snapshots on the Unity storage system includes create snapshot,
  delete snapshot, update snapshot, get snapshot, map host and unmap host.
version_added: '1.1.0'

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- P Srinivas Rao (@srinivas-rao5) <ansible.team@dell.com>
options:
  snapshot_name:
    description:
    - The name of the snapshot.
    - Mandatory parameter for creating a snapshot.
    - For all other operations either I(snapshot_name) or I(snapshot_id) is
      required.
    type: str
  vol_name:
    description:
    - The name of the volume for which snapshot is created.
    - For creation of a snapshot either I(vol_name) or I(cg_name) is required.
    - Not required for other operations.
    type: str
  cg_name:
    description:
    - The name of the Consistency Group for which snapshot is created.
    - For creation of a snapshot either I(vol_name) or I(cg_name) is required.
    - Not required for other operations.
    type: str
  snapshot_id:
    description:
    - The id of the snapshot.
    - For all operations other than creation either I(snapshot_name) or
      I(snapshot_id) is required.
    type: str
  auto_delete:
    description:
    - This option specifies whether the snapshot is auto deleted or not.
    - If set to C(true), snapshot will expire based on the pool auto deletion
      policy.
    - If set to (false), snapshot will not be auto deleted
      based on the pool auto deletion policy.
    - Option I(auto_delete) can not be set to C(true), if I(expiry_time) is specified.
    - If during creation neither I(auto_delete) nor I(expiry_time) is mentioned
      then snapshot will be created keeping I(auto_delete) as C(true).
    - Once the I(expiry_time) is set then snapshot cannot be assigned
      to the auto delete policy.
    type: bool
  expiry_time:
    description:
    - This option is for specifying the date and time after which the
      snapshot will expire.
    - The time is to be mentioned in UTC timezone.
    - The format is "MM/DD/YYYY HH:MM". Year must be in 4 digits.
    type: str
  description:
    description:
    - The additional information about the snapshot can be provided using
      this option.
    type: str
  new_snapshot_name:
    description:
    - New name for the snapshot.
    type: str
  state:
    description:
    - The I(state) option is used to mention the existence of
      the snapshot.
    type: str
    required: true
    choices: [ 'absent', 'present' ]
  host_name:
    description:
    - The name of the host.
    - Either I(host_name) or I(host_id) is required to map or unmap a snapshot from
      a host.
    - Snapshot can be attached to multiple hosts.
    type: str
  host_id:
    description:
    - The id of the host.
    - Either I(host_name) or I(host_id) is required to map or unmap a snapshot from
      a host.
    - Snapshot can be attached to multiple hosts.
    type: str
  host_state:
    description:
    - The I(host_state) option is used to mention the existence of the host
      for snapshot.
    - It is required when a snapshot is mapped or unmapped from host.
    type: str
    choices: ['mapped', 'unmapped']

notes:
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create a Snapshot for a CG
  snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    cg_name: "{{cg_name}}"
    snapshot_name: "{{cg_snapshot_name}}"
    description: "{{description}}"
    auto_delete: false
    state: "present"

- name: Create a Snapshot for a volume with Host attached
  snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    vol_name: "{{vol_name}}"
    snapshot_name: "{{vol_snapshot_name}}"
    description: "{{description}}"
    expiry_time: "04/15/2025 16:30"
    host_name: "{{host_name}}"
    host_state: "mapped"
    state: "present"

- name: Unmap a host for a Snapshot
  snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    snapshot_name: "{{vol_snapshot_name}}"
    host_name: "{{host_name}}"
    host_state: "unmapped"
    state: "present"

- name: Map snapshot to a host
  snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    snapshot_name: "{{vol_snapshot_name}}"
    host_name: "{{host_name}}"
    host_state: "mapped"
    state: "present"

- name: Update attributes of a Snapshot for a volume
  snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "{{vol_snapshot_name}}"
    new_snapshot_name: "{{new_snapshot_name}}"
    description: "{{new_description}}"
    host_name: "{{host_name}}"
    host_state: "unmapped"
    state: "present"

- name: Delete Snapshot of CG
  snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "{{cg_snapshot_name}}"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: True

snapshot_details:
    description: Details of the snapshot.
    returned: When snapshot exists
    type: dict
    contains:
        is_auto_delete:
            description: Additional information mentioned for snapshot.
            type: str
        expiration_time:
            description: Date and time after which the snapshot
                         will expire.
            type: str
        hosts_list:
            description: Contains the name and id of the associated
                         hosts.
            type: dict
        id:
            description: Unique identifier of the snapshot instance.
            type: str
        name:
            description: The name of the snapshot.
            type: str
        storage_resource_name:
            description: Name of the storage resource for which the
                         snapshot exists.
            type: str
        storage_resource_id:
            description: Id of the storage resource for which the snapshot
                         exists.
            type: str
    sample: {
        "access_type": null,
        "attached_wwn": null,
        "creation_time": "2022-10-21 08:20:25.803000+00:00",
        "creator_schedule": null,
        "creator_type": "SnapCreatorTypeEnum.USER_CUSTOM",
        "creator_user": {
            "id": "user_admin"
        },
        "description": "Test snap creation",
        "existed": true,
        "expiration_time": null,
        "hash": 8756689457056,
        "hosts_list": [],
        "id": "85899355291",
        "io_limit_policy": null,
        "is_auto_delete": true,
        "is_modifiable": false,
        "is_modified": false,
        "is_read_only": true,
        "is_system_snap": false,
        "last_writable_time": null,
        "lun": null,
        "name": "ansible_snap_cg_1_1",
        "parent_snap": null,
        "size": null,
        "snap_group": null,
        "state": "SnapStateEnum.READY",
        "storage_resource_id": "res_95",
        "storage_resource_name": "CG_ansible_test_2_new"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils
from datetime import datetime

LOG = utils.get_logger('snapshot')

application_type = "Ansible/1.7.1"


class Snapshot(object):
    """Class with Snapshot operations"""

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_snapshot_parameters())

        mutually_exclusive = [['snapshot_name', 'snapshot_id'],
                              ['vol_name', 'cg_name'],
                              ['host_name', 'host_id']]

        required_one_of = [['snapshot_name', 'snapshot_id']]
        # initialize the ansible module
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=False,
                                    mutually_exclusive=mutually_exclusive,
                                    required_one_of=required_one_of)
        utils.ensure_required_libs(self.module)

        # result is a dictionary that contains changed status and
        # snapshot details
        self.result = {"changed": False,
                       'snapshot_details': {}}

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        self.snap_obj = utils.snap.UnitySnap(self.unity_conn)
        LOG.info('Connection established with the Unity Array')

    def validate_expiry_time(self, expiry_time):
        """Validates the specified expiry_time"""
        try:
            datetime.strptime(expiry_time, '%m/%d/%Y %H:%M')
        except ValueError:
            error_msg = "expiry_time not in MM/DD/YYYY HH:MM format"
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def to_update(self, snapshot, new_name=None, description=None,
                  auto_del=None, expiry_time=None, host=None,
                  host_state=None):
        """Determines whether to update the snapshot or not"""
        # If the snapshot has is_auto_delete True,
        # Check if auto_delete in the input is either None or True
        if expiry_time and snapshot.is_auto_delete and \
                (auto_del is None or auto_del):
            self.module.fail_json(msg="expiry_time can be assigned "
                                      "when auto delete is False")
        if auto_del and snapshot.expiration_time:
            error_msg = "expiry_time for snapshot is set." \
                        " Once it is set then snapshot cannot" \
                        " be assigned to auto_delete policy"
            self.module.fail_json(msg=error_msg)
        if new_name and new_name != snapshot.name:
            return True
        if description and description != snapshot.description:
            return True
        if auto_del and auto_del != snapshot.is_auto_delete:
            return True
        if to_update_expiry_time(snapshot, expiry_time):
            return True
        if host and to_update_host_list(snapshot, host, host_state):
            return True
        return False

    def update_snapshot(self, snapshot, new_name=None,
                        description=None, auto_del=None, expiry_time=None,
                        host_access_list=None):
        try:
            duration = None
            if expiry_time:
                duration = convert_timestamp_to_sec(
                    expiry_time, self.unity_conn.system_time)
            if duration and duration <= 0:
                self.module.fail_json(msg="expiry_time should be after"
                                          " the current system time")
            snapshot.modify(name=new_name, retentionDuration=duration,
                            isAutoDelete=auto_del, description=description,
                            hostAccess=host_access_list)
            snapshot.update()
        except Exception as e:
            error_msg = "Failed to modify snapshot" \
                        " [name: %s , id: %s] with error %s"\
                        % (snapshot.name, snapshot.id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def create_snapshot(self, snap_name, storage_id, description=None,
                        auto_del=None, expiry_time=None):
        try:
            duration = None
            if expiry_time:
                duration = convert_timestamp_to_sec(
                    expiry_time, self.unity_conn.system_time)
                if duration <= 0:
                    self.module.fail_json(msg="expiry_time should be after"
                                          " the current system time")
            snapshot = self.snap_obj.create(
                cli=self.unity_conn._cli, storage_resource=storage_id,
                name=snap_name, description=description,
                is_auto_delete=auto_del, retention_duration=duration)
            return snapshot
        except Exception as e:
            error_msg = "Failed to create snapshot" \
                        " %s with error %s" % (snap_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def delete_snapshot(self, snapshot):
        try:
            if not bool(get_hosts_dict(snapshot)):
                snapshot.detach_from(None)
                snapshot.delete()
            else:
                snapshot.delete()
            return None

        except Exception as e:
            error_msg = "Failed to delete snapshot" \
                        " [name: %s, id: %s] with error %s" \
                        % (snapshot.name, snapshot.id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_snapshot_obj(self, name=None, id=None):
        snapshot = id if id else name
        msg = "Failed to get details of snapshot %s with error %s "
        try:
            return self.unity_conn.get_snap(name=name, _id=id)

        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = "Incorrect username or password , {0}".format(
                    e.message)
                self.module.fail_json(msg=cred_err)
            else:
                err_msg = msg % (snapshot, str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

        except utils.UnityResourceNotFoundError as e:
            err_msg = msg % (snapshot, str(e))
            LOG.error(err_msg)
            return None

        except Exception as e:
            err_msg = msg % (snapshot, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def get_volume_obj(self, name):
        try:
            return self.unity_conn.get_lun(name=name)
        except Exception as e:
            error_msg = "Failed to get volume %s with error %s"\
                        % (name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_cg_obj(self, name):
        try:
            return self.unity_conn.get_cg(name=name)
        except Exception as e:
            error_msg = "Failed to get cg %s with error %s" % (name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_host_obj(self, name=None, id=None):
        """ Get the Host object"""
        try:
            return self.unity_conn.get_host(name=name, _id=id)
        except Exception as e:
            host = id if id else name
            error_msg = "Failed to get host %s with error %s"\
                        % (host, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def attach_to_snap(self, snapshot, host):
        """ Attach snapshot to a host """
        try:
            if not get_hosts_dict(snapshot):
                snapshot.detach_from(None)
            snapshot.attach_to(host)
            snapshot.update()
        except Exception as e:
            error_msg = "Failed to attach snapshot [name: %s, id: %s]" \
                        " to host [%s, %s] with error %s"\
                        % (snapshot.name, snapshot.id,
                           host.name, host.id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on snapshot module based on parameters
        chosen in playbook
        """
        snapshot_name = self.module.params['snapshot_name']
        snapshot_id = self.module.params['snapshot_id']
        vol_name = self.module.params['vol_name']
        cg_name = self.module.params['cg_name']
        auto_delete = self.module.params['auto_delete']
        expiry_time = self.module.params['expiry_time']
        description = self.module.params['description']
        new_snapshot_name = self.module.params['new_snapshot_name']
        host_name = self.module.params['host_name']
        host_id = self.module.params['host_id']
        host_state = self.module.params['host_state']
        state = self.module.params['state']
        host = None
        storage_resource = None
        changed = False

        LOG.info("Getting Snapshot details")
        snapshot = self.get_snapshot_obj(name=snapshot_name, id=snapshot_id)

        if snapshot and not snapshot.existed:
            snapshot = None
        msg = "snapshot details: %s" % str(snapshot)
        LOG.info(msg)

        #  Get Volume Object
        if vol_name is not None:
            if vol_name == "" or vol_name.isspace():
                self.module.fail_json(msg="Invalid vol_name given, Please"
                                          " provide a valid vol_name")
            storage_resource = self.get_volume_obj(name=vol_name)

        # Get Consistency Group Object
        if cg_name is not None:
            if cg_name == "" or cg_name.isspace():
                self.module.fail_json(msg="Invalid cg_name given, Please"
                                          " provide a valid cg_name")
            storage_resource = self.get_cg_obj(name=cg_name)

        # Get host object for volume snapshots
        if host_id or host_name:
            if cg_name:
                self.module.fail_json(msg="Mapping CG snapshot to host"
                                          " is not supported.")
            host = self.get_host_obj(name=host_name, id=host_id)

        # Check whether host_name or host_id is given in input
        # along with host_state
        if (host and not host_state) or (not host and host_state):
            self.module.fail_json(
                msg="Either host_name or host_id along with host_state "
                    "is required to map or unmap a snapshot from a host")

        # Check for error, if user tries to create a snapshot with the
        # same name for other storage resource.
        if snapshot and storage_resource and\
                (snapshot.storage_resource.id != storage_resource.id):
            self.module.fail_json(
                msg="Snapshot %s is of %s storage resource. Cannot create new"
                    " snapshot with same name for %s storage resource"
                    % (snapshot.name, snapshot.storage_resource.name,
                       storage_resource.name))

        # check for valid expiry_time
        if expiry_time is not None and \
                (expiry_time == "" or expiry_time.isspace()):
            self.module.fail_json(msg="Please provide valid expiry_time,"
                                      " empty expiry_time given")
        # Check if in input auto_delete is True and expiry_time is not None
        if expiry_time and auto_delete:
            error_msg = "Cannot set expiry_time if auto_delete given as True"
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)

        # Check whether to modify the snapshot or not
        update_flag = False
        if snapshot:
            update_flag = self.to_update(snapshot,
                                         new_name=new_snapshot_name,
                                         description=description,
                                         auto_del=auto_delete,
                                         expiry_time=expiry_time,
                                         host=host, host_state=host_state)
        msg = "update_flag for snapshot %s" % str(update_flag)
        LOG.info(msg)

        # Create a Snapshot
        if not snapshot and state == "present":
            LOG.info("Creating a snapshot")
            if snapshot_id:
                self.module.fail_json(msg="Creation of Snapshot is allowed"
                                          " using snapshot_name only, "
                                          "snapshot_id given")
            if snapshot_name == "" or snapshot_name.isspace():
                self.module.fail_json(msg="snapshot_name is required for"
                                          " creation of a snapshot,"
                                          " empty snapshot_name given")
            if not storage_resource:
                self.module.fail_json(msg="vol_name or cg_name required to"
                                          " create a snapshot")

            if new_snapshot_name:
                self.module.fail_json(
                    msg="new_snapshot_name can not be assigned"
                        " during creation of a snapshot")

            snapshot = self.create_snapshot(snapshot_name,
                                            storage_resource.id,
                                            description, auto_delete,
                                            expiry_time)
            if host and host_state == "mapped":
                self.attach_to_snap(snapshot, host)
            changed = True

        # Update the Snapshot
        if snapshot and state == "present" and update_flag:

            LOG.info("Updating the Snapshot details")

            if host_state == 'mapped':
                self.attach_to_snap(snapshot, host)
                self.update_snapshot(
                    snapshot, new_name=new_snapshot_name,
                    description=description, auto_del=auto_delete,
                    expiry_time=expiry_time)

            elif host_state == 'unmapped':
                host_access_list = create_host_access_list(snapshot,
                                                           host,
                                                           host_state)
                self.update_snapshot(
                    snapshot, new_name=new_snapshot_name,
                    description=description, auto_del=auto_delete,
                    expiry_time=expiry_time,
                    host_access_list=host_access_list)

            else:
                self.update_snapshot(
                    snapshot, new_name=new_snapshot_name,
                    description=description, auto_del=auto_delete,
                    expiry_time=expiry_time)
            changed = True

        # Delete the Snapshot
        if state == "absent" and snapshot:
            snapshot = self.delete_snapshot(snapshot)
            changed = True

        # Add snapshot details to the result.
        if snapshot:
            snapshot.update()
            self.result["snapshot_details"] = \
                create_snapshot_details_dict(snapshot)
        else:
            self.result["snapshot_details"] = {}

        self.result["changed"] = changed
        self.module.exit_json(**self.result)


def create_snapshot_details_dict(snapshot):
    """ Add name and id of storage resource and hosts to snapshot details """
    snapshot_dict = snapshot._get_properties()
    del snapshot_dict['storage_resource']
    del snapshot_dict['host_access']
    snapshot_dict['hosts_list'] = get_hosts_list(
        get_hosts_dict(snapshot))
    snapshot_dict['storage_resource_name'] = \
        snapshot.storage_resource.name
    snapshot_dict['storage_resource_id'] = \
        snapshot.storage_resource.id
    return snapshot_dict


def get_hosts_list(hosts_dict):
    """ Get the host name and host id of all the associated hosts """
    hosts_list = []
    if not hosts_dict:
        return hosts_list

    for host in list(hosts_dict.keys()):
        hosts_list.append(
            {
                "host_name": host.name,
                "host_id": host.id
            }
        )
    return hosts_list


def create_host_access_list(snapshot, host, host_state):
    """ This method creates a List of dictionaries which will be used
        to modify the list of hosts mapped to a snapshot """
    host_access_list = []
    hosts_dict = get_hosts_dict(snapshot)
    # If snapshot is not attached to any host.
    if not hosts_dict:
        return None
    if to_update_host_list(snapshot, host, host_state):
        if host_state == "mapped":
            return None
        for snap_host in list(hosts_dict.keys()):
            if snap_host != host:
                access_dict = {'host': snap_host,
                               'allowedAccess': hosts_dict[snap_host]}
                host_access_list.append(access_dict)
    return host_access_list


def get_hosts_dict(snapshot):
    """ This method creates a dictionary, with host as key and
        allowed access as value """
    hosts_dict = {}
    LOG.info("Inside get_hosts_dict")
    if not snapshot.host_access:
        return hosts_dict
    for host_access_obj in snapshot.host_access:
        hosts_dict[host_access_obj.host] = \
            host_access_obj.allowed_access
    return hosts_dict


def to_update_host_list(snapshot, host, host_state):
    """ Determines whether to update hosts list or not"""
    hosts_dict = get_hosts_dict(snapshot)
    if (not hosts_dict or host not in list(hosts_dict.keys()))\
            and host_state == "mapped":
        return True
    if (hosts_dict and host in list(hosts_dict.keys())) \
            and host_state == "unmapped":
        return True
    return False


def to_update_expiry_time(snapshot, expiry_time=None):
    """ Check whether to update expiry_time or not"""
    if not expiry_time:
        return False
    if snapshot.expiration_time is None:
        return True
    if convert_timestamp_to_sec(expiry_time, snapshot.expiration_time) != 0:
        return True
    return False


def convert_timestamp_to_sec(expiry_time, snap_time):
    """Converts the time difference to seconds"""
    snap_time_str = snap_time.strftime('%m/%d/%Y %H:%M')
    snap_timestamp = datetime.strptime(snap_time_str, '%m/%d/%Y %H:%M')
    expiry_timestamp = datetime.strptime(expiry_time, "%m/%d/%Y %H:%M")
    return int((expiry_timestamp - snap_timestamp).total_seconds())


def get_snapshot_parameters():
    """This method provide parameter required for the ansible snapshot
    module on Unity"""
    return dict(
        snapshot_name=dict(required=False, type='str'),
        snapshot_id=dict(required=False, type='str'),
        vol_name=dict(required=False, type='str'),
        cg_name=dict(required=False, type='str'),
        auto_delete=dict(required=False, type='bool'),
        expiry_time=dict(required=False, type='str'),
        description=dict(required=False, type='str'),
        new_snapshot_name=dict(required=False, type='str'),
        host_name=dict(required=False, type='str'),
        host_id=dict(required=False, type='str'),
        host_state=dict(required=False, type='str',
                        choices=['mapped', 'unmapped']),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create Unity Snapshot object and perform actions on it
        based on user input from playbook"""
    obj = Snapshot()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
