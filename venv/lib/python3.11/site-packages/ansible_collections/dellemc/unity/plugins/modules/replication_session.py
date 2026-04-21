#!/usr/bin/python
# Copyright: (c) 2023-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing replication session on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""

module: replication_session
version_added: '1.7.0'
short_description: Manage replication session on Unity storage system
description:
- Managing replication session on Unity storage system includes getting details, pause,
  resume, sync, failover, failback and deleting the replication session.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Jennifer John (@Jennifer-John) <ansible.team@dell.com>

options:
  session_id:
    description:
    - ID of replication session.
    type: str
  session_name:
    description:
    - Name of replication session.
    type: str
  pause:
    description:
    - Pause or resume replication session.
    type: bool
  sync:
    description:
    - Sync a replication session.
    type: bool
  failover_with_sync:
    description:
    - If C(true), Sync the source and destination resources before failing over the asynchronous
      replication session or keep them in sync after failing over the synchronous
      replication session.
    - If C(false), Failover a replication session.
    type: bool
  failback:
    description:
    - Failback a replication session.
    type: bool
  force_full_copy:
    description:
    - Indicates whether to sync back all data from the destination SP to the source
      SP during the failback session. Needed during resume operation when replication
      session goes out of sync due to a fault.
    type: bool
  force:
    description:
    - Skip pre-checks on file system(s) replication sessions of a NAS server when a
      replication failover is issued from the source NAS server.
    type: bool
  state:
    description:
    - State variable to determine whether replication session will exist or not.
    choices: ['absent', 'present']
    default: present
    type: str

notes:
  - The I(check_mode) is supported.
"""

EXAMPLES = r"""
- name: Get replication session details
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"

- name: Get replication session details based on session_id
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_id: "103079215114_APM00213404195_0000_103079215274_APM00213404194_0000"

- name: Pause a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    pause: true

- name: Resume a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    pause: false
    force_full_copy: true

- name: Sync a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    sync: true

- name: Failover with sync a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    failover_with_sync: true
    force: true

- name: Failover a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    failover_with_sync: false

- name: Failback a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    failback: true
    force_full_copy: true

- name: Delete a replication session
  replication_session:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    session_name: "fs_replication"
    state: "absent"
"""

RETURN = r'''

changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

replication_session_details:
    description: Details of the replication session.
    returned: When replication session exists.
    type: dict
    contains:
        id:
            description: Unique identifier of the replicationSession instance.
            type: str
        name:
            description: User-specified replication session name.
            type: str
        replicationResourceType:
            description: Replication resource type of replication session endpoints.
            type: str
        status:
            description: Replication status of the replication session.
            type: str
        remoteSystem:
            description: Specifies the remote system to use as the destination for the replication session.
            type: dict
            contains:
                UnityRemoteSystem:
                    description: Information about remote storage system.
                    type: dict
                    contains:
                        id:
                            description: Unique identifier of the remote system instance.
                            type: str
                        serialNumber:
                            description: Serial number of the remote system.
                            type: str
        maxTimeOutOfSync:
            description: Maximum time to wait before the system syncs the source and destination resources.
            type: int
        srcStatus:
            description: Status of the source end of the session.
            type: str
        networkStatus:
            description: Status of the network connection used by the replication session.
            type: str
        dstStatus:
            description: Status of the destination end of the replication session.
            type: str
        lastSyncTime:
            description: Date and time of the last replication synchronization.
            type: str
        syncState:
            description: Synchronization state between source and destination resource of the replication session.
            type: str
        syncProgress:
            description: Synchronization completion percentage between source and destination resources of the replication session.
            type: int
        dstResourceId:
            description: Identifier of the destination resource.
            type: str
        currentTransferEstRemainTime:
            description: Estimated time left for the replication synchronization to complete.
            type: int
    sample: {
        "current_transfer_est_remain_time": 0,
        "daily_snap_replication_policy": null,
        "dst_resource_id": "nas_8",
        "dst_spa_interface": {
            "UnityRemoteInterface": {
                "hash": 8771253398547,
                "id": "APM00213404195:if_181"
            }
        },
        "dst_spb_interface": {
            "UnityRemoteInterface": {
                "hash": 8771253424144,
                "id": "APM00213404195:if_180"
            }
        },
        "dst_status": "ReplicationSessionStatusEnum.OK",
        "existed": true,
        "hash": 8771259012271,
        "health": {
            "UnityHealth": {
                "hash": 8771253424168
            }
        },
        "hourly_snap_replication_policy": null,
        "id": "103079215114_APM00213404195_0000_103079215274_APM00213404194_0000",
        "last_sync_time": "2023-04-18 10:35:25+00:00",
        "local_role": "ReplicationSessionReplicationRoleEnum.DESTINATION",
        "max_time_out_of_sync": 0,
        "members": null,
        "name": "rep_sess_nas",
        "network_status": "ReplicationSessionNetworkStatusEnum.OK",
        "remote_system": {
            "UnityRemoteSystem": {
                "hash": 8771253380142
            }
        },
        "replication_resource_type": "ReplicationEndpointResourceTypeEnum.NASSERVER",
        "src_resource_id": "nas_213",
        "src_spa_interface": {
            "UnityRemoteInterface": {
                "hash": 8771253475010,
                "id": "APM00213404194:if_195"
            }
        },
        "src_spb_interface": {
            "UnityRemoteInterface": {
                "hash": 8771253374169,
                "id": "APM00213404194:if_194"
            }
        },
        "src_status": "ReplicationSessionStatusEnum.OK",
        "status": "ReplicationOpStatusEnum.ACTIVE",
        "sync_progress": 0,
        "sync_state": "ReplicationSessionSyncStateEnum.IN_SYNC"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('replication_session')

application_type = "Ansible/1.7.0"


class ReplicationSession(object):

    """Class with replication session operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_replication_session_parameters())

        mutually_exclusive = [['session_id', 'session_name']]

        required_one_of = [['session_id', 'session_name']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=True,
            mutually_exclusive=mutually_exclusive,
            required_one_of=required_one_of)
        utils.ensure_required_libs(self.module)
        self.result = dict(
            changed=False,
            replication_session_details={}
        )

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        LOG.info('Check Mode Flag %s', self.module.check_mode)

    def get_replication_session(self, id=None, name=None):
        """Get the details of a replication session.
            :param id: The id of the replication session
            :param name: The name of the replication session
            :return: instance of the replication session if exist.
        """

        id_or_name = id if id else name
        errormsg = f"Retrieving details of replication session {id_or_name} failed with error"

        try:
            obj_replication_session = self.unity_conn.get_replication_session(name=name, _id=id)

            LOG.info("Successfully retrieved the replication session object %s ", obj_replication_session)
            if obj_replication_session.existed:
                return obj_replication_session
        except utils.HttpError as e:
            if e.http_status == 401:
                self.module.fail_json(msg=f"Incorrect username or password {str(e)}")
            else:
                msg = f"{errormsg} {str(e)}"
                self.module.fail_json(msg=msg)
        except utils.UnityResourceNotFoundError as e:
            msg = f"{errormsg} {str(e)}"
            LOG.error(msg)
            return None
        except Exception as e:
            msg = f"{errormsg} {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def pause(self, session_obj):
        """Pause the replication session.
            :param session_obj: Replication session object
            :return: True if pause is successful.
        """
        try:
            LOG.info("Pause replication session %s", session_obj.name)
            if session_obj.status.name != utils.ReplicationOpStatusEnum.PAUSED.name:
                if not self.module.check_mode:
                    session_obj.pause()
                return True
        except Exception as e:
            msg = f"Pause replication session {session_obj.name} failed with error {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def resume(self, session_obj, force_full_copy):
        """Resume the replication session.
            :param session_obj: Replication session object
            :param force_full_copy: needed when replication session goes out of sync due to a fault.
            :return: True if resume is successful.
        """
        try:
            LOG.info("Resume replication session %s", session_obj.name)
            if session_obj.status.name in (utils.ReplicationOpStatusEnum.PAUSED.name,
                                           utils.ReplicationOpStatusEnum.FAILED_OVER.name,
                                           utils.ReplicationOpStatusEnum.FAILED_OVER_WITH_SYNC.name):
                if not self.module.check_mode:
                    session_obj.resume(force_full_copy=force_full_copy)
                return True
        except Exception as e:
            msg = f"Resume replication session {session_obj.name} failed with error {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def sync(self, session_obj):
        """Sync the replication session.
            :param session_obj: Replication session object
            :return: True if sync is successful.
        """
        try:
            LOG.info("Sync replication session %s", session_obj.name)
            if not self.module.check_mode:
                session_obj.sync()
            return True
        except Exception as e:
            msg = f"Sync replication session {session_obj.name} failed with error {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def failover(self, session_obj, sync_failover, force):
        """Failover the replication session.
            :param session_obj: Replication session object
            :param sync_failover: To sync the source and destination resources
            :param force: Skip pre-checks on file system(s) replication sessions of a NAS server
            :return: True if failover is successful.
        """
        try:
            LOG.info("Failover replication session %s", session_obj.name)
            if (sync_failover and session_obj.status.name != utils.ReplicationOpStatusEnum.FAILED_OVER_WITH_SYNC.name) or \
                    (not sync_failover and session_obj.status.name != utils.ReplicationOpStatusEnum.FAILED_OVER.name):
                if not self.module.check_mode:
                    session_obj.failover(sync=sync_failover, force=force)
                return True
        except Exception as e:
            msg = f"Failover replication session {session_obj.name} failed with error {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def failback(self, session_obj, force_full_copy):
        """Failback the replication session.
            :param session_obj: Replication session object
            :param force_full_copy: needed when replication session goes out of sync due to a fault.
            :return: True if failback is successful.
        """
        try:
            LOG.info("Failback replication session %s", session_obj.name)
            if session_obj.status.name in (utils.ReplicationOpStatusEnum.FAILED_OVER.name,
                                           utils.ReplicationOpStatusEnum.FAILED_OVER_WITH_SYNC.name,
                                           utils.ReplicationOpStatusEnum.PAUSED.name):
                if not self.module.check_mode:
                    session_obj.failback(force_full_copy=force_full_copy)
                return True
        except Exception as e:
            msg = f"Failback replication session {session_obj.name} failed with error {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def delete(self, session_obj):
        """Delete the replication session.
            :param session_obj: Replication session object
            :return: True if delete is successful.
        """
        try:
            LOG.info("Delete replication session %s", session_obj.name)
            if not self.module.check_mode:
                session_obj.delete()
            return True
        except Exception as e:
            msg = f"Deleting replication session {session_obj.name} failed with error {str(e)}"
            LOG.error(msg)
            self.module.fail_json(msg=msg)


def get_replication_session_parameters():
    """This method provide parameters required for the ansible replication session
       module on Unity"""
    return dict(
        session_id=dict(type='str'), session_name=dict(type='str'),
        pause=dict(type='bool'), sync=dict(type='bool'),
        force=dict(type='bool'), failover_with_sync=dict(type='bool'),
        failback=dict(type='bool'), force_full_copy=dict(type='bool'),
        state=dict(type='str', choices=['present', 'absent'], default='present')
    )


class ReplicationSessionFailoverHandler():
    def handle(self, session_object, session_params, replication_session_obj):
        if replication_session_obj and session_params['state'] == 'present' and session_params['failover_with_sync'] is not None:
            session_object.result['changed'] = \
                session_object.failover(replication_session_obj, session_params['failover_with_sync'], session_params['force']) or False
            if session_object.result['changed']:
                replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        ReplicationSessionFailbackHandler().handle(session_object, session_params, replication_session_obj)


class ReplicationSessionFailbackHandler():
    def handle(self, session_object, session_params, replication_session_obj):
        if replication_session_obj and session_params['state'] == 'present' and session_params['failback']:
            session_object.result['changed'] = \
                session_object.failback(replication_session_obj, session_params['force_full_copy']) or False
            if session_object.result['changed']:
                replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        ReplicationSessionDeleteHandler().handle(session_object, session_params, replication_session_obj)


class ReplicationSessionSyncHandler():
    def handle(self, session_object, session_params, replication_session_obj):
        if replication_session_obj and session_params['state'] == 'present' and session_params['sync']:
            session_object.result['changed'] = session_object.sync(replication_session_obj)
            if session_object.result['changed']:
                replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        ReplicationSessionFailoverHandler().handle(session_object, session_params, replication_session_obj)


class ReplicationSessionDeleteHandler():
    def handle(self, session_object, session_params, replication_session_obj):
        if replication_session_obj and session_params['state'] == 'absent':
            session_object.result['changed'] = session_object.delete(replication_session_obj)
        if session_object.result['changed']:
            replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        ReplicationSessionExitHandler().handle(session_object, replication_session_obj)


class ReplicationSessionExitHandler():
    def handle(self, session_object, replication_session_obj):
        if replication_session_obj:
            session_object.result['replication_session_details'] = replication_session_obj._get_properties()
        session_object.module.exit_json(**session_object.result)


class ReplicationSessionResumeHandler():
    def handle(self, session_object, session_params, replication_session_obj):
        if replication_session_obj and session_params['state'] == 'present' and session_params['pause'] is False:
            session_object.result['changed'] = \
                session_object.resume(replication_session_obj, session_params['force_full_copy']) or False
            if session_object.result['changed']:
                replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        ReplicationSessionSyncHandler().handle(session_object, session_params, replication_session_obj)


class ReplicationSessionPauseHandler():
    def handle(self, session_object, session_params, replication_session_obj):
        if replication_session_obj and session_params['state'] == 'present' and session_params['pause']:
            session_object.result['changed'] = \
                session_object.pause(replication_session_obj) or False
            if session_object.result['changed']:
                replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        ReplicationSessionResumeHandler().handle(session_object, session_params, replication_session_obj)


class ReplicationSessionHandler():
    def handle(self, session_object, session_params):
        replication_session_obj = session_object.get_replication_session(session_params['session_id'], session_params['session_name'])
        if session_params['state'] == 'present' and not replication_session_obj:
            session_object.module.fail_json(msg=f"Replication session {session_params['session_id'] or session_params['session_name']} is invalid.")
        ReplicationSessionPauseHandler().handle(session_object, session_params, replication_session_obj)


def main():
    """ Create Unity replication session object and perform action on it
        based on user input from playbook"""
    obj = ReplicationSession()
    ReplicationSessionHandler().handle(obj, obj.module.params)


if __name__ == '__main__':
    main()
