#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_ip_partnership
short_description: This module manages IP partnerships on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkippartnership', 'rmpartnership', and 'chpartnership' commands
    on local and remote systems.
version_added: "1.9.0"
options:
    state:
        description:
            - Creates or updates (C(present)) or removes (C(absent)) an IP partnership.
        choices: [ 'present', 'absent' ]
        required: true
        type: str
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        type: str
        required: true
    remote_clustername:
        description:
            - The hostname or management IP of the remote Storage Virtualize system.
        type: str
        required: true
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    remote_domain:
        description:
            - Domain for the remote Storage Virtualize system.
            - Valid when hostname is used for the parameter I(remote_clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    remote_username:
        description:
            - REST API username for the remote Storage Virtualize system.
            - The parameters I(remote_username) and I(remote_password) are required if not using I(remote_token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    remote_password:
        description:
            - REST API password for the remote Storage Virtualize system.
            - The parameters I(remote_username) and I(remote_password) are required if not using I(remote_token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize system.
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    remote_token:
        description:
            - The authentication token to verify a user on the remote Storage Virtualize system.
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    remote_clusterip:
        description:
            - Specifies the partner system IP address, either IPv4 or IPv6.
            - Required when I(state=present), to create an IP partnership.
        type: str
    remote_cluster_id:
        description:
            - Specifies the partnership ID of the partner system.
            - Required when I(state=present), to modify an existing IP partnership.
            - Required when I(state=absent), to remove an existing IP partnership.
        type: str
    type:
        description:
            - Specifies the Internet Protocol (IP) address format for the partnership.
            - Valid when I(state=present).
        choices: [ 'ipv4', 'ipv6' ]
        type: str
    compressed:
        description:
            - Specifies whether compression is enabled for this partnership.
            - Valid when I(state=present).
        choices: [ 'yes', 'no' ]
        type: str
    linkbandwidthmbits:
        description:
            - Specifies the aggregate bandwidth of the RC link between two clustered systems (systems)
              in megabits per second (Mbps). This is a numeric value from 1 through 100000.
            - Valid when I(state=present).
        type: int
    backgroundcopyrate:
        description:
            - Specifies the maximum percentage of aggregate link bandwidth that can be used for background
              copy operations. This is a numeric value from 0 through 100. The default value is 50.
            - Valid when I(state=present).
        type: int
    pbrinuse:
        description:
            - Specifies whether policy-based replication will be used on the partnership.
            - Valid when I(state=present) to update a partnership.
        type: str
        choices: [ 'yes', 'no' ]
        version_added: 2.7.0
    link1:
        description:
            - Specifies the portset name to be used for WAN link 1 of the Storage Virtualize system.
            - Valid when I(state=present), to create an IP partnership.
        type: str
    remote_link1:
        description:
            - Specifies the portset name to be used for WAN link 1 of the remote Storage Virtualize system.
            - Valid when I(state=present), to create an IP partnership.
        type: str
    link2:
        description:
            - Specifies the portset name to be used for WAN link 2 of the Storage Virtualize system.
            - Valid when I(state=present), to create an IP partnership.
        type: str
    remote_link2:
        description:
            - Specifies the portset name to be used for WAN link 2 of the remote Storage Virtualize system.
            - Valid when I(state=present), to create an IP partnership.
        type: str
    validate_certs:
        description:
            - Validates certification for the local Storage Virtualize system.
        default: false
        type: bool
    remote_validate_certs:
        description:
            - Validates certification for the remote Storage Virtualize system.
        default: false
        type: bool
    log_path:
        description:
            - Path of debug log file.
        type: str
author:
    - Sreshtant Bohidar(@Sreshtant-Bohidar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create an IP partnership
  ibm.storage_virtualize.ibm_sv_manage_ip_partnership:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_domain: "{{ remote_domain }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    log_path: "/tmp/debug.log"
    remote_clusterip: "{{ partner_ip }}"
    type: "ipv4"
    linkbandwidthmbits: 100
    backgroundcopyrate: 50
    compressed: 'yes'
    link1: "{{ portsetname }}"
    remote_link1: "{{ remote_portsetname }}"
    state: "present"
- name: Update an IP partnership
  ibm.storage_virtualize.ibm_sv_manage_ip_partnership:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_domain: "{{ remote_domain }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    log_path: "/tmp/debug.log"
    remote_cluster_id: "{{ cluster_id }}"
    linkbandwidthmbits: 110
    backgroundcopyrate: 60
    compressed: 'no'
    state: "present"
- name: Remove an IP partnership
  ibm.storage_virtualize.ibm_sv_manage_ip_partnership:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    log_path: "/tmp/debug.log"
    remote_cluster_id: "{{ cluster_id }}"
    state: "absent"
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCIPPartnership(object):

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(type='str', required=True, choices=['present', 'absent']),
                type=dict(type='str', required=False, choices=['ipv4', 'ipv6']),
                remote_clusterip=dict(type='str', required=False),
                remote_cluster_id=dict(type='str', required=False),
                compressed=dict(type='str', required=False, choices=['yes', 'no']),
                linkbandwidthmbits=dict(type='int', required=False),
                backgroundcopyrate=dict(type='int', required=False),
                link1=dict(type='str', required=False),
                link2=dict(type='str', required=False),
                remote_clustername=dict(type='str', required=True),
                remote_domain=dict(type='str', default=None),
                remote_username=dict(type='str'),
                remote_password=dict(type='str', no_log=True),
                remote_token=dict(type='str', no_log=True),
                remote_validate_certs=dict(type='bool', default=False),
                pbrinuse=dict(type='str', choices=['yes', 'no']),
                remote_link1=dict(type='str', required=False),
                remote_link2=dict(type='str', required=False)
            )
        )
        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info
        # Required
        self.state = self.module.params['state']
        self.remote_clustername = self.module.params['remote_clustername']
        # Optional
        self.remote_username = self.module.params.get('remote_username', '')
        self.remote_password = self.module.params.get('remote_password', '')
        self.remote_clusterip = self.module.params.get('remote_clusterip', '')
        self.remote_cluster_id = self.module.params.get('remote_cluster_id', '')
        self.type = self.module.params.get('type', '')
        self.compressed = self.module.params.get('compressed', '')
        self.linkbandwidthmbits = self.module.params.get('linkbandwidthmbits', '')
        self.backgroundcopyrate = self.module.params.get('backgroundcopyrate', '')
        self.pbrinuse = self.module.params.get('pbrinuse', '')
        self.link1 = self.module.params.get('link1', '')
        self.link2 = self.module.params.get('link2', '')
        self.remote_domain = self.module.params.get('remote_domain', '')
        self.remote_token = self.module.params.get('remote_token', '')
        self.remote_validate_certs = self.module.params.get('remote_validate_certs', '')
        self.remote_link1 = self.module.params.get('remote_link1', '')
        self.remote_link2 = self.module.params.get('remote_link2', '')
        # Internal variable
        self.changed = False
        # creating an instance of IBMSVCRestApi for local system
        self.restapi_local = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )
        # creating an instance of IBMSVCRestApi for remote system
        self.restapi_remote = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['remote_clustername'],
            domain=self.module.params['remote_domain'],
            username=self.module.params['remote_username'],
            password=self.module.params['remote_password'],
            validate_certs=self.module.params['remote_validate_certs'],
            log_path=log_path,
            token=self.module.params['remote_token']
        )

    # perform some basic checks
    def basic_checks(self):
        # Handling for mandatory parameter 'state'
        if not self.state:
            self.module.fail_json(msg="Missing mandatory parameter: state")

    # Parameter validation for creating IP partnership
    def create_parameter_validation(self):
        if self.state == 'present':
            if not self.remote_clusterip:
                self.module.fail_json(msg="Missing required parameter during creation: remote_clusterip")
            if not (self.link1 or self.link2):
                self.module.fail_json(msg="At least one is required during creation: link1 or link2")
            if not (self.remote_link1 or self.remote_link2):
                self.module.fail_json(msg="At least one is required during creation: remote_link1 or remote_link2")
            if self.pbrinuse:
                self.module.fail_json(msg="Following parameter not supported during creation: pbrinuse")

    # Parameter validation for deleting IP partnership
    def delete_parameter_validation(self):
        if self.state == 'absent':
            if not self.remote_cluster_id:
                self.module.fail_json(msg="Missing required parameter during deletion: remote_cluster_id")
            unsupported = []
            check_list = {
                'remote_clusterip': self.remote_clusterip,
                'type': self.type,
                'linkbandwidthmbits': self.linkbandwidthmbits,
                'backgroundcopyrate': self.backgroundcopyrate,
                'compressed': self.compressed,
                'link1': self.link1,
                'link2': self.link2,
                'remote_link1': self.remote_link1,
                'remote_link2': self.remote_link2,
                'pbrinuse': self.pbrinuse
            }
            self.log('%s', check_list)
            for key, value in check_list.items():
                if value:
                    unsupported.append(key)
            if unsupported:
                self.module.fail_json(msg="Unsupported parameter during deletion: {0}".format(unsupported))

    # Parameter validation for updating IP partnership
    def update_parameter_validation(self):
        if self.state == 'present' and not self.remote_cluster_id:
            self.module.fail_json(msg="Missing required parameter during updation: remote_cluster_id")

    # fetch system IP address
    def get_ip(self, rest_obj):
        system_data = rest_obj.svc_obj_info('lssystem', {}, None)
        if system_data and 'console_IP' in system_data and ':' in system_data['console_IP']:
            return system_data['console_IP'].split(':')[0]
        else:
            self.module.fail_json(msg="Failed to fetch the IP address of local system")

    # get all partnership
    def get_all_partnership(self, rest_obj):
        return rest_obj.svc_obj_info(cmd='lspartnership', cmdopts=None, cmdargs=[])

    # filter partnership data
    def filter_partnership(self, data, ip):
        return list(
            filter(
                lambda item: item['cluster_ip'] == ip, data
            )
        )

    # get local partnership
    def get_local_partnership(self, data):
        return list(
            filter(
                lambda item: item['location'] == 'local', data
            )
        )

    # get all the attributes of a partnership
    def get_partnership_detail(self, rest_obj, id):
        return rest_obj.svc_obj_info(cmd='lspartnership', cmdopts=None, cmdargs=[id])

    # fetch partnership data
    def gather_all_validation_data(self, rest_local, rest_remote):
        local_data = {}
        remote_data = {}
        local_ip = self.get_ip(rest_local)
        local_id = None
        # while updating and removing existing partnership
        if self.remote_cluster_id:
            local_data = self.get_partnership_detail(rest_local, self.remote_cluster_id)
            all_local_partnership = self.get_all_partnership(rest_local)
            if all_local_partnership:
                local_partnership_data = self.get_local_partnership(all_local_partnership)
                if local_partnership_data:
                    local_id = local_partnership_data[0]['id']
                    remote_data = self.get_partnership_detail(rest_remote, local_id)
        # while creating partnership
        else:
            all_local_partnership = self.get_all_partnership(rest_local)
            if all_local_partnership:
                if self.remote_clusterip:
                    local_filter = self.filter_partnership(
                        all_local_partnership,
                        self.remote_clusterip
                    )
                    if local_filter:
                        local_data = self.get_partnership_detail(rest_local, local_filter[0]['id'])

            all_remote_partnership = self.get_all_partnership(rest_remote)
            if all_remote_partnership:
                remote_filter = self.filter_partnership(
                    all_remote_partnership,
                    local_ip
                )
                if remote_filter:
                    remote_data = self.get_partnership_detail(rest_remote, remote_filter[0]['id'])
        return local_ip, local_id, local_data, remote_data

    # create a new IP partnership
    def create_partnership(self, location, cluster_ip):
        # when executed with check mode
        if self.module.check_mode:
            self.changed = True
            return
        rest_api = None
        cmd = 'mkippartnership'
        cmd_opts = {
            'clusterip': cluster_ip
        }
        if self.type:
            cmd_opts['type'] = self.type
        if self.compressed:
            cmd_opts['compressed'] = self.compressed
        if self.linkbandwidthmbits:
            cmd_opts['linkbandwidthmbits'] = self.linkbandwidthmbits
        if self.backgroundcopyrate:
            cmd_opts['backgroundcopyrate'] = self.backgroundcopyrate
        if location == 'local':
            rest_api = self.restapi_local
            if self.link1:
                cmd_opts['link1'] = self.link1
            if self.link2:
                cmd_opts['link2'] = self.link2
        if location == 'remote':
            rest_api = self.restapi_remote
            if self.remote_link1:
                cmd_opts['link1'] = self.remote_link1
            if self.remote_link2:
                cmd_opts['link2'] = self.remote_link2
        result = rest_api.svc_run_command(cmd, cmd_opts, cmdargs=None)
        self.log("Create result '%s'.", result)
        if result == '':
            self.changed = True
            self.log("Created IP partnership for %s system.", location)
        else:
            self.module.fail_json(msg="Failed to create IP partnership for cluster ip {0}".format(cluster_ip))

    # delete an existing partnership
    def remove_partnership(self, location, id):
        # when executed with check mode
        if self.module.check_mode:
            self.changed = True
            return
        rest_api = None
        cmd = 'rmpartnership'
        if location == 'local':
            rest_api = self.restapi_local
        if location == 'remote':
            rest_api = self.restapi_remote
        rest_api.svc_run_command(cmd, {}, [id])
        self.log('Deleted partnership with name %s.', id)
        self.changed = True

    # probe a partnership
    def probe_partnership(self, local_data, remote_data):
        modify_local, modify_remote = {}, {}
        # unsupported parameters while updating
        unsupported = []
        if self.link1:
            if local_data and local_data['link1'] != self.link1:
                unsupported.append('link1')
        if self.link2:
            if local_data and local_data['link2'] != self.link2:
                unsupported.append('link2')
        if self.remote_link1:
            if remote_data and remote_data['link1'] != self.remote_link1:
                unsupported.append('remote_link1')
        if self.remote_link2:
            if remote_data and remote_data['link2'] != self.remote_link2:
                unsupported.append('remote_link2')
        if self.type:
            if (local_data and local_data['type'] != self.type) or (remote_data and remote_data['type'] != self.type):
                unsupported.append('type')
        if unsupported:
            self.module.fail_json(msg="parameters {0} cannot be updated".format(unsupported))
        # supported parameters while updating
        if self.compressed:
            if local_data and local_data['compressed'] != self.compressed:
                modify_local['compressed'] = self.compressed
            if remote_data and remote_data['compressed'] != self.compressed:
                modify_remote['compressed'] = self.compressed
        if self.linkbandwidthmbits:
            if local_data and int(local_data['link_bandwidth_mbits']) != self.linkbandwidthmbits:
                modify_local['linkbandwidthmbits'] = self.linkbandwidthmbits
            if remote_data and int(remote_data['link_bandwidth_mbits']) != self.linkbandwidthmbits:
                modify_remote['linkbandwidthmbits'] = self.linkbandwidthmbits
        if self.backgroundcopyrate:
            if local_data and int(local_data['background_copy_rate']) != self.backgroundcopyrate:
                modify_local['backgroundcopyrate'] = self.backgroundcopyrate
            if remote_data and int(remote_data['background_copy_rate']) != self.backgroundcopyrate:
                modify_remote['backgroundcopyrate'] = self.backgroundcopyrate
        if self.remote_clusterip:
            if local_data and self.remote_clusterip != local_data['cluster_ip']:
                modify_local['clusterip'] = self.remote_clusterip
        if self.pbrinuse:
            if local_data and local_data['pbr_in_use'] != self.pbrinuse:
                modify_local['pbrinuse'] = self.pbrinuse
            if remote_data and remote_data['pbr_in_use'] != self.pbrinuse:
                modify_remote['pbrinuse'] = self.pbrinuse
        return modify_local, modify_remote

    # start a partnership
    def start_partnership(self, rest_object, id):
        cmd = 'chpartnership'
        cmd_opts = {
            'start': True
        }
        cmd_args = [id]
        rest_object.svc_run_command(cmd, cmd_opts, cmd_args)
        self.log('Started the partnership %s.', id)

    # stop a partnership
    def stop_partnership(self, rest_object, id):
        cmd = 'chpartnership'
        cmd_opts = {
            'stop': True
        }
        cmd_args = [id]
        rest_object.svc_run_command(cmd, cmd_opts, cmd_args)
        self.log('Stopped partnership %s.', id)

    # update a partnership
    def update_partnership(self, location, id, modify_data):
        # when executed with check mode
        if self.module.check_mode:
            self.changed = True
            return
        cmd = 'chpartnership'
        cmd_args = [id]
        rest_object = None
        if location == 'local':
            rest_object = self.restapi_local
        if location == 'remote':
            rest_object = self.restapi_remote
        stop_before_update_params = ("compressed", "clusterip")
        operations_needing_stop = {parameter : value for parameter, value in modify_data.items() if parameter in stop_before_update_params}
        operations_not_needing_stop = {parameter : value for parameter, value in modify_data.items() if parameter not in stop_before_update_params}
        if operations_needing_stop:
            cmd_opts = {}
            for parameter, value in operations_needing_stop.items():
                cmd_opts[parameter] = value
            if cmd_opts:
                # stop the partnership
                self.stop_partnership(rest_object, id)
                # perform update operation
                rest_object.svc_run_command(cmd, cmd_opts, cmd_args)
                # start the partnership
                self.start_partnership(rest_object, id)
                self.changed = True
        if operations_not_needing_stop:
            cmd_opts = {}
            for parameter, value in operations_not_needing_stop.items():
                cmd_opts[parameter] = value
            if cmd_opts:
                # perform the update operation
                rest_object.svc_run_command(cmd, cmd_opts, cmd_args)
                self.changed = True

    def apply(self):
        msg = ''
        self.basic_checks()
        local_ip, local_id, local_data, remote_data = self.gather_all_validation_data(self.restapi_local, self.restapi_remote)
        if self.state == 'present':
            if local_data and remote_data:
                modify_local, modify_remote = self.probe_partnership(local_data, remote_data)
                if modify_local or modify_remote:
                    self.update_parameter_validation()
                    if modify_local:
                        self.update_partnership('local', self.remote_cluster_id, modify_local)
                        msg += 'IP partnership updated on local system.'
                    else:
                        msg += 'IP partnership already exists on local system.'
                    if modify_remote:
                        self.update_partnership('remote', local_id, modify_remote)
                        msg += ' IP partnership updated on remote system.'
                    else:
                        msg += ' IP partnership already exists on remote system.'
                else:
                    msg += 'IP partnership already exists on both local and remote system.'
            elif local_data and not remote_data:
                response = self.probe_partnership(local_data, remote_data)
                modify_local = response[0]
                self.create_parameter_validation()
                self.create_partnership('remote', local_ip)
                msg += 'IP partnership created on remote system.'
                if modify_local:
                    self.update_parameter_validation()
                    self.update_partnership('local', self.remote_cluster_id, modify_local)
                    msg += ' IP partnership updated on {0} system.'.format(['local'])
                else:
                    msg += ' IP Partnership already exists on local system.'
            elif not local_data and remote_data:
                response = self.probe_partnership(local_data, remote_data)
                modify_remote = response[1]
                self.create_parameter_validation()
                self.create_partnership('local', self.remote_clusterip)
                msg += ' IP partnership created on local system.'
                if modify_remote:
                    self.update_partnership('remote', local_id, modify_remote)
                    msg += 'IP partnership updated on {0} system.'.format(['remote'])
                else:
                    msg += 'IP Partnership already exists on remote system.'
            elif not local_data and not remote_data:
                self.create_parameter_validation()
                self.create_partnership('local', self.remote_clusterip)
                self.create_partnership('remote', local_ip)
                msg = 'IP partnership created on both local and remote system.'
        elif self.state == 'absent':
            # parameter vaidation while removing partnership
            self.delete_parameter_validation()
            # removal of partnership on both local and remote system
            if local_data and remote_data:
                self.remove_partnership('local', self.remote_cluster_id)
                self.remove_partnership('remote', local_id)
                msg += 'IP partnership deleted from both local and remote system.'
            elif local_data and not remote_data:
                self.remove_partnership('local', self.remote_cluster_id)
                msg += 'IP partnership deleted from local system.'
                msg += ' IP partnership does not exists on remote system.'
            elif not local_data and remote_data:
                self.remove_partnership('remote', local_id)
                msg += 'IP partnership deleted from remote system.'
                msg += ' IP partnership does not exists on local system.'
            elif not local_data and not remote_data:
                msg += 'IP partnership does not exists on both local and remote system. No modifications done.'

        if self.module.check_mode:
            msg = 'Skipping changes due to check mode.'

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCIPPartnership()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
