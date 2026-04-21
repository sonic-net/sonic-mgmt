#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_volume_efficiency
short_description: NetApp ONTAP enables, disables or modifies volume efficiency
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.2.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Enable, modify or disable volume efficiency.
  - Either path or volume_name is required.
  - Only admin user can modify volume efficiency.
options:
  state:
    description:
      - Whether the specified volume efficiency should be enabled or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
      - Specifies the vserver for the volume.
    required: true
    type: str

  path:
    description:
      - Specifies the path for the volume.
      - Either C(path) or C(volume_name) is required.
      - Requires ONTAP 9.9.1 or later with REST.
    type: str

  volume_name:
    description:
      - Specifies the volume name.
    version_added: 22.3.0
    type: str

  schedule:
    description:
      - Specifies the storage efficiency schedule.
      - Only supported with ZAPI.
    type: str

  policy:
    description:
      - Specifies the storage efficiency policy to use.
      - By default, the following names are available 'auto', 'default', 'inline-only', '-'.
      - Requires ONTAP 9.7 or later with REST.
    type: str

  enable_compression:
    description:
      - Specifies if compression is to be enabled.
    type: bool

  enable_inline_compression:
    description:
      - Specifies if in-line compression is to be enabled.
    type: bool

  enable_inline_dedupe:
    description:
      - Specifies if in-line deduplication is to be enabled, only supported on AFF systems or hybrid aggregates.
    type: bool

  enable_data_compaction:
    description:
      - Specifies if compaction is to be enabled.
    type: bool

  enable_cross_volume_inline_dedupe:
    description:
      - Specifies if in-line cross volume inline deduplication is to be enabled, this can only be enabled when inline deduplication is enabled.
    type: bool

  enable_cross_volume_background_dedupe:
    description:
      - Specifies if cross volume background deduplication is to be enabled, this can only be enabled when inline deduplication is enabled.
    type: bool

  volume_efficiency:
    description:
      - Start or Stop a volume efficiency operation on a given volume path.
      - Requires ONTAP 9.11.1 or later with REST.
    choices: ['start', 'stop']
    version_added: '21.4.0'
    type: str

  start_ve_scan_all:
    description:
      - Specifies the scanner to scan the entire volume without applying share block optimization.
      - Only supported with ZAPI.
    version_added: '21.4.0'
    type: bool

  start_ve_build_metadata:
    description:
      - Specifies the scanner to scan the entire and generate fingerprint database without attempting the sharing.
      - Only supported with ZAPI.
    version_added: '21.4.0'
    type: bool

  start_ve_delete_checkpoint:
    description:
      - Specifies the scanner to delete existing checkpoint and start the operation from the begining.
      - Only supported with ZAPI.
    version_added: '21.4.0'
    type: bool

  start_ve_queue_operation:
    description:
      - Specifies the operation to queue if an exisitng operation is already running on the volume and in the fingerprint verification phase.
      - Only supported with ZAPI.
    version_added: '21.4.0'
    type: bool

  start_ve_scan_old_data:
    description:
      - Specifies the operation to scan the file system to process all the existing data.
      - Requires ONTAP 9.11.1 or later with REST.
    version_added: '21.4.0'
    type: bool

  start_ve_qos_policy:
    description:
      - Specifies the QoS policy for the operation.
      - Default is best-effort in ZAPI.
      - Only supported with ZAPI.
    choices: ['background', 'best-effort']
    version_added: '21.4.0'
    type: str

  stop_ve_all_operations:
    description:
      - Specifies that all running and queued operations to be stopped.
      - Only supported with ZAPI.
    version_added: '21.4.0'
    type: bool

  storage_efficiency_mode:
    description:
      - Storage efficiency mode used by volume. This parameter is only supported on AFF platforms.
      - Requires ONTAP 9.10.1 or later.
    choices: ['default', 'efficient']
    type: str
    version_added: '21.14.0'

notes:
  - supports ZAPI and REST.  REST requires ONTAP 9.6 or later.
  - supports check mode.
"""

EXAMPLES = """
- name: Enable Volume efficiency
  netapp.ontap.na_ontap_volume_efficiency:
    state: present
    vserver: "TESTSVM"
    path: "/vol/test_sis"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Disable Volume efficiency test
  netapp.ontap.na_ontap_volume_efficiency:
    state: absent
    vserver: "TESTSVM"
    path: "/vol/test_sis"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Modify storage efficiency schedule with ZAPI.
  netapp.ontap.na_ontap_volume_efficiency:
    state: present
    vserver: "TESTSVM"
    path: "/vol/test_sis"
    schedule: "mon-sun@0,1,23"
    enable_compression: true
    enable_inline_compression: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Start volume efficiency
  netapp.ontap.na_ontap_volume_efficiency:
    state: present
    vserver: "TESTSVM"
    path: "/vol/test_sis"
    volume_efficiency: "start"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Stop volume efficiency
  netapp.ontap.na_ontap_volume_efficiency:
    state: present
    vserver: "TESTSVM"
    path: "/vol/test_sis"
    volume_efficiency: "stop"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: Modify volume efficiency with volume name in REST.
  netapp.ontap.na_ontap_volume_efficiency:
    state: present
    vserver: "TESTSVM"
    volume_name: "test_sis"
    volume_efficiency: "stop"
    enable_compression: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false
"""

RETURN = """

"""

import copy
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapVolumeEfficiency(object):
    """
        Creates, Modifies and Disables a Volume Efficiency
    """
    def __init__(self):
        """
            Initialize the ONTAP Volume Efficiency class
        """
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            path=dict(required=False, type='str'),
            volume_name=dict(required=False, type='str'),
            schedule=dict(required=False, type='str'),
            policy=dict(required=False, type='str'),
            enable_inline_compression=dict(required=False, type='bool'),
            enable_compression=dict(required=False, type='bool'),
            enable_inline_dedupe=dict(required=False, type='bool'),
            enable_data_compaction=dict(required=False, type='bool'),
            enable_cross_volume_inline_dedupe=dict(required=False, type='bool'),
            enable_cross_volume_background_dedupe=dict(required=False, type='bool'),
            storage_efficiency_mode=dict(required=False, choices=['default', 'efficient'], type='str'),
            volume_efficiency=dict(required=False, choices=['start', 'stop'], type='str'),
            start_ve_scan_all=dict(required=False, type='bool'),
            start_ve_build_metadata=dict(required=False, type='bool'),
            start_ve_delete_checkpoint=dict(required=False, type='bool'),
            start_ve_queue_operation=dict(required=False, type='bool'),
            start_ve_scan_old_data=dict(required=False, type='bool'),
            start_ve_qos_policy=dict(required=False, choices=['background', 'best-effort'], type='str'),
            stop_ve_all_operations=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            required_if=[('start_ve_scan_all', True, ['start_ve_scan_old_data'])],
            required_one_of=[('path', 'volume_name')],
            mutually_exclusive=[('policy', 'schedule'), ('path', 'volume_name')]
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if self.parameters['state'] == 'present':
            self.parameters['enabled'] = 'enabled'
        else:
            self.parameters['enabled'] = 'disabled'

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        partially_supported_rest_properties = [
            ['policy', (9, 7)], ['storage_efficiency_mode', (9, 10, 1)], ['path', (9, 9, 1)],
            # make op_state active/idle  is supported from 9.11.1 or later with REST.
            ['volume_efficiency', (9, 11, 1)], ['start_ve_scan_old_data', (9, 11, 1)]
        ]
        unsupported_rest_properties = [
            'schedule', 'start_ve_scan_all', 'start_ve_build_metadata', 'start_ve_delete_checkpoint',
            'start_ve_queue_operation', 'start_ve_qos_policy', 'stop_ve_all_operations'
        ]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties, partially_supported_rest_properties)
        self.volume_uuid = None
        if 'volume_efficiency' in self.parameters:
            if self.parameters['volume_efficiency'] == 'start':
                self.parameters['status'] = 'running' if not self.use_rest else 'active'
            else:
                self.parameters['status'] = 'idle'
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.validate_and_configure_zapi()
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def validate_and_configure_zapi(self):
        if self.parameters.get('storage_efficiency_mode'):
            self.module.fail_json(msg="Error: cannot set storage_efficiency_mode in ZAPI")
        # set default value for ZAPI like before as REST currently not support this option.
        if not self.parameters.get('start_ve_qos_policy'):
            self.parameters['start_ve_qos_policy'] = 'best-effort'
        if self.parameters.get('volume_name'):
            self.parameters['path'] = '/vol/' + self.parameters['volume_name']
            self.module.warn("ZAPI requires '/vol/' present in the volume path, updated path: %s" % self.parameters['path'])

    def get_volume_efficiency(self):
        """
        get the storage efficiency for a given path
        :return: dict of sis if exist, None if not
        """

        return_value = None

        if self.use_rest:
            api = 'storage/volumes'
            query = {'svm.name': self.parameters['vserver'], 'fields': 'uuid,efficiency'}
            if self.parameters.get('path'):
                query['efficiency.volume_path'] = self.parameters['path']
            else:
                query['name'] = self.parameters['volume_name']
            record, error = rest_generic.get_one_record(self.rest_api, api, query)
            if error:
                path_or_volume = self.parameters.get('path') or self.parameters.get('volume_name')
                self.module.fail_json(msg='Error getting volume efficiency for path %s on vserver %s: %s' % (
                    path_or_volume, self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )
            if record:
                return_value = self.format_rest_record(record)
            return return_value

        else:

            sis_get_iter = netapp_utils.zapi.NaElement('sis-get-iter')
            sis_status_info = netapp_utils.zapi.NaElement('sis-status-info')
            sis_status_info.add_new_child('path', self.parameters['path'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(sis_status_info)
            sis_get_iter.add_child_elem(query)
            try:
                result = self.server.invoke_successfully(sis_get_iter, True)
                if result.get_child_by_name('attributes-list'):
                    sis_status_attributes = result['attributes-list']['sis-status-info']
                    return_value = {
                        'path': sis_status_attributes['path'],
                        'enabled': sis_status_attributes['state'],
                        'status': sis_status_attributes['status'],
                        'schedule': sis_status_attributes['schedule'],
                        'enable_inline_compression': self.na_helper.get_value_for_bool(
                            True, sis_status_attributes.get_child_content('is-inline-compression-enabled')
                        ),
                        'enable_compression': self.na_helper.get_value_for_bool(True, sis_status_attributes.get_child_content('is-compression-enabled')),
                        'enable_inline_dedupe': self.na_helper.get_value_for_bool(True, sis_status_attributes.get_child_content('is-inline-dedupe-enabled')),
                        'enable_data_compaction': self.na_helper.get_value_for_bool(
                            True, sis_status_attributes.get_child_content('is-data-compaction-enabled')
                        ),
                        'enable_cross_volume_inline_dedupe': self.na_helper.get_value_for_bool(
                            True, sis_status_attributes.get_child_content('is-cross-volume-inline-dedupe-enabled')
                        ),
                        'enable_cross_volume_background_dedupe': self.na_helper.get_value_for_bool(
                            True, sis_status_attributes.get_child_content('is-cross-volume-background-dedupe-enabled')
                        )
                    }

                    if sis_status_attributes.get_child_by_name('policy'):
                        return_value['policy'] = sis_status_attributes['policy']
                    else:
                        return_value['policy'] = '-'

            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error getting volume efficiency for path %s on vserver %s: %s' % (
                    self.parameters['path'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )
            return return_value

    def enable_volume_efficiency(self):
        """
        Enables Volume efficiency for a given volume by path
        """
        sis_enable = netapp_utils.zapi.NaElement("sis-enable")
        sis_enable.add_new_child("path", self.parameters['path'])

        try:
            self.server.invoke_successfully(sis_enable, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error enabling storage efficiency for path %s on vserver %s: %s' % (self.parameters['path'],
                                  self.parameters['vserver'], to_native(error)), exception=traceback.format_exc())

    def disable_volume_efficiency(self):
        """
        Disables Volume efficiency for a given volume by path
        """
        sis_disable = netapp_utils.zapi.NaElement("sis-disable")
        sis_disable.add_new_child("path", self.parameters['path'])

        try:
            self.server.invoke_successfully(sis_disable, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error disabling storage efficiency for path %s: %s' % (self.parameters['path'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_volume_efficiency(self, body=None):
        """
        Modifies volume efficiency settings for a given volume by path
        """

        if self.use_rest:
            if not body:
                return
            dummy, error = rest_generic.patch_async(self.rest_api, 'storage/volumes', self.volume_uuid, body)
            if error:
                if 'Unexpected argument "storage_efficiency_mode".' in error or \
                        'The \"-storage-efficiency-mode\" parameter is only supported on AFF.' in error:
                    error = "cannot modify storage_efficiency mode in non AFF platform."
                if 'not authorized' in error:
                    error = "%s user is not authorized to modify volume efficiency" % self.parameters.get('username')
                self.module.fail_json(msg='Error in volume/efficiency patch: %s' % error)

        else:

            sis_config_obj = netapp_utils.zapi.NaElement("sis-set-config")
            sis_config_obj.add_new_child('path', self.parameters['path'])
            if 'schedule' in self.parameters:
                sis_config_obj.add_new_child('schedule', self.parameters['schedule'])
            if 'policy' in self.parameters:
                sis_config_obj.add_new_child('policy-name', self.parameters['policy'])
            if 'enable_compression' in self.parameters:
                sis_config_obj.add_new_child('enable-compression', self.na_helper.get_value_for_bool(False, self.parameters['enable_compression']))
            if 'enable_inline_compression' in self.parameters:
                sis_config_obj.add_new_child('enable-inline-compression', self.na_helper.get_value_for_bool(
                    False, self.parameters['enable_inline_compression'])
                )
            if 'enable_inline_dedupe' in self.parameters:
                sis_config_obj.add_new_child('enable-inline-dedupe', self.na_helper.get_value_for_bool(
                    False, self.parameters['enable_inline_dedupe'])
                )
            if 'enable_data_compaction' in self.parameters:
                sis_config_obj.add_new_child('enable-data-compaction', self.na_helper.get_value_for_bool(
                    False, self.parameters['enable_data_compaction'])
                )
            if 'enable_cross_volume_inline_dedupe' in self.parameters:
                sis_config_obj.add_new_child('enable-cross-volume-inline-dedupe', self.na_helper.get_value_for_bool(
                    False, self.parameters['enable_cross_volume_inline_dedupe'])
                )
            if 'enable_cross_volume_background_dedupe' in self.parameters:
                sis_config_obj.add_new_child('enable-cross-volume-background-dedupe', self.na_helper.get_value_for_bool(
                    False, self.parameters['enable_cross_volume_background_dedupe'])
                )

            try:
                self.server.invoke_successfully(sis_config_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error modifying storage efficiency for path %s: %s' % (self.parameters['path'], to_native(error)),
                                      exception=traceback.format_exc())

    def start_volume_efficiency(self):
        """
        Starts volume efficiency for a given flex volume by path
        """

        sis_start = netapp_utils.zapi.NaElement('sis-start')
        sis_start.add_new_child('path', self.parameters['path'])

        if 'start_ve_scan_all' in self.parameters:
            sis_start.add_new_child('scan-all', self.na_helper.get_value_for_bool(
                False, self.parameters['start_ve_scan_all'])
            )
        if 'start_ve_build_metadata' in self.parameters:
            sis_start.add_new_child('build-metadata', self.na_helper.get_value_for_bool(
                False, self.parameters['start_ve_build_metadata'])
            )
        if 'start_ve_delete_checkpoint' in self.parameters:
            sis_start.add_new_child('delete-checkpoint', self.na_helper.get_value_for_bool(
                False, self.parameters['start_ve_delete_checkpoint'])
            )
        if 'start_ve_queue_operation' in self.parameters:
            sis_start.add_new_child('queue-operation', self.na_helper.get_value_for_bool(
                False, self.parameters['start_ve_queue_operation'])
            )
        if 'start_ve_scan_old_data' in self.parameters:
            sis_start.add_new_child('scan', self.na_helper.get_value_for_bool(
                False, self.parameters['start_ve_scan_old_data'])
            )
        if 'start_ve_qos_policy' in self.parameters:
            sis_start.add_new_child('qos-policy', self.parameters['start_ve_qos_policy'])

        try:
            self.server.invoke_successfully(sis_start, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error starting storage efficiency for path %s on vserver %s: %s' % (self.parameters['path'],
                                  self.parameters['vserver'], to_native(error)), exception=traceback.format_exc())

    def stop_volume_efficiency(self):
        """
        Stops volume efficiency for a given flex volume by path
        """
        sis_stop = netapp_utils.zapi.NaElement('sis-stop')
        sis_stop.add_new_child('path', self.parameters['path'])
        if 'stop_ve_all_operations' in self.parameters:
            sis_stop.add_new_child('all-operations', self.na_helper.get_value_for_bool(
                False, self.parameters['stop_ve_all_operations'])
            )

        try:
            self.server.invoke_successfully(sis_stop, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error stopping storage efficiency for path %s on vserver %s: %s' % (self.parameters['path'],
                                  self.parameters['vserver'], to_native(error)), exception=traceback.format_exc())

    def format_rest_record(self, record):
        """
        returns current efficiency values.
        """
        self.volume_uuid = record['uuid']
        return_value = {
            'enabled': self.na_helper.safe_get(record, ['efficiency', 'state']),
            'status': self.na_helper.safe_get(record, ['efficiency', 'op_state']),
            'enable_compression': self.na_helper.safe_get(record, ['efficiency', 'compression']),
            'enable_inline_dedupe': self.na_helper.safe_get(record, ['efficiency', 'dedupe']),
            'enable_data_compaction': self.na_helper.safe_get(record, ['efficiency', 'compaction']),
            'enable_cross_volume_inline_dedupe': self.na_helper.safe_get(record, ['efficiency', 'cross_volume_dedupe'])
        }
        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            # efficiency is enabled if dedupe is either background or both.
            # it's disabled if both dedupe and compression is none.
            dedupe = self.na_helper.safe_get(record, ['efficiency', 'dedupe'])
            if dedupe in ['background', 'both']:
                return_value['enabled'] = 'enabled'
            elif dedupe == 'none' and self.na_helper.safe_get(record, ['efficiency', 'compression']) == 'none':
                return_value['enabled'] = 'disabled'
        if self.parameters.get('storage_efficiency_mode'):
            return_value['storage_efficiency_mode'] = self.na_helper.safe_get(record, ['efficiency', 'storage_efficiency_mode'])
        if self.parameters.get('policy'):
            return_value['policy'] = self.na_helper.safe_get(record, ['efficiency', 'policy', 'name'])
        compression, inline_compression, cross_volume_inline_dedupe, cross_volume_background_dedupe = False, False, False, False
        inline_dedupe, compaction = False, False
        if return_value['enable_compression'] in ['background', 'both']:
            compression = True
        if return_value['enable_compression'] in ['inline', 'both']:
            inline_compression = True
        if return_value['enable_cross_volume_inline_dedupe'] in ['inline', 'both']:
            cross_volume_inline_dedupe = True
        if return_value['enable_cross_volume_inline_dedupe'] in ['background', 'both']:
            cross_volume_background_dedupe = True
        if return_value['enable_inline_dedupe'] in ['inline', 'both']:
            inline_dedupe = True
        if return_value['enable_data_compaction'] == 'inline':
            compaction = True
        return_value['enable_compression'] = compression
        return_value['enable_inline_compression'] = inline_compression
        return_value['enable_cross_volume_inline_dedupe'] = cross_volume_inline_dedupe
        return_value['enable_cross_volume_background_dedupe'] = cross_volume_background_dedupe
        return_value['enable_inline_dedupe'] = inline_dedupe
        return_value['enable_data_compaction'] = compaction
        return return_value

    def form_modify_body_rest(self, modify, current):
        # disable volume efficiency requires dedupe and compression set to 'none'.
        if modify.get('enabled') == 'disabled':
            return {'efficiency': {'dedupe': 'none', 'compression': 'none', 'compaction': 'none', 'cross_volume_dedupe': 'none'}}
        body = {}
        if modify.get('enabled') == 'enabled':
            body['efficiency.dedupe'] = 'background'
        # there are cases where ZAPI allows setting cross_volume_background_dedupe and inline_dedupe and REST not.
        if 'enable_compression' in modify or 'enable_inline_compression' in modify:
            body['efficiency.compression'] = self.derive_efficiency_type(modify.get('enable_compression'), modify.get('enable_inline_compression'),
                                                                         current.get('enable_compression'), current.get('enable_inline_compression'))

        if 'enable_cross_volume_background_dedupe' in modify or 'enable_cross_volume_inline_dedupe' in modify:
            body['efficiency.cross_volume_dedupe'] = self.derive_efficiency_type(modify.get('enable_cross_volume_background_dedupe'),
                                                                                 modify.get('enable_cross_volume_inline_dedupe'),
                                                                                 current.get('enable_cross_volume_background_dedupe'),
                                                                                 current.get('enable_cross_volume_inline_dedupe'))

        if modify.get('enable_data_compaction'):
            body['efficiency.compaction'] = 'inline'
        elif modify.get('enable_data_compaction') is False:
            body['efficiency.compaction'] = 'none'

        if modify.get('enable_inline_dedupe'):
            body['efficiency.dedupe'] = 'both'
        elif modify.get('enable_inline_dedupe') is False:
            body['efficiency.dedupe'] = 'background'
        # REST changes policy to default, so use policy in params.
        if self.parameters.get('policy'):
            body['efficiency.policy.name'] = self.parameters['policy']
        if modify.get('storage_efficiency_mode'):
            body['efficiency.storage_efficiency_mode'] = modify['storage_efficiency_mode']

        # start/stop vol efficiency
        if modify.get('status'):
            body['efficiency.scanner.state'] = modify['status']
        if 'start_ve_scan_old_data' in self.parameters:
            body['efficiency.scanner.scan_old_data'] = self.parameters['start_ve_scan_old_data']
        return body

    @staticmethod
    def derive_efficiency_type(desired_background, desired_inline, current_background, current_inline):
        if ((desired_background and desired_inline) or
           (desired_background and desired_inline is None and current_inline) or
           (desired_background is None and desired_inline and current_background)):
            return 'both'
        elif ((desired_background and desired_inline is False) or
              (desired_background and desired_inline is None and not current_inline) or
              (desired_background is None and desired_inline is False and current_background)):
            return 'background'
        elif ((desired_background is False and desired_inline) or
              (desired_background is False and desired_inline is None and current_inline) or
              (desired_background is None and desired_inline and not current_background)):
            return 'inline'
        elif ((desired_background is False and desired_inline is False) or
              (desired_background is False and desired_inline is None and not current_inline) or
              (desired_background is None and desired_inline is False and not current_background)):
            return 'none'

    def validate_efficiency_compression(self, modify):
        """
        validate:
          - no efficiency keys are set when state is disabled.
        """
        if self.parameters['enabled'] == 'disabled':
            # if any of the keys are set, efficiency gets enabled, error out if any of eff keys are set and state is absent.
            unsupported_enable_eff_keys = [
                'enable_compression', 'enable_inline_compression', 'enable_inline_dedupe',
                'enable_cross_volume_inline_dedupe', 'enable_cross_volume_background_dedupe', 'enable_data_compaction'
            ]
            used_unsupported_enable_eff_keys = [key for key in unsupported_enable_eff_keys if self.parameters.get(key)]
            if used_unsupported_enable_eff_keys:
                disable_str = 'when volume efficiency already disabled, retry with state: present'
                if modify.get('enabled') == 'disabled':
                    disable_str = 'when trying to disable volume efficiency'
                self.module.fail_json(msg="Error: cannot set compression keys: %s %s" % (used_unsupported_enable_eff_keys, disable_str))

    def apply(self):
        current = self.get_volume_efficiency()
        ve_status = None

        # If the volume efficiency does not exist for a given path to create this current is set to disabled
        # this is for ONTAP systems that do not enable efficiency by default.
        if current is None:
            current = {'enabled': 'disabled'}
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        to_modify = copy.deepcopy(modify)
        self.validate_efficiency_compression(modify)
        if self.na_helper.changed and not self.module.check_mode:
            # enable/disable, start/stop & modify vol efficiency handled in REST PATCH.
            if self.use_rest:
                self.modify_volume_efficiency(self.form_modify_body_rest(modify, current))
            else:
                if 'enabled' in modify:
                    if modify['enabled'] == 'enabled':
                        self.enable_volume_efficiency()
                        # Checking to see if there are any additional parameters that need to be set after
                        # enabling volume efficiency required for Non-AFF systems
                        current = self.get_volume_efficiency()
                        modify = self.na_helper.get_modified_attributes(current, self.parameters)
                        to_modify['modify_after_enable'] = copy.deepcopy(modify)
                    elif modify['enabled'] == 'disabled':
                        self.disable_volume_efficiency()
                    # key may not exist anymore, if modify is refreshed at line 686
                    modify.pop('enabled', None)

                if 'status' in modify:
                    ve_status = modify['status']
                    del modify['status']

                # Removed the enabled and volume efficiency status,
                # if there is anything remaining in the modify dict we need to modify.
                if modify:
                    self.modify_volume_efficiency()

                if ve_status == 'running':
                    self.start_volume_efficiency()
                elif ve_status == 'idle':
                    self.stop_volume_efficiency()

        result = netapp_utils.generate_result(self.na_helper.changed, modify=to_modify)
        self.module.exit_json(**result)


def main():
    """
    Enables, modifies or disables NetApp Ontap volume efficiency
    """
    obj = NetAppOntapVolumeEfficiency()
    obj.apply()


if __name__ == '__main__':
    main()
