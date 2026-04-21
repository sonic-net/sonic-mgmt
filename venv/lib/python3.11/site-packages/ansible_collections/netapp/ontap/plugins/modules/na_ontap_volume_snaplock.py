#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_ontap_volume_snaplock

short_description: NetApp ONTAP manage volume snaplock retention.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_zapi
version_added: '20.2.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Modifies the snaplock retention of volumes on NetApp ONTAP.
options:
  name:
    description:
      - The name of the volume to manage.
    type: str
    required: true

  vserver:
    description:
      - Name of the vserver to use.
    type: str
    required: true

  default_retention_period:
    description:
      - Specifies the default retention period that will be applied.
      - The format is "<number> <units>" for example "10 days", the following units are valid
      - "seconds"
      - "minutes"
      - "hours"
      - "days"
      - "months"
      - "years"
      - If this option is specified as "max", then maximum_retention_period will be used as the default retention period.
    type: str

  autocommit_period:
    description:
      - Specifies the autocommit-period for the snaplock volume.
      - The format is "<number> <units>" for example "8 hours", the following units are valid
      - "seconds"
      - "minutes"
      - "hours"
      - "days"
      - "months"
      - "years"
    type: str

  is_volume_append_mode_enabled:
    description:
      - Specifies if the volume append mode must be enabled or disabled.
      - It can be modified only when the volume is not mounted and does not have any data or Snapshot copy.
      - Volume append mode is not supported on SnapLock audit log volumes.
      - When it is enabled, all files created with write permissions on the volume will be WORM appendable files by default.
      - All WORM appendable files not modified for a period greater than the autocommit period of the volume are also committed to WORM read-only state.
    type: bool

  maximum_retention_period:
    description:
      - Specifies the allowed maximum retention period that will be applied.
      - The format is "<number> <units>" for example "2 years", the following units are valid
      - "seconds"
      - "minutes"
      - "hours"
      - "days"
      - "months"
      - "years"
    type: str

  minimum_retention_period:
    description:
      - Specifies the allowed minimum retention period that will be applied.
      - The format is "<number> <units>" for example "1 days", the following units are valid
      - "seconds"
      - "minutes"
      - "hours"
      - "days"
      - "months"
      - "years"
    type: str

notes:
  - supports ZAPI only.
  - for REST, snaplock is supported in na_ontap_volume starting with 21.18.0.
'''

EXAMPLES = """
- name: Set volume snaplock
  netapp.ontap.na_ontap_volume_snaplock:
    vserver: ansibleSVM
    name: ansibleVolume
    default_retention_period: "5 days"
    minimum_retention_period: "0 years"
    maximum_retention_period: "10 days"
    is_volume_append_mode_enabled: false
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapVolumeSnaplock(object):
    '''Class with volume operations'''

    def __init__(self):
        '''Initialize module parameters'''

        self.argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            default_retention_period=dict(required=False, type='str'),
            maximum_retention_period=dict(required=False, type='str'),
            minimum_retention_period=dict(required=False, type='str'),
            autocommit_period=dict(required=False, type='str'),
            is_volume_append_mode_enabled=dict(required=False, type='bool'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.module.warn('The module only supports ZAPI; refer to netapp.ontap.na_ontap_volume module for RESTful equivalent.')

        if HAS_NETAPP_LIB is False:
            self.module.fail_json(msg="the python NetApp-Lib module is required")
        self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_volume_snaplock_attrs(self):
        """
        Return volume-get-snaplock-attrs query results
        :param vol_name: name of the volume
        :return: dict of the volume snaplock attrs
        """
        volume_snaplock = netapp_utils.zapi.NaElement('volume-get-snaplock-attrs')
        volume_snaplock.add_new_child('volume', self.parameters['name'])

        try:
            result = self.server.invoke_successfully(volume_snaplock, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching snaplock attributes for volume %s : %s'
                                      % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

        return_value = None

        if result.get_child_by_name('snaplock-attrs'):
            volume_snaplock_attributes = result['snaplock-attrs']['snaplock-attrs-info']
            return_value = {
                'autocommit_period': volume_snaplock_attributes['autocommit-period'],
                'default_retention_period': volume_snaplock_attributes['default-retention-period'],
                'is_volume_append_mode_enabled': self.na_helper.get_value_for_bool(True, volume_snaplock_attributes['is-volume-append-mode-enabled']),
                'maximum_retention_period': volume_snaplock_attributes['maximum-retention-period'],
                'minimum_retention_period': volume_snaplock_attributes['minimum-retention-period'],
            }
        return return_value

    def set_volume_snaplock_attrs(self, modify):
        '''Set ONTAP volume snaplock attributes'''
        volume_snaplock_obj = netapp_utils.zapi.NaElement('volume-set-snaplock-attrs')
        volume_snaplock_obj.add_new_child('volume', self.parameters['name'])
        if modify.get('autocommit_period') is not None:
            volume_snaplock_obj.add_new_child('autocommit-period', self.parameters['autocommit_period'])
        if modify.get('default_retention_period') is not None:
            volume_snaplock_obj.add_new_child('default-retention-period', self.parameters['default_retention_period'])
        if modify.get('is_volume_append_mode_enabled') is not None:
            volume_snaplock_obj.add_new_child('is-volume-append-mode-enabled',
                                              self.na_helper.get_value_for_bool(False, self.parameters['is_volume_append_mode_enabled']))
        if modify.get('maximum_retention_period') is not None:
            volume_snaplock_obj.add_new_child('maximum-retention-period', self.parameters['maximum_retention_period'])
        if modify.get('minimum_retention_period') is not None:
            volume_snaplock_obj.add_new_child('minimum-retention-period', self.parameters['minimum_retention_period'])
        try:
            self.server.invoke_successfully(volume_snaplock_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error setting snaplock attributes for volume %s : %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current, modify = self.get_volume_snaplock_attrs(), None
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            self.set_volume_snaplock_attrs(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    '''Set volume snaplock attributes from playbook'''
    obj = NetAppOntapVolumeSnaplock()
    obj.apply()


if __name__ == '__main__':
    main()
