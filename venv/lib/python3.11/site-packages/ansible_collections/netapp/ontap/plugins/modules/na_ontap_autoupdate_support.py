#!/usr/bin/python
"""
create auto-update module to enable automatic software update
"""

# (c) 2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_autoupdate_support
short_description: NetApp ONTAP enable auto update status.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '23.1.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Enable automatic software update.
options:
  enabled:
    description:
      - Flag indicating feature state.
    type: bool
  force:
    description:
      - Set the force flag to true to enable the automatic update feature regardless of how AutoSupport is configured.
      - Without this flag set to true, an attempt to enable the automatic update feature fails unless AutoSupport is enabled,
        its transport is HTTPS, and the AutoSupport OnDemand feature is enabled.
    type: bool
'''

EXAMPLES = """
- name: Modify status to enable automatic update
  netapp.ontap.na_ontap_autoupdate_support:
    enabled: true
    force: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""
from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPAutoUpdateSupport:
    """Class with auto update methods"""

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            enabled=dict(required=False, type='bool'),
            force=dict(required=False, type='bool'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_autoupdate_support', 9, 10, 1)
        partially_supported_rest_properties = [['force', (9, 16, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)

    def get_auto_update_status(self):
        """
        Retrieves the current status of the automatic update feature
        """
        query = {'fields': 'enabled'}
        api = 'support/auto-update'
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg="Error retrieving the current status of the automatic update feature info: %s" % error)
        return record

    def modify_auto_update_status(self, modify):
        """
        Updates the current enabled status of the automatic update feature
        """
        params = {}
        query = {}
        api = 'support/auto-update'
        if 'enabled' in modify:
            params['enabled'] = self.parameters.get('enabled')
        if 'force' in self.parameters:
            query['force'] = self.parameters.get('force')
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, params, query)
        if error:
            self.module.fail_json(msg="Error on modifying the current status of the automatic update feature: %s" % error)

    def apply(self):
        """
        Apply action to enable auto update support
        """
        current = self.get_auto_update_status()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None
        if self.na_helper.changed and not self.module.check_mode:
            if modify:
                self.modify_auto_update_status(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    community_obj = NetAppONTAPAutoUpdateSupport()
    community_obj.apply()


if __name__ == '__main__':
    main()
