#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_fdsp
short_description: NetApp ONTAP create or delete a file directory security policy
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create or delete a file directory security policy.
options:
  state:
    description:
    - Whether the specified policy should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  name:
    description:
    - Specifies the name of the policy.
    required: true
    type: str

  vserver:
    description:
    - Specifies the vserver for the security policy.
    required: true
    type: str
"""

EXAMPLES = """
- name: Create File Directory Security Policy
  netapp.ontap.na_ontap_fdsp:
    state: present
    name: "ansible_security_policyl"
    vserver: "svm1"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete File Directory Security Policy
  netapp.ontap.na_ontap_fdsp:
    state: absent
    vserver: "svm1"
    name: "ansible_security_policyl"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapFDSP():
    """
        Creates or Destroys a File Directory Security Policy
    """
    def __init__(self):
        """
            Initialize the ONTAP File Directory Security Policy class
        """
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            self.module.fail_json(msg=self.rest_api.requires_ontap_version('na_ontap_fdsp', '9.6'))

    def get_fdsp(self):
        """
        Get File Directory Security Policy
        """
        api = "private/cli/vserver/security/file-directory/policy"
        query = {
            'policy-name': self.parameters['name'],
            'vserver': self.parameters['vserver']
        }

        message, error = self.rest_api.get(api, query)
        records, error = rrh.check_for_0_or_more_records(api, message, error)

        if error:
            self.module.fail_json(msg=error)

        return records if records else None

    def add_fdsp(self):
        """
        Adds a new File Directory Security Policy
        """
        api = "private/cli/vserver/security/file-directory/policy"
        body = {
            'policy-name': self.parameters['name'],
            'vserver': self.parameters['vserver']
        }

        dummy, error = self.rest_api.post(api, body)
        if error:
            self.module.fail_json(msg=error)

    def remove_fdsp(self):
        """
        Deletes a File Directory Security Policy
        """
        api = "private/cli/vserver/security/file-directory/policy"
        body = {
            'policy-name': self.parameters['name'],
            'vserver': self.parameters['vserver']
        }

        dummy, error = self.rest_api.delete(api, body)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        current = self.get_fdsp()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.add_fdsp()
                elif cd_action == 'delete':
                    self.remove_fdsp()

        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """
    Creates or removes File Directory Security Policy
    """
    obj = NetAppOntapFDSP()
    obj.apply()


if __name__ == '__main__':
    main()
