#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_fdss
short_description: NetApp ONTAP File Directory Security Set.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Set file directory security information.
- This module is not idempotent. If re-running this module to apply the currently assigned policy, the policy will be reassigned.
options:
  state:
    description:
    - Whether the specified Policy Task should exist or not.
    choices: ['present']
    default: present
    type: str
  name:
    description:
    - Specifies the security policy to apply.
    required: true
    type: str

  vserver:
    description:
    - Specifies the Vserver that contains the path to which the security policy is applied.
    required: true
    type: str
"""
EXAMPLES = """
- name: Set File Directory Security
  netapp.ontap.na_ontap_fdss:
    state: present
    vserver: "svm1"
    name: "ansible_pl"
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapFDSS():
    """
        Applys a File Directory Security Policy
    """
    def __init__(self):
        """
            Initialize the Ontap File Directory Security class
        """

        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present'], default='present'),
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
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
            self.module.fail_json(msg=self.rest_api.requires_ontap_version('na_ontap_fdss', '9.6'))

    def set_fdss(self):
        """
        Apply File Directory Security
        """

        api = "private/cli/vserver/security/file-directory/apply"
        query = {
            'policy_name': self.parameters['name'],
            'vserver': self.parameters['vserver'],
        }

        response, error = self.rest_api.post(api, query)  # response will contain the job ID created by the post.
        response, error = rrh.check_for_error_and_job_results(api, response, error, self.rest_api)

        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        self.set_fdss()
        self.module.exit_json(changed=True)


def main():
    """
    File Directory Security Policy Tasks
    """
    obj = NetAppOntapFDSS()
    obj.apply()


if __name__ == '__main__':
    main()
