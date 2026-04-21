#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# This module implements the operations for ONTAP MCC Mediator.
# The Mediator is supported for MCC IP configs from ONTAP 9.7 or later.
# This module requires REST APIs for Mediator which is supported from
# ONTAP 9.8 (DW) or later

'''
na_ontap_mcc_mediator
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
module: na_ontap_mcc_mediator
short_description: NetApp ONTAP Add and Remove MetroCluster Mediator
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 20.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Add and remove ONTAP MCC Mediator
options:
  state:
    choices: ['present', 'absent']
    description:
      - "Whether MCCIP Mediator is present or not."
    default: present
    type: str

  mediator_address:
    description:
    - ip address of the mediator
    type: str
    required: true

  mediator_user:
    description:
    - username of the mediator
    type: str
    required: true

  mediator_password:
    description:
    - password of the mediator
    type: str
    required: true

'''

EXAMPLES = """
- name: Add ONTAP MCCIP Mediator
  netapp.ontap.na_ontap_mcc_mediator:
    state: present
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    mediator_address: mediator_ip
    mediator_user: metrocluster_admin
    mediator_password: metrocluster_password

- name: Delete ONTAP MCCIP Mediator
  netapp.ontap.na_ontap_mcc_mediator:
    state: absent
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    mediator_user: metrocluster_admin
    mediator_password: metrocluster_password
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule


class NetAppOntapMccipMediator(object):
    """
    Mediator object for Add/Remove/Display
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            mediator_address=dict(required=True, type='str'),
            mediator_user=dict(required=True, type='str'),
            mediator_password=dict(required=True, type='str', no_log=True),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            self.module.fail_json(msg=self.rest_api.requires_ontap_9_6('na_ontap_mcc_mediator'))

    def add_mediator(self):
        """
        Adds an ONTAP Mediator to MCC configuration
        """
        api = 'cluster/mediators'
        params = {
            'ip_address': self.parameters['mediator_address'],
            'password': self.parameters['mediator_password'],
            'user': self.parameters['mediator_user']
        }
        dummy, error = self.rest_api.post(api, params)
        if error:
            self.module.fail_json(msg=error)

    def remove_mediator(self, current_uuid):
        """
        Removes the ONTAP Mediator from MCC configuration
        """
        api = 'cluster/mediators/%s' % current_uuid
        params = {
            'ip_address': self.parameters['mediator_address'],
            'password': self.parameters['mediator_password'],
            'user': self.parameters['mediator_user']
        }
        dummy, error = self.rest_api.delete(api, params)
        if error:
            self.module.fail_json(msg=error)

    def get_mediator(self):
        """
        Determine if the MCC configuration has added an ONTAP Mediator
        """
        api = "cluster/mediators"
        message, error = self.rest_api.get(api, None)
        if error:
            self.module.fail_json(msg=error)
        if message['num_records'] > 0:
            return message['records'][0]['uuid']
        return None

    def apply(self):
        """
        Apply action to MCC Mediator
        """
        current = self.get_mediator()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == 'create':
                    self.add_mediator()
                elif cd_action == 'delete':
                    self.remove_mediator(current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """
    Add, Remove and display ONTAP MCC Mediator
    """
    mediator_obj = NetAppOntapMccipMediator()
    mediator_obj.apply()


if __name__ == '__main__':
    main()
