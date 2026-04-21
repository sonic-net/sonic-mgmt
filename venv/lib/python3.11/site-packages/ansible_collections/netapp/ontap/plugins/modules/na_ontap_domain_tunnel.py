#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
module: na_ontap_domain_tunnel
short_description: NetApp ONTAP domain tunnel
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete or modify the domain tunnel.
options:
  state:
    description:
    - Whether the domain tunnel should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - The name of the vserver that the domain tunnel should be created or deleted on.
    required: true
    type: str
'''

EXAMPLES = """
- name: Create Domain Tunnel
  netapp.ontap.na_ontap_domain_tunnel:
    state: present
    vserver: svm1
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

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapDomainTunnel(object):

    def __init__(self):
        """
            Initialize the ONTAP domain tunnel class
        """
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str')
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
            self.module.fail_json(msg=self.rest_api.requires_ontap_version('na_ontap_domain_tunnel', '9.7'))

    def get_domain_tunnel(self):
        """
            Get the current domain tunnel info
        """
        api = "/security/authentication/cluster/ad-proxy"
        message, error = self.rest_api.get(api)

        if error:
            if int(error['code']) != 4:  # error code 4 is empty table
                self.module.fail_json(msg=error)
        if message:
            message = {
                'vserver': message['svm']['name']
            }
            return message
        else:
            return None

    def create_domain_tunnel(self):
        """
            Creates the domain tunnel on the specified vserver
        """
        api = "/security/authentication/cluster/ad-proxy"
        body = {
            "svm": {
                "name": self.parameters['vserver']
            }
        }
        dummy, error = self.rest_api.post(api, body)
        if error:
            self.module.fail_json(msg=error)

    def modify_domain_tunnel(self):
        """
            Modifies the domain tunnel on the specified vserver
        """
        api = "/security/authentication/cluster/ad-proxy"
        body = {
            "svm": {
                "name": self.parameters['vserver']
            }
        }
        dummy, error = self.rest_api.patch(api, body)
        if error:
            self.module.fail_json(msg=error)

    def delete_domain_tunnel(self):
        """
            Deletes the current domain tunnel
        """
        api = "/security/authentication/cluster/ad-proxy"

        dummy, error = self.rest_api.delete(api)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        current = self.get_domain_tunnel()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.create_domain_tunnel()
                elif cd_action == 'delete':
                    self.delete_domain_tunnel()
                elif modify:
                    self.modify_domain_tunnel()

        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp ONTAP Domain Tunnel and runs the correct playbook task
    """
    obj = NetAppOntapDomainTunnel()
    obj.apply()


if __name__ == '__main__':
    main()
