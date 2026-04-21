#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_service_policy
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_service_policy

short_description: NetApp ONTAP service policy configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Add, modify, or remove service policies.
  - This module requires ONTAP 9.8 or later, and only supports REST.

options:
  state:
    description:
      - Whether the specified service policy should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'
  name:
    description:
      - The name of the service policy.
    required: true
    type: str
  ipspace:
    description:
      - Name of the ipspace.
      - Required for cluster-scoped service policies.
      - Optional for SVM-scoped service policies.
    type: str
  services:
    description:
      - List of services to associate to this service policy.
      - To remove all services, use "no_service".  No other value is allowed when no_service is present.
      - Note - not all versions of ONTAP support all values, and new ones may be added.
      - See C(known_services) and C(additional_services) to address unknow service errors.
    type: list
    elements: str
  vserver:
    description:
      - The name of the vserver to use.
      - Omit this option for cluster scoped user accounts.
    type: str
  scope:
    description:
      - Set to "svm" for interfaces owned by an SVM. Otherwise, set to "cluster".
      - svm is assumed if vserver is set.
      - cluster is assumed is vserver is not set.
    type: str
    choices: ['cluster', 'svm']
  known_services:
    description:
      - List of known services in 9.12.1
      - An error is raised if any service in C(services) is not in this list or C(new_services).
      - Modify this list to restrict the services you want to support if needed.
    default: [cluster_core, intercluster_core, management_core, management_autosupport, management_bgp, management_ems, management_https, management_http,
              management_ssh, management_portmap, data_core, data_nfs, data_cifs, data_flexcache, data_iscsi, data_s3_server, data_dns_server,
              data_fpolicy_client, management_ntp_client, management_dns_client, management_ad_client, management_ldap_client, management_nis_client,
              management_snmp_server, management_rsh_server, management_telnet_server, management_ntp_server, data_nvme_tcp, backup_ndmp_control,
              management_log_forwarding]
    type: list
    elements: str
    version_added: 22.0.0
  additional_services:
    description:
      - As an alternative to updating the C(known_services), new services can be specified here.
    type: list
    elements: str
    version_added: 22.0.0

notes:
  - This module supports check_mode.
  - This module does not support 'allowed-addresses' as REST does not support it.  It defaults to 0.0.0.0/0.
'''

EXAMPLES = """
- name: Create service policy
  netapp.ontap.na_ontap_service_policy:
    state: present
    name: "{{ service_policy_name }}"
    services:
      - data_core
      - data_nfs
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete single service policy
  netapp.ontap.na_ontap_service_policy:
    state: absent
    name: "{{ service_policy_name }}"
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify single service policy
  netapp.ontap.na_ontap_service_policy:
    state: present
    name: "{{ service_policy_name }}"
    services:
      - data_core
      - data_nfs
      - data_cifs
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify service policy, remove services
  netapp.ontap.na_ontap_service_policy:
    state: present
    name: "{{ service_policy_name }}"
    services:
      - no_service
    vserver: "{{ vserver }}"

- name: Modify service policy at cluster level
  netapp.ontap.na_ontap_service_policy:
    state: present
    name: "{{ service_policy_name }}"
    ipspace: ansibleIpspace
    scope: cluster
    services:
      - management_core
      - management_autosupport
      - management_ems
"""

RETURN = """
cd_action:
  description: whether a public key is created or deleted.
  returned: success
  type: str

modify:
  description: attributes that were modified if the key already exists.
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapServicePolicy:
    """
    Common operations to manage public keys.
    """

    def __init__(self):
        self.use_rest = False
        argument_spec = netapp_utils.na_ontap_rest_only_spec()
        argument_spec.update(dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            ipspace=dict(type='str'),
            scope=dict(type='str', choices=['cluster', 'svm']),
            services=dict(type='list', elements='str'),
            vserver=dict(type='str'),
            known_services=dict(type='list', elements='str',
                                default=['cluster_core', 'intercluster_core', 'management_core', 'management_autosupport', 'management_bgp', 'management_ems',
                                         'management_https', 'management_http', 'management_ssh', 'management_portmap', 'data_core', 'data_nfs', 'data_cifs',
                                         'data_flexcache', 'data_iscsi', 'data_s3_server', 'data_dns_server', 'data_fpolicy_client', 'management_ntp_client',
                                         'management_dns_client', 'management_ad_client', 'management_ldap_client', 'management_nis_client',
                                         'management_snmp_server', 'management_rsh_server', 'management_telnet_server', 'management_ntp_server',
                                         'data_nvme_tcp', 'backup_ndmp_control', 'management_log_forwarding']),
            additional_services=dict(type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=argument_spec,
            required_if=[
                ('scope', 'cluster', ['ipspace']),
                ('scope', 'svm', ['vserver']),
                ('vserver', None, ['ipspace']),
            ],
            required_one_of=[
                ('ipspace', 'vserver')
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # REST API is required
        self.rest_api = OntapRestAPI(self.module)
        # check version
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_service_policy', 9, 8)
        self.validate_inputs()

    def validate_inputs(self):
        services = self.parameters.get('services')
        if services and 'no_service' in services:
            if len(services) > 1:
                self.module.fail_json(msg='Error: no other service can be present when no_service is specified.  Got: %s' % services)
            self.parameters['services'] = []
        known_services = self.parameters.get('known_services', []) + self.parameters.get('additional_services', [])
        unknown_services = [service for service in self.parameters.get('services', []) if service not in known_services]
        if unknown_services:
            plural = 's' if len(services) > 1 else ''
            self.module.fail_json(msg='Error: unknown service%s: %s.  New services may need to be added to "additional_services".'
                                  % (plural, ','.join(unknown_services)))

        scope = self.parameters.get('scope')
        if scope is None:
            self.parameters['scope'] = 'cluster' if self.parameters.get('vserver') is None else 'svm'
        elif scope == 'cluster' and self.parameters.get('vserver') is not None:
            self.module.fail_json(msg='Error: vserver cannot be set when "scope: cluster" is specified.  Got: %s' % self.parameters.get('vserver'))
        elif scope == 'svm' and self.parameters.get('vserver') is None:
            self.module.fail_json(msg='Error: vserver cannot be None when "scope: svm" is specified.')

    def get_service_policy(self):
        api = 'network/ip/service-policies'
        query = {
            'name': self.parameters['name'],
            'fields': 'name,uuid,ipspace,services,svm,scope'
        }
        if self.parameters.get('vserver') is None:
            # vserser is empty for cluster
            query['scope'] = 'cluster'
        else:
            query['svm.name'] = self.parameters['vserver']

        if self.parameters.get('ipspace') is not None:
            query['ipspace.name'] = self.parameters['ipspace']
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            msg = "Error in get_service_policy: %s" % error
            self.module.fail_json(msg=msg)
        if record:
            return {
                'uuid': record['uuid'],
                'name': record['name'],
                'ipspace': record['ipspace']['name'],
                'scope': record['scope'],
                'vserver': self.na_helper.safe_get(record, ['svm', 'name']),
                'services': record['services']
            }
        return None

    def create_service_policy(self):
        api = 'network/ip/service-policies'
        body = {
            'name': self.parameters['name']
        }
        if self.parameters.get('vserver') is not None:
            body['svm.name'] = self.parameters['vserver']

        for attr in ('ipspace', 'scope', 'services'):
            value = self.parameters.get(attr)
            if value is not None:
                body[attr] = value

        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            msg = "Error in create_service_policy: %s" % error
            self.module.fail_json(msg=msg)

    def modify_service_policy(self, current, modify):
        # sourcery skip: dict-comprehension
        api = 'network/ip/service-policies/%s' % current['uuid']
        modify_copy = dict(modify)
        body = {}
        for key in modify:
            if key in ('services',):
                body[key] = modify_copy.pop(key)
        if modify_copy:
            msg = 'Error: attributes not supported in modify: %s' % modify_copy
            self.module.fail_json(msg=msg)
        if not body:
            msg = 'Error: nothing to change - modify called with: %s' % modify
            self.module.fail_json(msg=msg)

        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body)
        if error:
            msg = "Error in modify_service_policy: %s" % error
            self.module.fail_json(msg=msg)

    def delete_service_policy(self, current):
        api = 'network/ip/service-policies/%s' % current['uuid']

        dummy, error = rest_generic.delete_async(self.rest_api, api, None, None)
        if error:
            msg = "Error in delete_service_policy: %s" % error
            self.module.fail_json(msg=msg)

    def get_actions(self):
        """Determines whether a create, delete, modify action is required
        """
        cd_action, modify, current = None, None, None
        current = self.get_service_policy()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
        return cd_action, modify, current

    def apply(self):
        cd_action, modify, current = self.get_actions()

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_service_policy()
            elif cd_action == 'delete':
                self.delete_service_policy(current)
            elif modify:
                self.modify_service_policy(current, modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify, extra_responses={'scope': self.module.params})
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapServicePolicy()
    obj.apply()


if __name__ == '__main__':
    main()
