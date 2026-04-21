#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_dns
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_dns
short_description: NetApp ONTAP Create, delete, modify DNS servers.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Create, delete, modify DNS servers.
- With REST, the module is currently limited to data vservers for delete or modify operations.
options:
  state:
    description:
      - Whether the DNS servers should be enabled for the given vserver.
    choices: ['present', 'absent']
    type: str
    default: present

  vserver:
    description:
      - The name of the vserver to use.
      - With REST, for cluster scoped DNS, omit this option or set it to NULL for ONTAP 9.13.1 or later and
        provide cluster vserver as its value for ONTAP 9.12.1 or earlier.
      - With ZAPI or REST, for cluster scoped DNS, this can also be set to the cluster vserver name.
    type: str

  domains:
    description:
    - List of DNS domains such as 'sales.bar.com'. The first domain is the one that the Vserver belongs to.
    type: list
    elements: str

  nameservers:
    description:
    - List of IPv4 addresses of name servers such as '123.123.123.123'.
    type: list
    elements: str

  skip_validation:
    type: bool
    description:
    - By default, all nameservers are checked to validate they are available to resolve.
    - If you DNS servers are not yet installed or momentarily not available, you can set this option to 'true'
    - to bypass the check for all servers specified in nameservers field.
    - With REST, requires ONTAP 9.9.1 or later and ignored for cluster DNS operations.
    version_added: 2.8.0
'''

EXAMPLES = """
- name: Create or modify DNS
  netapp.ontap.na_ontap_dns:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    vserver: "{{ vservername }}"
    domains: sales.bar.com
    nameservers: 10.193.0.250,10.192.0.250
    skip_validation: true

- name: Create or modify cluster DNS with REST
  netapp.ontap.na_ontap_dns:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    domains: sales.bar.com
    nameservers: 10.193.0.250,10.192.0.250
"""

RETURN = """

"""
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule


class NetAppOntapDns:
    """
    Enable and Disable dns
    """

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=False, type='str'),
            domains=dict(required=False, type='list', elements='str'),
            nameservers=dict(required=False, type='list', elements='str'),
            skip_validation=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[('state', 'present', ['domains', 'nameservers'])],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Cluster vserver and data vserver use different REST API.
        self.is_cluster = False

        # REST API should be used for ONTAP 9.6 or higher, ZAPI for lower version
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, [['skip_validation', (9, 9, 1)]])
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            if not self.parameters.get('vserver'):
                self.module.fail_json(msg="Error: vserver is a required parameter with ZAPI.")
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
        return

    def patch_cluster_dns(self):
        api = 'cluster'
        body = {
            'dns_domains': self.parameters['domains'],
            'name_servers': self.parameters['nameservers']
        }
        if self.parameters.get('skip_validation'):
            self.module.warn("skip_validation is ignored for cluster DNS operations in REST.")
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body)
        if error:
            self.module.fail_json(msg="Error updating cluster DNS options: %s" % error)

    def create_dns_rest(self):
        """
        Create DNS server
        :return: none
        """
        if self.is_cluster or not self.parameters.get('vserver'):
            # with 9.13, using scope=cluster with POST on 'name-services/dns' does not work:
            # "svm.uuid" is a required field
            return self.patch_cluster_dns()

        api = 'name-services/dns'
        body = {
            'domains': self.parameters['domains'],
            'servers': self.parameters['nameservers'],
            'svm': {
                'name': self.parameters['vserver']
            }
        }
        if 'skip_validation' in self.parameters:
            body['skip_config_validation'] = self.parameters['skip_validation']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating DNS service: %s" % error)

    def create_dns(self):
        """
        Create DNS server
        :return: none
        """
        if self.use_rest:
            return self.create_dns_rest()

        dns = netapp_utils.zapi.NaElement('net-dns-create')
        nameservers = netapp_utils.zapi.NaElement('name-servers')
        domains = netapp_utils.zapi.NaElement('domains')
        for each in self.parameters['nameservers']:
            ip_address = netapp_utils.zapi.NaElement('ip-address')
            ip_address.set_content(each)
            nameservers.add_child_elem(ip_address)
        dns.add_child_elem(nameservers)
        for each in self.parameters['domains']:
            domain = netapp_utils.zapi.NaElement('string')
            domain.set_content(each)
            domains.add_child_elem(domain)
        dns.add_child_elem(domains)
        if self.parameters.get('skip_validation'):
            validation = netapp_utils.zapi.NaElement('skip-config-validation')
            validation.set_content(str(self.parameters['skip_validation']))
            dns.add_child_elem(validation)
        try:
            self.server.invoke_successfully(dns, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating dns: %s' % to_native(error),
                                  exception=traceback.format_exc())

    def destroy_dns_rest(self, dns_attrs):
        """
        Destroys an already created dns
        :return:
        """
        if self.is_cluster:
            error = 'Error: cluster scope when deleting DNS with REST requires ONTAP 9.9.1 or later.'
            self.module.fail_json(msg=error)
        api = 'name-services/dns'
        dummy, error = rest_generic.delete_async(self.rest_api, api, dns_attrs['uuid'])
        if error:
            self.module.fail_json(msg="Error deleting DNS service: %s" % error)

    def destroy_dns(self, dns_attrs):
        """
        Destroys an already created dns
        :return:
        """
        if self.use_rest:
            return self.destroy_dns_rest(dns_attrs)

        try:
            self.server.invoke_successfully(netapp_utils.zapi.NaElement('net-dns-destroy'), True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error destroying dns: %s' % to_native(error),
                                  exception=traceback.format_exc())

    def get_cluster(self):
        api = "cluster"
        record, error = rest_generic.get_one_record(self.rest_api, api)
        if error:
            self.module.fail_json(msg="Error getting cluster info: %s" % error)
        return record

    def get_cluster_dns(self):
        cluster_attrs = self.get_cluster()
        dns_attrs = None
        if not self.parameters.get('vserver') or self.parameters['vserver'] == cluster_attrs['name']:
            dns_attrs = {
                'domains': cluster_attrs.get('dns_domains'),
                'nameservers': cluster_attrs.get('name_servers'),
                'uuid': cluster_attrs['uuid'],
            }
            self.is_cluster = True
            if dns_attrs['domains'] is None and dns_attrs['nameservers'] is None:
                dns_attrs = None
        return dns_attrs

    def get_dns_rest(self):
        if not self.parameters.get('vserver') and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            # scope requires 9.9, so revert to cluster API
            return self.get_cluster_dns()

        api = "name-services/dns"
        params = {'fields': 'domains,servers,svm'}
        if self.parameters.get('vserver'):
            # omit scope as vserver may be a cluster vserver
            params['svm.name'] = self.parameters['vserver']
        else:
            params['scope'] = 'cluster'
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg="Error getting DNS service: %s" % error)
        if record:
            if params.get('scope') == 'cluster' or not self.na_helper.safe_get(record, ['svm', 'uuid']):
                uuid = record.get('uuid')
            else:
                uuid = self.na_helper.safe_get(record, ['svm', 'uuid'])
            if uuid is None:
                self.module.fail_json(msg="Error getting DNS service: could not retrieve UUID of the DNS object")
            return {
                'domains': record.get('domains'),
                'nameservers': record.get('servers'),
                'uuid': uuid
            }
        if self.parameters.get('vserver') and not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            # There is a chance we are working at the cluster level
            return self.get_cluster_dns()
        return None

    def get_dns(self):
        if self.use_rest:
            return self.get_dns_rest()

        dns_obj = netapp_utils.zapi.NaElement('net-dns-get')
        try:
            result = self.server.invoke_successfully(dns_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) == "15661":
                # 15661 is object not found
                return None
            else:
                self.module.fail_json(msg="Error getting DNS info: %s." % to_native(error), exception=traceback.format_exc())

        attributes = result.get_child_by_name('attributes')
        if attributes is None:
            return
        dns_info = attributes.get_child_by_name('net-dns-info')
        nameservers = dns_info.get_child_by_name('name-servers')
        attrs = {
            'nameservers': [
                each.get_content() for each in nameservers.get_children()
            ]
        }
        domains = dns_info.get_child_by_name('domains')
        attrs['domains'] = [each.get_content() for each in domains.get_children()]
        return attrs

    def modify_dns_rest(self, dns_attrs):
        if self.is_cluster:
            return self.patch_cluster_dns()
        body = {}
        if dns_attrs['nameservers'] != self.parameters['nameservers']:
            body['servers'] = self.parameters['nameservers']
        if dns_attrs['domains'] != self.parameters['domains']:
            body['domains'] = self.parameters['domains']
        if 'skip_validation' in self.parameters:
            body['skip_config_validation'] = self.parameters['skip_validation']
        api = "name-services/dns"
        dummy, error = rest_generic.patch_async(self.rest_api, api, dns_attrs['uuid'], body)
        if error:
            self.module.fail_json(msg="Error modifying DNS configuration: %s" % error)

    def modify_dns(self, dns_attrs):
        if self.use_rest:
            return self.modify_dns_rest(dns_attrs)
        dns = netapp_utils.zapi.NaElement('net-dns-modify')
        if dns_attrs['nameservers'] != self.parameters['nameservers']:
            nameservers = netapp_utils.zapi.NaElement('name-servers')
            for each in self.parameters['nameservers']:
                ip_address = netapp_utils.zapi.NaElement('ip-address')
                ip_address.set_content(each)
                nameservers.add_child_elem(ip_address)
            dns.add_child_elem(nameservers)
        if dns_attrs['domains'] != self.parameters['domains']:
            domains = netapp_utils.zapi.NaElement('domains')
            for each in self.parameters['domains']:
                domain = netapp_utils.zapi.NaElement('string')
                domain.set_content(each)
                domains.add_child_elem(domain)
            dns.add_child_elem(domains)
        if self.parameters.get('skip_validation'):
            validation = netapp_utils.zapi.NaElement('skip-config-validation')
            validation.set_content(str(self.parameters['skip_validation']))
            dns.add_child_elem(validation)
        try:
            self.server.invoke_successfully(dns, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying dns: %s' % to_native(error), exception=traceback.format_exc())

    def apply(self):
        dns_attrs = self.get_dns()
        cd_action = self.na_helper.get_cd_action(dns_attrs, self.parameters)
        modify = None
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(dns_attrs, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_dns()
            elif cd_action == 'delete':
                self.destroy_dns(dns_attrs)
            else:
                self.modify_dns(dns_attrs)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Create, Delete, Modify DNS servers.
    """
    obj = NetAppOntapDns()
    obj.apply()


if __name__ == '__main__':
    main()
