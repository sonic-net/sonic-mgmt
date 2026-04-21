#!/usr/bin/python

# (c) 2023-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_ems_destination
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_ems_destination
short_description: NetApp ONTAP configuration for EMS event destination
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.23.0
author: Bartosz Bielawski (@bielawb) <bartek.bielawski@live.com>
description:
  - Configure EMS destination.
options:
  state:
    description:
      - Whether the destination should be present or not.
    choices: ['present', 'absent']
    type: str
    default: present
  name:
    description:
      - Name of the EMS destination.
    required: true
    type: str
  type:
    description:
      - Type of the EMS destination.
    choices: ['email', 'syslog', 'rest_api']
    required: true
    type: str
  destination:
    description:
      - Destination - content depends on the type.
    required: true
    type: str
  filters:
    description:
      - List of filters that destination is linked to.
    required: true
    type: list
    elements: str
  certificate:
    description:
      - Name of the certificate
    required: false
    type: str
    version_added: 22.8.0
  ca:
    description:
      - Name of the CA certificate
    required: false
    type: str
    version_added: 22.8.0
  syslog:
    description:
      - The parameter is specified when the EMS destination type is C(syslog).
    required: false
    version_added: 22.9.0
    type: dict
    suboptions:
      transport:
        choices: [udp_unencrypted, tcp_unencrypted, tcp_encrypted]
        description:
          - Syslog Transport Protocol.
        type: str
        default: 'udp_unencrypted'
      timestamp_format_override:
        choices: [no_override, rfc_3164, iso_8601_local_time, iso_8601_utc]
        description:
          - Syslog Timestamp Format Override.
        type: str
        default: 'no_override'
      hostname_format_override:
        choices: [no_override, fqdn, hostname_only]
        description:
          - Syslog Hostname Format Override.
        type: str
        default: 'no_override'
      message_format:
        choices: [legacy_netapp, rfc_5424]
        description:
          - Syslog Message Format.
        type: str
        default: 'legacy_netapp'
      port:
        description:
          - Syslog Port.
        type: int
        default: 514
notes:
  - Supports check_mode.
  - This module only supports REST.
'''

EXAMPLES = """
- name: Configure REST EMS destination
  netapp.ontap.na_ontap_ems_destination:
    state: present
    name: rest
    type: rest_api
    filters: ['important_events']
    destination: http://my.rest.api/address
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Configure REST EMS destination with a certificate
  netapp.ontap.na_ontap_ems_destination:
    state: present
    name: rest
    type: rest_api
    filters: ['important_events']
    destination: http://my.rest.api/address
    certificate: my_cert
    ca: my_cert_ca
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Configure REST EMS destination with type syslog
  netapp.ontap.na_ontap_ems_destination:
    state: present
    name: syslog_destination
    type: syslog
    filters: ['important_events']
    destination: http://my.rest.api/address
    certificate: my_cert
    ca: my_cert_ca
    syslog:
      transport: udp_unencrypted
      port: 514
      message_format: legacy_netapp
      hostname_format_override: no_override
      timestamp_format_override: no_override
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Remove email EMS destination
  netapp.ontap.na_ontap_ems_destination:
    state: absent
    name: email_destination
    type: email
    filters: ['important_events']
    destination: netapp@company.com
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
"""

RETURN = """

"""
from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapEmsDestination:
    """Create/Modify/Remove EMS destination"""
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            type=dict(required=True, type='str', choices=['email', 'syslog', 'rest_api']),
            syslog=dict(required=False, type='dict',
                        options=dict(
                            transport=dict(required=False, type='str', choices=['udp_unencrypted', 'tcp_unencrypted', 'tcp_encrypted'],
                                           default='udp_unencrypted'),
                            port=dict(required=False, type='int', default=514),
                            message_format=dict(required=False, type='str', choices=['legacy_netapp', 'rfc_5424'], default='legacy_netapp'),
                            timestamp_format_override=dict(required=False, type='str',
                                                           choices=['no_override', 'rfc_3164', 'iso_8601_local_time', 'iso_8601_utc'], default='no_override'),
                            hostname_format_override=dict(required=False, type='str', choices=['no_override', 'fqdn', 'hostname_only'], default='no_override')
                        )),
            destination=dict(required=True, type='str'),
            filters=dict(required=True, type='list', elements='str'),
            certificate=dict(required=False, type='str'),
            ca=dict(required=False, type='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_together=[('certificate', 'ca')],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        partially_supported_rest_properties = [['certificate', (9, 11, 1)], ['syslog', (9, 12, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, partially_supported_rest_properties=partially_supported_rest_properties)

        if not self.use_rest:
            self.module.fail_json(msg='na_ontap_ems_destination is only supported with REST API')

    def fail_on_error(self, error, action):
        if error is None:
            return
        self.module.fail_json(msg="Error %s: %s" % (action, error))

    def generate_filters_list(self, filters):
        return [{'name': filter} for filter in filters]

    def get_ems_destination(self, name):
        api = 'support/ems/destinations'
        query = {'name': name,
                 'fields': 'type,'
                           'destination,'
                           'filters.name,'
                           'certificate.ca,'}
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 11, 1):
            query['fields'] += 'certificate.name,'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 12, 1):
            syslog_option_9_12 = ('syslog.transport,'
                                  'syslog.port,'
                                  'syslog.format.message,'
                                  'syslog.format.timestamp_override,'
                                  'syslog.format.hostname_override,')
            query['fields'] += syslog_option_9_12
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        self.fail_on_error(error, 'fetching EMS destination for %s' % name)
        if record:
            current = {
                'name': self.na_helper.safe_get(record, ['name']),
                'type': self.na_helper.safe_get(record, ['type']),
                'destination': self.na_helper.safe_get(record, ['destination']),
                'filters': None,
                'certificate': self.na_helper.safe_get(record, ['certificate', 'name']),
                'ca': self.na_helper.safe_get(record, ['certificate', 'ca']),
            }
            if record.get('syslog') is not None:
                current['syslog'] = {
                    'port': self.na_helper.safe_get(record, ['syslog', 'port']),
                    'transport': self.na_helper.safe_get(record, ['syslog', 'transport']),
                    'timestamp_format_override': self.na_helper.safe_get(record, ['syslog', 'format', 'timestamp_override']),
                    'hostname_format_override': self.na_helper.safe_get(record, ['syslog', 'format', 'hostname_override']),
                    'message_format': self.na_helper.safe_get(record, ['syslog', 'format', 'message']),
                }
            # 9.9.0 and earlier versions returns rest-api, convert it to rest_api.
            if current['type'] and '-' in current['type']:
                current['type'] = current['type'].replace('-', '_')
            if self.na_helper.safe_get(record, ['filters']):
                current['filters'] = [filter['name'] for filter in record['filters']]
            return current
        return None

    def get_certificate_serial(self, cert_name):
        """Retrieve the serial of a certificate"""
        api = 'security/certificates'
        query = {
            'scope': "cluster",
            'type': "client",
            'name': cert_name
        }
        fields = 'serial_number'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg='Error retrieving certificates: %s' % error)

        if not record:
            self.module.fail_json(msg='Error certificate not found: %s.'
                                  % (self.parameters['certificate']))
        return record['serial_number']

    def create_ems_destination(self):
        api = 'support/ems/destinations'
        name = self.parameters['name']
        body = {
            'name': name,
            'type': self.parameters['type'],
            'destination': self.parameters['destination'],
            'filters': self.generate_filters_list(self.parameters['filters'])
        }

        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 11, 1):
            if self.parameters.get('certificate') and self.parameters.get('ca') is not None:
                body['certificate'] = {
                    'serial_number': self.get_certificate_serial(self.parameters['certificate']),
                    'ca': self.parameters['ca'],
                }
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 12, 1):
            if self.parameters.get('syslog') is not None:
                body['syslog'] = {}
                for key, option in [
                    ('syslog.port', 'port'),
                    ('syslog.transport', 'transport'),
                    ('syslog.format.message', 'message_format'),
                    ('syslog.format.timestamp_override', 'timestamp_format_override'),
                    ('syslog.format.hostname_override', 'hostname_format_override')
                ]:
                    if self.parameters['syslog'].get(option) is not None:
                        body[key] = self.parameters['syslog'][option]
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        self.fail_on_error(error, 'creating EMS destinations for %s' % name)

    def delete_ems_destination(self, name):
        api = 'support/ems/destinations'
        dummy, error = rest_generic.delete_async(self.rest_api, api, name)
        self.fail_on_error(error, 'deleting EMS destination for %s' % name)

    def modify_ems_destination(self, name, modify):
        if 'type' in modify:
            # changing type is not supported
            self.delete_ems_destination(name)
            self.create_ems_destination()
        else:
            body = {}
            if any(item in modify for item in ['certificate', 'ca']):
                body['certificate'] = {}
            for option in modify:
                if option == 'filters':
                    body[option] = self.generate_filters_list(modify[option])
                elif option == 'certificate':
                    body[option]['serial_number'] = self.get_certificate_serial(modify[option])
                elif option == 'ca':
                    body['certificate']['ca'] = modify[option]
                elif option == 'syslog':
                    for key, option in [
                        ('syslog.port', 'port'),
                        ('syslog.transport', 'transport'),
                        ('syslog.format.message', 'message_format'),
                        ('syslog.format.timestamp_override', 'timestamp_format_override'),
                        ('syslog.format.hostname_override', 'hostname_format_override')
                    ]:
                        if option in modify['syslog']:
                            body[key] = modify['syslog'][option]
                else:
                    body[option] = modify[option]
            if body:
                api = 'support/ems/destinations'
                dummy, error = rest_generic.patch_async(self.rest_api, api, name, body)
                self.fail_on_error(error, 'modifying EMS destination for %s' % name)

    def apply(self):
        name = self.parameters['name']
        modify = None
        current = self.get_ems_destination(name)
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        saved_modify = str(modify)
        if self.na_helper.changed and not self.module.check_mode:
            if modify:
                self.modify_ems_destination(name, modify)
            elif cd_action == 'create':
                self.create_ems_destination()
            else:
                self.delete_ems_destination(name)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, saved_modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapEmsDestination()
    obj.apply()


if __name__ == '__main__':
    main()
