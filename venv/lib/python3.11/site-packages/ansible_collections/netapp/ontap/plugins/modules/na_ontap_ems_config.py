#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_ems_config
short_description: NetApp ONTAP module to modify EMS configuration.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: '22.8.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Configure event notification and logging for the cluster.
options:
  state:
    description:
      - modify EMS configuration, only present is supported.
    choices: ['present']
    type: str
    default: present
  mail_from:
    description:
      - The email address that the event notification system uses as the "From" address for email notifications.
    type: str
    required: false
  mail_server:
    description:
      - The name or IP address of the SMTP server that the event notification system uses to send email notification of events.
    type: str
    required: false
  proxy_url:
    description:
      - HTTP or HTTPS proxy server URL used by rest-api type EMS notification destinations if your organization uses a proxy.
    type: str
    required: false
  proxy_user:
    description:
      - User name for the HTTP or HTTPS proxy server if authentication is required.
    type: str
    required: false
  proxy_password:
    description:
      - Password for HTTP or HTTPS proxy.
    type: str
    required: false
  pubsub_enabled:
    description:
      - Indicates whether or not events are published to the Publish/Subscribe messaging broker.
      - Requires ONTAP 9.10 or later.
    type: bool
    required: false

notes:
  - Only supported with REST and requires ONTAP 9.6 or later.
  - Module is not idempotent when proxy_password is set.
"""

EXAMPLES = """
- name: Modify EMS mail config
  netapp.ontap.na_ontap_ems_config:
    state: present
    mail_from: administrator@mycompany.com
    mail_server: mail.mycompany.com
    pubsub_enabled: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"

- name: Modify EMS proxy config
  netapp.ontap.na_ontap_ems_config:
    state: present
    proxy_url: http://proxy.example.com:8080
    pubsub_enabled: true
    proxy_user: admin
    proxy_password: password
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: "{{ validate_certs }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapEmsConfig:
    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present'], default='present'),
            mail_from=dict(required=False, type='str'),
            mail_server=dict(required=False, type='str'),
            proxy_url=dict(required=False, type='str'),
            proxy_user=dict(required=False, type='str'),
            proxy_password=dict(required=False, type='str', no_log=True),
            pubsub_enabled=dict(required=False, type='bool')
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.uuid = None
        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.check_and_set_parameters(self.module)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_ems_config:', 9, 6)
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, [['pubsub_enabled', (9, 10, 1)]])

    def get_ems_config_rest(self):
        """Get EMS config details"""
        fields = 'mail_from,mail_server,proxy_url,proxy_user'
        if 'pubsub_enabled' in self.parameters and self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 10, 1):
            fields += ',pubsub_enabled'
        record, error = rest_generic.get_one_record(self.rest_api, 'support/ems', None, fields)
        if error:
            self.module.fail_json(msg="Error fetching EMS config: %s" % to_native(error), exception=traceback.format_exc())
        if record:
            return {
                'mail_from': record.get('mail_from'),
                'mail_server': record.get('mail_server'),
                'proxy_url': record.get('proxy_url'),
                'proxy_user': record.get('proxy_user'),
                'pubsub_enabled': record.get('pubsub_enabled')
            }
        return None

    def modify_ems_config_rest(self, modify):
        """Modify EMS config"""
        dummy, error = rest_generic.patch_async(self.rest_api, 'support/ems', None, modify)
        if error:
            self.module.fail_json(msg='Error modifying EMS config: %s.' % to_native(error), exception=traceback.format_exc())

    def check_proxy_url(self, current):
        # GET return the proxy url, if configured, along with port number
        # based on the existing config, append port numnber to input url to
        # maintain idempotency while modifying config
        port = None
        if current.get('proxy_url') is not None:
            # strip trailing '/' and extract the port no
            port = current['proxy_url'].rstrip('/').split(':')[-1]
        pos = self.parameters['proxy_url'].rstrip('/').rfind(':')
        if self.parameters['proxy_url'][pos + 1] == '/':
            # port is not mentioned in input proxy URL
            # if port is present in current url configured then add to the input url
            if port is not None and port != '':
                self.parameters['proxy_url'] = "%s:%s" % (self.parameters['proxy_url'].rstrip('/'), port)

    def apply(self):
        current = self.get_ems_config_rest()
        if self.parameters.get('proxy_url') not in [None, '']:
            self.check_proxy_url(current)
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        password_changed = False
        if self.parameters.get('proxy_password') not in [None, '']:
            modify['proxy_password'] = self.parameters['proxy_password']
            self.module.warn('Module is not idempotent when proxy_password is set.')
            password_changed = True
        if (self.na_helper.changed or password_changed) and not self.module.check_mode:
            self.modify_ems_config_rest(modify)
        result = netapp_utils.generate_result(changed=self.na_helper.changed | password_changed, modify=modify)
        self.module.exit_json(**result)


def main():
    ems_config = NetAppOntapEmsConfig()
    ems_config.apply()


if __name__ == '__main__':
    main()
