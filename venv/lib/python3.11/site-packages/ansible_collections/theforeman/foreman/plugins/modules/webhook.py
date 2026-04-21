#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023, Griffin Sullivan <gsulliva@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: webhook
version_added: 4.0.0
short_description: Manage Webhooks
description:
  - Manage Webhooks
author:
  - "Griffin Sullivan (@Griffin-Sullivan)"
options:
  name:
    description:
      - Name of the Webhook
    required: true
    type: str
  target_url:
    description:
      - The URL to call when the webhook is triggered
      - Required when creating a new webhook
    type: str
  http_method:
    description:
      - The HTTP method used in the webhook
    choices:
      - POST
      - GET
      - PUT
      - DELETE
      - PATCH
    type: str
  http_content_type:
    description:
      - The HTTP content type for the webhook
    type: str
  event:
    description:
      - Name of the event that shall trigger the webhook
      - Required when creating a new webhook
    type: str
  webhook_template:
    description:
      - Name of the webhook template
    type: str
  enabled:
    description:
      - Enable or disable the webhook
    type: bool
  verify_ssl:
    description:
      - Verify SSL certs for the webhook
    type: bool
  ssl_ca_certs:
    description:
      - X509 Certification Authorities concatenated in PEM format
    type: str
  webhook_username:
    description:
      - Username for the webhook, if required
    type: str
  webhook_password:
    description:
      - Password for the webhook, if required
    type: str
  http_headers:
    description:
      - HTTP headers for the webhook
    type: str
  proxy_authorization:
    description:
      - Authorize with client certificate and validate CA from Settings
    type: bool
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
  - theforeman.foreman.foreman.taxonomy
'''

EXAMPLES = '''
- name: 'Create Webhook'
  theforeman.foreman.webhook:
    username: 'admin'
    password: 'secret_password'
    server_url: 'https://foreman.example.com'
    name: 'test-webhook'
    target_url: 'https://google.com'
    http_method: 'GET'
    event: 'actions.katello.content_view.promote_succeeded'
    enabled: true
    organizations:
      - 'MyOrg'
    locations:
      - 'DC1'

- name: 'Remove Webhook'
  theforeman.foreman.webhook:
    username: 'admin'
    password: 'secret_password'
    server_url: 'https://foreman.example.com'
    name: 'test-webhook'
    state: 'absent'
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    webhooks:
      description: List of webhooks.
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanTaxonomicEntityAnsibleModule


class ForemanWebhookModule(ForemanTaxonomicEntityAnsibleModule):
    pass


def main():
    module = ForemanWebhookModule(
        foreman_spec=dict(
            name=dict(required=True),
            target_url=dict(),
            http_method=dict(choices=['POST', 'GET', 'PUT', 'DELETE', 'PATCH']),
            http_content_type=dict(),
            event=dict(),
            webhook_template=dict(type='entity'),
            verify_ssl=dict(type='bool'),
            enabled=dict(type='bool'),
            ssl_ca_certs=dict(),
            webhook_username=dict(flat_name='user'),
            webhook_password=dict(no_log=True, flat_name='password'),
            http_headers=dict(),
            proxy_authorization=dict(type='bool'),
        ),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
