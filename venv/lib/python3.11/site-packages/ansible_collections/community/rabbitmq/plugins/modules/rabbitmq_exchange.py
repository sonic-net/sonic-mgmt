#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Manuel Sousa <manuel.sousa@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: rabbitmq_exchange
author: Manuel Sousa (@manuel-sousa)

short_description: Manage rabbitMQ exchange
description:
  - This module uses rabbitMQ Rest API to create/delete exchanges
requirements: [ "requests >= 1.0.0" ]
options:
    name:
        description:
            - Name of the exchange to create.
        type: str
        required: true
    state:
        description:
            - Whether the exchange should be present or absent.
        type: str
        choices: [ "present", "absent" ]
        required: false
        default: present
    durable:
        description:
            - Whether exchange is durable or not.
        type: bool
        required: false
        default: true
    exchange_type:
        description:
            - Type for the exchange.
            - If using I(x-delayed-message), I(x-random), I(x-consistent-hash) or I(x-recent-history) the respective plugin on
            - the RabbitMQ server must be enabled.
        type: str
        required: false
        choices: [ "fanout", "direct", "headers", "topic", "x-delayed-message", "x-random", "x-consistent-hash", "x-recent-history" ]
        aliases: [ "type" ]
        default: direct
    auto_delete:
        description:
            - If the exchange should delete itself after all queues/exchanges unbound from it.
        type: bool
        required: false
        default: false
    internal:
        description:
            - Exchange is available only for other exchanges.
        type: bool
        required: false
        default: false
    arguments:
        description:
            - Extra arguments for exchange. If defined this argument is a key/value dictionary.
        type: dict
        required: false
        default: {}
extends_documentation_fragment:
  - community.rabbitmq.rabbitmq

'''

EXAMPLES = r'''
- name: Create direct exchange
  community.rabbitmq.rabbitmq_exchange:
    name: directExchange

- name: Create topic exchange on vhost
  community.rabbitmq.rabbitmq_exchange:
    name: topicExchange
    type: topic
    vhost: myVhost
'''

import json
import traceback

REQUESTS_IMP_ERR = None
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    REQUESTS_IMP_ERR = traceback.format_exc()
    HAS_REQUESTS = False

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.six.moves.urllib import parse as urllib_parse
from ansible_collections.community.rabbitmq.plugins.module_utils.rabbitmq import rabbitmq_argument_spec


def main():

    argument_spec = rabbitmq_argument_spec()
    argument_spec.update(
        dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            durable=dict(default=True, type='bool'),
            auto_delete=dict(default=False, type='bool'),
            internal=dict(default=False, type='bool'),
            exchange_type=dict(default='direct', aliases=['type'],
                               choices=['fanout', 'direct', 'headers', 'topic', 'x-delayed-message',
                                        'x-random', 'x-consistent-hash', 'x-recent-history'],
                               type='str'),
            arguments=dict(default=dict(), type='dict')
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    url = "%s://%s:%s/api/exchanges/%s/%s" % (
        module.params['login_protocol'],
        module.params['login_host'],
        module.params['login_port'],
        # Ensure provided data is safe to use in a URL.
        # https://docs.python.org/3/library/urllib.parse.html#url-quoting
        # NOTE: This will also encode '/' characters, as they are required
        # to be percent encoded in the RabbitMQ management API.
        urllib_parse.quote(module.params['vhost'], safe=''),
        urllib_parse.quote(module.params['name'], safe='')
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMP_ERR)

    # exchange plugin type to plugin name mapping
    exchange_plugins = {'x-consistent-hash': 'rabbitmq_consistent_hash_exchange',
                        'x-random': 'rabbitmq_random_exchange',
                        'x-delayed-message': 'rabbitmq_delayed_message_exchange',
                        'x-recent-history': 'rabbitmq_recent_history_exchange'}
    result = dict(changed=False, name=module.params['name'])

    # Check if exchange already exists
    r = requests.get(url, auth=(module.params['login_user'], module.params['login_password']),
                     verify=module.params['ca_cert'], cert=(module.params['client_cert'], module.params['client_key']))

    if r.status_code == 200:
        exchange_exists = True
        response = r.json()
    elif r.status_code == 404:
        exchange_exists = False
        response = r.text
    else:
        module.fail_json(
            msg="Invalid response from RESTAPI when trying to check if exchange exists",
            details=r.text
        )

    if module.params['state'] == 'present':
        change_required = not exchange_exists
    else:
        change_required = exchange_exists

    # Check if attributes change on existing exchange
    if not change_required and r.status_code == 200 and module.params['state'] == 'present':
        if not (
            response['durable'] == module.params['durable'] and
            response['auto_delete'] == module.params['auto_delete'] and
            response['internal'] == module.params['internal'] and
            response['type'] == module.params['exchange_type']
        ):
            module.fail_json(
                msg="RabbitMQ RESTAPI doesn't support attribute changes for existing exchanges"
            )

    # Exit if check_mode
    if module.check_mode:
        result['changed'] = change_required
        result['details'] = response
        result['arguments'] = module.params['arguments']
        module.exit_json(**result)

    # Do changes
    if change_required:
        if module.params['state'] == 'present':
            r = requests.put(
                url,
                auth=(module.params['login_user'], module.params['login_password']),
                headers={"content-type": "application/json"},
                data=json.dumps({
                    "durable": module.params['durable'],
                    "auto_delete": module.params['auto_delete'],
                    "internal": module.params['internal'],
                    "type": module.params['exchange_type'],
                    "arguments": module.params['arguments']
                }),
                verify=module.params['ca_cert'],
                cert=(module.params['client_cert'], module.params['client_key'])
            )
        elif module.params['state'] == 'absent':
            r = requests.delete(url, auth=(module.params['login_user'], module.params['login_password']),
                                verify=module.params['ca_cert'], cert=(module.params['client_cert'], module.params['client_key']))

        # RabbitMQ 3.6.7 changed this response code from 204 to 201
        if r.status_code == 204 or r.status_code == 201:
            result['changed'] = True
            module.exit_json(**result)
        else:
            rjson = r.json()
            if (rjson['reason'].startswith('unknown exchange type')):
                try:
                    module.fail_json(
                        msg=("Error creating exchange. You may need to enable the '%s' plugin for exchange type %s" %
                             (exchange_plugins[module.params['exchange_type']], module.params['exchange_type'])),
                        status=r.status_code,
                        details=r.text
                    )
                except KeyError:
                    module.fail_json(
                        msg=("Error creating exchange. You may need to enable a plugin for exchange type %s" %
                             module.params['exchange_type']),
                        status=r.status_code,
                        details=r.text
                    )
            else:
                module.fail_json(
                    msg="Error creating exchange",
                    status=r.status_code,
                    details=r.text
                )

    else:
        module.exit_json(
            changed=False,
            name=module.params['name']
        )


if __name__ == '__main__':
    main()
