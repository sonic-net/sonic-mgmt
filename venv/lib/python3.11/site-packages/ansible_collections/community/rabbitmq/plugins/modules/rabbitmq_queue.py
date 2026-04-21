#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Manuel Sousa <manuel.sousa@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: rabbitmq_queue
author: Manuel Sousa (@manuel-sousa)

short_description: Manage rabbitMQ queues
description:
  - This module uses rabbitMQ Rest API to create/delete queues.
  - Due to limitations in the API, it cannot modify existing queues.
requirements: [ "requests >= 1.0.0" ]
options:
    name:
        description:
            - Name of the queue.
        type: str
        required: true
    state:
        description:
            - Whether the queue should be present or absent.
        type: str
        choices: [ "present", "absent" ]
        default: present
    durable:
        description:
            - whether queue is durable or not.
        type: bool
        default: true
    auto_delete:
        description:
            - if the queue should delete itself after all queues/queues unbound from it.
        type: bool
        default: false
    message_ttl:
        description:
            - How long a message can live in queue before it is discarded (milliseconds).
        type: int
    auto_expires:
        description:
            - How long a queue can be unused before it is automatically deleted (milliseconds).
        type: int
    max_length:
        description:
            - How many messages can the queue contain before it starts rejecting.
        type: int
    dead_letter_exchange:
        description:
            - Optional name of an exchange to which messages will be republished if they
            - are rejected or expire.
        type: str
    dead_letter_routing_key:
        description:
            - Optional replacement routing key to use when a message is dead-lettered.
            - Original routing key will be used if unset.
        type: str
    max_priority:
        description:
            - Maximum number of priority levels for the queue to support.
            - If not set, the queue will not support message priorities.
            - Larger numbers indicate higher priority.
        type: int
    arguments:
        description:
            - extra arguments for queue. If defined this argument is a key/value dictionary
            - Arguments here take precedence over parameters. If both are defined, the
              argument will be used.
        type: dict
        default: {}
extends_documentation_fragment:
- community.rabbitmq.rabbitmq

'''

EXAMPLES = r'''
- name: Create a queue
  community.rabbitmq.rabbitmq_queue:
    name: myQueue

- name: Create a queue on remote host
  community.rabbitmq.rabbitmq_queue:
    name: myRemoteQueue
    login_user: user
    login_password: secret
    login_host: remote.example.org

# You may specify different types of queues using the arguments parameter.
- name: Create RabbitMQ stream
  become: yes
  community.rabbitmq.rabbitmq_queue:
    name: test-x
    arguments:
      x-queue-type: stream
      x-max-age: 24h
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


def check_if_arg_changed(module, current_args, desired_args, arg_name):
    if arg_name not in current_args:
        if arg_name in desired_args:
            module.fail_json(
                msg=("RabbitMQ RESTAPI doesn't support attribute changes for existing queues."
                     "Attempting to set %s which is not currently set." % arg_name),
            )
        # else don't care
    else:  # arg_name in current_args
        if arg_name in desired_args:
            if current_args[arg_name] != desired_args[arg_name]:
                module.fail_json(
                    msg=("RabbitMQ RESTAPI doesn't support attribute changes for existing queues.\n"
                         "Attempting to change %s from '%s' to '%s'" % (arg_name, current_args[arg_name], desired_args[arg_name]))
                )
        else:
            module.fail_json(
                msg=("RabbitMQ RESTAPI doesn't support attribute changes for existing queues."
                     "Attempting to unset %s which is currently set to '%s'." % (arg_name, current_args[arg_name])),
            )


def main():

    argument_spec = rabbitmq_argument_spec()
    argument_spec.update(
        dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            durable=dict(default=True, type='bool'),
            auto_delete=dict(default=False, type='bool'),
            message_ttl=dict(default=None, type='int'),
            auto_expires=dict(default=None, type='int'),
            max_length=dict(default=None, type='int'),
            dead_letter_exchange=dict(default=None, type='str'),
            dead_letter_routing_key=dict(default=None, type='str', no_log=False),
            arguments=dict(default=dict(), type='dict'),
            max_priority=dict(default=None, type='int')
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    url = "%s://%s:%s/api/queues/%s/%s" % (
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

    result = dict(changed=False, name=module.params['name'])

    # Check if queue already exists
    r = requests.get(url, auth=(module.params['login_user'], module.params['login_password']),
                     verify=module.params['ca_cert'], cert=(module.params['client_cert'], module.params['client_key']))

    if r.status_code == 200:
        queue_exists = True
        response = r.json()
    elif r.status_code == 404:
        queue_exists = False
        response = r.text
    else:
        module.fail_json(
            msg="Invalid response from RESTAPI when trying to check if queue exists",
            details=r.text
        )

    arg_map = {
        'message_ttl': 'x-message-ttl',
        'auto_expires': 'x-expires',
        'max_length': 'x-max-length',
        'dead_letter_exchange': 'x-dead-letter-exchange',
        'dead_letter_routing_key': 'x-dead-letter-routing-key',
        'max_priority': 'x-max-priority'
    }

    # Sync arguments with parameters (the final request uses module.params['arguments'])
    for k, v in arg_map.items():
        if module.params[k] is not None:
            module.params['arguments'][v] = module.params[k]

    if module.params['state'] == 'present':
        add_or_delete_required = not queue_exists
    else:
        add_or_delete_required = queue_exists

    # Check if attributes change on existing queue
    if not add_or_delete_required and r.status_code == 200 and module.params['state'] == 'present':
        check_if_arg_changed(module, response, module.params, 'durable')
        check_if_arg_changed(module, response, module.params, 'auto_delete')

        for arg in arg_map.values():
            check_if_arg_changed(module, response['arguments'], module.params['arguments'], arg)

    # Exit if check_mode
    if module.check_mode:
        result['changed'] = add_or_delete_required
        result['details'] = response
        result['arguments'] = module.params['arguments']
        module.exit_json(**result)

    # Do changes
    if add_or_delete_required:
        if module.params['state'] == 'present':
            r = requests.put(
                url,
                auth=(module.params['login_user'], module.params['login_password']),
                headers={"content-type": "application/json"},
                data=json.dumps({
                    "durable": module.params['durable'],
                    "auto_delete": module.params['auto_delete'],
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
            module.fail_json(
                msg="Error creating queue",
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
