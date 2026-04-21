#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position

"""This module creates, deletes or modifies metadata on Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_notification_target
version_added: 2.13.0
short_description:  Config notification target
description:
    - This module configures syslog notification targets on an Infinibox
author: Wei Wang (@wwang)
options:
  name:
    description:
      - Name of the syslog target
    type: str
    required: true
  host:
    description:
      - Host name or IP address of the target
    type: str
    required: false
  port:
    description:
      - Port of the target
    type: int
    required: false
    default: 514
  transport:
    description:
      -  TCP or UDP
    type: str
    required: false
    choices:
      - UDP
      - TCP
    default: UDP
  protocol:
    description:
      - Protocol used for this target. Currently, the only valid value is SYSLOG.
    type: str
    required: false
    choices:
      - SYSLOG
    default: SYSLOG
  facility:
    description:
      - Facility
    choices:
      - LOCAL0
      - LOCAL1
      - LOCAL2
      - LOCAL3
      - LOCAL4
      - LOCAL5
      - LOCAL6
      - LOCAL7
    type: str
    required: false
    default: LOCAL7
  visibility:
    description:
      - Visibility
    type: str
    choices:
      - CUSTOMER
      - INFINIDAT
    required: false
    default: CUSTOMER
  post_test:
    description:
      - Run a test after new target is created
    type: bool
    required: false
    default: true
  state:
    description:
      - Query or modifies target
    type: str
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]

extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Create notification targets
  infini_notification_target:
    state: present
    name: testgraylog1
    protocol: SYSLOG
    host: 172.31.77.214
    port: 8067
    facility: LOCAL7
    transport: TCP
    visibility: CUSTOMER
    post_test: true
    user: "{{ user }}"
    password: "{{ password }}"
    system: "{{ system }}"
- name: Create a new notification rule to a target
  infini_notification_rule:
    name: "test-rule-to-target" # this need to be uniq
    event_level:
      - ERROR
      - CRITICAL
    include_events:
      - ACTIVATION_PAUSED
    exclude_events:
      - ACTIVE_DIRECTORY_ALL_DOMAIN_CONTROLLERS_DOWN
      - ACTIVE_DIRECTORY_LEFT
    target: testgraylog1
    state: "present"
    user: "{{ user }}"
    password: "{{ password }}"
    system: "{{ system }}"
"""

# RETURN = r''' # '''

# -*- coding: utf-8 -*-
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    merge_two_dicts,
)

try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def get_target(module):
    """
    Find and return config setting value
    Use disable_fail when we are looking for config
    and it may or may not exist and neither case is an error.
    """
    name = module.params['name']
    path = f"notifications/targets?name={name}"
    system = get_system(module)

    try:
        target = system.api.get(path=path)
    except APICommandFailed as err:
        msg = f"Cannot find notification target {name}: {err}"
        module.fail_json(msg=msg)

    if not target:
        msg = f"Users repository {name} not found. Cannot stat."
        module.fail_json(msg=msg)
    result = target.get_result()
    return result


def handle_stat(module):
    """Return config stat"""
    name = module.params['name']
    try:
        result = get_target(module)[0]
    except IndexError:
        module.fail_json(f"Cannot stat notification target {name}. Target not found.")
    result2 = {
        "changed": False,
        "msg": f"Found notification target {name}",
    }
    result = merge_two_dicts(result, result2)
    module.exit_json(**result)


@api_wrapper
def find_target_id(module, system):
    """ Find the ID of the target by name """
    target_name = module.params["name"]

    try:
        path = f"notifications/targets?name={target_name}&fields=id"
        api_result = system.api.get(path=path)
    except APICommandFailed as err:
        msg = f"Cannot find ID for notification target {target_name}: {err}"
        module.fail_json(msg=msg)

    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
        target_id = result['id']
    else:
        target_id = None
    return target_id


@api_wrapper
def delete_target(module):
    """ Delete a notification target """
    system = get_system(module)
    name = module.params["name"]
    target_id = find_target_id(module, system)

    try:
        path = f"notifications/targets/{target_id}?approved=true"
        system.api.delete(path=path)
    except APICommandFailed as err:
        msg = f"Cannot delete notification target {name}: {err}"
        module.fail_json(msg=msg)


@api_wrapper
def create_target(module):
    """ Create a new notifition target """
    system = get_system(module)
    name = module.params["name"]
    protocol = module.params["protocol"]
    host = module.params["host"]
    port = module.params["port"]
    facility = module.params["facility"]
    transport = module.params["transport"]
    post_test = module.params["post_test"]
    visibility = module.params["visibility"]

    path = "notifications/targets"

    json_data = {
        "name": name,
        "protocol": protocol,
        "host": host,
        "port": port,
        "facility": facility,
        "transport": transport,
        "visibility": visibility
    }

    try:
        system.api.post(path=path, data=json_data)
    except APICommandFailed as err:
        msg = f"Cannot create notification target {name}: {err}"
        module.fail_json(msg=msg)

    if post_test:
        target_id = find_target_id(module, system)
        path = f"notifications/targets/{target_id}/test"
        json_data = {}
        try:
            system.api.post(path=path, data=json_data)
        except APICommandFailed as err:
            msg = f"Cannot test notification target {name}: {err}"
            module.fail_json(msg=msg)


@api_wrapper
def update_target(module):
    """ Update an existing target.  """
    delete_target(module)
    create_target(module)


def handle_present(module):
    """Make config present"""
    system = get_system(module)
    name = module.params["name"]
    changed = False
    if not module.check_mode:
        target_id = find_target_id(module, system)
        if not target_id:
            create_target(module)
            msg = f"Target {name} created"
        else:
            update_target(module)
            msg = f"Target {name} deleted and recreated"
        changed = True
        module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """Make config present"""
    changed = False
    name = module.params["name"]
    system = get_system(module)
    target_id = find_target_id(module, system)

    if not target_id:
        msg = f"Target {name} already does not exist"
        changed = False
    else:
        msg = f"Target {name} has been deleted"
        if not module.check_mode:
            changed = True
            delete_target(module)

    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """ Determine which state function to execute and do so """
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """ Verify module options are sane """
    if module.params['protocol'] != "SYSLOG":
        module.fail_json(msg="The only supported protocol is SYSLOG")


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()

    argument_spec.update(
        {
            "name": {"required": True},
            "host": {"required": False},
            "port": {"required": False, "type": "int", "default": 514},
            "transport": {"required": False, "default": "UDP", "choices": ["UDP", "TCP"]},
            "protocol": {"required": False, "default": "SYSLOG", "choices": ["SYSLOG"]},
            "facility": {"required": False, "default": "LOCAL7", "choices": ["LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]},
            "visibility": {"required": False, "default": "CUSTOMER", "choices": ["CUSTOMER", "INFINIDAT"]},
            "post_test": {"required": False, "default": True, "type": "bool"},
            "state": {"default": "present", "choices": ["stat", "present", "absent"]},
        }
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    check_options(module)
    execute_state(module)


if __name__ == '__main__':
    main()
