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
module: infini_notification_rule
version_added: 2.13.0
short_description:  Config notification rules
description:
    - This module config notification rules on Infinibox
author: Wei Wang (@wwang)
options:
  name:
    description:
      - Name of the rule
    type: str
    required: true
  event_level:
    description:
      - Event levels
    type: list
    elements: str
    required: false
    default: []
  include_events:
    description:
      - Included events
    type: list
    elements: str
    required: false
    default: []
  exclude_events:
    description:
      - Exclued events
    type: list
    elements: str
    required: false
    default: []
  recipients:
    description:
      - Email list of the recipients
      - Recipients and target are exclusive to each other, i.e. only recipients or target
        should be used, don't use both at the same time.
    type: list
    elements: str
    required: false
    default: []
  recipient_target_name:
    description:
      - When creating a rule using recipients, a notification target is required.
      - Usually, this target is named "customer-smtp".
      - If this is not the case, use this variable to specifiy another name.
    type: str
    required: false
    default: customer-smtp
  target:
    description:
      - Notification target
      - Recipients and target are exclusive to each other, i.e. only recipients or target
        should be used, don't use both at the same time.
    type: str
    required: false
  state:
    description:
      - Query or modifies config.
    type: str
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]

extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
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

HAS_ARROW = False

try:
    from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
        HAS_INFINISDK,
        api_wrapper,
        infinibox_argument_spec,
        get_system,
    )
except ModuleNotFoundError:
    from infinibox import (  # Used when hacking
        HAS_INFINISDK,
        api_wrapper,
        infinibox_argument_spec,
        get_system,
    )


@api_wrapper
def find_recipient_target_name_id(module, system):
    """ Find the ID of the target by name """
    target = module.params["recipient_target_name"]
    path = f"notifications/targets?name={target}&fields=id"
    api_result = system.api.get(
        path=path
    )
    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
        target_id = result['id']
    else:
        msg = f"Cannot find an ID for recipient_target_name {target}"
        module.fail_json(msg=msg)
    return target_id


@api_wrapper
def find_target_id(module, system):
    """ Find the ID of the target by name """
    target = module.params["target"]
    path = f"notifications/targets?name={target}&fields=id"
    api_result = system.api.get(
        path=path
    )
    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
        target_id = result['id']
    else:
        target_id = None
    return target_id


@api_wrapper
def get_rules(module):
    """ Get all rules """
    system = get_system(module)
    path = "notifications/rules"
    rules = system.api.get(path=path)
    return rules


@api_wrapper
def find_rule_id(module, system):
    """ Find the ID of the rule by name """
    rule_name = module.params["name"]
    path = f"notifications/rules?name={rule_name}&fields=id"
    api_result = system.api.get(
        path=path
    )
    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
        rule_id = result['id']
    else:
        rule_id = None
    return rule_id


@api_wrapper
def delete_rule(module):
    """ Delete a notification rule """
    system = get_system(module)
    rule_id = find_rule_id(module, system)
    path = f"notifications/rules/{rule_id}?approved=true"
    system.api.delete(path=path)


@api_wrapper
def create_rule(module):
    """ Create a new notifition rule """
    system = get_system(module)
    name = module.params["name"]
    event_level = module.params["event_level"]
    include_events = module.params["include_events"]
    exclude_events = module.params["exclude_events"]
    recipients = module.params["recipients"]
    target = module.params["target"]
    path = "notifications/rules"

    json_data = {
        "name": name,
        "event_level": event_level,
        "include_events": include_events,
        "exclude_events": exclude_events,
    }

    if recipients:
        target_parameters = {
            "recipients": recipients
        }
        json_data["target_id"] = find_recipient_target_name_id(module, system)  # Target ID for sending to recipients
        json_data["target_parameters"] = target_parameters
    elif target:
        json_data["target_id"] = find_target_id(module, system)
    else:
        msg = "Neither recipients nor target parameters specified"
        module.fail_json(msg=msg)

    system.api.post(path=path, data=json_data)


@api_wrapper
def update_rule(module):
    """
    Update an existing rule.
    """
    system = get_system(module)
    name = module.params["name"]
    event_level = module.params["event_level"]
    include_events = module.params["include_events"]
    exclude_events = module.params["exclude_events"]
    recipients = module.params["recipients"]
    target = module.params["target"]
    rule_id = find_rule_id(module, system)
    path = f"notifications/rules/{rule_id}"

    json_data = {
        "name": name,
        "event_level": event_level,
        "include_events": include_events,
        "exclude_events": exclude_events,
    }

    if recipients:
        target_parameters = {
            "recipients": recipients
        }
        json_data["target_id"] = find_recipient_target_name_id(module, system)  # Target ID for sending to recipients
        json_data["target_parameters"] = target_parameters
    elif target:
        json_data["target_id"] = find_target_id(module, system)
    else:
        msg = "Neither recipients nor target parameters specified"
        module.fail_json(msg=msg)

    system.api.put(path=path, data=json_data)


def handle_present(module):
    """ Create or update a rule """
    system = get_system(module)
    name = module.params["name"]
    changed = False
    if not module.check_mode:
        rule_id = find_rule_id(module, system)
        if not rule_id:
            create_rule(module)
            changed = True
            msg = f"Rule named {name} created"
        else:
            update_rule(module)
            msg = f"Rule named {name} updated"
            changed = True

    module.exit_json(changed=changed, msg=msg)


def handle_stat(module):
    """ Return rule stat """
    result = None
    system = get_system(module)
    name = module.params['name']
    rule_id = find_rule_id(module, system)
    if rule_id:
        path = f"notifications/rules/{rule_id}"
        api_result = system.api.get(path=path)
        result = api_result.get_json()['result']
        result["rule_id"] = result.pop("id")  # Rename id to rule_id
        result["msg"] = f"Stat for notification rule named {name}"
        result["changed"] = False
        module.exit_json(**result)
    msg = f"Notification rule {name} not found"
    module.fail_json(msg=msg)


def handle_absent(module):
    """ Remove rule """
    changed = False
    name = module.params["name"]
    system = get_system(module)

    rule_id = find_rule_id(module, system)
    if not rule_id:
        msg = f"Rule named {name} not found. Deletion not required."
        changed = False
    else:
        msg = f"Rule named {name} has been deleted"
        changed = True
        if not module.check_mode:
            delete_rule(module)

    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """Determine which state function to execute and do so"""
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
    """Verify module options are sane"""
    recipients = module.params['recipients']
    target = module.params['target']
    if recipients and target:
        msg = "Cannot specify both recipients and target parameters"
        module.fail_json(msg=msg)
    if recipients:
        for recipient in recipients:
            if len(recipient) == 1:
                msg = f"{recipient} is an invalid email address. Recipients '{recipients}' must be provided as a list, e.g. '[ \"user@example.com\" ]'"
                module.fail_json(msg=msg)
            if '@' not in recipient:
                msg = f"{recipient} is an invalid email address"
                module.fail_json(msg=msg)


def main():
    """Main module function"""
    argument_spec = infinibox_argument_spec()

    argument_spec.update(
        {
            "name": {"required": True},
            "event_level": {"required": False, "default": [], "type": "list", "elements": "str"},
            "include_events": {"required": False, "default": [], "type": "list", "elements": "str"},
            "exclude_events": {"required": False, "default": [], "type": "list", "elements": "str"},
            "recipients": {"required": False, "default": [], "type": "list", "elements": "str"},
            "recipient_target_name": {"required": False, "default": "customer-smtp", "type": "str"},
            "target": {"required": False, "type": "str", "default": None},
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
