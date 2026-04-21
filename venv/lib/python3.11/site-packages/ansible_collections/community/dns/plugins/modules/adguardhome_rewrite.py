#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 Markus Bergholz
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: adguardhome_rewrite

short_description: Add, update or delete DNS rewrite rules from AdGuardHome

version_added: 3.3.0

description:
  - Add, update or delete DNS rewrite rules from AdGuardHome.
extends_documentation_fragment:
  - community.dns.adguardhome.connectivity
  - community.dns.attributes
options:
  state:
    description:
      - Wether a rewrite rule should be added/updated (O(state=present)) or removed (O(state=absent)).
    type: str
    default: present
    choices:
      - present
      - absent
  domain:
    description:
      - Domain or wildcard domain that you want to be rewritten by AdGuardHome.
    type: str
    required: true
  answer:
    description:
      - Value for the domain rewrite.
      - Required when O(state=present).
      - Value can be a CNAME, A or AAAA record.
    type: str
    required: false
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  idempotent:
    support: full


author:
  - Markus Bergholz (@markuman) <markuman+spambelongstogoogle@gmail.com>
"""

EXAMPLES = r"""
- name: Add DNS rewrite rule in AdGuardHome
  community.dns.adguardhome_rewrite:
    state: present
    answer: 127.0.0.1
    domain: example.org

# When removing a rewrite, the current answer value must also match.
# Therefore you can just leave it out and the existing value
# will be used.
- name: Remove rewrite for example.org
  community.dns.adguardhome_rewrite:
    state: absent
    domain: example.org
"""

RETURN = r"""
rules:
  description: The modified list of rewrite rules afte rewrite rule is applied.
  type: list
  elements: dict
  returned: success
  contains:
    answer:
      description: Value of the rewrite.
      type: str
      sample: 192.168.178.71
    domain:
      description: Domain of the rewrite.
      type: str
      sample: dns.osuv.de
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.dns.plugins.module_utils.adguardhome.api import (
    AdGuardHomeAPIHandler,
    create_adguardhome_argument_spec,
)


def find_and_compare(rules, domain, answer):
    domain_exists = False
    value_is_different = False
    target = {}
    for rule in rules:
        if rule["domain"] == domain:
            domain_exists = True
            target = {"domain": domain, "answer": rule["answer"]}
            if rule["answer"] != answer:
                value_is_different = True
            break
    return domain_exists, value_is_different, target


def main():
    rewrite_arguments = {
        'state': {'type': 'str', 'default': 'present', 'choices': ['present', 'absent']},
        'answer': {'type': 'str', 'required': False},
        'domain': {'type': 'str', 'required': True}
    }
    argument_spec = create_adguardhome_argument_spec(
        required_if=[['state', 'present', ['answer']]],
        additional_argument_specs=rewrite_arguments
    )
    module = AnsibleModule(
        supports_check_mode=True,
        **argument_spec.to_kwargs()
    )

    domain = module.params.get('domain')
    answer = module.params.get('answer')
    state = module.params.get('state')

    adguardhome = AdGuardHomeAPIHandler(module.params, module.fail_json)

    before = adguardhome.list()  # Note that this is updated to the 'after' value in check mode (but not outside of check mode!)
    changed = False

    domain_exists, value_is_different, target = find_and_compare(before, domain, answer)
    if state == 'present':
        if not domain_exists and not value_is_different:
            changed = True
            if module.check_mode:
                before = before + [{"answer": answer, "domain": domain}]
            else:
                adguardhome.add_or_delete(domain, answer, "add", target)

        if domain_exists and value_is_different:
            changed = True
            if module.check_mode:
                for item in before:
                    if item['domain'] == 'example.org':
                        item['value'] = answer
                        break
            else:
                adguardhome.update(domain, answer, target)

    else:
        if domain_exists:
            changed = True
            if module.check_mode:
                before = [item for item in before if item["domain"] != domain]
            else:
                adguardhome.add_or_delete(domain, answer, "delete", target)

    after = adguardhome.list()

    if module.check_mode:
        return_rules = before
        diff_item = {
            'before': {'rules': after},
            'after': {'rules': before}
        }
    else:
        return_rules = after
        diff_item = {
            'before': {'rules': before},
            'after': {'rules': after}
        }

    module.exit_json(changed=changed, diff=diff_item, rules=return_rules)


if __name__ == '__main__':
    main()
