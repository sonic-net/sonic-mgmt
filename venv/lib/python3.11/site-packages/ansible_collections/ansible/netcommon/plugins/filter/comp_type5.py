#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The comp_type5 filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
name: comp_type5
author: Ken Celenza (@itdependsnetworks)
version_added: "1.0.0"
short_description: The comp_type5 filter plugin.
description:
  - The filter confirms configuration idempotency on use of type5_pw.
notes:
  - The filter confirms configuration idempotency on use of type5_pw.
  - Can be used to validate password post hashing
    username cisco secret 5 {{ ansible_ssh_pass | ansible.netcommon.comp_type5(encrypted, True) }}
options:
  unencrypted_password:
    description:
    - The unencrypted text.
    type: str
    required: True
  encrypted_password:
    description:
    - The encrypted text.
    type: str
    required: True
  return_original:
    description:
    - Return the original text.
    type: bool
"""

EXAMPLES = r"""
# Using comp_type5

# playbook

- name: Set the facts
  ansible.builtin.set_fact:
    unencrypted_password: "cisco@123"
    encrypted_password: "$1$avs$uSTOEMh65ADDBREAKqzvpb9yBMpzd/"

- name: Invoke comp_type5
  ansible.builtin.debug:
    msg: "{{ unencrypted_password | ansible.netcommon.comp_type5(encrypted_password, False) }}"

# Task Output
# -----------
#
# TASK [Set the facts]
# ok: [35.155.113.92] => changed=false
#   ansible_facts:
#     encrypted_password: $1$avs$uSTOEMh65ADDBREAKqzvpb9yBMpzd/
#     unencrypted_password: cisco@123

# TASK [Invoke comp_type5]
# ok: [35.155.113.92] =>
#   msg: true
"""

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ansible.netcommon.plugins.plugin_utils.comp_type5 import comp_type5


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _comp_type5(*args, **kwargs):
    """Extend vlan data"""

    keys = [
        "unencrypted_password",
        "encrypted_password",
        "return_original",
    ]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="comp_type5")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return comp_type5(**updated_data)


class FilterModule(object):
    """comp_type5"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"comp_type5": _comp_type5}
