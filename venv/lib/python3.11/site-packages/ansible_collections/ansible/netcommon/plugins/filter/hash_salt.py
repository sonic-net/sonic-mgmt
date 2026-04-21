#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The hash_salt filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
name: hash_salt
author: Ken Celenza (@itdependsnetworks)
version_added: "1.0.0"
short_description: The hash_salt filter plugin.
description:
  - The filter plugin produces the salt from a hashed password.
  - Using the parameters below - C(password | ansible.netcommon.hash_salt(template.yml))
notes:
  - The filter plugin produces the salt from a hashed password.
options:
  password:
    description:
    - This source data on which hash_salt invokes.
    - For example C(password | ansible.netcommon.hash_salt),
      in this case C(password) represents the hashed password.
    type: str
    required: True
"""

EXAMPLES = r"""
# Using hash_salt

# playbook

- name: Set the facts
  ansible.builtin.set_fact:
    password: "$1$avs$uSTOEMh65ADDBREAKqzvpb9yBMpzd/"

- name: Invoke hash_salt
  ansible.builtin.debug:
    msg: "{{ password | ansible.netcommon.hash_salt() }}"


# Task Output
# -----------
#
# TASK [Set the facts]
# ok: [host] => changed=false
#   ansible_facts:
#     password: $1$avs$uSTOEMh65ADDBREAKqzvpb9yBMpzd/

# TASK [Invoke hash_salt]
# ok: [host] =>
#   msg: avs
"""

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ansible.netcommon.plugins.plugin_utils.hash_salt import hash_salt


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _hash_salt(*args, **kwargs):
    """Extend vlan data"""

    keys = ["password"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="hash_salt")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return hash_salt(**updated_data)


class FilterModule(object):
    """hash_salt"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"hash_salt": _hash_salt}
