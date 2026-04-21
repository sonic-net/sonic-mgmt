#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The type5_pw filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
name: type5_pw
author: Ken Celenza (@itdependsnetworks)
version_added: "1.0.0"
short_description: The type5_pw filter plugin.
description:
  - Filter plugin to produce cisco type5 hashed password.
  - Using the parameters below - C(xml_data | ansible.netcommon.type5_pw(template.yml))
  - This plugin uses do_encrypt if used with ansible-core 2.20+ and passlib_or_crypt for versions before 2.20
notes:
  - The filter plugin generates cisco type5 hashed password.
options:
  password:
    description:
    - The password to be hashed.
    type: str
    required: True
  salt:
    description:
    - Mention the salt to hash the password.
    type: str
"""

EXAMPLES = r"""
# Using type5_pw

- name: Set some facts
  ansible.builtin.set_fact:
    password: "cisco@123"

- name: Filter type5_pw invocation
  ansible.builtin.debug:
    msg: "{{ password | ansible.netcommon.type5_pw(salt='avs') }}"


# Task Output
# -----------
#
# TASK [Set some facts]
# ok: [host] => changed=false
#   ansible_facts:
#     password: cisco@123

# TASK [Filter type5_pw invocation]
# ok: [host] =>
#   msg: $1$avs$uSTOEMh65qzvpb9yBMpzd/
"""

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ansible.netcommon.plugins.plugin_utils.type5_pw import type5_pw


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _type5_pw(*args, **kwargs):
    """Extend vlan data"""

    keys = ["password", "salt"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="type5_pw")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return type5_pw(**updated_data)


class FilterModule(object):
    """type5_pw"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"type5_pw": _type5_pw}
