# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
flatten a complex object to dot bracket notation
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: get_path
    author: Bradley Thornton (@cidrblock)
    version_added: "1.0.0"
    short_description: Retrieve the value in a variable using a path
    description:
        - Use a I(path) to retrieve a nested value from a I(var).
        - B(get_path) is also available as a B(lookup plugin) for convenience.
        - Using the parameters below- C(var|ansible.utils.get_path(path, wantlist))
    options:
      var:
        description:
        - The variable from which the value should be extracted.
        - This option represents the value that is passed to the filter plugin in pipe format.
        - For example C(config_data|ansible.utils.get_path()), in this case C(config_data) represents this option.
        type: raw
        required: True
      path:
        description:
        - The I(path) in the I(var) to retrieve the value of.
        - The I(path) needs to be a valid jinja path.
        type: str
        required: True
      wantlist:
        description:
        - If set to C(True), the return value will always be a list.
        type: bool

    notes:
"""

EXAMPLES = r"""
- ansible.builtin.set_fact:
    a:
      b:
        c:
          d:
            - 0
            - 1
          e:
            - true
            - false

- name: Retrieve a value deep inside a using a path
  ansible.builtin.set_fact:
    value: "{{ a|ansible.utils.get_path(path) }}"
  vars:
    path: b.c.d[0]

# TASK [Retrieve a value deep inside a using a path] ******************
# ok: [localhost] => changed=false
#   ansible_facts:
#     value: '0'


#### Working with hostvars

- name: Retrieve a value deep inside all of the host's vars
  ansible.builtin.set_fact:
    value: "{{ look_in|ansible.utils.get_path(look_for) }}"
  vars:
    look_in: "{{ hostvars[inventory_hostname] }}"
    look_for: a.b.c.d[0]

# TASK [Retrieve a value deep inside all of the host's vars] ********
# ok: [nxos101] => changed=false
#   ansible_facts:
#     as_filter: '0'
#     as_lookup: '0'


#### Used alongside ansible.utils.to_paths

- name: Get the paths for the object
  ansible.builtin.set_fact:
    paths: "{{ a|ansible.utils.to_paths(prepend='a') }}"

- name: Retrieve the value of each path from vars
  ansible.builtin.debug:
    msg: "The value of path {{ path }} in vars is {{ value }}"
  loop: "{{ paths.keys()|list }}"
  loop_control:
    label: "{{ item }}"
  vars:
    path: "{{ item }}"
    value: "{{ vars|ansible.utils.get_path(item) }}"

# TASK [Get the paths for the object] *******************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     paths:
#       a.b.c.d[0]: 0
#       a.b.c.d[1]: 1
#       a.b.c.e[0]: True
#       a.b.c.e[1]: False

# TASK [Retrieve the value of each path from vars] ******************
# ok: [nxos101] => (item=a.b.c.d[0]) =>
#   msg: The value of path a.b.c.d[0] in vars is 0
# ok: [nxos101] => (item=a.b.c.d[1]) =>
#   msg: The value of path a.b.c.d[1] in vars is 1
# ok: [nxos101] => (item=a.b.c.e[0]) =>
#   msg: The value of path a.b.c.e[0] in vars is True
# ok: [nxos101] => (item=a.b.c.e[1]) =>
#   msg: The value of path a.b.c.e[1] in vars is False


#### Working with complex structures and transforming results

- name: Retrieve the current interface config
  cisco.nxos.nxos_interfaces:
    state: gathered
  register: interfaces

- name: Get the description of several interfaces
  ansible.builtin.debug:
    msg: "{{ rekeyed|ansible.utils.get_path(item) }}"
  vars:
    rekeyed:
      by_name: "{{ interfaces.gathered|ansible.builtin.rekey_on_member('name') }}"
  loop:
    - by_name['Ethernet1/1'].description
    - by_name['Ethernet1/2'].description|upper
    - by_name['Ethernet1/3'].description|default('')


# TASK [Get the description of several interfaces] ******************
# ok: [nxos101] => (item=by_name['Ethernet1/1'].description) => changed=false
#   msg: Configured by ansible
# ok: [nxos101] => (item=by_name['Ethernet1/2'].description|upper) => changed=false
#   msg: CONFIGURED BY ANSIBLE
# ok: [nxos101] => (item=by_name['Ethernet1/3'].description|default('')) => changed=false
#   msg: ''
"""

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.get_path import get_path


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _get_path(*args, **kwargs):
    """Retrieve the value in a variable using a path."""
    keys = ["environment", "var", "path"]
    data = dict(zip(keys, args))
    data.update(kwargs)
    environment = data.pop("environment")
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="get_path")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    updated_data["environment"] = environment
    return get_path(**updated_data)


class FilterModule(object):
    """path filters"""

    def filters(self):
        return {"get_path": _get_path}
