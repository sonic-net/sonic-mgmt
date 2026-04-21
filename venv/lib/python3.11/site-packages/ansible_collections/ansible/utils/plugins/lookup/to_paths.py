# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
The to_paths lookup plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
    name: to_paths
    author: Bradley Thornton (@cidrblock)
    version_added: "1.0.0"
    short_description: Flatten a complex object into a dictionary of paths and values
    description:
      - Flatten a complex object into a dictionary of paths and values.
      - Paths are dot delimited whenever possible.
      - Brackets are used for list indices and keys that contain special characters.
      - B(to_paths) is also available as a filter plugin.
      - Using the parameters below- C(lookup('ansible.utils.to_paths', var, prepend, wantlist))
    options:
      var:
        description:
          - The value of I(var) will be used.
        type: raw
        required: True
      prepend:
        description:
          - Prepend each path entry. Useful to add the initial I(var) name.
        type: str
        required: False
      wantlist:
        description:
          - If set to I(True), the return value will always be a list.
          - This can also be accomplished using C(query) or B(q) instead of C(lookup).
          - U(https://docs.ansible.com/ansible/latest/plugins/lookup.html)
        type: bool

    notes:
"""

EXAMPLES = r"""

#### Simple examples

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

- ansible.builtin.set_fact:
    paths: "{{ lookup('ansible.utils.to_paths', a) }}"

# TASK [ansible.builtin.set_fact] ********************************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     paths:
#       b.c.d[0]: 0
#       b.c.d[1]: 1
#       b.c.e[0]: True
#       b.c.e[1]: False

- name: Use prepend to add the initial variable name
  ansible.builtin.set_fact:
    paths: "{{ lookup('ansible.utils.to_paths', a, prepend='a') }}"

# TASK [Use prepend to add the initial variable name] **************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     paths:
#       a.b.c.d[0]: 0
#       a.b.c.d[1]: 1
#       a.b.c.e[0]: True
#       a.b.c.e[1]: False


#### Using a complex object

- name: Make an API call
  ansible.builtin.uri:
    url: "https://nxos101/restconf/data/openconfig-interfaces:interfaces"
    headers:
      accept: "application/yang.data+json"
    url_password: password
    url_username: admin
    validate_certs: false
  register: result
  delegate_to: localhost

- name: Flatten the complex object
  ansible.builtin.set_fact:
    paths: "{{ lookup('ansible.utils.to_paths', result.json) }}"

# TASK [Flatten the complex object] ******************************************
# ok: [nxos101] => changed=false
#   ansible_facts:
#     paths:
#       interfaces.interface[0].config.enabled: 'true'
#       interfaces.interface[0].config.mtu: '1500'
#       interfaces.interface[0].config.name: eth1/71
#       interfaces.interface[0].config.type: ethernetCsmacd
#       interfaces.interface[0].ethernet.config['auto-negotiate']: 'true'
#       interfaces.interface[0].ethernet.state.counters['in-crc-errors']: '0'
#       interfaces.interface[0].ethernet.state.counters['in-fragment-frames']: '0'
#       interfaces.interface[0].ethernet.state.counters['in-jabber-frames']: '0'
#       interfaces.interface[0].ethernet.state.counters['in-mac-control-frames']: '0'
#       <...>
"""

RETURN = """
  _raw:
    description:
      - A dictionary of key value pairs.
      - The key is the path.
      - The value is the value.
"""

from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.to_paths import to_paths


class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):
        if isinstance(terms, list):
            keys = ["var", "prepend"]
            terms = dict(zip(keys, terms))
        terms.update(kwargs)

        aav = AnsibleArgSpecValidator(data=terms, schema=DOCUMENTATION, name="to_paths")
        valid, errors, updated_data = aav.validate()
        if not valid:
            raise AnsibleLookupError(errors)
        updated_data["wantlist"] = True
        res = to_paths(**updated_data)
        return res
