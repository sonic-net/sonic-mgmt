# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: cidr_merge
"""
from __future__ import absolute_import, division, print_function

from functools import partial

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_netaddr,
)


__metaclass__ = type

try:
    import netaddr

    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False
else:

    class mac_linux(netaddr.mac_unix):
        pass

    mac_linux.word_fmt = "%.2x"

try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment

DOCUMENTATION = """
    name: cidr_merge
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter can be used to merge subnets or individual addresses.
    description:
        - This filter can be used to merge subnets or individual addresses into their minimal representation, collapsing
        - overlapping subnets and merging adjacent ones wherever possible.
    options:
        value:
            description:
            - list of subnets or individual address to be merged
            type: list
            elements: str
            required: True
        action:
            description:
            - Action to be performed.example merge,span
            default: merge
            type: str
    notes:
"""

EXAMPLES = r"""
#### examples
- name: cidr_merge with merge action
  ansible.builtin.set_fact:
    value:
      - 192.168.0.0/17
      - 192.168.128.0/17
      - 192.168.128.1
- debug:
    msg: '{{ value|ansible.utils.cidr_merge }}'

# TASK [cidr_merge with merge action] **********************************************************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "value": [
#             "192.168.0.0/17",
#             "192.168.128.0/17",
#             "192.168.128.1"
#         ]
#     },
#     "changed": false
# }
# TASK [debug] *********************************************************************************************************
# ok: [loalhost] => {
#     "msg": [
#         "192.168.0.0/16"
#     ]
# }

- name: Cidr_merge with span.
  ansible.builtin.set_fact:
    value:
      - 192.168.1.1
      - 192.168.1.2
      - 192.168.1.3
      - 192.168.1.4
- debug:
    msg: '{{ value|ansible.utils.cidr_merge(''span'') }}'

# TASK [Cidr_merge with span.] ********************************************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "value": [
#             "192.168.1.1",
#             "192.168.1.2",
#             "192.168.1.3",
#             "192.168.1.4"
#         ]
#     },
#     "changed": false
# }
#
# TASK [debug] ************************************************************************************
# ok: [localhost] => {
#     "msg": "192.168.1.0/29"
# }
"""

RETURN = """
  data:
    type: raw
    description:
      - Returns a minified list of subnets or a single subnet that spans all of the inputs.
"""


@pass_environment
def _cidr_merge(*args, **kwargs):
    """Convert the given data from json to xml."""
    keys = ["value", "action"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="cidr_merge")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return cidr_merge(**updated_data)


def cidr_merge(value, action="merge"):
    if not hasattr(value, "__iter__"):
        raise AnsibleFilterError("cidr_merge: expected iterable, got " + repr(value))

    if action == "merge":
        try:
            return [str(ip) for ip in netaddr.cidr_merge(value)]
        except Exception as e:
            raise AnsibleFilterError("cidr_merge: error in netaddr:\n%s" % e)

    elif action == "span":
        # spanning_cidr needs at least two values
        if len(value) == 0:
            return None
        elif len(value) == 1:
            try:
                return str(netaddr.IPNetwork(value[0]))
            except Exception as e:
                raise AnsibleFilterError("cidr_merge: error in netaddr:\n%s" % e)
        else:
            try:
                return str(netaddr.spanning_cidr(value))
            except Exception as e:
                raise AnsibleFilterError("cidr_merge: error in netaddr:\n%s" % e)

    else:
        raise AnsibleFilterError("cidr_merge: invalid action '%s'" % action)


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "cidr_merge": _cidr_merge,
    }

    def filters(self):
        if HAS_NETADDR:
            return self.filter_map
        else:
            # Need to install python's netaddr for these filters to work
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
