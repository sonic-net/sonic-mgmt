# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: ipv6
"""
from __future__ import absolute_import, division, print_function

from functools import partial

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddr_utils import (
    _need_netaddr,
    ipaddr,
)


__metaclass__ = type


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment

try:
    import netaddr

    HAS_NETADDR = True
except ImportError:
    # in this case, we'll make the filters return error messages (see bottom)
    HAS_NETADDR = False
else:

    class mac_linux(netaddr.mac_unix):
        pass

    mac_linux.word_fmt = "%.2x"

DOCUMENTATION = """
    name: ipv6
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: To filter only Ipv6 addresses Ipv6 filter is used.
    description:
        - Sometimes you need only IPv6 addresses. To filter only Ipv6 addresses Ipv6 filter is used.
    options:
        value:
            description:
            - list of subnets or individual address or any other values input for ipv6 plugin
            type: raw
            required: True
        query:
            description:
            - You can provide a single argument to each ipv6() filter.
            - Example. query type 'ipv4' to convert ipv6 into ipv4
            type: str
            default: ''
    notes:
"""

EXAMPLES = r"""
#### examples
# Ipv6 filter plugin with different queries.
- name: Set value as input list
  ansible.builtin.set_fact:
    value:
      - 192.24.2.1
      - ::ffff:192.168.32.0/120
      - ''
      - ::ffff:192.24.2.1/128
      - 192.168.32.0/24
      - fe80::100/10
      - true
- name: IPv6 filter to filter Ipv6 Address
  debug:
    msg: "{{ value|ansible.utils.ipv6 }}"

- name: convert IPv6 addresses into IPv4 addresses.
  debug:
    msg: "{{ value|ansible.utils.ipv6('ipv4') }}"

- name: filter only  IPv6 addresses.
  debug:
    msg: "{{ value|ansible.utils.ipv6('address') }}"


# PLAY [Ipv6 filter plugin with different queries.] ******************************************************************
# TASK [Set value as input list] ***************************************************************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "value": [
#             "192.24.2.1",
#             "::ffff:192.168.32.0/120",
#             "",
#             "::ffff:192.24.2.1/128",
#             "192.168.32.0/24",
#             "fe80::100/10",
#             true
#         ]
#     },
#     "changed": false
# }
#
# TASK [IPv6 filter to filter Ipv6 Address] ****************************************************************************
# ok: [localhost] => {
#     "msg": [
#         "::ffff:192.168.32.0/120",
#         "::ffff:192.24.2.1/128",
#         "fe80::100/10"
#     ]
# }
#
# TASK [convert IPv6 addresses into IPv4 addresses.] *******************************************************************
# ok: [localhost] => {
#     "msg": [
#         "192.168.32.0/24",
#         "192.24.2.1/32"
#     ]
# }
#
# TASK [filter only  IPv6 addresses] *******************************************************************
# ok: [localhost] => {
#     "msg": [
#         "::ffff:192.168.32.0",
#         "::ffff:192.24.2.1",
#         "fe80::100"
#     ]
# }
#
"""

RETURN = """
  data:
    type: raw
    description:
      - Returns values valid for a particular query.
"""


@pass_environment
def _ipv6(*args, **kwargs):
    """This filter is designed to return the input value if a query is True, and False if a query is False"""
    keys = ["value", "query"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    try:
        if isinstance(data["value"], str):
            pass
        elif isinstance(data["value"], list):
            pass
        elif isinstance(data["value"], int):
            pass
        else:
            raise AnsibleFilterError(
                "Unrecognized type <{0}> for ipv6 filter <{1}>".format(
                    type(data["value"]),
                    "value",
                ),
            )

    except (TypeError, ValueError):
        raise AnsibleFilterError(
            "Unrecognized type <{0}> for ipv6 filter <{1}>".format(type(data["value"]), "value"),
        )
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ipv6")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ipv6(**updated_data)


def ipv6(value, query=""):
    return ipaddr(value, query, version=6, alias="ipv6")


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "ipv6": _ipv6,
    }

    def filters(self):
        """ipv6 filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
