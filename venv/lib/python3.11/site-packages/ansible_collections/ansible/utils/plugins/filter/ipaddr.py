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
    name: ipaddr
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter is designed to return the input value if a query is True, else False.
    description:
        - This filter is designed to return the input value if a query is True, and False if a query is False
        - This way it can be easily used in chained filters
        - For more details on how to use this plugin, please refer to `<docsite/rst/filters_ipaddr.rst>`_
    options:
        value:
            description:
            - list of subnets or individual address or any other values input for ipaddr plugin
            type: raw
            required: True
        query:
            description:
            - You can provide a single argument to each ipaddr() filter.
            - The filter will then treat it as a query and return values modified by that query.
            - >-
              Types of queries include:
              1. query by name: ansible.utils.ipaddr('address'), ansible.utils.ipv4('network');
              2. query by CIDR range: ansible.utils.ipaddr('192.168.0.0/24'), ansible.utils.ipv6('2001:db8::/32');
              3. query by index number: ansible.utils.ipaddr('1'), ansible.utils.ipaddr('-1');
            type: str
            default: ''
        version:
            type: int
            description: Ip version 4 or 6
        alias:
            type: str
            description: type of filter. example ipaddr, ipv4, ipv6, ipwrap
    notes:
    requirements:
        - netaddr>=0.10.1
"""

EXAMPLES = r"""
#### examples
# Ipaddr filter plugin with different queries.
- name: Set value as input list
  ansible.builtin.set_fact:
    value:
      - 192.24.2.1
      - host.fqdn
      - ::1
      - ''
      - 192.168.32.0/24
      - fe80::100/10
      - 42540766412265424405338506004571095040/64
      - true
- debug:
    msg: "{{ value|ansible.utils.ipaddr }}"

- name: Fetch only those elements that are host IP addresses and not network ranges
  debug:
    msg: "{{ value|ansible.utils.ipaddr('address') }}"

- name: |
    Fetch only host IP addresses with their correct CIDR prefixes (as is common with IPv6 addressing), you can use
    the ipaddr('host') filter.
  debug:
    msg: "{{ value|ansible.utils.ipaddr('host') }}"

- name: check if IP addresses or network ranges are accessible on a public Internet and return it.
  debug:
    msg: "{{ value|ansible.utils.ipaddr('public') }}"

- name: check if IP addresses or network ranges are accessible on a private Internet and return it.
  debug:
    msg: "{{ value|ansible.utils.ipaddr('private') }}"

- name: check which values are values are specifically network ranges and return it.
  debug:
    msg: "{{ value|ansible.utils.ipaddr('net') }}"

- name: check how many IP addresses can be in a certain range.
  debug:
    msg: "{{ value| ansible.utils.ipaddr('net') | ansible.utils.ipaddr('size') }}"

- name: By specifying a network range as a query, you can check if a given value is in that range.
  debug:
    msg: "{{ value|ansible.utils.ipaddr('192.0.0.0/8') }}"

# First IP address (network address)
- name: |
    If you specify a positive or negative integer as a query, ipaddr() will treat this as an index and will return
    the specific IP address from a network range, in the "host/prefix" format.
  debug:
    msg: "{{ value| ansible.utils.ipaddr('net') | ansible.utils.ipaddr('0') }}"

# Second IP address (usually the gateway host)
- debug:
    msg: "{{ value| ansible.utils.ipaddr('net') | ansible.utils.ipaddr('1') }}"

# Last IP address (the broadcast address in IPv4 networks)
- debug:
    msg: "{{ value| ansible.utils.ipaddr('net') | ansible.utils.ipaddr('-1') }}"


# PLAY [Ipaddr filter plugin with different queries.] ******************************************************************
# TASK [Set value as input list] ***************************************************************************************
# ok: [localhost] => {"ansible_facts": {"value": ["192.24.2.1", "host.fqdn", "::1", "", "192.168.32.0/24",
# "fe80::100/10", "42540766412265424405338506004571095040/64", true]}, "changed": false}
#
# TASK [debug] ********************************************************************************************************
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1",
#         "::1",
#         "192.168.32.0/24",
#         "fe80::100/10",
#         "2001:db8:32c:faad::/64"
#     ]
# }
#
# TASK [Fetch only those elements that are host IP addresses and not network ranges] ***********************************
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1",
#         "::1",
#         "fe80::100",
#         "2001:db8:32c:faad::"
#     ]
# }
#
# TASK [Fetch only host IP addresses with their correct CIDR prefixes (as is common with IPv6 addressing), you can use
# the ipaddr('host') filter.] *****************
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1/32",
#         "::1/128",
#         "fe80::100/10"
#     ]
# }
#
# TASK [check if IP addresses or network ranges are accessible on a public Internet and return it.] ********************
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1",
#         "2001:db8:32c:faad::/64"
#     ]
# }
#
# TASK [check if IP addresses or network ranges are accessible on a private Internet and return it.] *******************
# ok: [localhost] => {
#     "msg": [
#         "192.168.32.0/24",
#         "fe80::100/10"
#     ]
# }
#
# TASK [check which values are values are specifically network ranges and return it.] **********************************
# ok: [localhost] => {
#     "msg": [
#         "192.168.32.0/24",
#         "2001:db8:32c:faad::/64"
#     ]
# }
#
# TASK [check how many IP addresses can be in a certain range.] *********************************************************
# ok: [localhost] => {
#     "msg": [
#         256,
#         18446744073709551616
#     ]
# }
#
# TASK [By specifying a network range as a query, you can check if a given value is in that range.] ********************
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1",
#         "192.168.32.0/24"
#     ]
# }
#
# TASK [If you specify a positive or negative integer as a query, ipaddr() will treat this as an index and will
# return the specific IP address from a network range, in the "host/prefix" format.] ***
# ok: [localhost] => {
#     "msg": [
#         "192.168.32.0/24",
#         "2001:db8:32c:faad::/64"
#     ]
# }
#
# TASK [debug] *********************************************************************************************************
# ok: [localhost] => {
#     "msg": [
#         "192.168.32.1/24",
#         "2001:db8:32c:faad::1/64"
#     ]
# }
#
# TASK [debug] ********************************************************************************************************
# ok: [localhost] => {
#     "msg": [
#         "192.168.32.255/24",
#         "2001:db8:32c:faad:ffff:ffff:ffff:ffff/64"
#     ]
# }
"""

RETURN = """
  data:
    type: raw
    description:
      - Returns values valid for a particular query.
"""


@pass_environment
def _ipaddr(*args, **kwargs):
    """This filter is designed to return the input value if a query is True, and False if a query is False"""
    keys = ["value", "query", "version", "alias"]
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
                "Unrecognized type <{0}> for ipaddr filter <{1}>".format(
                    type(data["value"]),
                    "value",
                ),
            )

    except (TypeError, ValueError):
        raise AnsibleFilterError(
            "Unrecognized type <{0}> for ipaddr filter <{1}>".format(type(data["value"]), "value"),
        )

    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ipaddr")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ipaddr(**updated_data)


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "ipaddr": _ipaddr,
    }

    def filters(self):
        """ipaddr filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
