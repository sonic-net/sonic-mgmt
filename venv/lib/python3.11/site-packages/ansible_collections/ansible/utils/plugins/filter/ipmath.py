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
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddr_utils import _need_netaddr


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
    name: ipmath
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter is designed to do simple IP math/arithmetic.
    description:
        - This filter is designed to do simple IP math/arithmetic.
    options:
        value:
            description:
            - list of subnets or individual address or any other values input for ipaddr plugin
            type: str
            required: True
        amount:
            type: int
            description: integer for arithmetic. Example -1,2,3
"""

EXAMPLES = r"""
#### examples
# Ipmath filter plugin with different arthmetic.
# Get the next fifth address based on an IP address
- debug:
    msg: "{{ '192.168.1.5' | ansible.netcommon.ipmath(5) }}"

# Get the tenth previous address based on an IP address
- debug:
    msg: "{{ '192.168.1.5' | ansible.netcommon.ipmath(-10) }}"

# Get the next fifth address using CIDR notation
- debug:
    msg: "{{ '192.168.1.1/24' | ansible.netcommon.ipmath(5) }}"

# Get the previous fifth address using CIDR notation
- debug:
    msg: "{{ '192.168.1.6/24' | ansible.netcommon.ipmath(-5) }}"

# Get the previous tenth address using cidr notation
# It returns a address of the previous network range
- debug:
    msg: "{{ '192.168.2.6/24' | ansible.netcommon.ipmath(-10) }}"

# Get the next tenth address in IPv6
- debug:
    msg: "{{ '2001::1' | ansible.netcommon.ipmath(10) }}"

# Get the previous tenth address in IPv6
- debug:
    msg: "{{ '2001::5' | ansible.netcommon.ipmath(-10) }}"

# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "192.168.1.10"
# }
#
# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "192.168.0.251"
# }
#
# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "192.168.1.6"
# }
#
# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "192.168.1.1"
# }
#
# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "192.168.1.252"
# }
#
# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "2001::b"
# }
#
# TASK [debug] **********************************************************************************************************
# ok: [localhost] => {
#     "msg": "2000:ffff:ffff:ffff:ffff:ffff:ffff:fffb"
# }
"""

RETURN = """
  data:
    type: str
    description:
      - Returns result of IP math/arithmetic.
"""


@pass_environment
def _ipmath(*args, **kwargs):
    """Convert the given data from json to xml."""
    keys = ["value", "amount"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ipmath")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ipmath(**updated_data)


def ipmath(value, amount):
    try:
        if "/" in value:
            ip = netaddr.IPNetwork(value).ip
        else:
            ip = netaddr.IPAddress(value)
    except (netaddr.AddrFormatError, ValueError):
        msg = "You must pass a valid IP address; {0} is invalid".format(value)
        raise AnsibleFilterError(msg)

    if not isinstance(amount, int):
        msg = ("You must pass an integer for arithmetic; " "{0} is not a valid integer").format(
            amount,
        )
        raise AnsibleFilterError(msg)

    return str(ip + amount)


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # This filter is designed to do simple IP math/arithmetic
        "ipmath": _ipmath,
    }

    def filters(self):
        """ipmath filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
