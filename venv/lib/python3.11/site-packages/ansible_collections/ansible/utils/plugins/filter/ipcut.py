# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: ip_cut
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
    name: ipcut
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.11.0"
    short_description: This filter is designed to get 1st or last few bits of IP address.
    description:
        - This filter is designed to fetch 1st or last few bits of Ip address.
    options:
        value:
            description:
            - list of subnets or individual address or any other values input for ip_cut plugin
            type: str
            required: True
        amount:
            type: int
            description: integer for arithmetic. Example -1,2,3
"""

EXAMPLES = r"""
#### examples
- name: Get first 64 bits of Ipv6 address
  debug:
    msg: "{{ '1234:4321:abcd:dcba::17' | ansible.utils.ipcut(64) }}"

- name: Get last 80 bits of Ipv6 address
  debug:
    msg: "{{ '1234:4321:abcd:dcba::17' | ansible.utils.ipcut(-80) }}"
# PLAY [IPCUT filter plugin examples] ************************************************************************************************

# TASK [Get first X bits of Ipv6 address] ********************************************************************************************
# ok: [localhost] => {
#     "msg": "1234:4321:abcd:dcba"
# }

# TASK [Get last X bits of Ipv6 address] *********************************************************************************************
# ok: [localhost] => {
#     "msg": "dcba:0:0:0:17"
# }

# PLAY RECAP *************************************************************************************************************************
# localhost                  : ok=2    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
"""

RETURN = """
  data:
    type: str
    description:
      - Returns result of portion of IP.
"""


@pass_environment
def _ipcut(*args, **kwargs):
    """Fetch first or last bits of IPV6 address"""
    keys = ["value", "amount"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ipmath")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ipcut(**updated_data)


def ipcut(value, amount):
    try:
        ip = netaddr.IPAddress(value)
        if ip.version == 6:
            ip_bits = ip.bits().replace(":", "")
        elif ip.version == 4:
            ip_bits = ip.bits().replace(".", "")
        else:
            msg = "Unknown IP Address Version: {0}".format(ip.version)
            raise AnsibleFilterError(msg)
    except (netaddr.AddrFormatError, ValueError):
        msg = "You must pass a valid IP address; {0} is invalid".format(value)
        raise AnsibleFilterError(msg)

    if not isinstance(amount, int):
        msg = ("You must pass an integer for arithmetic; " "{0} is not a valid integer").format(
            amount,
        )
        raise AnsibleFilterError(msg)
    else:
        if amount < 0:
            ipsub = ip_bits[amount:]
        else:
            ipsub = ip_bits[0:amount]

    if ip.version == 6:
        ipv4_oct = []
        for i in range(0, len(ipsub), 16):
            oct_sub = i + 16
            ipv4_oct.append(
                hex(int(ipsub[i:oct_sub], 2)).replace("0x", ""),
            )
        result = str(":".join(ipv4_oct))
    else:  # ip.version == 4:
        ipv4_oct = []
        for i in range(0, len(ipsub), 8):
            oct_sub = i + 8
            ipv4_oct.append(
                str(int(ipsub[i:oct_sub], 2)),
            )
        result = str(".".join(ipv4_oct))
    return result


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # This filter is designed to fetch first or last bits of IPV6 address
        "ipcut": _ipcut,
    }

    def filters(self):
        """ipcut filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
