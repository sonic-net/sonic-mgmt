# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: slaac
"""
from __future__ import absolute_import, division, print_function

from functools import partial

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddr_utils import (
    _need_netaddr,
    hwaddr,
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
    name: slaac
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter returns the SLAAC address within a network for a given HW/MAC address.
    description:
    - This filter returns the SLAAC address within a network for a given HW/MAC address.
    - The filter slaac() generates an IPv6 address for a given network and a MAC Address in Stateless Configuration.
    options:
        value:
            description: The network address or range to test against.
            type: str
            required: True
        query:
            description: nth host
            type: str
    notes:
"""

EXAMPLES = r"""
#### examples
- name: The filter slaac() generates an IPv6 address for a given network and a MAC Address in Stateless Configuration.
  debug:
    msg: "{{ 'fdcf:1894:23b5:d38c:0000:0000:0000:0000' | slaac('c2:31:b3:83:bf:2b') }}"

# TASK [The filter slaac() generates an IPv6 address for a given network and a MAC Address in Stateless Configuration.] ***
# task path: /Users/amhatre/ansible-collections/playbooks/test_slaac.yaml:7
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "fdcf:1894:23b5:d38c:c031:b3ff:fe83:bf2b"
# }
"""

RETURN = """
  data:
    type: str
    description:
      - Returns the SLAAC address within a network for a given HW/MAC address.

"""


@pass_environment
def _slaac(*args, **kwargs):
    """This filter returns whether an address or a network passed as argument is in a network."""
    keys = ["value", "query"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="slaac")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return slaac(**updated_data)


def slaac(value, query=""):
    """Get the SLAAC address within given network"""
    try:
        vtype = ipaddr(value, "type")
        if vtype == "address":
            v = ipaddr(value, "cidr")
        elif vtype == "network":
            v = ipaddr(value, "subnet")

        if ipaddr(value, "version") != 6:
            return False

        value = netaddr.IPNetwork(v)
    except Exception:
        return False

    if not query:
        return False

    try:
        mac = hwaddr(query, alias="slaac")

        eui = netaddr.EUI(mac)
    except Exception:
        return False

    return str(eui.ipv6(value.network))


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "slaac": _slaac,
    }

    def filters(self):
        """ipaddr filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
