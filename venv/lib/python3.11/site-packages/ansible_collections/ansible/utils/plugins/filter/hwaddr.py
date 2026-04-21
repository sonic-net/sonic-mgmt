# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: hwaddr
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
        word_fmt = "%.2x"


DOCUMENTATION = """
    name: hwaddr
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: HWaddr / MAC address filters
    description:
    - This filter check if string is a HW/MAC address and filter it
    - You can use the hwaddr() filter to check if a given string is a MAC address or convert it between various
      formats.
    options:
        value:
            description: HW/MAC address.
            type: str
            required: True
        query:
            description: query string. Example. cisco,linux,unix etc
            type: str
            default: ""
        alias:
            description: alias
            type: str
            default: hwaddr
    notes:
"""

EXAMPLES = r"""
#### examples
- name: Check if given string is a MAC address
  debug:
    msg: "{{ '1a:2b:3c:4d:5e:6f' | ansible.utils.hwaddr }}"

- name: Convert HW address to Cisco format
  debug:
    msg: "{{ '1a:2b:3c:4d:5e:6f' | ansible.utils.hwaddr('cisco') }}"

# TASK [Check if given string is a MAC address] ***************************************************************
# ok: [localhost] => {
#     "msg": "1a:2b:3c:4d:5e:6f"
# }
#
# TASK [Convert HW address to Cisco format] ******************************************************************
# ok: [localhost] => {
#     "msg": "1a2b.3c4d.5e6f"
# }
"""

RETURN = """
  data:
    type: str
    description:
      - mac/Hw address

"""


@pass_environment
def _hwaddr(*args, **kwargs):
    """This filter check if string is a HW/MAC address and filter it"""
    keys = ["value", "query", "alias"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="hwaddr")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return hwaddr(**updated_data)


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "hwaddr": _hwaddr,
    }

    def filters(self):
        """ipaddr filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
