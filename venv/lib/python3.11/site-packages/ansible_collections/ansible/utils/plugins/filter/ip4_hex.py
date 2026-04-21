# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: ip4_hex
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
    name: ip4_hex
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter is designed to convert IPv4 address to Hexadecimal notation with optional delimiter.
    description:
        - This filter convert IPv4 address to Hexadecimal notation with optional delimiter
    options:
        arg:
            description: IPv4 address.
            type: str
            required: True
        delimiter:
            description:
            - You can provide a single argument to each ip4_hex() filter as delimiter.
            type: str
            default: ''
    notes:
"""

EXAMPLES = r"""
#### examples
# ip4_hex convert IPv4 address to Hexadecimal notation with optional delimiter
- debug:
    msg: "{{ '192.168.1.5' | ansible.utils.ip4_hex }}"

# ip4_hex with delimiter
- debug:
    msg: "{{ '192.168.1.5' | ansible.utils.ip4_hex(':') }}"

# TASK [debug] ************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_ip4_hex.yaml:7
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "c0a80105"
# }
#
# TASK [debug] ************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_ip4_hex.yaml:11
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "c0:a8:01:05"
# }
"""

RETURN = """
  data:
    type: str
    description:
      - Returns IPv4 address to Hexadecimal notation.
"""


@pass_environment
def _ip4_hex(*args, **kwargs):
    """This filter is designed to Convert an IPv4 address to Hexadecimal notation"""
    keys = ["arg", "delimiter"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ip4_hex")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ip4_hex(**updated_data)


def ip4_hex(arg, delimiter=""):
    """Convert an IPv4 address to Hexadecimal notation"""
    try:
        ip = netaddr.IPAddress(arg)
    except (netaddr.AddrFormatError, ValueError):
        msg = "You must pass a valid IP address; {0} is invalid".format(arg)
        raise AnsibleFilterError(msg)
    numbers = list(map(int, arg.split(".")))
    return "{0:02x}{sep}{1:02x}{sep}{2:02x}{sep}{3:02x}".format(*numbers, sep=delimiter)


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "ip4_hex": _ip4_hex,
    }

    def filters(self):
        """ip4_hex filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
