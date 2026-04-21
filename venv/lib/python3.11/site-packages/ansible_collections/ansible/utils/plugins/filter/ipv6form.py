# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: ipv6form
"""
from __future__ import absolute_import, division, print_function

from functools import partial

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddr_utils import _need_netaddr
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_address,
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
    name: ipv6form
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.11.0"
    short_description: This filter is designed to convert ipv6 address in different formats. For example expand, compressetc.
    description:
        - This filter is designed to convert ipv6 addresses in different formats.
    options:
        value:
            description:
            - individual ipv6 address input for ipv6_format plugin.
            type: str
            required: True
        format:
            type: str
            choices:
                ['compress', 'expand', 'x509']
            description: Different formats example. compress, expand, x509
"""

EXAMPLES = r"""
#### examples
# Ipv6form filter plugin with different format.
- name: Expand given Ipv6 address
  debug:
      msg: "{{ '1234:4321:abcd:dcba::17' | ansible.utils.ipv6form('expand') }}"

- name: Compress  given Ipv6 address
  debug:
      msg: "{{ '1234:4321:abcd:dcba:0000:0000:0000:0017' | ansible.utils.ipv6form('compress') }}"

- name: Covert given Ipv6 address in x509
  debug:
      msg: "{{ '1234:4321:abcd:dcba::17' | ansible.utils.ipv6form('x509') }}"

# TASK [Expand given Ipv6 address] ************************************************************************************
# task path: /home/amhatre/dev/playbook/test_ipform.yaml:7
# Loading collection ansible.utils from /home/amhatre/dev/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "1234:4321:abcd:dcba:0000:0000:0000:0017"
# }

# TASK [Compress  given Ipv6 address] *********************************************************************************
# task path: /home/amhatre/dev/playbook/test_ipform.yaml:11
# Loading collection ansible.utils from /home/amhatre/dev/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "1234:4321:abcd:dcba::17"
# }

# TASK [Covert given Ipv6 address in x509] ****************************************************************************
# task path: /home/amhatre/dev/playbook/test_ipform.yaml:15
# Loading collection ansible.utils from /home/amhatre/dev/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "1234:4321:abcd:dcba:0:0:0:17"
# }

# PLAY RECAP **********************************************************************************************************
# localhost                  : ok=3    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
"""

RETURN = """
  data:
    type: str
    description:
      - Returns result ipv6 address in expected format.
"""


@pass_environment
def _ipv6form(*args, **kwargs):
    """Convert the given data from json to xml."""
    keys = ["value", "format"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ipv6form")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ipv6form(**updated_data)


@_need_ipaddress
def ipv6form(value, format):
    try:
        if format == "expand":
            return ip_address(value).exploded
        elif format == "compress":
            return ip_address(value).compressed
        elif format == "x509":
            return _handle_x509(value)
    except ValueError:
        msg = "You must pass a valid IP address; {0} is invalid".format(value)
        raise AnsibleFilterError(msg)

    if not isinstance(format, str):
        msg = ("You must pass valid format; " "{0} is not a valid format").format(
            format,
        )
        raise AnsibleFilterError(msg)


def _handle_x509(value):
    """Convert ipv6 address into x509 format"""
    ip = netaddr.IPAddress(value)
    ipv6_oct = []
    ipv6address = ip.bits().split(":")
    for i in ipv6address:
        x = hex(int(i, 2))
        ipv6_oct.append(x.replace("0x", ""))
    return str(":".join(ipv6_oct))


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # This filter is designed to do ipv6 conversion in required format
        "ipv6form": _ipv6form,
    }

    def filters(self):
        """ipv6form filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
