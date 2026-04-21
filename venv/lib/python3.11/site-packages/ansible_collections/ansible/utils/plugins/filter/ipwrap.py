# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: ipwrap
"""
from __future__ import absolute_import, division, print_function

import types

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
    name: ipwrap
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter is designed to Wrap IPv6 addresses in [ ] brackets.
    description:
    - Some configuration files require IPv6 addresses to be "wrapped" in square brackets ([ ]).To accomplish that,
    - you can use the ipwrap() filter.It will wrap all IPv6 addresses and leave any other strings intact.
    options:
        value:
            description:
            - list of subnets or individual address or any other values input. Example. ['192.24.2.1', 'host.fqdn',
              '::1', '192.168.32.0/24', 'fe80::100/10', True, '', '42540766412265424405338506004571095040/64']
            type: raw
            required: True
        query:
            description:
            - You can provide a single argument to each ipwrap() filter.
            - The filter will then treat it as a query and return values modified by that query.
            type: str
            default: ''
    notes:
"""

EXAMPLES = r"""
#### examples
# Ipwrap filter plugin o Wrap IPv6 addresses in [ ] brackets.
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
    msg: "{{ value|ansible.utils.ipwrap }}"

- name: |
        ipwrap() did not filter out non-IP address values, which is usually what you want when for example
        you are mixing IP addresses with hostnames. If you still want to filter out all non-IP address values,
        you can chain both filters together.
  debug:
    msg: "{{ value|ansible.utils.ipaddr|ansible.utils.ipwrap  }}"

# PLAY [Ipwrap filter plugin o Wrap IPv6 addresses in [ ] brackets.] ***************************************************
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
# TASK [debug] ************************************************************************************************
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1",
#         "host.fqdn",
#         "[::1]",
#         "",
#         "192.168.32.0/24",
#         "[fe80::100]/10",
#         "[2001:db8:32c:faad::]/64",
#         "True"
#     ]
# }
#
# TASK [ipwrap() did not filter out non-IP address values, which is usually what you want when for example
# you are mixing IP addresses with hostnames. If you still want to filter out all non-IP address values,
# you can chain both filters together.] ***
# ok: [localhost] => {
#     "msg": [
#         "192.24.2.1",
#         "[::1]",
#         "192.168.32.0/24",
#         "[fe80::100]/10",
#         "[2001:db8:32c:faad::]/64"
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
def _ipwrap(*args, **kwargs):
    """This filter is designed to Wrap IPv6 addresses in [ ] brackets."""
    keys = ["value"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    try:
        if isinstance(data["value"], str):
            pass
        elif isinstance(data["value"], list):
            pass
        elif isinstance(data["value"], bool):
            pass
        else:
            raise AnsibleFilterError(
                "Unrecognized type <{0}> for ipwrap filter <{1}>".format(
                    type(data["value"]),
                    "value",
                ),
            )

    except (TypeError, ValueError):
        raise AnsibleFilterError(
            "Unrecognized type <{0}> for ipwrap filter <{1}>".format(type(data["value"]), "value"),
        )
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="ipwrap")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return ipwrap(**updated_data)


def ipwrap(value, query=""):
    try:
        if isinstance(value, (list, tuple, types.GeneratorType)):
            _ret = []
            for element in value:
                if ipaddr(element, query, version=False, alias="ipwrap"):
                    _ret.append(ipaddr(element, "wrap"))
                else:
                    _ret.append(element)

            return _ret
        else:
            _ret = ipaddr(value, query, version=False, alias="ipwrap")
            if _ret:
                return ipaddr(_ret, "wrap")
            else:
                return value

    except Exception:
        return value


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "ipwrap": _ipwrap,
    }

    def filters(self):
        """ipwrap filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
