# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: nthhost
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
    name: nthhost
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter returns the nth host within a network described by value.
    description:
    - This filter returns the nth host within a network described by value. To return the nth ip from a network, use the filter nthhost.
    - Nthhost also supports a negative value.
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
- name: To return the nth ip from a network, use the filter nthhost.
  debug:
    msg: "{{ '10.0.0.0/8' | ansible.utils.nthhost(305)  }}"

- name: nthhost also supports a negative value.
  debug:
    msg: "{{ '10.0.0.0/8' | ansible.utils.nthhost(-1) }}"

# TASK [To return the nth ip from a network, use the filter nthhost.] *****************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_nthhost.yaml:7
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "10.0.1.49"
# }
#
# TASK [nthhost also supports a negative value.] **************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_nthhost.yaml:11
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "10.255.255.255"
# }
"""

RETURN = """
  data:
    type: str
    description:
      - Returns nth host from network

"""


@pass_environment
def _nthhost(*args, **kwargs):
    """This filter returns whether an address or a network passed as argument is in a network."""
    keys = ["value", "query"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="nthhost")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return nthhost(**updated_data)


def nthhost(value, query=""):
    """Returns the nth host within a network described by value."""
    try:
        vtype = ipaddr(value, "type")
        if vtype == "address":
            v = ipaddr(value, "cidr")
        elif vtype == "network":
            v = ipaddr(value, "subnet")

        value = netaddr.IPNetwork(v)
    except Exception:
        return False

    if not query:
        return False

    try:
        nth = int(query)
        if value.size > nth:
            return str(value[nth])

    except ValueError:
        return False

    return False


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "nthhost": _nthhost,
    }

    def filters(self):
        """ipaddr filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
