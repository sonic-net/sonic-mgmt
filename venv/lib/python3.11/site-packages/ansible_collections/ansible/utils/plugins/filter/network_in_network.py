# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: network_in_network
"""
from __future__ import absolute_import, division, print_function

from functools import partial

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddr_utils import (
    _address_normalizer,
    _need_netaddr,
    _range_checker,
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
    name: network_in_network
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter returns whether an address or a network passed as argument is in a network.
    description:
        - This filter returns whether an address or a network passed as argument is in a network.
    options:
        value:
            description: The network address or range to test against.
            type: str
            required: True
        test:
            description: The address or network to validate if it is within the range of 'value'.
            type: str
    notes:
"""

EXAMPLES = r"""
#### examples
- name: Check ip address 1 is part of another network
  debug:
    msg: "{{ '192.168.0.0/24' | ansible.utils.network_in_network( '192.168.0.1' ) }}"

- name: Check ip address 2 is part of another network
  debug:
    msg: "{{ '192.168.0.0/24' | ansible.utils.network_in_network( '10.0.0.1' ) }}"

- name: Check in a network is part of another network.
  debug:
    msg: "{{ '192.168.0.0/16' | ansible.utils.network_in_network( '192.168.0.0/24' ) }}"

# TASK [Check ip address 1 is part of another network] ********************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_network_in_network.yaml:7
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": true
# }
#
# TASK [Check ip address 2 is part of another network] ********************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_network_in_network.yaml:11
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": false
# }
#
# TASK [Check in a network is part of another network.] *******************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_network_in_network.yaml:15
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": true
# }
"""

RETURN = """
  data:
    type: bool
    description:
      - Returns whether an address or a network passed as argument is in a network.

"""


@pass_environment
def _network_in_network(*args, **kwargs):
    """This filter returns whether an address or a network passed as argument is in a network."""
    keys = ["value", "test"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="network_in_network")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return network_in_network(**updated_data)


def network_in_network(value, test):
    """
    Checks whether the 'test' address or addresses are in 'value', including broadcast and network
    :param: value: The network address or range to test against.
    :param test: The address or network to validate if it is within the range of 'value'.
    :return: bool
    """
    # normalize value and test variables into an ipaddr
    v = _address_normalizer(value)
    w = _address_normalizer(test)

    # get first and last addresses as integers to compare value and test; or cathes value when case is /32
    v_first = ipaddr(ipaddr(v, "network") or ipaddr(v, "address"), "int")
    v_last = ipaddr(ipaddr(v, "broadcast") or ipaddr(v, "address"), "int")
    w_first = ipaddr(ipaddr(w, "network") or ipaddr(w, "address"), "int")
    w_last = ipaddr(ipaddr(w, "broadcast") or ipaddr(w, "address"), "int")

    if _range_checker(w_first, v_first, v_last) and _range_checker(w_last, v_first, v_last):
        return True
    else:
        return False


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "network_in_network": _network_in_network,
    }

    def filters(self):
        """ipaddr filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
