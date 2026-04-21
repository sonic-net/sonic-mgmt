# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
filter plugin file for ipaddr filters: reduce_on_network
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
    name: reduce_on_network
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.5.0"
    short_description: This filter reduces a list of addresses to only the addresses that match a given network.
    description:
    - This filter reduces a list of addresses to only the addresses that match a given network.
    - To check whether multiple addresses belong to a network, use the reduce_on_network filter.
    options:
        value:
            description: the list of addresses to filter on.
            type: list
            elements: str
            required: True
        network:
            description: The network to validate against.
            type: str
    notes:
"""

EXAMPLES = r"""

- name: To check whether multiple addresses belong to a network, use the reduce_on_network filter.
  debug:
    msg: "{{ ['192.168.0.34', '10.3.0.3', '192.168.2.34'] | ansible.utils.reduce_on_network( '192.168.0.0/24' ) }}"

# TASK [To check whether multiple addresses belong to a network, use the reduce_on_network filter.] ***********
# task path: /Users/amhatre/ansible-collections/playbooks/test_reduce_on_network.yaml:7
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": [
#         "192.168.0.34"
#     ]
# }
"""

RETURN = """
  data:
    type: bool
    description:
      - Returns whether an address or a network passed as argument is in a network.

"""


@pass_environment
def _reduce_on_network(*args, **kwargs):
    """This filter returns whether an address or a network passed as argument is in a network."""
    keys = ["value", "network"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="reduce_on_network")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return reduce_on_network(**updated_data)


def reduce_on_network(value, network):
    """
    Reduces a list of addresses to only the addresses that match a given network.
    :param: value: The list of addresses to filter on.
    :param: network: The network to validate against.
    :return: The reduced list of addresses.
    """
    # normalize network variable into an ipaddr
    n = _address_normalizer(network)

    # get first and last addresses as integers to compare value and test; or cathes value when case is /32
    n_first = ipaddr(ipaddr(n, "network") or ipaddr(n, "address"), "int")
    n_last = ipaddr(ipaddr(n, "broadcast") or ipaddr(n, "address"), "int")

    # create an empty list to fill and return
    r = []

    for address in value:
        # normalize address variables into an ipaddr
        a = _address_normalizer(address)

        # get first and last addresses as integers to compare value and test; or cathes value when case is /32
        a_first = ipaddr(ipaddr(a, "network") or ipaddr(a, "address"), "int")
        a_last = ipaddr(ipaddr(a, "broadcast") or ipaddr(a, "address"), "int")

        if _range_checker(a_first, n_first, n_last) and _range_checker(a_last, n_first, n_last):
            r.append(address)

    return r


class FilterModule(object):
    """IP address and network manipulation filters"""

    filter_map = {
        # IP addresses and networks
        "reduce_on_network": _reduce_on_network,
    }

    def filters(self):
        """ipaddr filter"""
        if HAS_NETADDR:
            return self.filter_map
        else:
            return dict((f, partial(_need_netaddr, f)) for f in self.filter_map)
