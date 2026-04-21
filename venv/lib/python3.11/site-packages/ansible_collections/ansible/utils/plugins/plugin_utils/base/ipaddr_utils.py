# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The utils file for all ipaddr filters
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import types

from ansible.errors import AnsibleFilterError
from ansible.module_utils.basic import missing_required_lib
from ansible.utils.display import Display


try:
    import netaddr
except ImportError:
    # in this case, we'll make the filters return error messages (see bottom)
    netaddr = None
else:

    class mac_linux(netaddr.mac_unix):
        pass

    mac_linux.word_fmt = "%.2x"

display = Display()


# ---- IP address and network query helpers ----
def _empty_ipaddr_query(v, vtype):
    # We don't have any query to process, so just check what type the user
    # expects, and return the IP address in a correct format
    if v:
        if vtype == "address":
            return str(v.ip)
        elif vtype == "network":
            return str(v)


def _first_last(v):
    if v.size == 2:
        first_usable = int(netaddr.IPAddress(v.first))
        last_usable = int(netaddr.IPAddress(v.last))
        return first_usable, last_usable
    elif v.size > 1:
        first_usable = int(netaddr.IPAddress(v.first + 1))
        last_usable = int(netaddr.IPAddress(v.last - 1))
        return first_usable, last_usable


def _6to4_query(v, vtype, value):
    if v.version == 4:
        if v.size == 1:
            ipconv = str(v.ip)
        elif v.size > 1:
            if v.ip != v.network:
                ipconv = str(v.ip)
            else:
                return False

        if ipaddr(ipconv, "public") or ipaddr(ipconv, "private"):
            numbers = list(map(int, ipconv.split(".")))

        try:
            return "2002:{:02x}{:02x}:{:02x}{:02x}::1/48".format(*numbers)
        except Exception:
            pass

    elif v.version == 6:
        if vtype == "address":
            if ipaddr(str(v), "2002::/16"):
                return value
        elif vtype == "network":
            if v.ip != v.network:
                if ipaddr(str(v.ip), "2002::/16"):
                    return value

    return False


def _ip_query(v):
    if v.size == 1:
        return str(v.ip)
    if v.size > 1:
        # /31 networks in netaddr have no broadcast address
        if v.ip != v.network or not v.broadcast:
            return str(v.ip)
        # For the first IPv6 address in a network, netaddr will return it as a network address, despite it being a valid host address.
        elif v.version == 6 and v.ip == v.network:
            return str(v.ip)


def _address_prefix_query(v):
    if v.size > 2 and v.ip in (v.network, v.broadcast):
        return False
    return str(v.ip) + "/" + str(v.prefixlen)


def _bool_ipaddr_query(v):
    if v:
        return True


def _broadcast_query(v):
    if v.size > 2:
        return str(v.broadcast)


def _cidr_query(v):
    return str(v)


def _cidr_lookup_query(v, iplist, value):
    try:
        if v in iplist:
            return value
    except Exception:
        return False


def _first_usable_query(v, vtype):
    if vtype == "address":
        # Does it make sense to raise an error
        raise AnsibleFilterError("Not a network address")
    elif vtype == "network":
        if v.size == 2:
            return str(netaddr.IPAddress(int(v.network)))
        elif v.size > 1:
            return str(netaddr.IPAddress(int(v.network) + 1))


def _host_query(v):
    if v.size == 1:
        return str(v)
    elif v.size > 1:
        if v.ip != v.network or not v.broadcast:
            return str(v.ip) + "/" + str(v.prefixlen)


def _hostmask_query(v):
    return str(v.hostmask)


def _int_query(v, vtype):
    if vtype == "address":
        return int(v.ip)
    elif vtype == "network":
        return str(int(v.ip)) + "/" + str(int(v.prefixlen))


def _ip_prefix_query(v):
    if v.size == 2:
        return str(v.ip) + "/" + str(v.prefixlen)
    elif v.size > 1:
        if v.ip != v.network:
            return str(v.ip) + "/" + str(v.prefixlen)


def _ip_netmask_query(v):
    if v.size == 2:
        return str(v.ip) + " " + str(v.netmask)
    elif v.size > 1:
        if v.ip != v.network:
            return str(v.ip) + " " + str(v.netmask)


def _ipv4_query(v, value):
    if v.version == 6:
        try:
            return str(v.ipv4())
        except Exception:
            return False
    else:
        return value


def _ipv6_query(v, value):
    if v.version == 4:
        return str(v.ipv6())
    else:
        return value


def _last_usable_query(v, vtype):
    if vtype == "address":
        # Does it make sense to raise an error
        raise AnsibleFilterError("Not a network address")
    elif vtype == "network":
        if v.size > 1:
            first_usable, last_usable = _first_last(v)
            return str(netaddr.IPAddress(last_usable))


def _link_local_query(v, value):
    v_ip = netaddr.IPAddress(str(v.ip))
    if v.version == 4:
        if ipaddr(str(v_ip), "169.254.0.0/16"):
            return value

    elif v.version == 6:
        if ipaddr(str(v_ip), "fe80::/10"):
            return value


def _loopback_query(v, value):
    v_ip = netaddr.IPAddress(str(v.ip))
    if v_ip.is_loopback():
        return value


def _multicast_query(v, value):
    if v.is_multicast():
        return value


def _net_query(v):
    if v.size > 1:
        if v.ip == v.network:
            return str(v.network) + "/" + str(v.prefixlen)


def _netmask_query(v):
    return str(v.netmask)


def _network_query(v):
    """Return the network of a given IP or subnet"""
    return str(v.network)


def _network_netmask_query(v):
    return str(v.network) + " " + str(v.netmask)


def _network_wildcard_query(v):
    return str(v.network) + " " + str(v.hostmask)


def _next_usable_query(v, vtype):
    if vtype == "address":
        # Does it make sense to raise an error
        raise AnsibleFilterError("Not a network address")
    elif vtype == "network":
        if v.size > 1:
            first_usable, last_usable = _first_last(v)
            next_ip = int(netaddr.IPAddress(int(v.ip) + 1))
            if next_ip >= first_usable and next_ip <= last_usable:
                return str(netaddr.IPAddress(int(v.ip) + 1))


def _peer_query(v, vtype):
    if vtype == "address":
        raise AnsibleFilterError("Not a network address")
    elif vtype == "network":
        if v.size == 2:
            return str(netaddr.IPAddress(int(v.ip) ^ 1))
        if v.size == 4:
            if int(v.ip) % 4 == 0:
                raise AnsibleFilterError("Network address of /30 has no peer")
            if int(v.ip) % 4 == 3:
                raise AnsibleFilterError("Broadcast address of /30 has no peer")
            return str(netaddr.IPAddress(int(v.ip) ^ 3))
        raise AnsibleFilterError("Not a point-to-point network")


def _prefix_query(v):
    return int(v.prefixlen)


def _previous_usable_query(v, vtype):
    if vtype == "address":
        # Does it make sense to raise an error
        raise AnsibleFilterError("Not a network address")
    elif vtype == "network":
        if v.size > 1:
            first_usable, last_usable = _first_last(v)
            previous_ip = int(netaddr.IPAddress(int(v.ip) - 1))
            if previous_ip >= first_usable and previous_ip <= last_usable:
                return str(netaddr.IPAddress(int(v.ip) - 1))


def _ip_is_global(ip):
    # fallback to support netaddr < 1.0.0
    # attempt to emulate IPAddress.is_global() if it's not available
    # note that there still might be some behavior differences (e.g. exceptions)
    has_is_global = callable(getattr(ip, "is_global", None))
    return (
        ip.is_global()
        if has_is_global
        else (
            not (ip.is_private() or ip.is_link_local() or ip.is_reserved())
            and all(
                ip not in netaddr.IPNetwork(ipv6net)
                for ipv6net in [
                    "::1/128",
                    "::/128",
                    "::ffff:0:0/96",
                    "64:ff9b:1::/48",
                    "100::/64",
                    "2001::/23",
                    "2001:db8::/32",
                    "2002::/16",
                ]
            )
            or ip in netaddr.IPRange("239.0.0.0", "239.255.255.255")  # Administrative Multicast
            or ip in netaddr.IPNetwork("233.252.0.0/24")  # Multicast test network
            or ip in netaddr.IPRange("234.0.0.0", "238.255.255.255")
            or ip in netaddr.IPRange("225.0.0.0", "231.255.255.255")
            or ip in netaddr.IPNetwork("192.88.99.0/24")  # 6to4 anycast relays (RFC 3068)
            or ip in netaddr.IPNetwork("192.0.0.9/32")
            or ip in netaddr.IPNetwork("192.0.0.10/32")
        )
    )


def _private_query(v, value):
    if not _ip_is_global(v.ip):
        return value


def _public_query(v, value):
    v_ip = netaddr.IPAddress(str(v.ip))
    if all(
        [
            v_ip.is_unicast(),
            _ip_is_global(v_ip),
            not v_ip.is_loopback(),
            not v_ip.is_netmask(),
            not v_ip.is_hostmask(),
        ],
    ):
        return value


def _range_usable_query(v, vtype):
    if vtype == "address":
        # Does it make sense to raise an error
        raise AnsibleFilterError("Not a network address")
    elif vtype == "network":
        if v.size > 1:
            first_usable, last_usable = _first_last(v)
            first_usable = str(netaddr.IPAddress(first_usable))
            last_usable = str(netaddr.IPAddress(last_usable))
            return "{0}-{1}".format(first_usable, last_usable)


def _revdns_query(v):
    v_ip = netaddr.IPAddress(str(v.ip))
    return v_ip.reverse_dns


def _size_query(v):
    return v.size


def _size_usable_query(v):
    if v.size == 1:
        return 0
    elif v.size == 2:
        return 2
    return v.size - 2


def _subnet_query(v):
    return str(v.cidr)


def _type_query(v):
    if v.size == 1:
        return "address"
    if v.size > 1:
        if v.ip != v.network:
            return "address"
        else:
            return "network"


def _unicast_query(v, value):
    if v.is_unicast():
        return value


def _version_query(v):
    return v.version


def _wrap_query(v, vtype, value):
    if v.version == 6:
        if vtype == "address":
            return "[" + str(v.ip) + "]"
        elif vtype == "network":
            return "[" + str(v.ip) + "]/" + str(v.prefixlen)
    else:
        return value


def ipaddr(value, query="", version=False, alias="ipaddr"):
    """Check if string is an IP address or network and filter it"""

    query_func_extra_args = {
        "": ("vtype",),
        "6to4": ("vtype", "value"),
        "cidr_lookup": ("iplist", "value"),
        "first_usable": ("vtype",),
        "int": ("vtype",),
        "ipv4": ("value",),
        "ipv6": ("value",),
        "last_usable": ("vtype",),
        "link-local": ("value",),
        "loopback": ("value",),
        "lo": ("value",),
        "multicast": ("value",),
        "next_usable": ("vtype",),
        "peer": ("vtype",),
        "previous_usable": ("vtype",),
        "private": ("value",),
        "public": ("value",),
        "unicast": ("value",),
        "range_usable": ("vtype",),
        "wrap": ("vtype", "value"),
    }

    query_func_map = {
        "": _empty_ipaddr_query,
        "6to4": _6to4_query,
        "address": _ip_query,
        "address/prefix": _address_prefix_query,  # deprecate
        "bool": _bool_ipaddr_query,
        "broadcast": _broadcast_query,
        "cidr": _cidr_query,
        "cidr_lookup": _cidr_lookup_query,
        "first_usable": _first_usable_query,
        "gateway": _address_prefix_query,  # deprecate
        "gw": _address_prefix_query,  # deprecate
        "host": _host_query,
        "host/prefix": _address_prefix_query,  # deprecate
        "hostmask": _hostmask_query,
        "hostnet": _address_prefix_query,  # deprecate
        "int": _int_query,
        "ip": _ip_query,
        "ip/prefix": _ip_prefix_query,
        "ip_netmask": _ip_netmask_query,
        # 'ip_wildcard': _ip_wildcard_query, built then could not think of use case
        "ipv4": _ipv4_query,
        "ipv6": _ipv6_query,
        "last_usable": _last_usable_query,
        "link-local": _link_local_query,
        "lo": _loopback_query,
        "loopback": _loopback_query,
        "multicast": _multicast_query,
        "net": _net_query,
        "next_usable": _next_usable_query,
        "netmask": _netmask_query,
        "network": _network_query,
        "network_id": _network_query,
        "network/prefix": _subnet_query,
        "network_netmask": _network_netmask_query,
        "network_wildcard": _network_wildcard_query,
        "peer": _peer_query,
        "prefix": _prefix_query,
        "previous_usable": _previous_usable_query,
        "private": _private_query,
        "public": _public_query,
        "range_usable": _range_usable_query,
        "revdns": _revdns_query,
        "router": _address_prefix_query,  # deprecate
        "size": _size_query,
        "size_usable": _size_usable_query,
        "subnet": _subnet_query,
        "type": _type_query,
        "unicast": _unicast_query,
        "v4": _ipv4_query,
        "v6": _ipv6_query,
        "version": _version_query,
        "wildcard": _hostmask_query,
        "wrap": _wrap_query,
    }

    vtype = None

    # Check if value is a list and parse each element
    if isinstance(value, (list, tuple, types.GeneratorType)):
        _ret = [ipaddr(element, str(query), version) for element in value]
        return [item for item in _ret if item]

    elif not value or value is True:
        # TODO: Remove this check in a major version release of collection with porting guide
        # TODO: and raise exception commented out below
        display.warning(
            "The value '%s' is not a valid IP address or network, passing this value to ipaddr filter"
            " might result in breaking change in future." % value,
        )
        return False

    # Check if value is a number and convert it to an IP address
    elif str(value).isdigit():
        # We don't know what IP version to assume, so let's check IPv4 first,
        # then IPv6
        try:
            if (not version) or (version and version == 4):
                v = netaddr.IPNetwork("0.0.0.0/0")
                v.value = int(value)
                v.prefixlen = 32
            elif version and version == 6:
                v = netaddr.IPNetwork("::/0")
                v.value = int(value)
                v.prefixlen = 128

        # IPv4 didn't work the first time, so it definitely has to be IPv6
        except Exception:
            try:
                v = netaddr.IPNetwork("::/0")
                v.value = int(value)
                v.prefixlen = 128

            # The value is too big for IPv6. Are you a nanobot?
            except Exception:
                return False

        # We got an IP address, let's mark it as such
        value = str(v)
        vtype = "address"

    # value has not been recognized, check if it's a valid IP string
    else:
        try:
            v = netaddr.IPNetwork(value)

            # value is a valid IP string, check if user specified
            # CIDR prefix or just an IP address, this will indicate default
            # output format
            try:
                address, prefix = value.split("/")
                vtype = "network"
            except Exception:
                vtype = "address"

        # value hasn't been recognized, maybe it's a numerical CIDR?
        except Exception:
            try:
                address, prefix = value.split("/")
                address.isdigit()
                address = int(address)
                prefix.isdigit()
                prefix = int(prefix)

            # It's not numerical CIDR, give up
            except Exception:
                return False

            # It is something, so let's try and build a CIDR from the parts
            try:
                v = netaddr.IPNetwork("0.0.0.0/0")
                v.value = address
                v.prefixlen = prefix

            # It's not a valid IPv4 CIDR
            except Exception:
                try:
                    v = netaddr.IPNetwork("::/0")
                    v.value = address
                    v.prefixlen = prefix

                # It's not a valid IPv6 CIDR. Give up.
                except Exception:
                    return False

            # We have a valid CIDR, so let's write it in correct format
            value = str(v)
            vtype = "network"

    # We have a query string but it's not in the known query types. Check if
    # that string is a valid subnet, if so, we can check later if given IP
    # address/network is inside that specific subnet
    try:
        # ?? 6to4 and link-local were True here before.  Should they still?
        if (
            query
            and (query not in query_func_map or query == "cidr_lookup")
            and not str(query).isdigit()
            and ipaddr(query, "network")
        ):
            iplist = netaddr.IPSet([netaddr.IPNetwork(query)])
            query = "cidr_lookup"
    except Exception:
        pass

    # This code checks if value maches the IP version the user wants, ie. if
    # it's any version ("ipaddr()"), IPv4 ("ipv4()") or IPv6 ("ipv6()")
    # If version does not match, return False
    if version and v.version != version:
        return False

    extras = []
    for arg in query_func_extra_args.get(query, tuple()):
        extras.append(locals()[arg])
    try:
        return query_func_map[query](v, *extras)
    except KeyError:
        try:
            float(query)
            if v.size == 1:
                if vtype == "address":
                    return str(v.ip)
                elif vtype == "network":
                    return str(v)

            elif v.size > 1:
                try:
                    return str(v[query]) + "/" + str(v.prefixlen)
                except Exception:
                    return False

            else:
                return value

        except Exception:
            raise AnsibleFilterError(alias + ": unknown filter type: %s" % query)

    return False


def _need_netaddr(f_name, *args, **kwargs):
    """
    verify python's netaddr for these filters to work
    """
    raise AnsibleFilterError(missing_required_lib("netaddr"))


def _address_normalizer(value):
    """
    Used to validate an address or network type and return it in a consistent format.
    This is being used for future use cases not currently available such as an address range.
    :param value: The string representation of an address or network.
    :return: The address or network in the normalized form.
    """
    try:
        vtype = ipaddr(value, "type")
        if vtype == "address" or vtype == "network":
            v = ipaddr(value, "subnet")
        else:
            return False
    except Exception:
        return False

    return v


def _range_checker(ip_check, first, last):
    """
    Tests whether an ip address is within the bounds of the first and last address.
    :param ip_check: The ip to test if it is within first and last.
    :param first: The first IP in the range to test against.
    :param last: The last IP in the range to test against.
    :return: bool
    """
    if first <= ip_check <= last:
        return True
    else:
        return False


# ---- HWaddr query helpers ----
def _bare_query(v):
    v.dialect = netaddr.mac_bare
    return str(v)


def _bool_hwaddr_query(v):
    if v:
        return True


def _int_hwaddr_query(v):
    return int(v)


def _cisco_query(v):
    v.dialect = netaddr.mac_cisco
    return str(v)


def _empty_hwaddr_query(v, value):
    if v:
        return value


def _linux_query(v):
    v.dialect = mac_linux
    return str(v)


def _postgresql_query(v):
    v.dialect = netaddr.mac_pgsql
    return str(v)


def _unix_query(v):
    v.dialect = netaddr.mac_unix
    return str(v)


def _win_query(v):
    v.dialect = netaddr.mac_eui48
    return str(v)


# ---- HWaddr / MAC address filters ----
def hwaddr(value, query="", alias="hwaddr"):
    """Check if string is a HW/MAC address and filter it"""

    query_func_extra_args = {"": ("value",)}

    query_func_map = {
        "": _empty_hwaddr_query,
        "bare": _bare_query,
        "bool": _bool_hwaddr_query,
        "int": _int_hwaddr_query,
        "cisco": _cisco_query,
        "eui48": _win_query,
        "linux": _linux_query,
        "pgsql": _postgresql_query,
        "postgresql": _postgresql_query,
        "psql": _postgresql_query,
        "unix": _unix_query,
        "win": _win_query,
    }

    try:
        v = netaddr.EUI(value)
    except Exception:
        v = None
        if query and query != "bool":
            raise AnsibleFilterError(alias + ": not a hardware address: %s" % value)

    extras = []
    for arg in query_func_extra_args.get(query, tuple()):
        extras.append(locals()[arg])
    try:
        return query_func_map[query](v, *extras)
    except KeyError:
        raise AnsibleFilterError(alias + ": unknown filter type: %s" % query)
