"""Shared helpers for BGP SRv6 GRT system tests."""

import ipaddress
import re
import shlex
from contextlib import contextmanager


# P1 is the logical ingress PE, PE1 is the egress PE, and P3 is the transit P
# router in the 7-node virtual topologies.
EGRESS_PE_BGP_NEIGHBOR = "fc00::71"
INGRESS_PE_BGP_NEIGHBOR = "fc00::72"
INGRESS_TO_TRANSIT_NEXTHOP = "fc00::7e"
EGRESS_TO_TRANSIT_NEXTHOP = "fc02::2"
TRANSIT_TO_EGRESS_PE = "fc02::1"
TRANSIT_TO_INGRESS_PE = "fc00::7d"
EGRESS_PE_LOCATOR = "lsid1"

IPV4_ADVERTISEMENT_PREFIX = "203.0.113.10/32"
IPV6_ADVERTISEMENT_PREFIX = "2001:db8:200::10/128"
IPV4_POLICY_ALLOW_PREFIX = "203.0.113.20/32"
IPV4_POLICY_DENY_PREFIX = "203.0.113.21/32"
IPV6_POLICY_ALLOW_PREFIX = "2001:db8:200::20/128"
IPV6_POLICY_DENY_PREFIX = "2001:db8:200::21/128"
IPV4_DATAPLANE_PREFIX = "203.0.113.30/32"
IPV6_DATAPLANE_PREFIX = "2001:db8:200::30/128"


class ConfigDBPatch:
    """Temporarily update CONFIG_DB fields and restore their prior values."""

    def __init__(self, host):
        self.host = host
        self.original = {}

    def _command(self, command):
        result = self.host.command(
            "sonic-db-cli CONFIG_DB {}".format(command),
            module_ignore_errors=True
        )
        assert result.get("rc", 0) == 0, \
            "CONFIG_DB command failed on {}: {}".format(self.host, result)
        return result.get("stdout", "").strip()

    def _snapshot_field(self, key, field):
        identity = (key, field)
        if identity not in self.original:
            current = self._command(
                "HGET {} {}".format(shlex.quote(key), shlex.quote(field))
            )
            self.original[identity] = None if current in ("", "(nil)", "None") else current

    def set(self, key, field, value):
        self._snapshot_field(key, field)
        if value is None:
            command = "HDEL {} {}".format(shlex.quote(key), shlex.quote(field))
        else:
            command = "HSET {} {} {}".format(
                shlex.quote(key), shlex.quote(field), shlex.quote(str(value))
            )
        self._command(command)

    def set_fields(self, key, fields):
        """Update related CONFIG_DB fields with one atomic HSET."""
        for field in fields:
            self._snapshot_field(key, field)
        args = " ".join(
            "{} {}".format(shlex.quote(field), shlex.quote(str(value)))
            for field, value in fields.items()
        )
        self._command("HSET {} {}".format(shlex.quote(key), args))

    def restore(self):
        for (key, field), value in reversed(list(self.original.items())):
            if value is None:
                command = "HDEL {} {}".format(shlex.quote(key), shlex.quote(field))
            else:
                command = "HSET {} {} {}".format(
                    shlex.quote(key), shlex.quote(field), shlex.quote(value)
                )
            self._command(command)


def _set_static_grt_route(config_patch, prefix, next_hop=None):
    """Configure a temporary static route through CONFIG_DB."""
    route_key = "STATIC_ROUTE|default|{}".format(prefix)
    fields = {"nexthop": next_hop} if next_hop else {"blackhole": "true"}
    config_patch.set_fields(route_key, fields)


@contextmanager
def configured_grt_advertisement(
        egress_pe, ingress_pe, family, prefixes,
        prefix_set_name=None, route_map_name=None, permit_prefixes=(),
        relaxed_neighbor=False, route_next_hop=None, source_address=None):
    """Configure GRT SID advertisement at the egress PE using CONFIG_DB."""
    egress_config = ConfigDBPatch(egress_pe)
    ingress_config = ConfigDBPatch(ingress_pe)
    version = "ipv4" if family == "ipv4" else "ipv6"
    af = "{}_unicast".format(version)
    egress_af_key = "BGP_GLOBALS_AF|default|{}".format(af)
    egress_neighbor_af_key = "BGP_NEIGHBOR_AF|default|{}|{}".format(
        EGRESS_PE_BGP_NEIGHBOR, af
    )
    ingress_neighbor_af_key = "BGP_NEIGHBOR_AF|default|{}|{}".format(
        INGRESS_PE_BGP_NEIGHBOR, af
    )
    neighbor_mode = "srv6-relax" if relaxed_neighbor else "srv6"

    try:
        egress_config.set("BGP_GLOBALS|default", "srv6_locator", EGRESS_PE_LOCATOR)
        egress_config.set(egress_af_key, "redistribute_static_rmap", "pass_all")

        if family == "ipv4":
            # These testbed peers use IPv6 transport, so activate IPv4 unicast
            # over that existing BGP session at both ends.
            egress_config.set(egress_neighbor_af_key, "admin_status", "true")
            ingress_config.set(ingress_neighbor_af_key, "admin_status", "true")

        if source_address:
            ingress_config.set(
                "SRV6_GLOBAL|default", "encap_src_addr", source_address
            )

        if route_map_name:
            assert prefix_set_name, "A prefix-set name is required with a SID advertisement route map"
            mode = "IPv4" if family == "ipv4" else "IPv6"
            egress_config.set("PREFIX_SET|{}".format(prefix_set_name), "mode", mode)
            for sequence, prefix in enumerate(permit_prefixes, start=10):
                prefix_key = "PREFIX|{}|{}|{}|exact".format(
                    prefix_set_name, sequence, prefix
                )
                egress_config.set(prefix_key, "action", "permit")

            route_map_key = "ROUTE_MAP|{}|10".format(route_map_name)
            egress_config.set(route_map_key, "route_operation", "permit")
            egress_config.set(route_map_key, "match_prefix_set", prefix_set_name)

        # Build SID advertisement fields together so the route map and enable
        # flag are applied together by either BGP config daemon.
        sid_advertise_fields = {}
        if route_map_name:
            sid_advertise_fields["srv6_sid_advertise_route_map"] = route_map_name
        else:
            egress_config.set(egress_af_key, "srv6_sid_advertise_route_map", None)
        sid_advertise_fields["srv6_sid_advertise"] = "true"
        egress_config.set_fields(egress_af_key, sid_advertise_fields)
        egress_config.set(egress_neighbor_af_key, "encapsulation_type", neighbor_mode)

        for prefix in prefixes:
            _set_static_grt_route(egress_config, prefix, next_hop=route_next_hop)

        yield
    finally:
        try:
            ingress_config.restore()
        finally:
            egress_config.restore()


def get_appl_route_field(host, prefix, field):
    result = host.command(
        "sonic-db-cli APPL_DB HGET {} {}".format(
            shlex.quote("ROUTE_TABLE:{}".format(prefix)),
            shlex.quote(field)
        ),
        module_ignore_errors=True
    )
    value = result.get("stdout", "").strip()
    return None if value in ("", "(nil)", "None") else value


def appl_route_exists(host, prefix):
    result = host.command(
        "sonic-db-cli APPL_DB EXISTS {}".format(
            shlex.quote("ROUTE_TABLE:{}".format(prefix))
        ),
        module_ignore_errors=True
    )
    return result.get("stdout", "").strip() == "1"


def route_has_vpn_sid(host, prefix):
    return bool(get_appl_route_field(host, prefix, "vpn_sid"))


def route_has_source_address(host, prefix, source_address):
    actual = get_appl_route_field(host, prefix, "seg_src")
    if not actual:
        return False
    try:
        return ipaddress.IPv6Address(actual) == ipaddress.IPv6Address(source_address)
    except ipaddress.AddressValueError:
        return False


def fib_route_has_sid(host, family, prefix, sid):
    command = "ip route show {}".format(prefix) if family == "ipv4" else \
        "ip -6 route show {}".format(prefix)
    output = host.command(command, module_ignore_errors=True).get("stdout", "")
    return "encap seg6" in output.lower() and sid.lower() in output.lower()


def mysid_is_programmed(host, sid):
    keys = host.command(
        "sonic-db-cli APPL_DB KEYS 'SRV6_MY_SID_TABLE*'",
        module_ignore_errors=True
    ).get("stdout", "").splitlines()
    for key in keys:
        if sid.lower() in key.lower():
            entry = host.command(
                "sonic-db-cli APPL_DB HGETALL {}".format(shlex.quote(key)),
                module_ignore_errors=True
            ).get("stdout", "").lower()
            return "udt46" in entry and "default" in entry
    return False


def get_srv6_source_address(host):
    """Select the ingress PE's global IPv6 Loopback0 address for SRv6 encap."""
    output = host.command(
        "ip -6 -o addr show dev Loopback0 scope global",
        module_ignore_errors=True
    ).get("stdout", "")
    for match in re.finditer(r"\binet6\s+([0-9a-fA-F:]+)/\d+", output):
        address = ipaddress.IPv6Address(match.group(1))
        if not address.is_link_local and not address.is_unspecified and not address.is_multicast:
            return str(address)
    raise AssertionError("Ingress PE has no global IPv6 address on Loopback0: {}".format(output))


def fib_route_via(host, address, next_hop):
    output = host.command(
        "ip -6 route get {}".format(shlex.quote(address)),
        module_ignore_errors=True
    ).get("stdout", "").lower()
    return "via {}".format(next_hop.lower()) in output


def get_interface_toward(host, address):
    route = host.command(
        "ip -6 route get {}".format(shlex.quote(address)),
        module_ignore_errors=True
    ).get("stdout", "")
    match = re.search(r"\bdev\s+(\S+)", route)
    if not match:
        raise AssertionError(
            "Could not resolve interface toward {} on {}: {}".format(address, host, route)
        )
    return match.group(1)
