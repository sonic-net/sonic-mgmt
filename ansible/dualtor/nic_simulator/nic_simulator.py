#!/usr/bin/env python3
r"""
_   _ _____ _____    _____ _____ __  __ _    _ _            _______ ____  _____
| \ | |_   _/ ____|  / ____|_   _|  \/  | |  | | |        /\|__   __/ __ \|  __ \
|  \| | | || |      | (___   | | | \  / | |  | | |       /  \  | | | |  | | |__) |
| . ` | | || |       \___ \  | | | |\/| | |  | | |      / /\ \ | | | |  | |  _  /
| |\  |_| || |____   ____) |_| |_| |  | | |__| | |____ / ____ \| | | |__| | | \ \
|_| \_|_____\_____| |_____/|_____|_|  |_|\____/|______/_/    \_\_|  \____/|_|  \_\

"""
import abc
import argparse
import contextlib
import fcntl
import grpc
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import struct
import subprocess
import threading

from concurrent import futures
from logging.handlers import RotatingFileHandler
# from grpc_reflection.v1alpha import reflection

import nic_simulator_grpc_service_pb2
import nic_simulator_grpc_service_pb2_grpc
import nic_simulator_grpc_mgmt_service_pb2
import nic_simulator_grpc_mgmt_service_pb2_grpc


THREAD_CONCURRENCY_PER_SERVER = 2
USE_HASH_SELECTION_METHOD_EXPLICITLY = False

# name templates
ACTIVE_ACTIVE_BRIDGE_TEMPLATE = r"baa-%s-%d"
NETNS_IFACE_TEMPLATE = r"eth%s"
NETNS_IFACE_PATTERN = r"eth\d+"
ACTIVE_ACTIVE_INTERFACES_TEMPLATE = r"iaa-%s-%d"
ACTIVE_ACTIVE_INTERFACE_PATTERN = r"iaa-[\w-]+-\d+"
SERVER_NIC_INTERFACE_TEMPLATE = r"nic-%s-%d"
SERVER_NIC_INTERFACE_PATTERN = r"nic-[\w-]+-\d+"
OVS_VERSION_PATTERN = r"ovs-vsctl \(Open vSwitch\) (.*)"

# gRPC settings
GRPC_TIMEOUT = 0.5
GRPC_SERVER_OPTIONS = [
    ('grpc.http2.min_ping_interval_without_data_ms', 1000),
    ('grpc.http2.max_ping_strikes',  0)
]
GRPC_CLIENT_OPTIONS = [
    ('grpc.keepalive_timeout_ms', 8000),
    ('grpc.keepalive_time_ms', 4000),
    ('grpc.keepalive_permit_without_calls', True),
    ('grpc.http2.max_pings_without_data', 0)
]


def get_ip_address(ifname):
    """Get interface IP address."""
    ifname = ifname.encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except OSError:
        addr = None
    return addr


def get_ipv6_addresses(ifname):
    """Return stable, usable global-scope IPv6 addresses (including ULA)."""
    try:
        result = subprocess.run(
            ["ip", "-j", "-6", "addr", "show", "dev", ifname],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            text=True, shell=False
        )
        interfaces = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        # Missing IPv6 tooling must not break an existing IPv4 deployment.
        logging.warning("Cannot discover IPv6 addresses on %s: %s", ifname, error)
        return []

    addresses = set()
    excluded_flags = {"tentative", "dadfailed", "deprecated", "temporary"}
    for interface in interfaces:
        for info in interface.get("addr_info", []):
            if info.get("family") != "inet6" or info.get("scope") != "global":
                continue
            if excluded_flags.intersection(info.get("flags", [])):
                continue
            if any(info.get(flag, False) for flag in excluded_flags):
                continue
            if str(info.get("preferred_life_time")) == "0" or str(info.get("valid_life_time")) == "0":
                continue
            try:
                address = ipaddress.IPv6Address(info["local"])
            except (KeyError, ValueError):
                continue
            if (address.is_link_local or address.is_loopback or address.is_multicast
                    or address.is_unspecified or address.is_site_local or address.ipv4_mapped):
                continue
            addresses.add(address)
    return [str(address) for address in sorted(addresses)]


def validate_loopback_ips(addresses, version):
    """Validate and normalize a Loopback2/upper Loopback3/lower Loopback3 triplet."""
    if isinstance(addresses, str):
        addresses = addresses.split(",")
    if len(addresses) != 3:
        raise ValueError("Expected exactly three IPv%s loopback addresses" % version)
    result = []
    for value in addresses:
        address = ipaddress.ip_address(value.strip())
        if address.version != version or "%" in value:
            raise ValueError("Expected an IPv%s loopback address, got %s" % (version, value))
        result.append(str(address))
    return tuple(result)


def grpc_target(address, port):
    """Format an IP literal for a gRPC listener or channel."""
    address = ipaddress.ip_address(address)
    if address.version == 6:
        return "[%s]:%s" % (address, port)
    return "%s:%s" % (address, port)


def bind_grpc_addresses(server, addresses, port):
    """Bind every specific address to one server, failing on partial setup."""
    try:
        if not addresses:
            raise ValueError("At least one specific gRPC binding address is required")
        for address in dict.fromkeys(addresses):
            if ipaddress.ip_address(address).is_unspecified:
                raise ValueError("Wildcard gRPC listeners are not allowed: %s" % address)
            target = grpc_target(address, port)
            bound_port = server.add_insecure_port(target)
            if not bound_port:
                raise RuntimeError("Failed to bind gRPC listener %s" % target)
            # Keep a single port across listeners even when requesting an ephemeral port.
            if port == 0:
                port = bound_port
    except Exception:
        server.stop(grace=None)
        raise
    return port


def run_command(cmd, check=True):
    """Run a command."""
    logging.debug("COMMAND: %s", cmd)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,  # nosemgrep: subprocess-shell-true
        check=check
    )
    result.stdout = result.stdout.decode()
    result.stderr = result.stderr.decode()
    logging.debug("COMMAND STDOUT:\n%s\n", result.stdout)
    logging.debug("COMMAND STDERR:\n%s\n", result.stderr)
    return result


class OVSCommand(object):
    """OVS related commands."""

    OVS_VSCTL_SHOW_VERSION_COMD = "ovs-vsctl -V"
    OVS_VSCTL_LIST_BR_CMD = "ovs-vsctl list-br"
    OVS_VSCTL_LIST_PORTS_CMD = "ovs-vsctl list-ports {bridge_name}"
    OVS_OFCTL_DEL_FLOWS_CMD = "ovs-ofctl del-flows {bridge_name}"
    OVS_OFCTL_ADD_FLOWS_CMD = "ovs-ofctl add-flow {bridge_name} {flow}"
    OVS_OFCTL_MOD_FLOWS_CMD = "ovs-ofctl --strict mod-flows {bridge_name} {flow}"
    OVS_OFCTL_DEL_GROUPS_CMD = "ovs-ofctl -O OpenFlow13 del-groups {bridge_name}"
    OVS_OFCTL_ADD_GROUP_CMD = "ovs-ofctl -O OpenFlow13 add-group {bridge_name} {group}"
    OVS_OFCTL_MOD_GROUP_CMD = "ovs-ofctl -O OpenFlow13 mod-group {bridge_name} {group}"

    @staticmethod
    def setup_openflow_version():

        def _versiontuple(v):
            return tuple(map(int, (v.split("."))))

        try:
            out = run_command(OVSCommand.OVS_VSCTL_SHOW_VERSION_COMD)
            first_line = out.stdout.splitlines()[0]
            ovs_version = _versiontuple(re.search(OVS_VERSION_PATTERN, first_line).groups()[0])
            # NOTE: use openflow15 for OVS 2.10 and above
            if ovs_version >= _versiontuple("2.10"):
                global USE_HASH_SELECTION_METHOD_EXPLICITLY
                USE_HASH_SELECTION_METHOD_EXPLICITLY = True
                OVSCommand.OVS_OFCTL_DEL_GROUPS_CMD = "ovs-ofctl -O OpenFlow15 del-groups {bridge_name}"
                OVSCommand.OVS_OFCTL_ADD_GROUP_CMD = "ovs-ofctl -O OpenFlow15 add-group {bridge_name} {group}"
                OVSCommand.OVS_OFCTL_MOD_GROUP_CMD = "ovs-ofctl -O OpenFlow15 mod-group {bridge_name} {group}"
        except Exception:
            raise ValueError("Failed to find/setup openflow version: %s" % out.stdout)

    @staticmethod
    def ovs_vsctl_list_br():
        return run_command(OVSCommand.OVS_VSCTL_LIST_BR_CMD)

    @staticmethod
    def ovs_vsctl_list_ports(bridge_name):
        return run_command(OVSCommand.OVS_VSCTL_LIST_PORTS_CMD.format(bridge_name=bridge_name))

    @staticmethod
    def ovs_ofctl_del_flows(bridge_name):
        return run_command(OVSCommand.OVS_OFCTL_DEL_FLOWS_CMD.format(bridge_name=bridge_name))

    @staticmethod
    def ovs_ofctl_add_flow(bridge_name, flow):
        return run_command(OVSCommand.OVS_OFCTL_ADD_FLOWS_CMD.format(bridge_name=bridge_name, flow=flow))

    @staticmethod
    def ovs_ofctl_mod_flow(bridge_name, flow):
        return run_command(OVSCommand.OVS_OFCTL_MOD_FLOWS_CMD.format(bridge_name=bridge_name, flow=flow))

    @staticmethod
    def ovs_ofctl_add_group(bridge_name, group):
        return run_command(OVSCommand.OVS_OFCTL_ADD_GROUP_CMD.format(bridge_name=bridge_name, group=group))

    @staticmethod
    def ovs_ofctl_del_groups(bridge_name):
        return run_command(OVSCommand.OVS_OFCTL_DEL_GROUPS_CMD.format(bridge_name=bridge_name))

    @staticmethod
    def ovs_ofctl_mod_groups(bridge_name, group):
        return run_command(OVSCommand.OVS_OFCTL_MOD_GROUP_CMD.format(bridge_name=bridge_name, group=group))


class StrObj(abc.ABC):
    """Abstract class defines objects that could be represented as a string."""

    __slots__ = ("_str",)

    @abc.abstractmethod
    def to_string(self):
        pass

    def reset(self):
        """Reset object string representation."""
        with contextlib.suppress(AttributeError):
            del self._str

    def __str__(self):
        if not hasattr(self, "_str"):
            self._str = self.to_string()
        return self._str

    def __repr__(self):
        return self.__str__()


class OVSGroup(StrObj):
    """Object to represent an OVS group."""

    __slots__ = ("group_id", "group_type", "output_ports", "_str_prefix",  "optional_fields")

    def __init__(self, group_id, group_type, output_ports=[], optional_fields=None):
        self.group_id = group_id
        self.group_type = group_type
        self.output_ports = set(output_ports)
        self._str_prefix = "group_id=%s,type=%s" % (
            self.group_id, self.group_type)
        if optional_fields:
            self._str_prefix += ","
            self._str_prefix += ",".join("%s=%s" % kv for kv in optional_fields.items())
        self.optional_fields = optional_fields or []

    def to_string(self):
        group_parts = [self._str_prefix]
        if self.output_ports:
            group_parts.extend("bucket=output:%s" %
                               _ for _ in self.output_ports)
        else:
            group_parts.append("bucket=drop")
        return ",".join(group_parts)


class OVSFlow(StrObj):
    """Object to represent an OVS flow."""

    __slots__ = ("in_port", "packet_filter", "output_ports", "group", "priority", "_str_prefix", "drop")

    def __init__(self, in_port, packet_filter=None, output_ports=[], group=None, priority=None):
        self.in_port = in_port
        self.packet_filter = packet_filter
        self.output_ports = output_ports
        self.group = group
        self.priority = priority
        self._str_prefix = []
        if self.priority:
            self._str_prefix.append("priority=%s" % self.priority)
        if self.packet_filter:
            self._str_prefix.append(str(self.packet_filter))
        self._str_prefix.append("in_port=%s" % self.in_port)
        self._str_prefix = ",".join(self._str_prefix)
        self.drop = False

    def to_string(self):
        flow_parts = [self._str_prefix]
        if self.drop:
            flow_parts.append("actions=drop")
        elif self.output_ports:
            output = ["output:%s" % _ for _ in self.output_ports]
            flow_parts.append("actions=%s" % ",".join(output))
        elif self.group:
            flow_parts.append("actions=group:%s" % self.group.group_id)
        else:
            flow_parts.append("actions=drop")
        return ",".join(flow_parts)

    def set_drop(self, recover=False):
        if recover:
            self.drop = False
        else:
            self.drop = True
        self.reset()


class OVSUpstreamFlow(OVSFlow):
    """Object to represent an OVS upstream flow to output to both ToRs."""

    __slots__ = ("drop_output", "enable_output_ports")

    def __init__(self, in_port, packet_filter=None, output_ports=[],
                 group=None, priority=None, enable_output_ports=None):
        super(OVSUpstreamFlow, self).__init__(
            in_port, packet_filter, output_ports, group, priority)
        self.drop_output = [False, False]
        self.enable_output_ports = enable_output_ports if enable_output_ports else [True, True]

    def to_string(self):
        flow_parts = [self._str_prefix]
        has_output = False
        if self.output_ports:
            output = ["output:%s" % port for (portid, port) in enumerate(self.output_ports)
                      if (self.get_port_enable(portid) and (not self.get_drop(portid)))]
            has_output = bool(output)
            if has_output:
                flow_parts.append("actions=%s" % ",".join(output))

        if not has_output:
            flow_parts.append("actions=drop")
        return ",".join(flow_parts)

    def get_port_enable(self, portid):
        return self.enable_output_ports[portid]

    def get_drop(self, portid):
        return self.drop_output[portid]

    def set_drop(self, portid=None, recover=False):
        is_drop = not recover

        if portid is None:
            self.drop_output = [is_drop, is_drop]
        else:
            self.drop_output[portid] = is_drop

        if self.get_port_enable(portid):
            self.reset()


class ForwardingState(object):
    """Forwarding state"""
    STANDBY = False
    ACTIVE = True
    STATE_LABELS = {
        STANDBY: "STANDBY",
        ACTIVE: "ACTIVE"
    }


class UpstreamECMPGroup(OVSGroup):
    """Object to represent a OVS group that selects active tor ports to send packets."""

    __slots__ = (
        "upper_tor_port",
        "lower_tor_port",
        "upper_tor_forwarding_state",
        "lower_tor_forwarding_state",
        "group_str_cache"
    )

    def __init__(
        self, group_id, upper_tor_port, lower_tor_port,
        upper_tor_forwarding_state=ForwardingState.ACTIVE,
        lower_tor_forwarding_state=ForwardingState.ACTIVE
    ):
        output_ports = []
        if upper_tor_forwarding_state == ForwardingState.ACTIVE:
            output_ports.append(upper_tor_port)
        if lower_tor_forwarding_state == ForwardingState.ACTIVE:
            output_ports.append(lower_tor_port)
        optional_fields = {"selection_method": "hash"} if USE_HASH_SELECTION_METHOD_EXPLICITLY else None
        super(UpstreamECMPGroup, self).__init__(
            group_id, "select", output_ports=output_ports, optional_fields=optional_fields
        )
        self.upper_tor_port = upper_tor_port
        self.lower_tor_port = lower_tor_port
        self.upper_tor_forwarding_state = upper_tor_forwarding_state
        self.lower_tor_forwarding_state = lower_tor_forwarding_state
        self.group_str_cache = {}

    def set_upper_tor_forwarding_state(self, state):
        if state == self.upper_tor_forwarding_state:
            return False
        if state == ForwardingState.ACTIVE:
            if self.upper_tor_forwarding_state == ForwardingState.STANDBY:
                self.output_ports.add(self.upper_tor_port)
                self.upper_tor_forwarding_state = ForwardingState.ACTIVE
                self.reset()
        elif state == ForwardingState.STANDBY:
            if self.upper_tor_forwarding_state == ForwardingState.ACTIVE:
                self.output_ports.remove(self.upper_tor_port)
                self.upper_tor_forwarding_state = ForwardingState.STANDBY
                self.reset()
        return True

    def set_lower_tor_forwarding_state(self, state):
        if state == self.lower_tor_forwarding_state:
            return False
        if state == ForwardingState.ACTIVE:
            if self.lower_tor_forwarding_state == ForwardingState.STANDBY:
                self.output_ports.add(self.lower_tor_port)
                self.lower_tor_forwarding_state = ForwardingState.ACTIVE
                self.reset()
        elif state == ForwardingState.STANDBY:
            if self.lower_tor_forwarding_state == ForwardingState.ACTIVE:
                self.output_ports.remove(self.lower_tor_port)
                self.lower_tor_forwarding_state = ForwardingState.STANDBY
                self.reset()
        return True

    def __str__(self):
        return self.group_str_cache.setdefault(
            (self.upper_tor_forwarding_state, self.lower_tor_forwarding_state),
            super(UpstreamECMPGroup, self).__str__()
        )


class UpstreamECMPFlow(OVSFlow):
    """Object to represent an upstream ECMP flow that selects one of its output ports to send packets."""

    __slots__ = ()

    def __init__(self, in_port, group, priority=None):
        super(UpstreamECMPFlow, self).__init__(
            in_port, group=group, priority=priority)

    def set_upper_tor_forwarding_state(self, state):
        return self.group.set_upper_tor_forwarding_state(state)

    def set_lower_tor_forwarding_state(self, state):
        return self.group.set_lower_tor_forwarding_state(state)

    def get_upper_tor_forwarding_state(self):
        return self.group.upper_tor_forwarding_state

    def get_lower_tor_forwarding_state(self):
        return self.group.lower_tor_forwarding_state


class OVSBridge(object):
    """
    Object to represent the OVS bridge for the active-active port testbed setup.

                                   +--------------+
                   PTF (host_if) --+              +----- upper_if
                                   |  OVS bridge  |
    simulator netns (server_nic) --+              +----- lower_if
                                   +--------------+
    """

    __slots__ = (
        "bridge_name",
        "loopback2_ip",
        "upper_tor_loopback3_ip",
        "lower_tor_loopback3_ip",
        "ipv6_loopback_ips",
        "ports",
        "lower_tor_port",
        "upper_tor_port",
        "server_nic",
        "ptf_port",
        "lock",
        "flows",
        "groups",
        "upstream_ecmp_flow",
        "upstream_ecmp_group",
        "states_getter",
        "states_setter",
        "downstream_flows",
        "downstream_upper_tor_flow",
        "downstream_lower_tor_flow",
        "upstream_nic_flow",
        "upstream_upper_tor_nic_flow",
        "upstream_lower_tor_nic_flow",
        "upstream_loopback2_flow",
        "upstream_upper_tor_loopback3_flow",
        "upstream_lower_tor_loopback3_flow",
        "upstream_arp_flow",
        "upstream_icmpv6_flow",
        "flap_counter"
    )

    def __init__(self, bridge_name, loopback_ips, duplicate_nic_upstream=False, ipv6_loopback_ips=None):
        loopback_ips = validate_loopback_ips(loopback_ips, 4)
        self.ipv6_loopback_ips = (validate_loopback_ips(ipv6_loopback_ips, 6)
                                  if ipv6_loopback_ips is not None else None)
        self.bridge_name = bridge_name
        self.loopback2_ip = loopback_ips[0]
        self.upper_tor_loopback3_ip = loopback_ips[1]
        self.lower_tor_loopback3_ip = loopback_ips[2]
        self.lock = threading.RLock()
        self.ports = None
        self.lower_tor_port = None
        self.upper_tor_port = None
        self.server_nic = None
        self.ptf_port = None
        self.upstream_ecmp_flow = None
        self.upstream_ecmp_group = None
        self.flows = []
        self.groups = []
        self._init_ports()
        self._init_flows(duplicate_nic_upstream)
        self.states_getter = {
            1: self.upstream_ecmp_flow.get_upper_tor_forwarding_state,
            0: self.upstream_ecmp_flow.get_lower_tor_forwarding_state
        }
        self.states_setter = {
            1: self.upstream_ecmp_flow.set_upper_tor_forwarding_state,
            0: self.upstream_ecmp_flow.set_lower_tor_forwarding_state
        }
        self.downstream_flows = {
            1: self.downstream_upper_tor_flow,
            0: self.downstream_lower_tor_flow
        }
        self.flap_counter = {
            1: 0,
            0: 0
        }

    def _init_ports(self):
        """Initialize ports."""
        self.ports = self._get_ports()
        if len(self.ports) != 4:
            raise ValueError("Unhealthy bridge: %s, ports: %s" %
                             (self.bridge_name, self.ports))
        tor_ports = []
        for port in self.ports:
            if re.search(ACTIVE_ACTIVE_INTERFACE_PATTERN, port):
                self.ptf_port = port
            elif re.search(SERVER_NIC_INTERFACE_PATTERN, port):
                self.server_nic = port
            else:
                tor_ports.append(port)
        if len(tor_ports) != 2:
            raise ValueError("Unhealthy bridge: %s, could not parse existing ports: %s"
                             % (self.bridge_name, self.ports))
        tor_ports.sort()
        self.upper_tor_port = tor_ports[0]
        self.lower_tor_port = tor_ports[1]
        logging.info(
            "Init ports for bridge %s, server_nic: %s, ptf_port: %s, upper_tor_port: %s, lower_tor_port: %s",
            self.bridge_name,
            self.server_nic,
            self.ptf_port,
            self.upper_tor_port,
            self.lower_tor_port
        )

    def _init_flows(self, duplicate_nic_upstream=False):
        """Initialize OVS flows for the bridge."""
        logging.info("Init flows for bridge %s", self.bridge_name)
        self._del_flows()
        self._del_groups()
        # downstream flows
        self.downstream_upper_tor_flow = self._add_flow(self.upper_tor_port,
                                                        output_ports=[self.ptf_port, self.server_nic], priority=11)
        self.downstream_lower_tor_flow = self._add_flow(self.lower_tor_port,
                                                        output_ports=[self.ptf_port, self.server_nic], priority=11)

        # upstream flows
        if not duplicate_nic_upstream:
            # NOTE: add two flows to direct gRPC traffic to its correct destination
            # upstream packet to the upper ToR loopback3 from server NiC should be forwarded to the upper ToR
            self.upstream_upper_tor_nic_flow = self._add_flow(
                self.server_nic,
                packet_filter="tcp,ip_dst=%s" % self.upper_tor_loopback3_ip,
                output_ports=[self.lower_tor_port, self.upper_tor_port],
                priority=10,
                upstream=True,
                enable_output_ports=[False, True]
            )
            # upstream packet to the lower ToR loopback3 from server NiC should be forwarded to the lower ToR
            self.upstream_lower_tor_nic_flow = self._add_flow(
                self.server_nic,
                packet_filter="tcp,ip_dst=%s" % self.lower_tor_loopback3_ip,
                output_ports=[self.lower_tor_port, self.upper_tor_port],
                priority=10,
                upstream=True,
                enable_output_ports=[True, False]
            )
        # upstream packet from server NiC should be directed to both ToRs
        self.upstream_nic_flow = self._add_flow(
            self.server_nic,
            output_ports=[self.lower_tor_port, self.upper_tor_port],
            priority=9,
            upstream=True
        )
        # upstream packet to loopback2 from ptf port should be duplicated to both ToRs
        self.upstream_loopback2_flow = self._add_flow(
            self.ptf_port,
            packet_filter="ip,ip_dst=%s" % self.loopback2_ip,
            output_ports=[self.lower_tor_port, self.upper_tor_port],
            priority=8,
            upstream=True
        )
        # upstream packet to the upper ToR loopback3 from ptf should be duplicated to both ToRs
        self.upstream_upper_tor_loopback3_flow = self._add_flow(
            self.ptf_port,
            packet_filter="ip,ip_dst=%s" % self.upper_tor_loopback3_ip,
            output_ports=[self.lower_tor_port, self.upper_tor_port],
            priority=7,
            upstream=True
        )
        # upstream packet to the lower ToR loopback3 from ptf should be duplicated to both ToRs
        self.upstream_lower_tor_loopback3_flow = self._add_flow(
            self.ptf_port,
            packet_filter="ip,ip_dst=%s" % self.lower_tor_loopback3_ip,
            output_ports=[self.lower_tor_port, self.upper_tor_port],
            priority=7,
            upstream=True
        )
        if self.ipv6_loopback_ips is not None:
            loopback2, upper_loopback3, lower_loopback3 = self.ipv6_loopback_ips
            if not duplicate_nic_upstream:
                for address, enabled in ((upper_loopback3, [False, True]),
                                         (lower_loopback3, [True, False])):
                    self._add_flow(
                        self.server_nic, packet_filter="tcp6,ipv6_dst=%s" % address,
                        output_ports=[self.lower_tor_port, self.upper_tor_port],
                        priority=10, upstream=True, enable_output_ports=enabled
                    )
            for address, priority in ((loopback2, 8), (upper_loopback3, 7), (lower_loopback3, 7)):
                self._add_flow(
                    self.ptf_port, packet_filter="ipv6,ipv6_dst=%s" % address,
                    output_ports=[self.lower_tor_port, self.upper_tor_port],
                    priority=priority, upstream=True
                )
        # upstream arp packet from ptf port should be duplicated to both ToRs
        self.upstream_arp_flow = self._add_flow(
            self.ptf_port, packet_filter="arp",
            output_ports=[self.lower_tor_port, self.upper_tor_port],
            priority=6,
            upstream=True
        )
        # upstream ipv6 icmp packet from ptf port should be duplicated to both ToRs
        self.upstream_icmpv6_flow = self._add_flow(
            self.ptf_port, packet_filter="ipv6,nw_proto=58",
            output_ports=[self.lower_tor_port, self.upper_tor_port],
            priority=5,
            upstream=True
        )
        # upstream packet from ptf port should be ECMP directed to active ToRs
        self.upstream_ecmp_group = self._add_upstream_ecmp_group(
            1,
            self.upper_tor_port,
            self.lower_tor_port
        )
        self.upstream_ecmp_flow = self._add_upstream_ecmp_flow(
            self.ptf_port,
            self.upstream_ecmp_group,
            priority=4
        )

    def _get_ports(self):
        result = OVSCommand.ovs_vsctl_list_ports(self.bridge_name)
        return result.stdout.split()

    def _del_flows(self):
        OVSCommand.ovs_ofctl_del_flows(self.bridge_name)
        self.upstream_ecmp_flow = None
        self.flows.clear()

    def _del_groups(self):
        OVSCommand.ovs_ofctl_del_groups(self.bridge_name)
        self.upstream_ecmp_group = None
        self.groups.clear()

    def _add_flow(self, in_port, packet_filter=None, output_ports=[], group=None, priority=None,
                  upstream=False, enable_output_ports=None):
        if upstream:
            flow = OVSUpstreamFlow(in_port, packet_filter=packet_filter, output_ports=output_ports,
                                   group=group, priority=priority, enable_output_ports=enable_output_ports)
        else:
            flow = OVSFlow(in_port, packet_filter=packet_filter, output_ports=output_ports,
                           group=group, priority=priority)
        logging.info("Add flow to bridge %s: %s", self.bridge_name, flow)
        OVSCommand.ovs_ofctl_add_flow(self.bridge_name, flow)
        self.flows.append(flow)
        return flow

    def _add_upstream_ecmp_group(self, group_id, upper_tor_port, lower_tor_port):
        group = UpstreamECMPGroup(group_id, upper_tor_port, lower_tor_port)
        logging.info("Add upstream ecmp group to bridge %s: %s",
                     self.bridge_name, group)
        OVSCommand.ovs_ofctl_add_group(self.bridge_name, group)
        self.groups.append(group)
        return group

    def _add_upstream_ecmp_flow(self, in_port, group, priority=None):
        flow = UpstreamECMPFlow(in_port, group, priority=priority)
        logging.info("Add upstream ecmp flow to bridge %s: %s",
                     self.bridge_name, flow)
        OVSCommand.ovs_ofctl_add_flow(self.bridge_name, flow)
        self.flows.append(flow)
        return flow

    def set_forwarding_state(self, portids, states):
        """Set forwarding state."""
        with self.lock:
            for portid, state in zip(portids, states):
                logging.info("Set bridge %s port %s forwarding state: %s",
                             self.bridge_name, portid, ForwardingState.STATE_LABELS[state])
                self.flap_counter[portid] += self.states_setter[portid](state)
            OVSCommand.ovs_ofctl_mod_groups(
                self.bridge_name, self.upstream_ecmp_group)
            return self.query_forwarding_state(portids)

    def query_forwarding_state(self, portids):
        """Query forwarding state."""
        with self.lock:
            states = [self.states_getter[portid]() for portid in portids]
            logging.info("Query bridge %s forwarding state for ports %s: %s",
                         self.bridge_name, portids, tuple(ForwardingState.STATE_LABELS[_] for _ in states))
            return states

    def _set_upstream_drop(self, portid, recover):
        """Apply link drop/recovery to both IP families and all duplicated traffic."""
        for flow in self.flows:
            if not isinstance(flow, OVSUpstreamFlow) or not flow.get_port_enable(portid):
                continue
            if flow.get_drop(portid) == recover:
                flow.set_drop(portid=portid, recover=recover)
                OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, flow)

    def set_drop(self, portids, directions, recover):
        """Set drop on a link."""
        logging.info("Set drop on bridge %s: portids=%s, directions=%s, recover=%s"
                     % (self.bridge_name, portids, directions, recover))
        with self.lock:
            result = []
            for portid, direction in zip(portids, directions):
                downstream_flow = self.downstream_flows[portid]
                forwarding_state_getter = self.states_getter[portid]
                forwarding_state_setter = self.states_setter[portid]
                if recover:
                    # recover both upstream and downstream flows
                    # recover downstream
                    if downstream_flow.drop:
                        downstream_flow.set_drop(recover=recover)
                        OVSCommand.ovs_ofctl_mod_flow(
                            self.bridge_name, downstream_flow)

                    self._set_upstream_drop(portid, recover=True)

                    forwarding_state = forwarding_state_getter()
                    if forwarding_state == ForwardingState.STANDBY:
                        forwarding_state_setter(ForwardingState.ACTIVE)
                        OVSCommand.ovs_ofctl_mod_groups(
                            self.bridge_name, self.upstream_ecmp_group)
                else:
                    if direction == 0:
                        # downstream
                        if not downstream_flow.drop:
                            downstream_flow.set_drop()
                            OVSCommand.ovs_ofctl_mod_flow(
                                self.bridge_name, downstream_flow)
                    elif direction == 1:
                        # upstream
                        self._set_upstream_drop(portid, recover=False)

                        forwarding_state = forwarding_state_getter()
                        # use set forwarding state to standby to simulator link drop
                        if forwarding_state == ForwardingState.ACTIVE:
                            forwarding_state_setter(ForwardingState.STANDBY)
                            OVSCommand.ovs_ofctl_mod_groups(
                                self.bridge_name, self.upstream_ecmp_group)
                    else:
                        raise ValueError("Invalid direction %s, please use 0 for downstream and 1 for upstream"
                                         % (direction))
                result.append(True)
            return result

    def query_flap_counter(self, portids):
        """Query flap counter."""
        with self.lock:
            flap_counter = [self.flap_counter[portid] for portid in portids]
            logging.info("Query bridge %s flap counter for ports %s: %s",
                         self.bridge_name, portids, flap_counter)
            return flap_counter

    def reset_flap_counter(self, portids):
        """Reset flap counter."""
        with self.lock:
            flap_counter = []
            for portid in portids:
                self.flap_counter[portid] = 0
                flap_counter.append(0)
            logging.info("Reset bridge %s flap counter for ports %s: %s",
                         self.bridge_name, portids, flap_counter)
            return flap_counter


class InterruptableThread(threading.Thread):
    """Thread class that can be interrupted by Exception raised."""

    def __init__(self, **kwargs):
        super(InterruptableThread, self).__init__(**kwargs)
        self._e = None

    def set_error_handler(self, error_handler):
        """Add error handler callback that will be called when the thread exits with error."""
        self.error_handler = error_handler

    def run(self):
        """
        @summary: Run the target function, call `start()` to start the thread
                  instead of directly calling this one.
        """
        try:
            threading.Thread.run(self)
        except Exception as e:
            self._e = e
            if getattr(self, "error_handler", None) is not None:
                self.error_handler(self._e)

    def join(self, timeout=None, suppress_exception=False):
        """
        @summary: Join the thread, if `target` raises an exception, reraise it.
        @timeout: Wait timeout for `target` to finish.
        @suppress_exception: Default False, reraise the exception raised in
                             `target`. If True, return the exception instead of
                             raising.
        """
        threading.Thread.join(self, timeout=timeout)
        if self._e:
            if suppress_exception:
                return self._e
            else:
                raise (self._e) from None


class NiCServer(nic_simulator_grpc_service_pb2_grpc.DualToRActiveServicer):
    """gRPC for a NiC."""

    def __init__(self, nic_addr, ovs_bridge, binding_port, nic_addresses=None):
        self.nic_addr = nic_addr
        self.nic_addresses = tuple(dict.fromkeys([nic_addr] + list(nic_addresses or [])))
        self.ovs_bridge = ovs_bridge
        self.binding_port = binding_port
        self.server = None
        self.thread = None
        self.started = False

    def QueryAdminForwardingPortState(self, request, context):
        logging.debug("QueryAdminForwardingPortState: request to server %s from client %s\n",
                      self.nic_addr, context.peer())
        portids = request.portid
        response = nic_simulator_grpc_service_pb2.AdminReply(
            portid=portids,
            state=self.ovs_bridge.query_forwarding_state(portids)
        )
        logging.debug("QueryAdminForwardingPortState: response to client %s from server %s:\n%s",
                      context.peer(), self.nic_addr, response)
        return response

    def SetAdminForwardingPortState(self, request, context):
        logging.debug("SetAdminForwardingPortState: request to server %s from client %s\n",
                      self.nic_addr, context.peer())
        portids, states = request.portid, request.state
        response = nic_simulator_grpc_service_pb2.AdminReply(
            portid=portids,
            state=self.ovs_bridge.set_forwarding_state(portids, states)
        )
        logging.debug("SetAdminForwardingPortState: response to client %s from server %s:\n%s",
                      context.peer(), self.nic_addr, response)
        return response

    def QueryOperationPortState(self, request, context):
        # TODO: Add QueryOperationPortState implementation
        return nic_simulator_grpc_service_pb2.OperationReply()

    def QueryLinkState(self, request, context):
        # TODO: add QueryLinkState implementation
        return nic_simulator_grpc_service_pb2.LinkStateReply()

    def QueryServerVersion(self, request, context):
        # TODO: add QueryServerVersion implementation
        return nic_simulator_grpc_service_pb2.ServerVersionReply()

    def SetDrop(self, request, context):
        logging.debug("SetDrop: request to server %s from client %s\n",
                      self.nic_addr, context.peer())
        portids, directions, recover = request.portid, request.direction, request.recover
        response = nic_simulator_grpc_service_pb2.DropReply(
            portid=portids,
            success=self.ovs_bridge.set_drop(portids, directions, recover)
        )
        logging.debug("SetDrop: response to client %s from server %s\n%s",
                      context.peer(), self.nic_addr, response)
        return response

    def QueryFlapCounter(self, request, context):
        logging.debug("QueryFlapCounter: request to server %s from client %s\n",
                      self.nic_addr, context.peer())
        portids = request.portid
        response = nic_simulator_grpc_service_pb2.FlapCounterReply(
            portid=portids,
            flaps=self.ovs_bridge.query_flap_counter(portids)
        )
        logging.debug("QueryFlapCounter: response to client %s from server %s:\n%s",
                      context.peer(), self.nic_addr, response)
        return response

    def ResetFlapCounter(self, request, context):
        logging.debug("ResetFlapCounter: request to server %s from client %s\n",
                      self.nic_addr, context.peer())
        portids = request.portid
        response = nic_simulator_grpc_service_pb2.FlapCounterReply(
            portid=portids,
            flaps=self.ovs_bridge.reset_flap_counter(portids)
        )
        logging.debug("ResetFlapCounter: response to client %s from server %s:\n%s",
                      context.peer(), self.nic_addr, response)
        return response

    def _start_server(self, binding_port):
        """Bind and start synchronously so startup failures reach the caller."""
        self.server = grpc.server(
            futures.ThreadPoolExecutor(
                max_workers=THREAD_CONCURRENCY_PER_SERVER),
            options=GRPC_SERVER_OPTIONS
        )
        nic_simulator_grpc_service_pb2_grpc.add_DualToRActiveServicer_to_server(
            self,
            self.server
        )
        self.binding_port = bind_grpc_addresses(self.server, self.nic_addresses, binding_port)
        self.server.start()

    def start(self):
        """Start the gRPC server thread."""
        if self.started:
            return
        self._start_server(self.binding_port)
        self.thread = InterruptableThread(target=self.server.wait_for_termination)
        self.thread.start()
        self.started = True

    def stop(self):
        """Stop the gRPC server thread."""
        if self.server is not None:
            self.server.stop(grace=None)
        self.started = False

    def join(self, timeout=None, suppress_exception=False):
        """Wait the gRPC server thread termination."""
        if self.thread is not None:
            self.thread.join(
                timeout=timeout, suppress_exception=suppress_exception)


class MgmtServer(nic_simulator_grpc_mgmt_service_pb2_grpc.DualTorMgmtServiceServicer):
    """Management gRPC server to interact with sonic-mgmt."""

    def __init__(self, binding_address, binding_port, nic_servers, binding_addresses=None):
        self.binding_address = binding_address
        self.binding_addresses = tuple(dict.fromkeys([binding_address] + list(binding_addresses or [])))
        self.binding_port = binding_port
        self.nic_servers = nic_servers
        self.client_stubs = {}
        self.admin_lock = threading.Lock()
        self.server = None

    def _get_client_stub(self, nic_address):
        nic_address = str(ipaddress.ip_address(nic_address))
        if nic_address in self.client_stubs:
            client_stub = self.client_stubs[nic_address]
        else:
            client_stub = nic_simulator_grpc_service_pb2_grpc.DualToRActiveStub(
                grpc.insecure_channel(
                    grpc_target(nic_address, self.binding_port),
                    options=GRPC_CLIENT_OPTIONS
                )
            )
            self.client_stubs[nic_address] = client_stub
        return client_stub

    def QueryAdminForwardingPortState(self, request, context):
        nic_addresses = request.nic_addresses
        admin_requests = request.admin_requests
        logging.debug(
            "QueryAdminForwardingPortState[mgmt]: request query admin port state for %s\n", nic_addresses)
        query_responses = []
        for nic_address, admin_request in zip(nic_addresses, admin_requests):
            client_stub = self._get_client_stub(nic_address)
            try:
                state = client_stub.QueryAdminForwardingPortState(
                    admin_request,
                    timeout=GRPC_TIMEOUT
                )
                query_responses.append(state)
            except Exception as e:
                context.set_code(grpc.StatusCode.ABORTED)
                context.set_details(
                    "Error in QueryAdminForwardingPortState to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfAdminReply()
        response = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminReply(
            nic_addresses=nic_addresses,
            admin_replies=query_responses
        )
        logging.debug(
            "QueryAdminForwardingPortState[mgmt]: response of query: %s", response)
        return response

    def SetAdminForwardingPortState(self, request, context):
        nic_addresses = request.nic_addresses
        admin_requests = request.admin_requests
        logging.debug(
            "SetAdminForwardingPortState[mgmt]: request set admin port state: %s\n", request)
        set_responses = []
        for nic_address, admin_request in zip(nic_addresses, admin_requests):
            client_stub = self._get_client_stub(nic_address)
            try:
                state = client_stub.SetAdminForwardingPortState(
                    admin_request,
                    timeout=GRPC_TIMEOUT
                )
                set_responses.append(state)
            except Exception as e:
                context.set_code(grpc.StatusCode.ABORTED)
                context.set_details(
                    "Error in SetAdminForwardingPortState to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest()
        response = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminReply(
            nic_addresses=nic_addresses,
            admin_replies=set_responses
        )
        logging.debug(
            "SetAdminForwardingPortState[mgmt]: response of query: %s", response)
        return response

    def QueryOperationPortState(self, request, context):
        return nic_simulator_grpc_mgmt_service_pb2.ListOfOperationReply()

    def SetDrop(self, request, context):
        nic_addresses = request.nic_addresses
        drop_requests = request.drop_requests
        logging.debug("SetDrop[mgmt]: request set drop: %s\n", request)
        set_drop_responses = []
        for nic_address, drop_request in zip(nic_addresses, drop_requests):
            client_stub = self._get_client_stub(nic_address)
            try:
                set_drop_response = client_stub.SetDrop(
                    drop_request,
                    timeout=10
                )
                set_drop_responses.append(set_drop_response)
            except Exception as e:
                context.set_code(grpc.StatusCode.ABORTED)
                context.set_details("Error in SetDrop to %s: %s" %
                                    (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfDropReply()
        response = nic_simulator_grpc_mgmt_service_pb2.ListOfDropReply(
            nic_addresses=nic_addresses,
            drop_replies=set_drop_responses
        )
        logging.debug("SetDrop[mgmt]: response of set drop: %s\n", response)
        return response

    def SetNicServerAdminState(self, request, context):
        # IPv4 and IPv6 callers may administer the same object concurrently.
        with self.admin_lock:
            return self._set_nic_server_admin_state(request, context)

    def _set_nic_server_admin_state(self, request, context):
        nic_addresses = request.nic_addresses
        admin_states = request.admin_states
        logging.debug(
            "SetNicServerAdminState[mgmt]: request set nic server admin state:%s\n", request)

        successes = []
        for nic_address, admin_state in zip(nic_addresses, admin_states):
            nic_server = self.nic_servers[str(ipaddress.ip_address(nic_address))]
            success = True
            if admin_state:
                if not nic_server.started:
                    try:
                        nic_server.start()
                    except Exception:
                        logging.error("Failed to start nic server %s",
                                      nic_address, exc_info=True)
                        success = False
                logging.debug("Started nic server %s", nic_address)
            else:
                if nic_server.started:
                    try:
                        nic_server.stop()
                        nic_server.join()
                    except Exception:
                        logging.error("Failed to stop nic server %s",
                                      nic_address, exc_info=True)
                        success = False
                logging.debug("Stopped nic server %s", nic_address)

            successes.append(success)

        response = nic_simulator_grpc_mgmt_service_pb2.ListOfNiCServerAdminStateReply(
            nic_addresses=nic_addresses,
            admin_states=admin_states,
            successes=successes
        )
        logging.debug(
            "SetNicServerAdminState[mgmt]: response of set nic server admin state:%s\n", response)
        return response

    def QueryFlapCounter(self, request, context):
        nic_addresses = request.nic_addresses
        flap_counter_requests = request.flap_counter_requests
        logging.debug(
            "QueryFlapCounter[mgmt]: request query port flap counter for %s\n", nic_addresses)

        query_responses = []
        for nic_address, flap_counter_request in zip(nic_addresses, flap_counter_requests):
            client_stub = self._get_client_stub(nic_address)
            try:
                flap_counter_reply = client_stub.QueryFlapCounter(
                    flap_counter_request,
                    timeout=GRPC_TIMEOUT
                )
                query_responses.append(flap_counter_reply)
            except Exception as e:
                context.set_code(grpc.StatusCode.ABORTED)
                context.set_details(
                    "Error in QueryFlapCounter to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfFlapCounterReply()

        response = nic_simulator_grpc_mgmt_service_pb2.ListOfFlapCounterReply(
            nic_addresses=nic_addresses,
            flap_counter_replies=query_responses
        )
        logging.debug(
            "QueryFlapCounter[mgmt]: response of query: %s", response)
        return response

    def ResetFlapCounter(self, request, context):
        nic_addresses = request.nic_addresses
        flap_counter_requests = request.flap_counter_requests
        logging.debug(
            "ResetFlapCounter[mgmt]: request reset port flap counter for %s\n", nic_addresses)

        reset_responses = []
        for nic_address, flap_counter_request in zip(nic_addresses, flap_counter_requests):
            client_stub = self._get_client_stub(nic_address)
            try:
                flap_counter_reply = client_stub.ResetFlapCounter(
                    flap_counter_request,
                    timeout=GRPC_TIMEOUT
                )
                reset_responses.append(flap_counter_reply)
            except Exception as e:
                context.set_code(grpc.StatusCode.ABORTED)
                context.set_details(
                    "Error in ResetFlapCounter to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfFlapCounterReply()

        response = nic_simulator_grpc_mgmt_service_pb2.ListOfFlapCounterReply(
            nic_addresses=nic_addresses,
            flap_counter_replies=reset_responses
        )
        logging.debug(
            "ResetFlapCounter[mgmt]: response of reset: %s", response)
        return response

    def start(self):
        self.server = grpc.server(
            futures.ThreadPoolExecutor(
                max_workers=THREAD_CONCURRENCY_PER_SERVER),
            options=GRPC_SERVER_OPTIONS
        )
        nic_simulator_grpc_mgmt_service_pb2_grpc.add_DualTorMgmtServiceServicer_to_server(
            self, self.server)
        self.binding_port = bind_grpc_addresses(self.server, self.binding_addresses, self.binding_port)
        self.server.start()
        self.server.wait_for_termination()


class NiCSimulator(nic_simulator_grpc_service_pb2_grpc.DualToRActiveServicer):
    """NiC simulator class, define all the gRPC calls."""

    def __init__(self, vm_set, mgmt_port, binding_port, loopback_ips, duplicate_nic_upstream=False,
                 ipv6_loopback_ips=None):
        loopback_ips = validate_loopback_ips(loopback_ips, 4)
        if ipv6_loopback_ips is not None:
            ipv6_loopback_ips = validate_loopback_ips(ipv6_loopback_ips, 6)
        self.vm_set = vm_set
        self.server_nics = self._find_all_server_nics()
        self.server_nic_addresses = {
            nic: get_ip_address(nic) for nic in self.server_nics}
        self.server_nic_ipv6_addresses = {
            nic: get_ipv6_addresses(nic) for nic in self.server_nics}
        self.mgmt_port = mgmt_port
        self.mgmt_port_address = get_ip_address(mgmt_port)
        self.mgmt_port_addresses = ([self.mgmt_port_address] if self.mgmt_port_address else [])
        self.mgmt_port_addresses.extend(get_ipv6_addresses(mgmt_port))
        if not self.mgmt_port_addresses:
            raise ValueError("No usable IPv4 or global IPv6 address on management interface %s" % mgmt_port)
        self.mgmt_port_address = self.mgmt_port_addresses[0]
        self.ovs_bridges = {}
        self.servers = {}
        self.binding_port = binding_port
        for bridge_name in self._find_all_bridges():
            index = bridge_name.split("-")[-1]
            server_nic = NETNS_IFACE_TEMPLATE % index
            # only manipulate active server nics
            if server_nic in self.server_nic_addresses:
                server_nic_addr = self.server_nic_addresses[server_nic]
                addresses = ([server_nic_addr] if server_nic_addr else [])
                addresses.extend(self.server_nic_ipv6_addresses[server_nic])
                if addresses:
                    ovs_bridge = OVSBridge(bridge_name, loopback_ips, duplicate_nic_upstream, ipv6_loopback_ips)
                    server = NiCServer(addresses[0], ovs_bridge, binding_port, addresses)
                    for address in addresses:
                        self.ovs_bridges[address] = ovs_bridge
                        self.servers[address] = server

        logging.info("Starting NiC simulator to manipulate OVS bridges: %s",
                     json.dumps(list(self.ovs_bridges.keys()), indent=4))

        self.mgmt_server = MgmtServer(
            self.mgmt_port_address, binding_port, self.servers, self.mgmt_port_addresses)

    def _find_all_server_nics(self):
        return [_ for _ in os.listdir('/sys/class/net') if re.search(NETNS_IFACE_PATTERN, _)]

    def _find_all_bridges(self):
        result = OVSCommand.ovs_vsctl_list_br()
        bridges = [_ for _ in result.stdout.split() if self.vm_set in
                   _ and _.startswith(ACTIVE_ACTIVE_BRIDGE_TEMPLATE[0])]
        return bridges

    def start_nic_servers(self):
        for server in dict.fromkeys(self.servers.values()):
            logging.debug("Starting gRPC server on NiC %s", server.nic_addr)
            server.start()

    def stop_nic_servers(self):
        for server in dict.fromkeys(self.servers.values()):
            logging.debug("Stopping gRPC server on NiC %s", server.nic_addr)
            server.stop()
            server.join()

    def start_mgmt_server(self):
        logging.debug("Starting gRPC server on mgmt port %s",
                      self.mgmt_port_address)
        self.mgmt_server.start()


def parse_args():
    parser = argparse.ArgumentParser(
        description="NiC simulator"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        required=True,
        help="the port to listen to"
    )
    parser.add_argument(
        "-v",
        "--vm_set",
        required=True,
        help="the vm_set to identify testbed"
    )
    parser.add_argument(
        "-l",
        "--log_level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug"],
        help="the logging level"
    )
    parser.add_argument(
        "-s",
        "--stdout_log",
        default=False,
        action="store_true",
        help="Redirect log to stdout"
    )
    parser.add_argument(
        "-d",
        "--duplication-loopback-ips",
        default="10.1.0.36,10.1.0.38,10.1.0.39",
        help="the Loopback IPs to duplicate to both ToRs: <Loopback2>,<upper ToR Loopback3>,<lower ToR Loopback3>",
        dest="loopback_ips"
    )
    parser.add_argument(
        "--ipv6-loopback-ips",
        help="Optional IPv6 triplet: <Loopback2>,<upper ToR Loopback3>,<lower ToR Loopback3>"
    )
    parser.add_argument(
        "-n",
        "--duplicate_nic_upstream",
        default=False,
        action="store_true",
        help="Duplicate NIC upstream traffic to both ToRs (default: False)",
    )
    args = parser.parse_args()
    try:
        validate_loopback_ips(args.loopback_ips, 4)
        if args.ipv6_loopback_ips is not None:
            validate_loopback_ips(args.ipv6_loopback_ips, 6)
    except ValueError as error:
        parser.error(str(error))
    return args


def config_logging(vm_set, log_level, log_to_stdout=False):
    """
    Configure log to rotating file

    Remove the default handler from app.logger.
    Add RotatingFileHandler to the app.logger.
        File size: 10MB
        File number: 3
    The Werkzeug handler is untouched.
    """
    log_format = "%(asctime)s %(funcName)-20.20s %(levelname)-5.5s #%(lineno)-.4d| %(message)s"
    root = logging.getLogger()
    root.handlers.clear()
    handler = RotatingFileHandler(
        "/tmp/nic_simulator_{}.log".format(vm_set),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3)
    fmt = logging.Formatter(log_format)
    handler.setFormatter(fmt)
    handler.setLevel(log_level)
    root = logging.getLogger()
    root.setLevel(log_level)
    root.addHandler(handler)

    if log_to_stdout:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        root.addHandler(handler)


def config_env():
    """Config environment variables."""
    # NOTE: https://github.com/grpc/grpc/issues/14056
    os.environ["GRPC_ENABLE_FORK_SUPPORT"] = "0"


def main():
    print(sys.modules[__name__].__doc__)
    args = parse_args()
    logging.debug("Start nic_simulator with args: %s", args)
    config_env()
    config_logging(args.vm_set, args.log_level.upper(), args.stdout_log)
    OVSCommand.setup_openflow_version()
    loopback_ips = validate_loopback_ips(args.loopback_ips, 4)
    nic_simulator = NiCSimulator(args.vm_set, "mgmt", args.port, loopback_ips, args.duplicate_nic_upstream,
                                 args.ipv6_loopback_ips)
    try:
        nic_simulator.start_nic_servers()
        nic_simulator.start_mgmt_server()
    except KeyboardInterrupt:
        pass
    finally:
        if nic_simulator.mgmt_server.server is not None:
            nic_simulator.mgmt_server.server.stop(grace=None)
        nic_simulator.stop_nic_servers()


if __name__ == "__main__":
    main()
