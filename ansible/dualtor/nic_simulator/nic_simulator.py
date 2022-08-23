#!/usr/bin/env python3
"""
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
import functools
import grpc
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

# name templates
ACTIVE_ACTIVE_BRIDGE_TEMPLATE = "baa-%s-%d"
NETNS_IFACE_TEMPLATE = "eth%s"
NETNS_IFACE_PATTERN = "eth\d+"
ACTIVE_ACTIVE_INTERFACES_TEMPLATE = "iaa-%s-%d"
ACTIVE_ACTIVE_INTERFACE_PATTERN = "iaa-[\w-]+-\d+"
SERVER_NIC_INTERFACE_TEMPLATE = "nic-%s-%d"
SERVER_NIC_INTERFACE_PATTERN = "nic-[\w-]+-\d+"

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


def run_command(cmd, check=True):
    """Run a command."""
    logging.debug("COMMAND: %s", cmd)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        check=check
    )
    result.stdout = result.stdout.decode()
    result.stderr = result.stderr.decode()
    logging.debug("COMMAND STDOUT:\n%s\n", result.stdout)
    logging.debug("COMMAND STDERR:\n%s\n", result.stderr)
    return result


class OVSCommand(object):
    """OVS related commands."""

    OVS_VSCTL_LIST_BR_CMD = "ovs-vsctl list-br"
    OVS_VSCTL_LIST_PORTS_CMD = "ovs-vsctl list-ports {bridge_name}"
    OVS_OFCTL_DEL_FLOWS_CMD = "ovs-ofctl del-flows {bridge_name}"
    OVS_OFCTL_ADD_FLOWS_CMD = "ovs-ofctl add-flow {bridge_name} {flow}"
    OVS_OFCTL_MOD_FLOWS_CMD = "ovs-ofctl mod-flows {bridge_name} {flow}"
    OVS_OFCTL_DEL_GROUPS_CMD = "ovs-ofctl -O OpenFlow13 del-groups {bridge_name}"
    OVS_OFCTL_ADD_GROUP_CMD = "ovs-ofctl -O OpenFlow13 add-group {bridge_name} {group}"
    OVS_OFCTL_MOD_GROUP_CMD = "ovs-ofctl -O OpenFlow13 mod-group {bridge_name} {group}"

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

    __slots__ = ("group_id", "group_type", "output_ports", "_str_prefix")

    def __init__(self, group_id, group_type, output_ports=[]):
        self.group_id = group_id
        self.group_type = group_type
        self.output_ports = set(output_ports)
        self._str_prefix = "group_id=%s,type=%s" % (self.group_id, self.group_type)

    def to_string(self):
        group_parts = [self._str_prefix]
        if self.output_ports:
            group_parts.extend("bucket=output:%s" % _ for _ in self.output_ports)
        else:
            group_parts.append("bucket=drop")
        return ",".join(group_parts)


class OVSFlow(StrObj):
    """Object to represent an OVS flow."""

    __slots__ = ("in_port", "output_ports", "group", "priority", "_str_prefix")

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

    __slots__ = ("drop_output",)

    def __init__(self, in_port, packet_filter=None, output_ports=[], group=None, priority=None):
        super(OVSUpstreamFlow, self).__init__(in_port, packet_filter, output_ports, group, priority)
        self.drop_output = [False, False]

    def to_string(self):
        flow_parts = [self._str_prefix]
        has_output = False
        if self.output_ports:
            output = ["output:%s" % port for (portid, port) in enumerate(self.output_ports) if not self.drop_output[portid]]
            has_output = bool(output)
            if has_output:
                flow_parts.append("actions=%s" % ",".join(output))

        if not has_output:
            flow_parts.append("actions=drop")
        return ",".join(flow_parts)

    def get_drop(self, portid):
        return self.drop_output[portid]

    def set_drop(self, portid=None, recover=False):
        is_drop = not recover
  
        if portid is None:
            self.drop_output = [is_drop, is_drop]
        else:
            self.drop_output[portid] = is_drop

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
        super(UpstreamECMPGroup, self).__init__(group_id, "select", output_ports=output_ports)
        self.upper_tor_port = upper_tor_port
        self.lower_tor_port = lower_tor_port
        self.upper_tor_forwarding_state = upper_tor_forwarding_state
        self.lower_tor_forwarding_state = lower_tor_forwarding_state
        self.group_str_cache = {}

    def set_upper_tor_forwarding_state(self, state):
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

    def set_lower_tor_forwarding_state(self, state):
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

    def __str__(self):
        return self.group_str_cache.setdefault(
            (self.upper_tor_forwarding_state, self.lower_tor_forwarding_state),
            super(UpstreamECMPGroup, self).__str__()
        )


class UpstreamECMPFlow(OVSFlow):
    """Object to represent an upstream ECMP flow that selects one of its output ports to send packets."""

    __slots__ = ()

    def __init__(self, in_port, group, priority=None):
        super(UpstreamECMPFlow, self).__init__(in_port, group=group, priority=priority)

    def set_upper_tor_forwarding_state(self, state):
        self.group.set_upper_tor_forwarding_state(state)

    def set_lower_tor_forwarding_state(self, state):
        self.group.set_lower_tor_forwarding_state(state)

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
        "upstream_icmp_flow",
        "upstream_arp_flow"
    )

    def __init__(self, bridge_name):
        self.bridge_name = bridge_name
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
        self._init_flows()
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

    def _init_ports(self):
        """Initialize ports."""
        self.ports = self._get_ports()
        if len(self.ports) != 4:
            raise ValueError("Unhealthy bridge: %s, ports: %s" % (self.bridge_name, self.ports))
        tor_ports = []
        for port in self.ports:
            if re.search(ACTIVE_ACTIVE_INTERFACE_PATTERN, port):
                self.ptf_port = port
            elif re.search(SERVER_NIC_INTERFACE_PATTERN, port):
                self.server_nic = port
            else:
                tor_ports.append(port)
        if len(tor_ports) != 2:
            raise ValueError("Unhealthy bridge: %s, could not parse existing ports: %s" % (self.bridge_name, self.ports))
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

    def _init_flows(self):
        """Initialize OVS flows for the bridge."""
        logging.info("Init flows for bridge %s", self.bridge_name)
        self._del_flows()
        self._del_groups()
        # downstream flows
        self.downstream_upper_tor_flow = self._add_flow(self.upper_tor_port, output_ports=[self.ptf_port, self.server_nic], priority=10)
        self.downstream_lower_tor_flow = self._add_flow(self.lower_tor_port, output_ports=[self.ptf_port, self.server_nic], priority=10)

        # upstream flows
        # upstream packet from server NiC should be directed to both ToRs
        self.upstream_nic_flow = self._add_flow(self.server_nic, output_ports=[self.lower_tor_port, self.upper_tor_port], priority=9, upstream=True)
        # upstream icmp packet from ptf port should be directed to both ToRs
        self.upstream_icmp_flow = self._add_flow(self.ptf_port, packet_filter="icmp", output_ports=[self.lower_tor_port, self.upper_tor_port], priority=8, upstream=True)
        # upstream arp packet from ptf port should be directed to both ToRs
        self.upstream_arp_flow = self._add_flow(self.ptf_port, packet_filter="arp", output_ports=[self.lower_tor_port, self.upper_tor_port], priority=7, upstream=True)
        # upstream packet from ptf port should be ECMP directed to active ToRs
        self.upstream_ecmp_group = self._add_upstream_ecmp_group(1, self.upper_tor_port, self.lower_tor_port)
        self.upstream_ecmp_flow = self._add_upstream_ecmp_flow(self.ptf_port, self.upstream_ecmp_group, priority=6)

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

    def _add_flow(self, in_port, packet_filter=None, output_ports=[], group=None, priority=None, upstream=False):
        if upstream:
            flow = OVSUpstreamFlow(in_port, packet_filter=packet_filter, output_ports=output_ports, group=group, priority=priority)
        else:
            flow = OVSFlow(in_port, packet_filter=packet_filter, output_ports=output_ports, group=group, priority=priority)
        logging.info("Add flow to bridge %s: %s", self.bridge_name, flow)
        OVSCommand.ovs_ofctl_add_flow(self.bridge_name, flow)
        self.flows.append(flow)
        return flow

    def _add_upstream_ecmp_group(self, group_id, upper_tor_port, lower_tor_port):
        group = UpstreamECMPGroup(group_id, upper_tor_port, lower_tor_port)
        logging.info("Add upstream ecmp group to bridge %s: %s", self.bridge_name, group)
        OVSCommand.ovs_ofctl_add_group(self.bridge_name, group)
        self.groups.append(group)
        return group

    def _add_upstream_ecmp_flow(self, in_port, group, priority=None):
        flow = UpstreamECMPFlow(in_port, group, priority=priority)
        logging.info("Add upstream ecmp flow to bridge %s: %s", self.bridge_name, flow)
        OVSCommand.ovs_ofctl_add_flow(self.bridge_name, flow)
        self.flows.append(flow)
        return flow

    def set_forwarding_state(self, portids, states):
        """Set forwarding state."""
        with self.lock:
            for portid, state in zip(portids, states):
                logging.info("Set bridge %s port %s forwarding state: %s", self.bridge_name, portid, ForwardingState.STATE_LABELS[state])
                self.states_setter[portid](state)
            OVSCommand.ovs_ofctl_mod_groups(self.bridge_name, self.upstream_ecmp_group)
            return self.query_forwarding_state(portids)

    def query_forwarding_state(self, portids):
        """Query forwarding state."""
        with self.lock:
            states = [self.states_getter[portid]() for portid in portids]
            logging.info("Query bridge %s forwarding state for ports %s: %s", self.bridge_name, portids, tuple(ForwardingState.STATE_LABELS[_] for _ in states))
            return states

    def set_drop(self, portids, directions, recover):
        """Set drop on a link."""
        logging.info("Set drop on bridge %s: portids=%s, directions=%s, recover=%s" % (self.bridge_name, portids, directions, recover))
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
                        OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, downstream_flow)

                    # recover upstream
                    # recover upstream traffic from server NiC
                    if self.upstream_nic_flow.get_drop(portid):
                        self.upstream_nic_flow.set_drop(portid=portid, recover=recover)
                        OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, self.upstream_nic_flow)
                    # recover upstream icmp traffic(heartbeats) from ptf
                    if self.upstream_icmp_flow.get_drop(portid):
                        self.upstream_icmp_flow.set_drop(portid=portid, recover=recover)
                        OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, self.upstream_icmp_flow)
                    # recover upstream arp traffic from ptf
                    if self.upstream_arp_flow.get_drop(portid):
                        self.upstream_arp_flow.set_drop(portid=portid, recover=recover)
                        OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, self.upstream_arp_flow)

                    forwarding_state = forwarding_state_getter()
                    if forwarding_state == ForwardingState.STANDBY:
                        forwarding_state_setter(ForwardingState.ACTIVE)
                        OVSCommand.ovs_ofctl_mod_groups(self.bridge_name, self.upstream_ecmp_group)
                else:
                    if direction == 0:
                        # downstream
                        if not downstream_flow.drop:
                            downstream_flow.set_drop()
                            OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, downstream_flow)
                    elif direction == 1:
                        # upstream
                        # drop upstream traffic from server NiC
                        if not self.upstream_nic_flow.get_drop(portid):
                            self.upstream_nic_flow.set_drop(portid)
                            OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, self.upstream_nic_flow)
                        # drop upstream icmp traffic(heartbeats) from ptf
                        if not self.upstream_icmp_flow.get_drop(portid):
                            self.upstream_icmp_flow.set_drop(portid)
                            OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, self.upstream_icmp_flow)
                        # drop upstream arp traffic from ptf
                        if not self.upstream_arp_flow.get_drop(portid):
                            self.upstream_arp_flow.set_drop(portid)
                            OVSCommand.ovs_ofctl_mod_flow(self.bridge_name, self.upstream_arp_flow)

                        forwarding_state = forwarding_state_getter()
                        # use set forwarding state to standby to simulator link drop
                        if forwarding_state == ForwardingState.ACTIVE:
                            forwarding_state_setter(ForwardingState.STANDBY)
                            OVSCommand.ovs_ofctl_mod_groups(self.bridge_name, self.upstream_ecmp_group)
                    else:
                        raise ValueError("Invalid direction %s, please use 0 for downstream and 1 for upstream" % (direction))
                result.append(True)
            return result

def validate_request_certificate(response):
    """Decorator to validate client certificate."""
    def _validate_request_certificate(rpc_func):
        @functools.wraps(rpc_func)
        def _decorated(nic_simulator, request, context):
            logging.debug("Validate client certificate")
            # TODO: Add client authentication
            return rpc_func(nic_simulator, request, context)
        return _decorated
    return _validate_request_certificate


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
                raise(self._e) from None


class NiCServer(nic_simulator_grpc_service_pb2_grpc.DualToRActiveServicer):
    """gRPC for a NiC."""

    def __init__(self, nic_addr, ovs_bridge):
        self.nic_addr = nic_addr
        self.ovs_bridge = ovs_bridge
        self.server = None
        self.thread = None

    @validate_request_certificate(nic_simulator_grpc_service_pb2.AdminReply())
    def QueryAdminForwardingPortState(self, request, context):
        logging.debug("QueryAdminForwardingPortState: request to server %s from client %s\n", self.nic_addr, context.peer())
        portids = request.portid
        response = nic_simulator_grpc_service_pb2.AdminReply(
            portid=portids,
            state=self.ovs_bridge.query_forwarding_state(portids)
        )
        logging.debug("QueryAdminForwardingPortState: response to client %s from server %s:\n%s", context.peer(), self.nic_addr, response)
        return response

    @validate_request_certificate(nic_simulator_grpc_service_pb2.AdminReply())
    def SetAdminForwardingPortState(self, request, context):
        logging.debug("SetAdminForwardingPortState: request to server %s from client %s\n", self.nic_addr, context.peer())
        portids, states = request.portid, request.state
        response = nic_simulator_grpc_service_pb2.AdminReply(
            portid=portids,
            state=self.ovs_bridge.set_forwarding_state(portids, states)
        )
        logging.debug("SetAdminForwardingPortState: response to client %s from server %s:\n%s", context.peer(), self.nic_addr, response)
        return response

    @validate_request_certificate(nic_simulator_grpc_service_pb2.OperationReply())
    def QueryOperationPortState(self, request, context):
        # TODO: Add QueryOperationPortState implementation
        return nic_simulator_grpc_service_pb2.OperationReply()

    @validate_request_certificate(nic_simulator_grpc_service_pb2.LinkStateReply())
    def QueryLinkState(self, request, context):
        # TODO: add QueryLinkState implementation
        return nic_simulator_grpc_service_pb2.LinkStateReply()

    @validate_request_certificate(nic_simulator_grpc_service_pb2.ServerVersionReply())
    def QueryServerVersion(self, request, context):
        # TODO: add QueryServerVersion implementation
        return nic_simulator_grpc_service_pb2.ServerVersionReply()

    @validate_request_certificate(nic_simulator_grpc_service_pb2.DropReply())
    def SetDrop(self, request, context):
        logging.debug("SetDrop: request to server %s from client %s\n", self.nic_addr, context.peer())
        portids, directions, recover = request.portid, request.direction, request.recover
        response = nic_simulator_grpc_service_pb2.DropReply(
            portid=portids,
            success=self.ovs_bridge.set_drop(portids, directions, recover)
        )
        logging.debug("SetDrop: response to client %s from server %s\n%s", context.peer(), self.nic_addr, response)
        return response

    def _run_server(self, binding_port):
        """Run the gRPC server."""
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=THREAD_CONCURRENCY_PER_SERVER),
            options=GRPC_SERVER_OPTIONS
        )
        nic_simulator_grpc_service_pb2_grpc.add_DualToRActiveServicer_to_server(
            self,
            self.server
        )
        self.server.add_insecure_port("%s:%s" % (self.nic_addr, binding_port))
        self.server.start()
        self.server.wait_for_termination()

    def start(self, binding_port):
        """Start the gRPC server thread."""
        self.thread = InterruptableThread(target=self._run_server, args=(binding_port,))
        self.thread.start()

    def stop(self):
        """Stop the gRPC server thread."""
        self.server._state.termination_event.set()

    def join(self, timeout=None, suppress_exception=False):
        """Wait the gRPC server thread termination."""
        self.thread.join(timeout=timeout, suppress_exception=suppress_exception)


class MgmtServer(nic_simulator_grpc_mgmt_service_pb2_grpc.DualTorMgmtServiceServicer):
    """Management gRPC server to interact with sonic-mgmt."""

    def __init__(self, binding_address, binding_port):
        self.binding_address = binding_address
        self.binding_port = binding_port
        self.client_stubs = {}
        self.server = None

    def _get_client_stub(self, nic_address):
        if nic_address in self.client_stubs:
            client_stub = self.client_stubs[nic_address]
        else:
            client_stub = nic_simulator_grpc_service_pb2_grpc.DualToRActiveStub(
                grpc.insecure_channel(
                    "%s:%s" % (nic_address, self.binding_port),
                    options=GRPC_CLIENT_OPTIONS
                )
            )
            self.client_stubs[nic_address] = client_stub
        return client_stub

    def QueryAdminForwardingPortState(self, request, context):
        nic_addresses = request.nic_addresses
        logging.debug("QueryAdminForwardingPortState[mgmt]: request query admin port state for %s\n", nic_addresses)
        query_responses = []
        for nic_address in nic_addresses:
            client_stub = self._get_client_stub(nic_address)
            try:
                state = client_stub.QueryAdminForwardingPortState(
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[True, True]
                    ),
                    timeout=GRPC_TIMEOUT
                )
                query_responses.append(state)
            except Exception as e:
                context.set_code(grpc.StatusCode.ABORTED)
                context.set_details("Error in QueryAdminForwardingPortState to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfAdminReply()
        response = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminReply(
            nic_addresses=nic_addresses,
            admin_replies=query_responses
        )
        logging.debug("QueryAdminForwardingPortState[mgmt]: response of query: %s", response)
        return response

    def SetAdminForwardingPortState(self, request, context):
        nic_addresses = request.nic_addresses
        admin_requests = request.admin_requests
        logging.debug("SetAdminForwardingPortState[mgmt]: request set admin port state: %s\n", request)
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
                context.set_details("Error in SetAdminForwardingPortState to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest()
        response = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminReply(
            nic_addresses=nic_addresses,
            admin_replies=set_responses
        )
        logging.debug("SetAdminForwardingPortState[mgmt]: response of query: %s", response)
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
                context.set_details("Error in SetDrop to %s: %s" % (nic_address, repr(e)))
                return nic_simulator_grpc_mgmt_service_pb2.ListOfDropReply()
        response = nic_simulator_grpc_mgmt_service_pb2.ListOfDropReply(
            nic_addresses=nic_addresses,
            drop_replies=set_drop_responses
        )
        logging.debug("SetDrop[mgmt]: response of set drop: %s\n", response)
        return response

    def start(self):
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=THREAD_CONCURRENCY_PER_SERVER),
            options=GRPC_SERVER_OPTIONS
        )
        nic_simulator_grpc_mgmt_service_pb2_grpc.add_DualTorMgmtServiceServicer_to_server(self, self.server)
        self.server.add_insecure_port("%s:%s" % (self.binding_address, self.binding_port))
        self.server.start()
        self.server.wait_for_termination()


class NiCSimulator(nic_simulator_grpc_service_pb2_grpc.DualToRActiveServicer):
    """NiC simulator class, define all the gRPC calls."""

    def __init__(self, vm_set, mgmt_port, binding_port):
        self.vm_set = vm_set
        self.server_nics = self._find_all_server_nics()
        self.server_nic_addresses = {nic: get_ip_address(nic) for nic in self.server_nics}
        self.mgmt_port = mgmt_port
        self.mgmt_port_address = get_ip_address(mgmt_port)
        self.ovs_bridges = {}
        self.binding_port = binding_port
        for bridge_name in self._find_all_bridges():
            index = bridge_name.split("-")[-1]
            server_nic = NETNS_IFACE_TEMPLATE % index
            # only manipulate active server nics
            if server_nic in self.server_nic_addresses:
                server_nic_addr = self.server_nic_addresses[server_nic]
                if server_nic_addr is not None:
                    self.ovs_bridges[server_nic_addr] = OVSBridge(bridge_name)
        logging.info("Starting NiC simulator to manipulate OVS bridges: %s", json.dumps(list(self.ovs_bridges.keys()), indent=4))

        self.servers = {}
        self.servers = {nic_addr: NiCServer(nic_addr, ovs_bridge) for nic_addr, ovs_bridge in self.ovs_bridges.items()}
        self.mgmt_server = MgmtServer(self.mgmt_port_address, binding_port)

    def _find_all_server_nics(self):
        return [_ for _ in os.listdir('/sys/class/net') if re.search(NETNS_IFACE_PATTERN, _)]

    def _find_all_bridges(self):
        result = OVSCommand.ovs_vsctl_list_br()
        bridges = [_ for _ in result.stdout.split() if self.vm_set in _ and _.startswith(ACTIVE_ACTIVE_BRIDGE_TEMPLATE[0])]
        return bridges

    def start_nic_servers(self):
        for nic_addr, server in self.servers.items():
            logging.debug("Starting gRPC server on NiC %s", nic_addr)
            server.start(self.binding_port)

    def stop_nic_servers(self):
        for nic_addr, server in self.servers.items():
            logging.debug("Stopping gRPC server on NiC %s", nic_addr)
            server.stop()
            server.join()

    def start_mgmt_server(self):
        logging.debug("Starting gRPC server on mgmt port %s", self.mgmt_port_address)
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
    args = parser.parse_args()
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
    nic_simulator = NiCSimulator(args.vm_set, "mgmt", args.port)
    nic_simulator.start_nic_servers()
    try:
        nic_simulator.start_mgmt_server()
    except KeyboardInterrupt:
        nic_simulator.stop_nic_servers()


if __name__ == "__main__":
    main()
