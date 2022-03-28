#!/usr/bin/env python3
import abc
import argparse
import contextlib
import functools
import json
import logging
import fcntl
import functools
import grpc
import os
import re
import socket
import sys
import struct
import subprocess
import threading

from concurrent import futures
from logging.handlers import RotatingFileHandler

import nic_simulator_grpc_service_pb2
import nic_simulator_grpc_service_pb2_grpc


# name templates
ACTIVE_ACTIVE_BRIDGE_TEMPLATE = "baa-%s-%d"
NETNS_IFACE_TEMPLATE = "eth%s"
NETNS_IFACE_PATTERN = "eth\d+"
ACTIVE_ACTIVE_INTERFACES_TEMPLATE = "iaa-%s-%d"
ACTIVE_ACTIVE_INTERFACE_PATTERN = "iaa-[\w-]+-\d+"
SERVER_NIC_INTERFACE_TEMPLATE = "nic-%s-%d"
SERVER_NIC_INTERFACE_PATTERN = "nic-[\w-]+-\d+"


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
    logging.debug("COMMAND STDOUT: %s\n", result.stdout)
    logging.debug("COMMAND_STDERR: %s\n", result.stderr)
    return result


class OVSCommand(object):
    """OVS related commands."""

    OVS_VSCTL_LIST_BR_CMD = "ovs-vsctl list-br"
    OVS_VSCTL_LIST_PORTS = "ovs-vsctl list-ports {bridge_name}"
    OVS_OFCTL_DEL_FLOWS = "ovs-ofctl del-flows {bridge_name}"
    OVS_OFCTL_ADD_FLOWS = "ovs-ofctl add-flow {bridge_name} {flow}"
    OVS_OFCTL_DEL_GROUPS = "ovs-ofctl -O OpenFlow13 del-groups {bridge_name}"
    OVS_OFCTL_ADD_GROUP = "ovs-ofctl -O OpenFlow13 add-group {bridge_name} {group}"
    OVS_OFCTL_MOD_GROUP = "ovs-ofctl -O OpenFlow13 mod-group {bridge_name} {group}"

    @staticmethod
    def ovs_vsctl_list_br():
        return run_command(OVSCommand.OVS_VSCTL_LIST_BR_CMD)

    @staticmethod
    def ovs_vsctl_list_ports(bridge_name):
        return run_command(OVSCommand.OVS_VSCTL_LIST_PORTS.format(bridge_name=bridge_name))

    @staticmethod
    def ovs_ofctl_del_flows(bridge_name):
        return run_command(OVSCommand.OVS_OFCTL_DEL_FLOWS.format(bridge_name=bridge_name))

    @staticmethod
    def ovs_ofctl_add_flow(bridge_name, flow):
        return run_command(OVSCommand.OVS_OFCTL_ADD_FLOWS.format(bridge_name=bridge_name, flow=flow))

    @staticmethod
    def ovs_ofctl_add_group(bridge_name, group):
        return run_command(OVSCommand.OVS_OFCTL_ADD_GROUP.format(bridge_name=bridge_name, group=group))

    @staticmethod
    def ovs_ofctl_del_groups(bridge_name):
        return run_command(OVSCommand.OVS_OFCTL_DEL_GROUPS.format(bridge_name=bridge_name))

    @staticmethod
    def ovs_ofctl_mod_groups(bridge_name, group):
        return run_command(OVSCommand.OVS_OFCTL_MOD_GROUP.format(bridge_name=bridge_name, group=group))


class StrObj(abc.ABC):
    """Abstract class defines objects that could be represented as a string."""

    __slots__ = ("_str",)

    @abc.abstractmethod
    def to_string():
        pass

    def reinit(self):
        """Re-initialize object string representation."""
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

    __slots__ = ("in_port", "output_ports", "group", "_str_prefix")

    def __init__(self, in_port, packet_filter=None, output_ports=[], group=None):
        self.in_port = in_port
        self.packet_filter = packet_filter
        self.output_ports = set(output_ports)
        self.group = group
        if self.packet_filter:
            self._str_prefix = "%s,in_port=%s" % (self.packet_filter, self.in_port)
        else:
            self._str_prefix = "in_port=%s" % (self.in_port)

    def to_string(self):
        flow_parts = [self._str_prefix]
        if self.output_ports:
            flow_parts.append("actions=")
            flow_parts.extend("output:%s" % _ for _ in self.output_ports)
        elif self.group:
            flow_parts.append("actions=group:%s" % self.group.group_id)
        else:
            flow_parts.append("actions=drop")
        return ",".join(flow_parts)


class ToRState(object):
    """ToR's admin forwarding state"""
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
        upper_tor_forwarding_state=ToRState.ACTIVE,
        lower_tor_forwarding_state=ToRState.ACTIVE
    ):
        output_ports = []
        if upper_tor_forwarding_state == ToRState.ACTIVE:
            output_ports.append(upper_tor_port)
        if lower_tor_forwarding_state == ToRState.ACTIVE:
            output_ports.append(lower_tor_port)
        super(UpstreamECMPGroup, self).__init__(group_id, "select", output_ports=output_ports)
        self.upper_tor_port = upper_tor_port
        self.lower_tor_port = lower_tor_port
        self.upper_tor_forwarding_state = upper_tor_forwarding_state
        self.lower_tor_forwarding_state = lower_tor_forwarding_state
        self.group_str_cache = {}

    def set_upper_tor_forwarding_state(self, state):
        if state == ToRState.ACTIVE:
            if self.upper_tor_forwarding_state == ToRState.STANDBY:
                self.output_ports.add(self.upper_tor_port)
                self.upper_tor_forwarding_state = ToRState.ACTIVE
                self.reinit()
        elif state == ToRState.STANDBY:
            if self.upper_tor_forwarding_state == ToRState.ACTIVE:
                self.output_ports.remove(self.upper_tor_port)
                self.upper_tor_forwarding_state = ToRState.STANDBY
                self.reinit()

    def set_lower_tor_forwarding_state(self, state):
        if state == ToRState.ACTIVE:
            if self.lower_tor_forwarding_state == ToRState.STANDBY:
                self.output_ports.add(self.lower_tor_port)
                self.lower_tor_forwarding_state = ToRState.ACTIVE
                self.reinit()
        elif state == ToRState.STANDBY:
            if self.lower_tor_forwarding_state == ToRState.ACTIVE:
                self.output_ports.remove(self.lower_tor_port)
                self.lower_tor_forwarding_state = ToRState.STANDBY
                self.reinit()

    def __str__(self):
        return self.group_str_cache.setdefault(
            (self.upper_tor_forwarding_state, self.lower_tor_forwarding_state),
            super(UpstreamECMPGroup, self).__str__()
        )


class UpstreamECMPFlow(OVSFlow):
    """Object to represent an upstream ECMP flow that selects one of its output ports to send packets."""

    __slots__ = ("upper_tor_port", "lower_tor_port", "upper_tor_forwarding_state", "lower_tor_forwarding_state")

    def __init__(self, in_port, group):
        super(UpstreamECMPFlow, self).__init__(in_port, group=group)

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
    simulator netns (NiC) --+              +----- lower_if
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
        "upstream_ecmp_group"
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

    def _init_ports(self):
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
        logging.info("Init flows for bridge %s", self.bridge_name)
        self._del_flows()
        self._del_groups()
        # downstream flows
        self._add_flow(self.upper_tor_port, output_ports=[self.ptf_port, self.server_nic])
        self._add_flow(self.lower_tor_port, output_ports=[self.ptf_port, self.server_nic])

        # upstream flows
        # upstream packet from server NiC should be directed to both ToRs
        self._add_flow(self.server_nic, output_ports=[self.upper_tor_port, self.lower_tor_port])
        # upstream icmp packet from ptf port should be directed to both ToRs
        self._add_flow(self.ptf_port, packet_filter="icmp", output_ports=[self.upper_tor_port, self.lower_tor_port])
        # upstream packet from ptf port should be ECMP directed to active ToRs
        self.upstream_ecmp_group = self._add_upstream_ecmp_group(1, self.upper_tor_port, self.lower_tor_port)
        self.upstream_ecmp_flow = self._add_upstream_ecmp_flow(self.ptf_port, self.upstream_ecmp_group)

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

    def _add_flow(self, in_port, packet_filter=None, output_ports=[], group=None):
        flow = OVSFlow(in_port, packet_filter=packet_filter, output_ports=output_ports, group=group)
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

    def _add_upstream_ecmp_flow(self, in_port, group):
        flow = UpstreamECMPFlow(in_port, group)
        logging.info("Add upstream ecmp flow to bridge %s: %s", self.bridge_name, flow)
        OVSCommand.ovs_ofctl_add_flow(self.bridge_name, flow)
        self.flows.append(flow)
        return flow

    def set_forwarding_state(self, states):
        with self.lock:
            logging.info("Set bridge %s forwarding state: %s", self.bridge_name, tuple(ToRState.STATE_LABELS[_] for _ in states))
            self.upstream_ecmp_flow.set_upper_tor_forwarding_state(states[0])
            self.upstream_ecmp_flow.set_lower_tor_forwarding_state(states[1])
            OVSCommand.ovs_ofctl_mod_groups(self.bridge_name, self.upstream_ecmp_group)
            return self.query_forwarding_state()

    def query_forwarding_state(self):
        with self.lock:
            states = (self.upstream_ecmp_flow.get_upper_tor_forwarding_state(), self.upstream_ecmp_flow.get_lower_tor_forwarding_state())
            logging.info("Query bridge %s forwarding state: %s", self.bridge_name, tuple(ToRState.STATE_LABELS[_] for _ in states))
            return states


def validate_request_target(response):
    """Decorator to validate target gRPC server address is included in request metadata."""
    def _validate_request_target(rpc_func):
        @functools.wraps(rpc_func)
        def _decorated(nic_simulator, request, context):
            logging.debug("Validate request metadata includes 'grpc_server'")
            grpc_server = None
            for meta in context.invocation_metadata():
                if meta.key == "grpc_server":
                    grpc_server = meta.value
                    break
            if not grpc_server:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("grpc_server metadata not found in the request")
                return response
            elif grpc_server not in nic_simulator.ovs_bridges:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("grpc_server not found by nic_simulator")
            else:
                context.grpc_server = grpc_server
                return rpc_func(nic_simulator, request, context)
        return _decorated
    return _validate_request_target


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


class NiCSimulator(nic_simulator_grpc_service_pb2_grpc.DualTorServiceServicer):
    """NiC simulator class, define all the gRPC calls."""

    def __init__(self, vm_set):
        self.vm_set = vm_set
        self.server_nics = self._find_all_server_nics()
        self.server_nic_addresses = {nic: get_ip_address(nic) for nic in self.server_nics}
        self.ovs_bridges = {}
        for bridge_name in self._find_all_bridges():
            index = bridge_name.split("-")[-1]
            server_nic = NETNS_IFACE_TEMPLATE % index
            # only manipulate active server nics
            if server_nic in self.server_nic_addresses:
                server_nic_addr = self.server_nic_addresses[server_nic]
                if server_nic_addr is not None:
                    self.ovs_bridges[server_nic_addr] = OVSBridge(bridge_name)
        logging.info("Starting NiC simulator that receives for requests to: %s", json.dumps(list(self.ovs_bridges.keys()), indent=4))

    def _find_all_server_nics(self):
        return [_ for _ in os.listdir('/sys/class/net') if re.search(NETNS_IFACE_PATTERN, _)]

    def _find_all_bridges(self):
        result = OVSCommand.ovs_vsctl_list_br()
        bridges = [_ for _ in result.stdout.split() if self.vm_set in _ and _.startswith(ACTIVE_ACTIVE_INTERFACE_PATTERN[0])]
        return bridges

    def _find_target_server(self, context):
        for meta in context.invocation_metadata():
            if meta.key == "grpc_server":
                return meta.value
        return None

    def _validate_client(self, context):
        return True

    def _generate_error_response(context, status_code, details):
        context.set_code(status_code)
        context.set_details(details)

    def _init_admin_response(self):
        return nic_simulator_grpc_service_pb2.AdminReply(
            portid=[0, 1],
            state=[False, False]
        )

    def _init_operation_reponse(self):
        return nic_simulator_grpc_service_pb2.OperationReply(
            portid=[0, 1],
            state=[False, False]
        )

    @validate_request_target(nic_simulator_grpc_service_pb2.AdminReply())
    @validate_request_certificate(nic_simulator_grpc_service_pb2.AdminReply())
    def QueryAdminPortState(self, request, context):
        target_server = context.grpc_server
        response = nic_simulator_grpc_service_pb2.AdminReply(
            portid=[0, 1],
            state=self.ovs_bridges[target_server].query_forwarding_state()
        )
        logging.debug("QueryAdminPortState: response to client %s:\n%s", context.peer(), response)
        return response

    @validate_request_target(nic_simulator_grpc_service_pb2.AdminReply())
    @validate_request_certificate(nic_simulator_grpc_service_pb2.AdminReply())
    def SetAdminPortState(self, request, context):
        target_server = context.grpc_server
        response = nic_simulator_grpc_service_pb2.AdminReply(
            portid=[0, 1],
            state=self.ovs_bridges[target_server].set_forwarding_state(request.state)
        )
        return response

    def QueryOperationPortState(self, request, context):
        # TODO: Add QueryOperationPortState implementation
        return nic_simulator_grpc_service_pb2.OperationReply()


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
    title = \
        """
    _   _ _____ _____    _____ _____ __  __ _    _ _            _______ ____  _____  
    | \ | |_   _/ ____|  / ____|_   _|  \/  | |  | | |        /\|__   __/ __ \|  __ \ 
    |  \| | | || |      | (___   | | | \  / | |  | | |       /  \  | | | |  | | |__) |
    | . ` | | || |       \___ \  | | | |\/| | |  | | |      / /\ \ | | | |  | |  _  / 
    | |\  |_| || |____   ____) |_| |_| |  | | |__| | |____ / ____ \| | | |__| | | \ \ 
    |_| \_|_____\_____| |_____/|_____|_|  |_|\____/|______/_/    \_\_|  \____/|_|  \_\

    """
    print(title)
    args = parse_args()
    logging.debug("Start nic_simulator with args: %s", args)
    config_env()
    config_logging(args.vm_set, args.log_level.upper(), args.stdout_log)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    nic_simulator_grpc_service_pb2_grpc.add_DualTorServiceServicer_to_server(
        NiCSimulator(args.vm_set),
        server
    )
    server.add_insecure_port("0.0.0.0:%s" % args.port)
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    main()
