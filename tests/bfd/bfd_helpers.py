import logging
import random
import re
import sys
import time

import pytest
from ptf import testutils

from tests.common import config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def prepare_bfd_state(dut, flag, expected_bfd_state):
    modify_all_bfd_sessions(dut, flag)
    config_reload(dut, safe_reload=True)
    # Verification that all BFD sessions are deleted
    asics = [asic.split("asic")[1] for asic in dut.get_asic_namespace_list()]
    for asic in asics:
        assert wait_until(
            600,
            10,
            0,
            lambda: find_bfd_peers_with_given_state(dut, asic, expected_bfd_state),
        )


def verify_bfd_only(dut, nexthops, asic, expected_bfd_state):
    logger.info("BFD verifications")
    assert wait_until(
        300,
        10,
        0,
        lambda: verify_bfd_state(dut, nexthops.values(), asic, expected_bfd_state),
    )


def create_and_verify_bfd_state(asic, prefix, dut, dut_nexthops):
    logger.info("BFD addition on dut")
    add_bfd(asic.asic_index, prefix, dut)
    verify_bfd_only(dut, dut_nexthops, asic, "Up")


def verify_bfd_and_static_route(dut, dut_nexthops, asic, expected_bfd_state, request, prefix,
                                expected_prefix_state, version):
    logger.info("BFD & Static route verifications")
    verify_bfd_only(dut, dut_nexthops, asic, expected_bfd_state)
    verify_static_route(
        request,
        asic,
        prefix,
        dut,
        expected_prefix_state,
        version,
    )


def get_dut_asic_static_routes(version, dut):
    if version == "ipv4":
        static_route_command = "show ip route static"
    elif version == "ipv6":
        static_route_command = "show ipv6 route static"
    else:
        assert False, "Invalid version"

    stdout = dut.shell(static_route_command, module_ignore_errors=True)["stdout"]
    if sys.version_info.major < 3:
        static_routes_output = stdout.encode("utf-8").strip().split("\n")
    else:
        static_routes_output = stdout.strip().split("\n")

    asic_static_routes = extract_routes(static_routes_output, version)
    logger.info("asic routes, {}".format(asic_static_routes))
    assert len(asic_static_routes) > 0, "static routes on dut are empty"
    return asic_static_routes


def verify_bfd_state(dut, dut_nexthops, dut_asic, expected_bfd_state):
    logger.info("Verifying BFD state on {} ".format(dut))
    for nexthop in dut_nexthops:
        current_bfd_state = extract_current_bfd_state(
            nexthop, dut_asic.asic_index, dut
        )
        logger.info("current_bfd_state: {}".format(current_bfd_state))
        logger.info("expected_bfd_state: {}".format(expected_bfd_state))
        if current_bfd_state != expected_bfd_state:
            return False
    return True


def verify_static_route(
    request,
    asic,
    prefix,
    dut,
    expected_prefix_state,
    version,
):
    # Verification of static route
    if version == "ipv4":
        command = "show ip route static"
    elif version == "ipv6":
        command = "show ipv6 route static"
    else:
        assert False, "Invalid version"

    static_route = dut.shell(command, module_ignore_errors=True)["stdout"]
    if sys.version_info.major < 3:
        static_route_output = static_route.encode("utf-8").strip().split("\n")
    else:
        static_route_output = static_route.strip().split("\n")

    asic_routes = extract_routes(static_route_output, version)
    logger.info("Here are asic routes, {}".format(asic_routes))

    if expected_prefix_state == "Route Removal":
        if len(asic_routes) == 0 and request.config.interface_shutdown:
            logger.info("asic routes are empty post interface shutdown")
        else:
            assert len(asic_routes) > 0, "static routes on source dut are empty"
            assert (
                prefix
                not in asic_routes.get("asic{}".format(asic.asic_index), {}).keys()
            ), "Prefix removal is not successful. Prefix being validated: {}.".format(
                prefix
            )
    elif expected_prefix_state == "Route Addition":
        assert (
            prefix in asic_routes.get("asic{}".format(asic.asic_index), {}).keys()
        ), "Prefix has not been added even though BFD is expected. Prefix: {}".format(
            prefix
        )


def batch_control_interface_state(dut, asic, interfaces, action):
    if action == "shutdown":
        target_state = "down"
    elif action == "startup":
        target_state = "up"
    else:
        raise ValueError("Invalid action specified")

    int_status = get_interfaces_status(dut, asic)
    cmds = []
    for interface in interfaces:
        oper_state = int_status[interface]["oper_state"]
        if oper_state != target_state:
            command = "shutdown" if action == "shutdown" else "startup"
            exec_cmd = "sudo config interface -n asic{} {} {}".format(asic.asic_index, command, interface)
            cmds.append(exec_cmd)
            logger.info("Target state for interface {} is {}. Command: {}".format(
                interface,
                target_state,
                exec_cmd,
            ))
        else:
            raise ValueError("Invalid action specified for interface {}".format(interface))

    toggle_interfaces_in_parallel(cmds, dut, asic, interfaces, target_state)


def toggle_interfaces_in_parallel(cmds, dut, asic, interfaces, target_state):
    if cmds:
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for cmd in cmds:
                executor.submit(dut.shell, cmd)

        assert wait_until(
            180,
            10,
            0,
            lambda: check_interfaces_oper_state(dut, asic, interfaces, target_state),
        )


def check_interfaces_oper_state(dut, asic, interfaces, target_state):
    int_status = get_interfaces_status(dut, asic)
    for interface in interfaces:
        if int_status[interface]["oper_state"] != target_state:
            return False

    return True


def get_interfaces_status(dut, asic):
    return dut.show_interface(
        command="status",
        include_internal_intfs=True,
        asic_index=asic.asic_index,
    )["ansible_facts"]["int_status"]


def check_bgp_status(request):
    check_bgp = request.getfixturevalue("check_bgp")
    results = check_bgp()
    failed = [
        result for result in results if "failed" in result and result["failed"]
    ]
    if failed:
        pytest.fail(
            "BGP check failed, not all BGP sessions are up. Failed: {}".format(failed)
        )


def selecting_route_to_delete(asic_routes, nexthops):
    for asic in asic_routes:
        for prefix in asic_routes[asic]:
            nexthops_in_static_route_output = asic_routes[asic][prefix]
            # If nexthops on source dut are same destination dut's interfaces, we are picking that static route
            if sorted(nexthops_in_static_route_output) == sorted(nexthops):
                time.sleep(2)
                logger.info("Nexthops from static route output")
                logger.info(sorted(nexthops_in_static_route_output))
                logger.info("Given Nexthops")
                logger.info(sorted(nexthops))
                logger.info("Prefix")
                logger.info(prefix)
                return prefix


def parse_colon_speparated_lines(lines):
    """
    @summary: Helper function for parsing lines which consist of key-value pairs
              formatted like "<key>: <value>", where the colon can be surrounded
              by 0 or more whitespace characters
    @return: A dictionary containing key-value pairs of the output
    """
    res = {}
    for line in lines:
        fields = line.split(":")
        if len(fields) != 2:
            continue
        res[fields[0].strip()] = fields[1].strip()
    return res


def modify_all_bfd_sessions(dut, flag):
    # Extracting asic count
    cmd = "show platform summary"
    logging.info("Verifying output of '{}' on '{}'...".format(cmd, dut.hostname))
    summary_output_lines = dut.command(cmd)["stdout_lines"]
    summary_dict = parse_colon_speparated_lines(summary_output_lines)
    asic_count = int(summary_dict["ASIC Count"])

    # Creating bfd.json, bfd0.json, bfd1.json, bfd2.json ...
    for i in range(asic_count):
        file_name = "config_db{}.json".format(i)
        dut.shell("cp /etc/sonic/{} /etc/sonic/{}.bak".format(file_name, file_name))
        if flag == "false":
            command = """sed -i 's/"bfd": "true"/"bfd": "false"/' {}""".format(
                "/etc/sonic/" + file_name
            )
        elif flag == "true":
            command = """sed -i 's/"bfd": "false"/"bfd": "true"/' {}""".format(
                "/etc/sonic/" + file_name
            )
        dut.shell(command)


def extract_backend_portchannels(dut):
    output = dut.show_and_parse("show int port -d all")
    port_channel_dict = {}

    for item in output:
        if "BP" in item.get("ports", ""):
            port_channel = item.get("team dev", "")
            ports_with_status = [
                port.strip()
                for port in item.get("ports", "").split()
                if "BP" in port
            ]
            ports = [
                (
                    re.match(r"^([\w-]+)\([A-Za-z]\)", port).group(1)
                    if re.match(r"^([\w-]+)\([A-Za-z]\)", port)
                    else None
                )
                for port in ports_with_status
            ]
            status_match = re.search(
                r"LACP\(A\)\((\w+)\)", item.get("protocol", "")
            )
            status = status_match.group(1) if status_match else ""
            if ports:
                port_channel_dict[port_channel] = {
                    "members": ports,
                    "status": status,
                }

    return port_channel_dict


def extract_ip_addresses_for_backend_portchannels(dut, dut_asic, version, backend_port_channels=None):
    if not backend_port_channels:
        backend_port_channels = extract_backend_portchannels(dut)

    if version == "ipv4":
        command = "show ip int -d all"
    elif version == "ipv6":
        command = "show ipv6 int -d all"
    output = dut.show_and_parse("{} -n asic{}".format(command, dut_asic.asic_index))
    result_dict = {}
    for item in output:
        if version == "ipv4":
            ip_address = item.get("ipv4 address/mask", "").split("/")[0]
        elif version == "ipv6":
            ip_address = item.get("ipv6 address/mask", "").split("/")[0]
        interface = item.get("interface", "")

        if interface in backend_port_channels:
            result_dict[interface] = ip_address
    return result_dict


def delete_bfd(asic_number, prefix, dut):
    command = "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'false'".format(
        asic_number, prefix
    ).replace(
        "\\", ""
    )
    logger.info(command)
    dut.shell(command)
    time.sleep(15)


def add_bfd(asic_number, prefix, dut):
    command = "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'true'".format(
        asic_number, prefix
    ).replace(
        "\\", ""
    )
    logger.info(command)
    dut.shell(command)
    time.sleep(15)


def list_to_dict(sample_list):
    data_rows = sample_list[3:]
    for data in data_rows:
        data_dict = {}
        if sys.version_info.major < 3:
            data = data.encode("utf-8").split()
        else:
            data = data.split()

        data_dict["Peer Addr"] = data[0]
        data_dict["Interface"] = data[1]
        data_dict["Vrf"] = data[2]
        data_dict["State"] = data[3]
        data_dict["Type"] = data[4]
        data_dict["Local Addr"] = data[5]
        data_dict["TX Interval"] = data[6]
        data_dict["RX Interval"] = data[7]
        data_dict["Multiplier"] = data[8]
        data_dict["Multihop"] = data[9]
        data_dict["Local Discriminator"] = data[10]
    return data_dict


def extract_current_bfd_state(nexthop, asic_number, dut):
    bfd_peer_command = "ip netns exec asic{} show bfd peer {}".format(
        asic_number, nexthop
    )
    logger.info("Verifying BFD status on {}".format(dut))
    logger.info(bfd_peer_command)
    bfd_peer_status = dut.shell(bfd_peer_command, module_ignore_errors=True)["stdout"]
    if sys.version_info.major < 3:
        bfd_peer_output = bfd_peer_status.encode("utf-8").strip().split("\n")
    else:
        bfd_peer_output = bfd_peer_status.strip().split("\n")

    if "No BFD sessions found" in bfd_peer_output[0]:
        return "No BFD sessions found"
    else:
        entry = list_to_dict(bfd_peer_output)
        return entry["State"]


def parse_bfd_output(output):
    data_rows = output[3:]
    data_dict = {}
    for data in data_rows:
        data = data.split()
        data_dict[data[0]] = {}
        data_dict[data[0]]['Interface'] = data[1]
        data_dict[data[0]]['Vrf'] = data[2]
        data_dict[data[0]]['State'] = data[3]
        data_dict[data[0]]['Type'] = data[4]
        data_dict[data[0]]['Local Addr'] = data[5]
        data_dict[data[0]]['TX Interval'] = data[6]
        data_dict[data[0]]['RX Interval'] = data[7]
        data_dict[data[0]]['Multiplier'] = data[8]
        data_dict[data[0]]['Multihop'] = data[9]
        data_dict[data[0]]['Local Discriminator'] = data[10]
    return data_dict


def find_bfd_peers_with_given_state(dut, dut_asic, expected_bfd_state):
    # Expected BFD states: Up, Down, No BFD sessions found
    bfd_cmd = "ip netns exec asic{} show bfd sum"
    result = True
    asic_bfd_sum = dut.shell(bfd_cmd.format(dut_asic))["stdout"]
    if sys.version_info.major < 3:
        bfd_peer_output = asic_bfd_sum.encode("utf-8").strip().split("\n")
    else:
        bfd_peer_output = asic_bfd_sum.strip().split("\n")

    invalid_peers = []
    if any(
        keyword in bfd_peer_output[0]
        for keyword in ("Total number of BFD sessions: 0", "No BFD sessions found")
    ):
        return result
    else:
        bfd_output = parse_bfd_output(bfd_peer_output)
        for peer in bfd_output:
            if bfd_output[peer]["State"] != expected_bfd_state:
                invalid_peers.append(peer)

    if len(invalid_peers) > 0:
        result = False
    return result


def extract_routes(static_route_output, version):
    asic_routes = {}
    asic = None

    for line in static_route_output:
        if line.startswith("asic"):
            asic = line.split(":")[0]
            asic_routes[asic] = {}
        elif line.startswith("S>*") or line.startswith("  *"):
            parts = line.split(",")
            if line.startswith("S>*"):
                if version == "ipv4":
                    prefix_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", parts[0])
                elif version == "ipv6":
                    prefix_match = re.search(r"([0-9a-fA-F:.\/]+)", parts[0])
                if prefix_match:
                    prefix = prefix_match.group(1)
                else:
                    continue
            if version == "ipv4":
                next_hop_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", parts[0])
            elif version == "ipv6":
                next_hop_match = re.search(r"via\s+([0-9a-fA-F:.\/]+)", parts[0])
            if next_hop_match:
                next_hop = next_hop_match.group(1)
            else:
                continue

            asic_routes[asic].setdefault(prefix, []).append(next_hop)
    return asic_routes


def ensure_interfaces_are_up(dut, asic, interfaces):
    int_status = get_interfaces_status(dut, asic)
    cmds = []
    for interface in interfaces:
        if int_status[interface]["oper_state"] == "down":
            cmds.append("sudo config interface -n asic{} startup {}".format(asic.asic_index, interface))

    toggle_interfaces_in_parallel(cmds, dut, asic, interfaces, "up")


def clear_bfd_configs(dut, asic_index, prefix):
    logger.info("Clearing BFD configs on {}".format(dut))
    command = (
        "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'false'".format(
            asic_index,
            prefix,
        ).replace("\\", "")
    )

    dut.shell(command)


def get_random_bgp_neighbor_ip_of_asic(dut, asic_index, version):
    command = "show ip bgp sum"
    if version == "ipv4":
        command = "show ip bgp sum"
    elif version == "ipv6":
        command = "show ipv6 bgp sum"

    output = dut.show_and_parse("{} -n asic{}".format(command, asic_index))
    if not output:
        return None

    random_neighbor_bgp_info = random.choice(output)
    if "neighbhor" in random_neighbor_bgp_info:
        return random_neighbor_bgp_info["neighbhor"]
    elif "neighbor" in random_neighbor_bgp_info:
        return random_neighbor_bgp_info["neighbor"]
    else:
        return None


def get_bgp_neighbor_ip_of_port_channel(dut, asic_index, port_channel, version):
    command = None
    if version == "ipv4":
        command = "show ip int"
    elif version == "ipv6":
        command = "show ipv6 int"

    output = dut.show_and_parse("{} -n asic{}".format(command, asic_index))
    for item in output:
        if item.get("interface", "") == port_channel:
            return item.get("neighbor ip", "")

    return None


def get_asic_frontend_port_channels(dut, dst_asic_index):
    output = dut.show_and_parse("show int port -n asic{}".format(dst_asic_index))
    asic_port_channel_info = {}

    for item in output:
        port_channel = item.get("team dev", "")
        ports_with_status = [port.strip() for port in item.get("ports", "").split()]
        ports = [
            (
                re.match(r"^([\w-]+)\([A-Za-z]\)", port).group(1)
                if re.match(r"^([\w-]+)\([A-Za-z]\)", port)
                else None
            )
            for port in ports_with_status
        ]
        status_match = re.search(
            r"LACP\(A\)\((\w+)\)", item.get("protocol", "")
        )
        status = status_match.group(1) if status_match else ""
        if ports:
            asic_port_channel_info[port_channel] = {
                "members": ports,
                "status": status,
            }

    return asic_port_channel_info


def get_ptf_src_port(src_asic, tbinfo):
    src_asic_mg_facts = src_asic.get_extended_minigraph_facts(tbinfo)
    ptf_src_ports = list(src_asic_mg_facts["minigraph_ptf_indices"].values())
    if not ptf_src_ports:
        pytest.skip("No PTF ports found for asic{}".format(src_asic.asic_index))

    return random.choice(ptf_src_ports)


def clear_interface_counters(dut):
    dut.shell("sonic-clear counters")


def send_packets_batch_from_ptf(
    packet_count,
    version,
    src_asic_router_mac,
    ptfadapter,
    ptf_src_port,
    dst_neighbor_ip,
):
    for _ in range(packet_count):
        if version == "ipv4":
            pkt = testutils.simple_ip_packet(
                eth_dst=src_asic_router_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
                # ip_src=src_ip_addr,
                ip_dst=dst_neighbor_ip,
                ip_proto=47,
                ip_tos=0x84,
                ip_id=0,
                ip_ihl=5,
                ip_ttl=121
            )
        else:
            pkt = testutils.simple_ipv6ip_packet(
                eth_dst=src_asic_router_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
                # ip_src=src_ip_addr,
                ipv6_dst=dst_neighbor_ip,
            )

        ptfadapter.dataplane.flush()
        testutils.send(test=ptfadapter, port_id=ptf_src_port, pkt=pkt)


def get_backend_interface_in_use_by_counter(
    src_dut,
    dst_dut,
    packet_count,
    version,
    src_asic_router_mac,
    ptfadapter,
    ptf_src_port,
    dst_neighbor_ip,
    src_asic_index,
    dst_asic_index,
):
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for dut in [src_dut, dst_dut]:
            executor.submit(clear_interface_counters, dut)

    send_packets_batch_from_ptf(packet_count, version, src_asic_router_mac, ptfadapter, ptf_src_port, dst_neighbor_ip)
    src_output = src_dut.show_and_parse("show int counters -n asic{} -d all".format(src_asic_index))
    dst_output = dst_dut.show_and_parse("show int counters -n asic{} -d all".format(dst_asic_index))
    src_bp_iface = None
    for item in src_output:
        if "BP" in item.get("iface", "") and int(item.get("tx_ok", "0").replace(',', '')) >= packet_count:
            src_bp_iface = item.get("iface", "")

    dst_bp_iface = None
    for item in dst_output:
        if "BP" in item.get("iface", "") and int(item.get("rx_ok", "0").replace(',', '')) >= packet_count:
            dst_bp_iface = item.get("iface", "")

    if not src_bp_iface or not dst_bp_iface:
        pytest.fail("Backend interface in use not found")

    return src_bp_iface, dst_bp_iface


def get_src_dst_asic_next_hops(version, src_dut, src_asic, src_backend_port_channels, dst_dut, dst_asic,
                               dst_backend_port_channels):
    src_asic_next_hops = extract_ip_addresses_for_backend_portchannels(
        dst_dut,
        dst_asic,
        version,
        backend_port_channels=dst_backend_port_channels,
    )

    assert len(src_asic_next_hops) != 0, "Source next hops are empty"
    dst_asic_next_hops = extract_ip_addresses_for_backend_portchannels(
        src_dut,
        src_asic,
        version,
        backend_port_channels=src_backend_port_channels,
    )

    assert len(dst_asic_next_hops) != 0, "Destination next hops are empty"
    return src_asic_next_hops, dst_asic_next_hops


def get_port_channel_by_member(backend_port_channels, member):
    for port_channel in backend_port_channels:
        if member in backend_port_channels[port_channel]["members"]:
            return port_channel

    return None


def toggle_port_channel_or_member(
    target_to_toggle,
    dut,
    asic,
    request,
    action,
):
    request.config.portchannels_on_dut = "dut"
    request.config.selected_portchannels = [target_to_toggle]
    request.config.dut = dut
    request.config.asic = asic

    batch_control_interface_state(dut, asic, [target_to_toggle], action)
    if action == "shutdown":
        time.sleep(120)


def assert_bp_iface_after_shutdown(
    src_bp_iface_before_shutdown,
    dst_bp_iface_before_shutdown,
    src_bp_iface_after_shutdown,
    dst_bp_iface_after_shutdown,
    src_asic_index,
    dst_asic_index,
    src_dut_hostname,
    dst_dut_hostname,
):
    if src_bp_iface_before_shutdown == src_bp_iface_after_shutdown:
        pytest.fail(
            "Source backend interface in use on asic{} of dut {} does not change after shutdown".format(
                src_asic_index,
                src_dut_hostname,
            )
        )

    if dst_bp_iface_before_shutdown == dst_bp_iface_after_shutdown:
        pytest.fail(
            "Destination backend interface in use on asic{} of dut {} does not change after shutdown".format(
                dst_asic_index,
                dst_dut_hostname,
            )
        )


def assert_port_channel_after_shutdown(
    src_port_channel_before_shutdown,
    dst_port_channel_before_shutdown,
    src_port_channel_after_shutdown,
    dst_port_channel_after_shutdown,
    src_asic_index,
    dst_asic_index,
    src_dut_hostname,
    dst_dut_hostname,
):
    if src_port_channel_before_shutdown == src_port_channel_after_shutdown:
        pytest.fail(
            "Source port channel in use on asic{} of dut {} does not change after shutdown".format(
                src_asic_index,
                src_dut_hostname,
            )
        )

    if dst_port_channel_before_shutdown == dst_port_channel_after_shutdown:
        pytest.fail(
            "Destination port channel in use on asic{} of dut {} does not change after shutdown".format(
                dst_asic_index,
                dst_dut_hostname,
            )
        )


def verify_given_bfd_state(asic_next_hops, port_channel, asic_index, dut, expected_state):
    current_state = extract_current_bfd_state(asic_next_hops[port_channel], asic_index, dut)
    return current_state == expected_state


def wait_until_given_bfd_down(next_hops, port_channel, asic_index, dut):
    assert wait_until(
        300,
        10,
        0,
        lambda: verify_given_bfd_state(next_hops, port_channel, asic_index, dut, "Down"),
    )


def assert_traffic_switching(
    src_dut,
    dst_dut,
    src_backend_port_channels,
    dst_backend_port_channels,
    src_asic_index,
    src_bp_iface_before_shutdown,
    src_bp_iface_after_shutdown,
    src_port_channel_before_shutdown,
    dst_asic_index,
    dst_bp_iface_after_shutdown,
    dst_bp_iface_before_shutdown,
    dst_port_channel_before_shutdown,
):
    assert_bp_iface_after_shutdown(
        src_bp_iface_before_shutdown,
        dst_bp_iface_before_shutdown,
        src_bp_iface_after_shutdown,
        dst_bp_iface_after_shutdown,
        src_asic_index,
        dst_asic_index,
        src_dut.hostname,
        dst_dut.hostname,
    )

    src_port_channel_after_shutdown = get_port_channel_by_member(
        src_backend_port_channels,
        src_bp_iface_after_shutdown,
    )

    dst_port_channel_after_shutdown = get_port_channel_by_member(
        dst_backend_port_channels,
        dst_bp_iface_after_shutdown,
    )

    assert_port_channel_after_shutdown(
        src_port_channel_before_shutdown,
        dst_port_channel_before_shutdown,
        src_port_channel_after_shutdown,
        dst_port_channel_after_shutdown,
        src_asic_index,
        dst_asic_index,
        src_dut.hostname,
        dst_dut.hostname,
    )


def get_upstream_and_downstream_dut_pool(frontend_nodes):
    upstream_dut_pool = []
    downstream_dut_pool = []
    for node in frontend_nodes:
        bgp_neighbors = node.get_bgp_neighbors()
        for neighbor_info in bgp_neighbors.values():
            if "t3" in neighbor_info["description"].lower():
                upstream_dut_pool.append(node)
                break
            elif "t1" in neighbor_info["description"].lower():
                downstream_dut_pool.append(node)
                break

    return upstream_dut_pool, downstream_dut_pool
