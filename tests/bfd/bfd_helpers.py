import logging
import re
import sys
import time

import pytest

from tests.common.utilities import wait_until
from tests.platform_tests.cli import util

logger = logging.getLogger(__name__)


def select_src_dst_dut_with_asic(
    request, get_src_dst_asic_and_duts, version
):
    logger.debug("Selecting source and destination DUTs with ASICs...")
    # Random selection of dut & asic.
    src_asic = get_src_dst_asic_and_duts["src_asic"]
    dst_asic = get_src_dst_asic_and_duts["dst_asic"]
    src_dut = get_src_dst_asic_and_duts["src_dut"]
    dst_dut = get_src_dst_asic_and_duts["dst_dut"]

    logger.info("Source Asic: %s", src_asic)
    logger.info("Destination Asic: %s", dst_asic)
    logger.info("Source dut: %s", src_dut)
    logger.info("Destination dut: %s", dst_dut)

    request.config.src_asic = src_asic
    request.config.dst_asic = dst_asic
    request.config.src_dut = src_dut
    request.config.dst_dut = dst_dut

    # Extracting static routes
    if version == "ipv4":
        static_route_command = "show ip route static"
    elif version == "ipv6":
        static_route_command = "show ipv6 route static"
    else:
        assert False, "Invalid version"

    src_dut_static_route = src_dut.shell(static_route_command, module_ignore_errors=True)["stdout"]
    if sys.version_info.major < 3:
        src_dut_static_route_output = src_dut_static_route.encode("utf-8").strip().split("\n")
    else:
        src_dut_static_route_output = src_dut_static_route.strip().split("\n")

    src_asic_routes = extract_routes(
        src_dut_static_route_output, version
    )
    logger.info("Source asic routes, {}".format(src_asic_routes))
    assert len(src_asic_routes) > 0, "static routes on source dut are empty"

    dst_dut_static_route = dst_dut.shell(static_route_command, module_ignore_errors=True)["stdout"]
    if sys.version_info.major < 3:
        dst_dut_static_route_output = dst_dut_static_route.encode("utf-8").strip().split("\n")
    else:
        dst_dut_static_route_output = dst_dut_static_route.strip().split("\n")

    dst_asic_routes = extract_routes(
        dst_dut_static_route_output, version
    )
    logger.info("Destination asic routes, {}".format(dst_asic_routes))
    assert len(dst_asic_routes) > 0, "static routes on destination dut are empty"

    # Extracting nexthops
    dst_dut_nexthops = (
        extract_ip_addresses_for_backend_portchannels(
            src_dut, src_asic, version
        )
    )
    logger.info("Destination nexthops, {}".format(dst_dut_nexthops))
    assert len(dst_dut_nexthops) != 0, "Destination Nexthops are empty"

    src_dut_nexthops = (
        extract_ip_addresses_for_backend_portchannels(
            dst_dut, dst_asic, version
        )
    )
    logger.info("Source nexthops, {}".format(src_dut_nexthops))
    assert len(src_dut_nexthops) != 0, "Source Nexthops are empty"

    # Picking a static route to delete correspinding BFD session
    src_prefix = selecting_route_to_delete(
        src_asic_routes, src_dut_nexthops.values()
    )
    logger.info("Source prefix: %s", src_prefix)
    request.config.src_prefix = src_prefix
    assert src_prefix is not None and src_prefix != "", "Source prefix not found"

    dst_prefix = selecting_route_to_delete(
        dst_asic_routes, dst_dut_nexthops.values()
    )
    logger.info("Destination prefix: %s", dst_prefix)
    request.config.dst_prefix = dst_prefix
    assert (
        dst_prefix is not None and dst_prefix != ""
    ), "Destination prefix not found"

    return (
        src_asic,
        dst_asic,
        src_dut,
        dst_dut,
        src_dut_nexthops,
        dst_dut_nexthops,
        src_prefix,
        dst_prefix,
    )


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


def control_interface_state(dut, asic, interface, action):
    int_status = dut.show_interface(
        command="status", include_internal_intfs=True, asic_index=asic.asic_index
    )["ansible_facts"]["int_status"][interface]
    oper_state = int_status["oper_state"]
    if action == "shutdown":
        target_state = "down"
    elif action == "startup":
        target_state = "up"
    else:
        raise ValueError("Invalid action specified")

    if oper_state != target_state:
        command = "shutdown" if action == "shutdown" else "startup"
        exec_cmd = (
            "sudo ip netns exec asic{} config interface -n asic{} {} {}".format(
                asic.asic_index, asic.asic_index, command, interface
            )
        )
        logger.info("Command: {}".format(exec_cmd))
        logger.info("Target state: {}".format(target_state))
        dut.shell(exec_cmd)
        assert wait_until(
            180,
            10,
            0,
            lambda: dut.show_interface(
                command="status",
                include_internal_intfs=True,
                asic_index=asic.asic_index,
            )["ansible_facts"]["int_status"][interface]["oper_state"]
            == target_state,
        )
    else:
        raise ValueError("Invalid action specified")


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


def modify_all_bfd_sessions(dut, flag):
    # Extracting asic count
    cmd = "show platform summary"
    logging.info("Verifying output of '{}' on '{}'...".format(cmd, dut.hostname))
    summary_output_lines = dut.command(cmd)["stdout_lines"]
    summary_dict = util.parse_colon_speparated_lines(summary_output_lines)
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


def extract_ip_addresses_for_backend_portchannels(dut, dut_asic, version):
    backend_port_channels = extract_backend_portchannels(dut)
    if version == "ipv4":
        command = "show ip int -d all"
    elif version == "ipv6":
        command = "show ipv6 int -d all"
    data = dut.show_and_parse("{} -n asic{}".format(command, dut_asic.asic_index))
    result_dict = {}
    for item in data:
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


def ensure_interface_is_up(dut, asic, interface):
    int_oper_status = dut.show_interface(
        command="status", include_internal_intfs=True, asic_index=asic.asic_index
    )["ansible_facts"]["int_status"][interface]["oper_state"]
    if int_oper_status == "down":
        logger.info(
            "Starting downed interface {} on {} asic{}".format(interface, dut, asic.asic_index)
        )
        exec_cmd = (
            "sudo ip netns exec asic{} config interface -n asic{} startup {}".format(
                asic.asic_index, asic.asic_index, interface
            )
        )

        logger.info("Command: {}".format(exec_cmd))
        dut.shell(exec_cmd)
        assert wait_until(
            180,
            10,
            0,
            lambda: dut.show_interface(
                command="status",
                include_internal_intfs=True,
                asic_index=asic.asic_index,
            )["ansible_facts"]["int_status"][interface]["oper_state"] == "up",
        )
