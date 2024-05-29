import logging
import sys

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def select_src_dst_dut_with_asic(
    request, get_src_dst_asic_and_duts, bfd_base_instance, version
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

    src_asic_routes = bfd_base_instance.extract_routes(
        src_dut_static_route_output, version
    )
    logger.info("Source asic routes, {}".format(src_asic_routes))
    assert len(src_asic_routes) > 0, "static routes on source dut are empty"

    dst_dut_static_route = dst_dut.shell(static_route_command, module_ignore_errors=True)["stdout"]
    if sys.version_info.major < 3:
        dst_dut_static_route_output = dst_dut_static_route.encode("utf-8").strip().split("\n")
    else:
        dst_dut_static_route_output = dst_dut_static_route.strip().split("\n")

    dst_asic_routes = bfd_base_instance.extract_routes(
        dst_dut_static_route_output, version
    )
    logger.info("Destination asic routes, {}".format(dst_asic_routes))
    assert len(dst_asic_routes) > 0, "static routes on destination dut are empty"

    # Extracting nexthops
    dst_dut_nexthops = (
        bfd_base_instance.extract_ip_addresses_for_backend_portchannels(
            src_dut, src_asic, version
        )
    )
    logger.info("Destination nexthops, {}".format(dst_dut_nexthops))
    assert len(dst_dut_nexthops) != 0, "Destination Nexthops are empty"

    src_dut_nexthops = (
        bfd_base_instance.extract_ip_addresses_for_backend_portchannels(
            dst_dut, dst_asic, version
        )
    )
    logger.info("Source nexthops, {}".format(src_dut_nexthops))
    assert len(src_dut_nexthops) != 0, "Source Nexthops are empty"

    # Picking a static route to delete correspinding BFD session
    src_prefix = bfd_base_instance.selecting_route_to_delete(
        src_asic_routes, src_dut_nexthops.values()
    )
    logger.info("Source prefix: %s", src_prefix)
    request.config.src_prefix = src_prefix
    assert src_prefix is not None and src_prefix != "", "Source prefix not found"

    dst_prefix = bfd_base_instance.selecting_route_to_delete(
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


def verify_static_route(
    request,
    asic,
    prefix,
    dut,
    expected_prefix_state,
    bfd_base_instance,
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

    asic_routes = bfd_base_instance.extract_routes(static_route_output, version)
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
    bgp_failures = []
    for result in results:
        if "failed" in result and result["failed"]:
            bgp_failures.append(result)

    if bgp_failures:
        logger.info("BGP check failed: {}".format(bgp_failures))
        return False
    else:
        return True
