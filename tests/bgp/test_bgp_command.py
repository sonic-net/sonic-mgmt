import pytest
import logging
import re

from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("t0", "t1", "m0", "mx", "m1"),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


# Function to parse the "Displayed X routes and Y total paths" line
def parse_routes_and_paths(output):
    match = re.search(r"Displayed\s+(\d+)\s+routes\s+and\s+(\d+)\s+total paths", output)
    if match:
        routes = int(match.group(1))
        paths = int(match.group(2))
        return routes, paths
    return None


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_bgp_network_command(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ip_version, tbinfo
):
    """
    @summary: This test case is to verify the output of "show ip bgp network" command
    if it matches the output of "docker exec -i bgp vtysh -c show bgp ipv4 all" command
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Determine if we are on IPv6 only topology
    ipv6_only_topo = (
        "-v6-" in tbinfo["topo"]["name"]
        if tbinfo and "topo" in tbinfo and "name" in tbinfo["topo"]
        else False
    )

    if ip_version == "ipv4":
        if ipv6_only_topo:
            pytest.skip("Skipping IPv4 BGP network command test in IPv6 only topology")
        bgp_network_cmd = "show ip bgp network"
        bgp_docker_cmd = 'docker exec -i bgp vtysh -c "show bgp ipv4 all"'
    elif ip_version == "ipv6":
        bgp_network_cmd = "show ipv6 bgp network"
        bgp_docker_cmd = 'docker exec -i bgp vtysh -c "show bgp ipv6 all"'

    bgp_network_result = duthost.shell(bgp_network_cmd)
    bgp_network_output = bgp_network_result["stdout"]
    pytest_assert(
        bgp_network_result["rc"] == 0,
        "{} return value is not 0, output={}".format(
            bgp_network_cmd, bgp_network_output
        ),
    )
    pytest_assert(
        "*=" in bgp_network_output or "*>" in bgp_network_output,
        "Failed to run '{}' command, output={}".format(
            bgp_network_cmd, bgp_network_output
        ),
    )

    bgp_docker_result = duthost.shell(bgp_docker_cmd)
    bgp_docker_output = bgp_docker_result["stdout"]
    pytest_assert(
        bgp_docker_result["rc"] == 0,
        "{} return value is not 0, output:{}".format(bgp_docker_cmd, bgp_docker_output),
    )
    pytest_assert(
        "*=" in bgp_docker_output or "*>" in bgp_docker_output,
        "Failed to run '{}' command, output={}".format(
            bgp_docker_cmd, bgp_docker_output
        ),
    )
    # Remove the first two lines from the docker command output
    bgp_docker_output_lines = bgp_docker_output.splitlines()[2:]
    bgp_docker_output_modified = "\n".join(bgp_docker_output_lines)

    pytest_assert(
        bgp_network_output == bgp_docker_output_modified,
        "The output of {} and {} mismatch".format(bgp_network_cmd, bgp_docker_cmd),
    )

    # Parse routes and paths from both outputs
    bgp_network_routes_and_paths = parse_routes_and_paths(bgp_network_output)
    bgp_docker_routes_and_paths = parse_routes_and_paths(bgp_docker_output)
    logger.info(
        "Routes and paths from '{}': {}".format(
            bgp_network_cmd, bgp_network_routes_and_paths
        )
    )
    logger.info(
        "Routes and paths from '{}': {}".format(
            bgp_docker_cmd, bgp_docker_routes_and_paths
        )
    )

    if bgp_network_routes_and_paths is None or bgp_docker_routes_and_paths is None:
        pytest_assert(
            bgp_network_routes_and_paths is not None
            and bgp_docker_routes_and_paths is not None,
            "Failed to parse routes and paths from one of the outputs.",
        )

    # Compare the routes and paths
    pytest_assert(
        bgp_network_routes_and_paths == bgp_docker_routes_and_paths,
        "Routes and total path value are mismatched: {} != {}".format(
            bgp_network_routes_and_paths, bgp_docker_routes_and_paths
        ),
    )


def test_get_FRR_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("FRR configuration on {}:".format(duthost.hostname))

    cmd = "vtysh -c 'show running-config'"
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.info("FRR configuration on {}: \n{}".format(cmd, cmd_response.get('stdout_lines', None)))
