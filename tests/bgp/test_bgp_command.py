import pytest
import logging
import re

from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("t0", "t1", "m0", "mx"),
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
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ip_version
):
    """
    @summary: This test case is to verify the output of "show ip bgp network" command
    if it matches the output of "docker exec -i bgp vtysh -c show bgp ipv4 all" command
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if ip_version == "ipv4":
        bgp_network_cmd = "show ip bgp network"
        bgp_docker_cmd = 'docker exec -i bgp vtysh -c "show bgp ipv4 all"'
    elif ip_version == "ipv6":
        bgp_network_cmd = "show ipv6 bgp network"
        bgp_docker_cmd = 'docker exec -i bgp vtysh -c "show bgp ipv6 all"'

    bgp_network_output = duthost.shell(bgp_network_cmd)["stdout"]
    pytest_assert(
        "*=" in bgp_network_output, "Failed to run '{}' command".format(bgp_network_cmd)
    )

    bgp_docker_output = duthost.shell(bgp_docker_cmd)["stdout"]
    pytest_assert(
        "*=" in bgp_docker_output,
        "Failed to run '{}' command".format(bgp_docker_output),
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
