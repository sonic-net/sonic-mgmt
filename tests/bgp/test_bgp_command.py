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


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_bgp_commands_with_like_bgp_container(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ip_version, tbinfo
):
    """
    @summary: Verify BGP show/clear commands work correctly when there are
    multiple containers with "bgp" in their names.
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
            pytest.skip("Skipping IPv4 BGP commands test in IPv6 only topology")
        bgp_summary_cmd = "show ip bgp summary"
    else:
        bgp_summary_cmd = "show ipv6 bgp summary"

    # Create like-bgp container with "bgp" in name
    like_bgp_container_name = "database-like-bgp"

    create_result = duthost.shell(
        'docker run --rm --detach --name={} -e DEV= docker-database:latest sleep infinity'.format(
            like_bgp_container_name
        ),
        module_ignore_errors=True
    )

    pytest_assert(
        create_result["rc"] == 0,
        "Failed to create like-bgp container: {}".format(create_result.get("stderr", ""))
    )

    try:
        verify_result = duthost.shell(
            "docker ps | grep {}".format(like_bgp_container_name),
            module_ignore_errors=True
        )
        pytest_assert(
            verify_result["rc"] == 0 and like_bgp_container_name in verify_result["stdout"],
            "Like-bgp container {} not found in running containers".format(like_bgp_container_name)
        )

        # Verify BGP command works with like-bgp container present
        summary_result = duthost.shell(bgp_summary_cmd, module_ignore_errors=True)

        if summary_result["rc"] != 0:
            error_output = summary_result.get("stderr", "") + summary_result.get("stdout", "")
            pytest_assert(
                "No such command" not in error_output,
                "BGP command failed with 'No such command' error when like-bgp container is present. "
                "Error: {}".format(error_output)
            )

        pytest_assert(
            summary_result["rc"] == 0,
            "Command '{}' failed with like-bgp container present: {}".format(
                bgp_summary_cmd, summary_result.get("stderr", "")
            ),
        )

        # Stop like-bgp container and verify command still works
        stop_result = duthost.shell(
            "docker stop {}".format(like_bgp_container_name),
            module_ignore_errors=True
        )
        pytest_assert(
            stop_result["rc"] == 0,
            "Failed to stop like-bgp container: {}".format(stop_result.get("stderr", ""))
        )

        summary_result_after = duthost.shell(bgp_summary_cmd, module_ignore_errors=True)
        pytest_assert(
            summary_result_after["rc"] == 0,
            "Command '{}' failed after stopping like-bgp container: {}".format(
                bgp_summary_cmd, summary_result_after.get("stderr", "")
            ),
        )

    except Exception as e:
        logger.error("Test failed: {}".format(str(e)))
        duthost.shell("docker stop {}".format(like_bgp_container_name), module_ignore_errors=True)
        raise

    # Verify cleanup (container should be auto-removed via --rm flag)
    verify_cleanup = duthost.shell(
        "docker ps -a | grep {}".format(like_bgp_container_name),
        module_ignore_errors=True
    )
    if verify_cleanup["rc"] == 0 and like_bgp_container_name in verify_cleanup["stdout"]:
        duthost.shell("docker rm -f {}".format(like_bgp_container_name), module_ignore_errors=True)
