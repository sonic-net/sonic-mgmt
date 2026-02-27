import pytest
import logging

from tests.community.route_helpers import NUM_ROUTES, ROUTE_PREFIX, apply_routes

logger = logging.getLogger(__name__)

_summary_data = {}


@pytest.fixture(scope="module")
def nexthop_ip(duthost):
    """Get a gateway address from the DUT's default route."""
    output = duthost.shell("ip -4 route show default", module_ignore_errors=True)["stdout"]
    for line in output.split('\n'):
        if 'via' in line:
            parts = line.split()
            return parts[parts.index('via') + 1]
    pytest.fail("No default gateway found on DUT")


@pytest.fixture(scope="module")
def baseline_route_count(duthost):
    """Snapshot how many routes already match ROUTE_PREFIX before any test routes are added."""
    result = duthost.shell(
        "show ip route | grep -c '{}'".format(ROUTE_PREFIX),
        module_ignore_errors=True
    )
    count = int(result["stdout"].strip() or "0")
    logger.info("Baseline routes matching '%s': %d", ROUTE_PREFIX, count)
    return count


@pytest.fixture(scope="module")
def test_summary():
    """Module-scoped dict to accumulate test results for the final summary."""
    return _summary_data


@pytest.fixture(scope="module", autouse=True)
def manage_routes_cleanup(duthost, nexthop_ip):
    """Remove all test routes and temp files after the module finishes."""
    yield
    logger.info("Cleanup: removing test routes")
    apply_routes(duthost, "del", NUM_ROUTES, nexthop_ip)
    duthost.shell("rm -f /tmp/routes_*.txt", module_ignore_errors=True)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print the 40K routes stress test summary at the very end of output."""
    if not _summary_data:
        return

    write = terminalreporter.write_line
    sep = "=" * 80

    write("")
    write(sep)
    write("  40K STATIC ROUTES STRESS TEST SUMMARY")
    write(sep)

    add_info = _summary_data.get("add", {})
    write("")
    write("1. Configure 40K static routes and verify how much time it takes")
    write("   for them to be shown in the CLI show commands.")
    write("   (Note: If routes are configured by directly writing redis db,")
    write("   they will not be displayed by 'show ip route' CLI command.)")
    if add_info:
        write("   - Pre-existing routes (baseline)       : {}".format(
            add_info["baseline"]))
        write("   - Route addition (ip -batch) duration : {:.2f} seconds".format(
            add_info["add_duration"]))
        write("   - Time for routes to appear in CLI     : {:.2f} seconds".format(
            add_info["convergence_time"]))
        write("   - 'show ip route' execution time       : {:.2f} seconds".format(
            add_info["show_duration"]))
        write("   - Routes found in 'show ip route'      : {} (baseline {} + added {})".format(
            add_info["route_count"], add_info["baseline"],
            add_info["route_count"] - add_info["baseline"]))
    else:
        write("   - SKIPPED (test_add_40k_static_routes did not run)")

    cpu_mem = _summary_data.get("cpu_memory", {})
    write("")
    write("2. Verify memory and CPU (monitored using 'top'):")
    if cpu_mem:
        write("   --- top output ---")
        for line in cpu_mem["top_output"].splitlines():
            write("   {}".format(line))
        write("   --- system-memory ---")
        for line in cpu_mem["mem_output"].splitlines():
            write("   {}".format(line))
    else:
        write("   - SKIPPED (test_verify_cpu_and_memory did not run)")

    remove_info = _summary_data.get("remove", {})
    write("")
    write("3. Remove 40K static routes and verify how much time it takes")
    write("   for them to be not shown in the CLI show commands:")
    if remove_info:
        write("   - Route removal (ip -batch) duration   : {:.2f} seconds".format(
            remove_info["del_duration"]))
        write("   - Time for routes to disappear from CLI: {:.2f} seconds".format(
            remove_info["convergence_time"]))
        write("   - 'show ip route' execution time       : {:.2f} seconds".format(
            remove_info["show_duration"]))
        write("   - Routes remaining in 'show ip route'  : {} (baseline was {})".format(
            remove_info["remaining_routes"], remove_info["baseline"]))
    else:
        write("   - SKIPPED (test_remove_40k_static_routes did not run)")

    write("")
    write(sep)
