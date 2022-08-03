"""
Test the warm restart feature of containers
"""
import logging

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes

pytestmark = [
    pytest.mark.topology('any')
]

POST_CHECK_INTERVAL_SECS = 1
POST_CHECK_THRESHOLD_SECS = 360

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        ignoreRegex = [
            ".*ERR syncd.*: :- checkPluginRegistered: Plugin .* already registered.*",
            ".*ERR systemd\[1\]: Failed to start NAT container.*",
            ".*ERR nat#natsyncd: :- main: Nat conntrack table restore is not finished after timed-out, exit.*",
            ".*ERR nat#restore_nat_entries.py: \[Errno 2\] No such file or directory: '/var/warmboot/nat/nat_entries.dump'.*"
        ]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

    yield

def post_test_check(duthost, up_bgp_neighbors, request):
    """Restarts the containers which hit the restart limitation. Then post checks
       to see whether all the critical processes are alive ,all test ports oper
       status are up and expected BGP sessions are up after testing the autorestart feature.

    Args:
      duthost: An ansible object of DuT.
      up_bgp_neighbors: A list includes the IP of neighbors whose BGP session are up.

    Returns:
      True if critical processes are running, all test ports oper stats are up and
      BGP sessions are up; Otherwise False.
    """
    #Verify all critical services are fully started
    critical_proceses = wait_critical_processes(duthost, POST_CHECK_THRESHOLD_SECS, POST_CHECK_INTERVAL_SECS, 0, False)
    if not critical_proceses :
        logging.info("Not all critical services are fully started")
        return False, "[Critical Process]"

    #Verify all ports are up correctly
    logging.info("Wait until all ports are up correctly")
    check_interfaces = request.getfixturevalue("check_interfaces")
    results = check_interfaces(force_retry_timeout=POST_CHECK_THRESHOLD_SECS)
    interfaces_check = not [ result for result in results if "failed" in result and result["failed"]]
    if not interfaces_check :
        logging.info("Not all ports are up correctly. {} ".format(results))
        return False, "[INTERFACE]"

    # Verify bgp sessions are established
    logging.info("wait until all bgp session are established")
    bgp_check = wait_until(
        POST_CHECK_THRESHOLD_SECS, POST_CHECK_INTERVAL_SECS, 0,
        duthost.check_bgp_session_state, up_bgp_neighbors, "established"
    )

    if not bgp_check :
        logging.info("Not all bgp session are established")
        return False, "[BGP]"

    return True, ""

@pytest.mark.parametrize("container, setting",
                        [("bgp", {"timer_name": "bgp_timer", "timer": 2000}),
                         ("teamd", {"timer_name": "teamsyncd_timer", "timer": 3000}),
                         ("swss", {"timer_name": "neighsyncd_timer", "timer": 2000}),
                         ("syncd", {"timer_name": "", "timer": 0})])
def test_container_warm_restart(duthosts, rand_one_dut_hostname, container, setting, request):
    """
    Description:
    Test the container warm restart feature of the supported containers

    Test scenario:
    1. Check if the critical processes are running in all containers
    2. Use "sudo config warm_restart enable" to enable the system warm_restart
    3. Use "sudo config warm_restart enable <container>" to enable the warm_restart of target container
    4. Use "sudo systemctl restart <container>" to restart the target container
    5. Check if the critical processes are running in all containers within 1 minute
    6. Restore the device setting
    """
    duthost = duthosts[rand_one_dut_hostname]

    logging.info("Start checking container warm restart: {}".format(container))
    check_critical_processes(duthost)

    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]

    duthost.shell("sudo config warm_restart enable")
    duthost.shell("sudo config warm_restart enable {}".format(container))
    if setting['timer_name'] and setting['timer']:
        duthost.shell("sudo config warm_restart {} {}".format(setting['timer_name'], setting['timer']))
    duthost.shell("sudo systemctl restart {}".format(container))

    post_test_check_result , failed_item = post_test_check(duthost, up_bgp_neighbors, request)
    duthost.shell("sudo config warm_restart disable {}".format(container))
    duthost.shell("sudo config warm_restart disable")
    pytest_assert(post_test_check_result, "post_test_check failed at {}".format(failed_item))

    logging.info("End checking container warm restart: {}".format(container))
