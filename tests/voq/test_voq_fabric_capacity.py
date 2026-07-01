import logging
import pytest
import random
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# This test only runs on t2 systems.
pytestmark = [
    pytest.mark.topology('t2', 'lrh', 'urh')
]

# This test checks the output of the "show fabric monitor capacity" command
# on a linecard. It is designed to run on a modular chassis.


def test_fabric_capacity(duthosts, enum_rand_one_per_hwsku_hostname):
    """Checks if the fabric capacity monitor works"""

    # get a start state from system
    # by running "show fabric monitor capcity" command
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asic = 0
    if duthost.is_multi_asic:
        asic = random.choice(duthost.facts['asics_present'])
    asicName = "asic{}".format(asic)
    logger.info(asicName)

    if duthost.is_multi_asic:
        cmd = "show fabric monitor capacity -n asic{}".format(asic)
    else:
        cmd = "show fabric monitor capacity"
    # The output of this show command is:
    # # show fabric monitor capacity
    # Monitored fabric capacity threshold:  100%
    #
    #  ASIC    Operating    Isolated     Total #    % Operating    Last Event     Last Time
    #              Links       Links    of Links          Links
    # ------  -----------  ----------  ----------  -------------  ------------  ------------
    # asic0          111           1         112        36.9792         Lower  19:16:42 ago

    cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    operating_links = 0
    for line in cmd_output:
        if not line:
            continue
        token = line.split()
        if token[0].startswith("asic"):
            operating_links = int(token[1])

    # get list of up/unisolated links by running "show fabric isolation" with Isolated=0
    # example output:
    # # show fabric isolation -n asic0
    #

    # asic0
    #   Local Link    Auto Isolated    Manual Isolated    Isolated    Isolate Reason
    # ------------  ---------------  -----------------  ----------  ----------------
    #           20                0                  1           1      config
    #           21                0                  0           0        none
    up_link_list = []
    if duthost.is_multi_asic:
        cmd = "show fabric isolation -n asic{}".format(asic)
    else:
        cmd = "show fabric isolation"

    cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    for line in cmd_output:
        if not line:
            continue
        token = line.split()
        if not token[0].isdigit():
            continue
        localPort = token[0]
        isolateSt = token[3]
        if isolateSt == "0":
            up_link_list.append(localPort)

    if len(up_link_list) > 0:
        shutlink = random.choice(up_link_list)
    else:
        return

    # Start the test. Isolate a link and check if the capacity command get updated.
    # Unisolate the link and check if the capacity command get updated.
    if duthost.is_multi_asic:
        asicName = "asic{}".format(asic)
    else:
        asicName = ""
    try:
        # isolate a link on the chip
        cmd = "sudo config fabric port isolate {} {}".format(shutlink, asicName)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")

        # check the output of "show fabric monitor capcity" command
        exp_links = operating_links - 1
        pytest_assert(wait_until(180, 30, 0, check_operational_link,
                                 duthost, asic, exp_links, 1),
                      "The number of opertional links should be {} and Isolated links should be {}".
                      format(exp_links, 1))

        pytest_assert(wait_until(180, 30, 0, check_isolated_link,
                                 duthost, asic, shutlink, 'config'),
                      "The Port Isolate Reason is not 'config'")
        # unisolate the link so the capacity is back
        cmd = "sudo config fabric port unisolate {} {}".format(shutlink, asicName)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")

        # check the output of "show fabric monitor capcity" command
        exp_links = operating_links
        pytest_assert(wait_until(180, 30, 0, check_operational_link,
                                 duthost, asic, exp_links, 0),
                      "The number of opertional links should be {} and Isolated links should be {}".
                      format(exp_links, 0))

        pytest_assert(not wait_until(180, 30, 0, check_isolated_link, duthost, asic,
                                     shutlink, 'config'), "The Port Isolate Reason is not removed")

    finally:
        # clean up the test
        cmd = "sudo config fabric port unisolate {} {}".format(shutlink, asicName)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")


def check_operational_link(duthost, asic, op_links, iso_links):
    if duthost.is_multi_asic:
        cmd = "show fabric monitor capacity -n asic{}".format(asic)
    else:
        cmd = "show fabric monitor capacity"
    # Example output is:
    # # show fabric monitor capacity
    #
    #  ASIC    Operating    Isolated     Total #    % Operating    Last Event     Last Time
    #              Links       Links    of Links          Links
    # ------  -----------  ----------  ----------  -------------  ------------  ------------
    # asic0          111           1         112        36.9792         Lower  19:16:42 ago

    cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    operating_links = 0
    isolated_links = 0
    for line in cmd_output:
        if not line:
            continue
        token = line.split()
        if token[0].startswith("asic"):
            operating_links = int(token[1])
            isolated_links = int(token[2])
    if operating_links == op_links and isolated_links == iso_links:
        return True
    else:
        return False


def check_isolated_link(duthost, asic, port, iso_reason):
    if duthost.is_multi_asic:
        cmd = "show fabric isolation -n asic{} -nz".format(asic)
    else:
        cmd = "show fabric isolation -nz"
    # Example output is:
    # # show fabric isolation
    #
    # asic0
    #   Local Link    Auto Isolated    Manual Isolated    Isolated    Isolate Reason
    # ------------  ---------------  -----------------  ----------  ----------------
    #           20                0                  1           1      config
    #           21                0                  0           0        none

    cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    isolate_state = "0"
    isolate_reason = "unknown"
    for line in cmd_output:
        if not line:
            continue
        token = line.split()
        if not token[0].isdigit():
            continue
        localPort = token[0]
        if localPort == port:
            isolate_state = token[3]
            isolate_reason = token[4]
            break
    if isolate_state == "1" and isolate_reason == iso_reason:
        return True
    else:
        return False
