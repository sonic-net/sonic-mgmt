import pytest

import time
import logging

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-ecmp'),
]


def check_bgp_container(duthost):
    cmd = "docker ps|grep bgp|grep -v grep"
    output = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return output != ''


def check_isis_route_dst(duthost):
    cmd = "show ip route 202.2.1.0/24"
    output = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return output != ''


def check_isis_route_src(duthost):
    cmd = "show ip route 7.7.7.7/32"
    output = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return output != ''


@pytest.fixture(scope="module")
def common_setup_teardown(duthosts):
    logger.info("########### Setup dut interfaces ###########")

    wait_until(60, 10, 0, check_bgp_container, duthosts['vlab-01'])
    wait_until(60, 10, 0, check_bgp_container, duthosts['vlab-02'])

    run_cmds = ["sudo config interface ip add Ethernet12 7.7.7.7/32",
                "sudo config interface ip add Ethernet12 48.0.0.1/16",
                "sudo config interface ip add Ethernet12 9.9.9.9/32",
                "sudo config interface ip add Ethernet12 201.1.0.1/24",
                "sudo config interface ip add Ethernet12 16.0.0.1/8",
                "sudo config interface startup Ethernet12"]
    duthosts['vlab-01'].shell_cmds(cmds=run_cmds)

    run_cmds = ["sudo config interface startup Ethernet12",
                "sudo config interface ip add Ethernet12 202.2.1.3/24"]
    duthosts['vlab-02'].shell_cmds(cmds=run_cmds)

    wait_until(120, 10, 0, check_isis_route_dst, duthosts['vlab-01'])
    wait_until(120, 10, 0, check_isis_route_src, duthosts['vlab-02'])

    yield

    run_cmds = ["sudo config interface ip remove Ethernet12 7.7.7.7/32",
                "sudo config interface ip remove Ethernet12 9.9.9.9/32",
                "sudo config interface ip remove Ethernet12 48.0.0.1/16",
                "sudo config interface ip remove Ethernet12 201.1.0.1/24",
                "sudo config interface ip remove Ethernet12 16.0.0.1/8"]
    duthosts['vlab-01'].shell_cmds(cmds=run_cmds)

    run_cmds = ["sudo config interface ip remove Ethernet12 202.2.1.3/24"]
    duthosts['vlab-02'].shell_cmds(cmds=run_cmds)


def test_isis_ecmp(duthosts, nbrhosts, common_setup_teardown):

    path = 0
    run_cmds = ["clear counters"]
    for _, nbr in nbrhosts.items():
        nbr['host'].eos_command(commands=run_cmds)

    run_cmds = ["ping 202.2.1.3 -I 7.7.7.7 -c 2&",
                "ping 202.2.1.3 -I 9.9.9.9 -c 2 &",
                "ping 202.2.1.3 -I 48.0.0.1 -c 2 &",
                "ping 202.2.1.3 -I 201.1.0.1 -c 2 &",
                "ping 202.2.1.3 -I 16.0.0.1 -c 2 &"]

    duthosts['vlab-01'].shell_cmds(cmds=run_cmds)

    time.sleep(15)
    run_cmds = ["show interfaces counters incoming |grep Po1|awk '{print $3}'"]
    for _, nbr in nbrhosts.items():
        global path
        output = nbr['host'].eos_command(commands=run_cmds)
        if int(output["stdout"][0]) > 2:
            path += 1

    assert path >= 2, "ECMP test failed!"
