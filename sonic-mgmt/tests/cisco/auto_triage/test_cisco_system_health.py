"""
Tests for the cisco_system_health script
"""
import time
import random
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def test_cisco_system_health(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify the Cisco platform system health via cisco_system_health.py
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo python3 /opt/cisco/tools/bin/cisco_system_health.py")
    logging.info(result)
    assert "Platform services state check Passed" in result["stdout"], "Platform services state check Failed!"
    assert "Container check Passed" in result["stdout"], "Container check Failed!"
    assert "Platform Health Check Passed" in result["stdout"], "Platform Health Check Failed!"
    assert "Container Critical Process check Passed" in result["stdout"], "Container Critical Process Check Failed!"

def test_port_channel_health(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify the Cisco platform portchannel health via cisco_system_health.py
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo python3 /opt/cisco/tools/bin/cisco_system_health.py", module_ignore_errors=True)
    logging.info(result)
    assert "Portchannel state check Passed!" in result["stdout"], "Portchannel state check Failed!"
    ns_str = ""
    if duthost.is_multi_asic:
        nslist = duthost.get_asic_namespace_list()
        ns = random.choice(nslist)
        ns_str = f"-n {ns}"
    output = duthost.command(f"show int port -d all {ns_str}")['stdout_lines']
    for item in output:
        if 'LACP(A)(Up)' in item:
            pc = item.split()[1]
            cmd = f"sudo config interface {ns_str} shutdown {pc}"
            duthost.shell(cmd, module_ignore_errors=False)
            result = duthost.command("sudo python3 /opt/cisco/tools/bin/cisco_system_health.py", module_ignore_errors=True)
            logging.info(result)
            assert "Portchannel state check Passed!" in result["stdout"], "Portchannel state check Failed!"
            cmd = f"sudo config interface {ns_str} startup {pc}"
            duthost.shell(cmd, module_ignore_errors=False)
            result = duthost.command("sudo python3 /opt/cisco/tools/bin/cisco_system_health.py", module_ignore_errors=True)
            logging.info(result)
            assert "Portchannel state check Passed!" in result["stdout"], "Portchannel state check Failed!"
            break

