"""
Tests for the `show platform npu...` commands in SONiC
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

npu_cli_dict = {
        #feature cli keyword : list of options under the cli
        "asic-errors": " ",
        "counters": " ",
        "ecmp": " ",
        "event-trap": " ",
        "global": " ",
        "lag": ["members"],
        "lpts": " ",
        "next-hop": ["entries", "usage"],
        "port": ["counters", "entries"],
        "rate-check": " ",
        "resource": " ",
        "router": ["route-table", "entries", "ports", "port-counters", "details"],
        "switch": ["entries", "ports"],
        "temperatures": " ",
        "trap": " "

}

def get_asic_str(duthost):
    if duthost.is_multi_asic:
        return " -n asic0"
    else:
        return ""

def check_config_flags(duthost):
    config_file = duthost.command("docker exec syncd cat /etc/supervisor/conf.d/dshell_client.conf")["stdout"].split("\n")
    for line in config_file:
        if "autostart" in line and "true" not in line:
            return False, "autostart flag is not set to True"
        elif "autorestart" in line and "true" not in line:
            assert False, "autorestart flag is not set to True"
    return True, ""

def check_dshell_client(duthost, enabled=True, change=True):
    """
    @summary: This function can either modify the state of dshell_client or check it. 
    Args:
        @change : if set to true, dshell_client will either be enabled or disabled based on "enabled"
        @enabled : whether or not we expect dshell client to be enabled
    """
    check_dshell = duthost.command("docker exec syncd ps -efl")
    action = "start" if enabled else "stop"
    timeout = 12
    while timeout > 0 and ("/usr/bin/dshell_client.py" in check_dshell["stdout"]) is not enabled:
        if change:
            duthost.command("docker exec syncd supervisorctl " + action + " dshell_client")
        time.sleep(30)
        timeout -= 1
        check_dshell = duthost.command("docker exec syncd ps -efl")
    result = ("/usr/bin/dshell_client.py" in check_dshell["stdout"]) is enabled
    if change:
        assert result, logging.error("Unable to %s dshell client." % (action))
    return result

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec syncd supervisorctl stop dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    result = duthost.command("docker exec syncd supervisorctl stop dshell_client")
    logging.info(result)
    assert check_dshell_client(duthost, False, False), "dshell_client still running"
    assert "dshell_client: stopped" in result["stdout"], "dshell_client stopped : expected output is missing"

def test_disable_sdk_debug(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("sudo config platform cisco sdk-debug disable")
    logging.info(result)
    assert check_dshell_client(duthost, False, False), "dshell_client still running"
    assert "Disabling sdk-debug on all ASICs" in result["stdout"], "sdk-debug not disabled on all ASICS"
    assert "Disabling sdk-debug on syncd" in result["stdout"], "sdk-debug not disabled on syncd"
    assert "sdk-debug has been disabled on syncd" in result["stdout"], "sdk-debug not disabled on syncd"

def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec syncd supervisorctl start dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("docker exec syncd supervisorctl start dshell_client")
    logging.info(result)
    assert check_dshell_client(duthost, True, False), "dshell_client not started"
    assert "dshell_client: started" in result["stdout"], "dshell_client started : expected output is missing"

def test_enable_sdk_debug(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("sudo config platform cisco sdk-debug enable")
    logging.info(result)
    assert check_dshell_client(duthost, True, False), "dshell_client not started"
    assert "Enabling sdk-debug on all ASICs" in result["stdout"], "sdk-debug not enabled on all ASICS"
    assert "Enabling sdk-debug on syncd" in result["stdout"], "sdk-debug not enabled on syncd"
    assert "sdk-debug has been enabled on syncd, please wait 10 seconds before using it" in result["stdout"], "sdk-debug not enabled on syncd"

def test_show_platform_npu_all(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu` , update the npu_cli_dict at the top for new platform npu command check.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Not supported on RP")
    check_dshell_client(duthost)

    result_list = []
    for cli in npu_cli_dict:
        for opt in npu_cli_dict[cli]:
            result = duthost.shell("sudo show platform npu {} {} {}".
                    format(cli, opt, get_asic_str(duthost)), module_ignore_errors=True)
            logging.info(result["stdout"])
            traceback_found = "Traceback" in result["stdout"]

            if traceback_found:
                result_list.append("Traceback found in show platform npu {} {}".format(cli, opt))
            elif result is None:
                result_list.append("No ouput for this CLI show platform npu {} {}".format(cli, opt))
            elif result["failed"]:
                result_list.append("Failed CLI show platform npu {} {}".format(cli, opt))

    for result in result_list:
        logging.error(result)

    assert not result_list, "One or more show platform npu commands failed {}".format(result_list)
