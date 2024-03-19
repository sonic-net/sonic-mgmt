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

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
    if "/usr/bin/dshell_client.py" not in result:
        # dshell_client is not running. enable it
        result = duthost.shell("sudo config platform cisco sdk-debug enable", module_ignore_errors=True)['stdout']
        logging.info(result)
        time.sleep(360)
        assert "dshell_client: started" in result, "dshell_client not started"
        result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
        assert "/usr/bin/dshell_client.py" in result, "dshell_client is not running"
   
    result = duthost.shell("sudo config platform cisco sdk-debug disable", module_ignore_errors=True)['stdout']
    logging.info(result)
    assert "sdk-debug has been disabled" in result, "dshell_client is not stopped"
    time.sleep(10)
    result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
    assert "/usr/bin/dshell_client.py" not in result, "dshell_client is still running"

def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("sudo config platform cisco sdk-debug enable", module_ignore_errors=True)['stdout']
    logging.info(result)
    time.sleep(360)
    assert "dshell_client: started" in result, "dshell_client not started"

def test_check_dshell_client_after_enable(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `"ps -efl "`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
    logging.info(result)
    assert "/usr/bin/dshell_client.py" in result, "dshell_client is not running"

def test_show_platform_npu_all(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu` , update the npu_cli_dict at the top for new platform npu command check.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Not supported on RP")

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
