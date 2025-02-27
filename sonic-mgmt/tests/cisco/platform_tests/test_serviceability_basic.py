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

SCRIPT_FILE = "/opt/cisco/silicon-one/res/script.txt"

npu_cli_dict_general = {
        #feature cli keyword : list of options under the cli (for all topologies)
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
        "trap": " ",
        "script": [f"-s {SCRIPT_FILE} -t 60"]
}

npu_cli_dict_t2 = {
        #feature cli keyword : list of options under the cli (only for t2 topology)
        "bp-interface-map" : " "
}

def get_asic_str(duthost):
    if duthost.is_multi_asic:
        return " -n asic0"
    else:
        return ""

def check_dshell_client(duthost, enabled=True, change=True):
    """
    @summary: This function can either modify the state of dshell_client or check it. 
    Args:
        @change : if set to true, dshell_client will either be enabled or disabled based on "enabled"
        @enabled : whether or not we expect dshell client to be enabled
    """
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    result = True
    for asic in asics:
        check_dshell = duthost.command(f"docker exec syncd{asic} ps -efl")
        action = "start" if enabled else "stop"
        timeout = 0
        while timeout < 12 and ("/usr/bin/dshell_client.py" in check_dshell["stdout"]) is not enabled:
            if timeout:
                time.sleep(15)
            if change:
                duthost.command(f"docker exec syncd{asic} supervisorctl " + action + " dshell_client")
            check_dshell = duthost.command(f"docker exec syncd{asic} ps -efl")
            timeout += 1
        result &= ("/usr/bin/dshell_client.py" in check_dshell["stdout"]) is enabled
        if change:
            assert result, logging.error(f"Unable to {action} dshell client in syncd{asic}")
    return result

def test_check_dshell_enabled_default(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify dshell is enabled by default
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    assert check_dshell_client(duthost, True, False), "dshell_client not running by default"

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec syncd supervisorctl stop dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    for asic in asics:
        result = duthost.command(f"docker exec syncd{asic} supervisorctl stop dshell_client")
        logging.info(result)
        assert "dshell_client: stopped" in result["stdout"], f"dshell_client stopped : expected output is missing for asic {asic}"
    assert check_dshell_client(duthost, False, False), "dshell_client still running"

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
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    for asic in asics:
        result = duthost.command(f"docker exec syncd{asic} supervisorctl start dshell_client")
        logging.info(result)
        assert f"dshell_client: started" in result["stdout"], f"dshell_client started : expected output is missing for asic {asic}"
    assert check_dshell_client(duthost, True, False), "dshell_client not started"
    
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
    assert "sdk-debug has been enabled on syncd" in result["stdout"], "sdk-debug not enabled on syncd"

def test_show_platform_npu_all(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo):
    """
    @summary: Verify output of `show platform npu` , update the npu_cli_dict at the top for new platform npu command check.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    check_dshell_client(duthost)

    result = duthost.shell(f"sudo echo 'dapi.dump_router_ports()' > {SCRIPT_FILE}")

    result_list = []
    npu_cli_dict = npu_cli_dict_general.copy()

    if 't2' in tbinfo['topo']['name']:
        npu_cli_dict.update(npu_cli_dict_t2)

    for cli in npu_cli_dict:
        for opt in npu_cli_dict[cli]:
            result = duthost.shell("sudo show platform npu {} {} {}".
                    format(cli, opt, get_asic_str(duthost)), module_ignore_errors=True)
            logging.info(result["stdout"])
            traceback_found = "Traceback" in result["stdout"]

            if traceback_found:
                result_list.append("Traceback found in show platform npu {} {}".format(cli, opt))
            elif result is None:
                result_list.append("No output for this CLI show platform npu {} {}".format(cli, opt))
            elif result["failed"]:
                result_list.append("Failed CLI show platform npu {} {}".format(cli, opt))

    for result in result_list:
        logging.error(result)

    assert not result_list, "One or more show platform npu commands failed {}".format(result_list)
