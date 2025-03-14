"""
Cisco specific tests for the debug shell client in SONiC
"""
import logging
import pytest
import time

pytestmark = [
    pytest.mark.asic("cisco-8000"),
    pytest.mark.topology('any')
]


def check_config_flags(duthost):
    """
    @summary: This function checks the dshell_client.conf file(s) in the syncd container(s), and ensures that
    the autorestart and autostart config flags are set to True i.e. debug shell client is enabled by default.

    @returns: This function returns a dictionary, with list of syncd containers where autostart,
              autorestart are not set to True.
    """
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    config_flags = {
        "autostart":    [],
        "autorestart":  []
    }
    for asic in asics:
        config_file = duthost.command(f"docker exec syncd{asic} cat \
                                      /etc/supervisor/conf.d/dshell_client.conf")["stdout"].split("\n")
        for line in config_file:
            if "autostart" in line and "true" not in line:
                config_flags["autostart"].append(f"syncd{asic}")
            elif "autorestart" in line and "true" not in line:
                config_flags["autostart"].append(f"syncd{asic}")
    return config_flags


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


def test_dshell_default_enabled(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that the dshell client config flags have both been set to true,
              and dshell client is enabled by default
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    config_flags = check_config_flags(duthost)
    assert not config_flags["autostart"], f"autostart flag is set to False in {config_flags['autostart']}"
    assert not config_flags["autorestart"], f"autorestart flag is set to False {config_flags['autorestart']}"
    assert check_dshell_client(duthost, True, False), "debug shell is not running"
    logging.info("dshell client has been enabled by default")


def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that we are able to succesfully disable debug shell client and
              validate the output of `docker exec syncd supervisorctl start dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    for asic in asics:
        result = duthost.command(f"docker exec syncd{asic} supervisorctl start dshell_client")
        logging.info(result)
        assert "dshell_client: started" in result["stdout"], \
            f"\"dshell_client started\" : expected output is missing for asic {asic}"
    assert check_dshell_client(duthost, True, False), "dshell_client not started"


def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that we are able to successfully enable debug shell client and
              validate the output of `docker exec syncd supervisorctl stop dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    for asic in asics:
        result = duthost.command(f"docker exec syncd{asic} supervisorctl stop dshell_client")
        logging.info(result)
        assert "dshell_client: stopped" in result["stdout"], \
            f"\"dshell_client stopped\" : expected output is missing for asic {asic}"
    assert check_dshell_client(duthost, False, False), "dshell_client still running"


def test_enable_sdk_debug(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that the command to enable sdk-debug is functional, and starts debug shell client
              and validate the output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("sudo config platform cisco sdk-debug enable")
    logging.info(result)
    assert check_dshell_client(duthost, True, False), "dshell_client not started"
    assert "Enabling sdk-debug on all ASICs" in result["stdout"], "sdk-debug not enabled on all ASICS"
    assert "Enabling sdk-debug on syncd" in result["stdout"], "sdk-debug not enabled on syncd"
    assert "sdk-debug has been enabled on syncd" in result["stdout"], "sdk-debug not enabled on syncd"


def test_disable_sdk_debug(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that the command to disable sdk-debug is functional, and stops debug shell client
              and validate the output of `sudo config platform cisco sdk-debug enable"
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("sudo config platform cisco sdk-debug disable")
    logging.info(result)
    assert check_dshell_client(duthost, False, False), "dshell_client still running"
    assert "Disabling sdk-debug on all ASICs" in result["stdout"], "sdk-debug not disabled on all ASICS"
    assert "Disabling sdk-debug on syncd" in result["stdout"], "sdk-debug not disabled on syncd"
    assert "sdk-debug has been disabled on syncd" in result["stdout"], "sdk-debug not disabled on syncd"
