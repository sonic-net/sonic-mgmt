"""
Cisco specific tests for the debug shell client in SONiC
"""
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.asic("cisco-8000"),
    pytest.mark.topology('any')
]


def check_config_flags(duthost):
    """
    @summary: This function checks the dshell_client.conf file(s) in the syncd container(s), and ensures that 
              the autorestart, and autostart config flags are set to True i.e. debug shell client is enabled by default.
              
    @returns: This function returns a dictionary, with list of syncd containers where autostart, autorestart are not set to True.
    """
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    config_flags = {
        "autostart":    [],
        "autorestart":  []
    }
    for asic in asics:
        config_file = duthost.command(f"docker exec syncd{asic} cat /etc/supervisor/conf.d/dshell_client.conf")["stdout"].split("\n")
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
