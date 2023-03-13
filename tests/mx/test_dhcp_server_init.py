import pytest
import logging
from tests.common import config_reload, reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from mx_utils import create_vlan, get_vlan_config, check_dnsmasq, refresh_dut_mac_table

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('mx')
]

logger = logging.getLogger(__name__)
VLAN_NUMBER = 1


def do_check(duthost, intf_count, check_type, localhost, ptfhost, config, ptf_index_port):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="test_dhcp_server_init")
    # If dhcp_server init is done, below log would show in syslog.
    loganalyzer.expect_regex = [r".*DnsmasqStaticHostMonitor init success.*"]
    duthost.shell("docker exec -i dhcp_relay cat /dev/null > /etc/dnsmasq.hosts", module_ignore_errors=True)
    try:
        with loganalyzer:
            if check_type == "config_reload":
                config_reload(duthost, safe_reload=True)
            elif check_type == "reboot":
                reboot(duthost, localhost, reboot_type="cold")
            else:
                pytest.fail("Unsupported check_type: {}".format(check_type))
    except LogAnalyzerError as err:
        logger.error(err)
        pytest.fail("Unable to find dnsmasq init success log in syslog")
    refresh_dut_mac_table(ptfhost, config, ptf_index_port)
    # Check whether number of line of ip-mac mapping in dnsmasq.hosts is correct.
    pytest_assert(wait_until(600, 3, 0, check_dnsmasq, duthost, intf_count), "dnsmasq.hosts check fialed")


@pytest.fixture(scope="module")
def setup_vlan(duthost, module_fixture_remove_all_vlans, mx_common_setup_teardown):
    dut_index_port, ptf_index_port, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, VLAN_NUMBER)
    intf_count = create_vlan(duthost, vlan_config, dut_index_port)
    # Save config_db of mx vlan, to make it to take affect after reboot.
    duthost.shell("config save -y")

    yield intf_count, vlan_config, ptf_index_port


@pytest.mark.parametrize("check_type", ["config_reload", "reboot"])
def test_dhcp_server_init(localhost, ptfhost, duthost, setup_vlan, check_type):
    intf_count, vlan_config, ptf_index_port = setup_vlan
    do_check(duthost, intf_count, check_type, localhost, ptfhost, vlan_config, ptf_index_port)
