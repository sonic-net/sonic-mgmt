import pytest
import logging
from tests.common import config_reload, reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from mx_utils import check_dnsmasq, refresh_dut_mac_table

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('mx')
]

logger = logging.getLogger(__name__)


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


@pytest.mark.parametrize("check_type", ["config_reload", "reboot"])
@pytest.mark.parametrize("vlan_number", [1])
def test_dhcp_server_init(localhost, ptfhost, duthost, setup_vlan, check_type):
    intf_count, vlan_config, ptf_index_port = setup_vlan
    do_check(duthost, intf_count, check_type, localhost, ptfhost, vlan_config, ptf_index_port)
