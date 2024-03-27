import pytest

from netaddr import valid_ipv6
from tests.tacacs.utils import check_output
from tests.bgp.test_bgp_fact import run_bgp_facts
from tests.test_features import run_show_features
from tests.tacacs.test_ro_user import ssh_remote_run
from tests.common.helpers.assertions import pytest_require
from tests.syslog.test_syslog import run_syslog, check_default_route # noqa F401
from tests.common.fixtures.duthost_utils import convert_and_restore_config_db_to_ipv6_only  # noqa F401

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def get_mgmt_ipv6(duthost):
    config_facts = duthost.get_running_config_facts()
    mgmt_interfaces = config_facts.get("MGMT_INTERFACE", {})
    mgmt_ipv6 = None

    for mgmt_interface, ip_configs in mgmt_interfaces.items():
        for ip_addr_with_prefix in ip_configs.keys():
            ip_addr = ip_addr_with_prefix.split("/")[0]
            if valid_ipv6(ip_addr):
                mgmt_ipv6 = ip_addr
    return mgmt_ipv6


def test_bgp_facts_ipv6_only(duthosts, enum_frontend_dut_hostname, enum_asic_index,
                             convert_and_restore_config_db_to_ipv6_only): # noqa F811
    run_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index)


def test_show_features_ipv6_only(duthosts, enum_dut_hostname, convert_and_restore_config_db_to_ipv6_only): # noqa F811
    run_show_features(duthosts, enum_dut_hostname)


def test_image_download_ipv6_only(creds, duthosts, enum_dut_hostname,
                                  convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """
    Test image download in mgmt ipv6 only scenario
    """
    duthost = duthosts[enum_dut_hostname]
    image_url = creds.get("test_image_url", {}).get("ipv6", "")
    pytest_require(len(image_url) != 0, "Cannot get image url")
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mgmt_interfaces = cfg_facts.get("MGMT_INTERFACE", {}).keys()
    for mgmt_interface in mgmt_interfaces:
        output = duthost.shell("curl --fail --interface {} {}".format(mgmt_interface, image_url),
                               module_ignore_errors=True)
        if output["rc"] == 0:
            break
    else:
        pytest.fail("Failed to download image from image_url {} via any of {}"
                    .format(image_url, list(mgmt_interfaces)))


@pytest.mark.parametrize("dummy_syslog_server_ip_a, dummy_syslog_server_ip_b",
                         [("fd82:b34f:cc99::100", None),
                          ("fd82:b34f:cc99::100", "fd82:b34f:cc99::200")])
def test_syslog_ipv6_only(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b,
                          check_default_route, convert_and_restore_config_db_to_ipv6_only): # noqa F811
    run_syslog(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, check_default_route)


def test_ro_user_ipv6_only(localhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs_v6,
                           convert_and_restore_config_db_to_ipv6_only): # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutipv6 = get_mgmt_ipv6(duthost)

    if not dutipv6:
        pytest.skip("Skip IPv6 only test, DUT has no mgmt IPv6.")

    res = ssh_remote_run(localhost, dutipv6, tacacs_creds['tacacs_ro_user'],
                         tacacs_creds['tacacs_ro_user_passwd'], 'cat /etc/passwd')
    check_output(res, 'test', 'remote_user')


def test_rw_user_ipv6_only(localhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds, check_tacacs_v6,
                           convert_and_restore_config_db_to_ipv6_only): # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutipv6 = get_mgmt_ipv6(duthost)

    if not dutipv6:
        pytest.skip("Skip IPv6 only test, DUT has no mgmt IPv6.")

    res = ssh_remote_run(localhost, dutipv6, tacacs_creds['tacacs_rw_user'],
                         tacacs_creds['tacacs_rw_user_passwd'], "cat /etc/passwd")
    check_output(res, 'testadmin', 'remote_user_su')
