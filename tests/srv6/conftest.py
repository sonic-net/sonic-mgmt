import pytest
import time
import re
import logging
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.srv6_helper import SRv6Packets, create_srv6_locator, del_srv6_locator, create_srv6_sid, \
    del_srv6_sid
from tests.srv6.srv6_utils import MyLocators, MySIDs, get_srv6_mysid_entry_usage, \
    enable_srv6_counterpoll, disable_srv6_counterpoll, set_srv6_counterpoll_interval, verify_srv6_counterpoll_status, \
    verify_srv6_crm_status, ROUTE_BASE, prepare_l3_ethernet_ports, cleanup_l3_ethernet_ports

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def l3_regular_ports(rand_selected_dut, ptfhost, tbinfo):
    """Regular Ethernet L3 pair for all SRv6 dataplane tests (never PortChannel)."""
    prepared = prepare_l3_ethernet_ports(rand_selected_dut, ptfhost, tbinfo, count=2)
    yield prepared
    cleanup_l3_ethernet_ports(rand_selected_dut, ptfhost, prepared)
    rand_selected_dut.command("config save -y", module_ignore_errors=True)


@pytest.fixture(scope='class')
def prepare_param(rand_selected_dut, srv6_packet_type, l3_regular_ports):  # noqa F811
    prepare_param = {}
    prepare_param['packet_num'] = 100
    prepare_param['router_mac'] = rand_selected_dut.facts["router_mac"]
    prepare_param['srv6_packets'] = SRv6Packets.generate_srv6_packets(MyLocators.my_locator_list, srv6_packet_type)
    prepare_param['srv6_next_header'] = SRv6Packets.srv6_next_header

    assert prepare_param['router_mac'], "No router MAC found"
    # Send on one regular Ethernet, expect uN-shifted packets on the other
    prepare_param['ptf_downlink_port'] = l3_regular_ports[1]['ptf_id']
    prepare_param['ptf_uplink_ports'] = l3_regular_ports[0]['ptf_ids']
    prepare_param['l3_regular_ports'] = l3_regular_ports

    return prepare_param


@pytest.fixture(scope='module')
def srv6_crm_total_sids(rand_selected_dut):
    '''
    Get the default available SRV6 SID entries.
    '''
    output = rand_selected_dut.command('crm show summary')['stdout']
    parsed = re.findall(r'Polling Interval: +(\d+) +second', output)
    original_crm_polling_interval = int(parsed[0])

    rand_selected_dut.command("crm config polling interval 1")
    logger.info("Waiting 2 sec for CRM counters to become updated")
    time.sleep(2)
    mysid_crm_status = get_srv6_mysid_entry_usage(rand_selected_dut)

    yield mysid_crm_status['total_count']

    rand_selected_dut.command(f"crm config polling interval {original_crm_polling_interval}")


@pytest.fixture(scope="class", params=MySIDs.TUNNEL_MODE)
def config_setup(request, rand_selected_dut, srv6_crm_total_sids, l3_regular_ports):  # noqa F811
    '''
    Configure 128 instances of SRV6_MY_SIDS
    '''
    with allure.step('Create static route for SRv6'):
        ifname = l3_regular_ports[0]['intf']
        nexthop = l3_regular_ports[0]['nhip']
        logger.info(f"Selected regular Ethernet outgoing interface and nexthop: {ifname}, nexthop: {nexthop}")
        rand_selected_dut.command(f"sonic-db-cli CONFIG_DB HSET STATIC_ROUTE\\|default\\|{ROUTE_BASE}::/16 "
                                  f"nexthop {nexthop} ifname {ifname}")

    with allure.step('Enable SRv6 counterpoll'):
        enable_srv6_counterpoll(rand_selected_dut)
        set_srv6_counterpoll_interval(rand_selected_dut, 1000)
        verify_srv6_counterpoll_status(rand_selected_dut, 'enable', 1000)

    with allure.step('Create SRv6 Locators and SIDs'):
        for locator_param in MyLocators.my_locator_list:
            locator_name = locator_param[0]
            locator_prefix = locator_param[1]
            create_srv6_locator(rand_selected_dut, locator_name, locator_prefix)

        for sid_param in MySIDs.MY_SID_LIST:
            locator_name = sid_param[0]
            ip_addr = sid_param[1]
            action = sid_param[2]
            vrf = sid_param[3]
            dscp_mode = request.param
            create_srv6_sid(rand_selected_dut, locator_name, ip_addr, action, vrf, dscp_mode)

    with allure.step('Verify the CRM usage of SRv6 SID'):
        used_mysid_num = len(MySIDs.MY_SID_LIST)
        available_mysid_num = srv6_crm_total_sids - used_mysid_num
        wait_until(10, 1, 0, verify_srv6_crm_status, rand_selected_dut, used_mysid_num, available_mysid_num)

    rand_selected_dut.shell('sudo config save -y')

    yield dscp_mode

    with allure.step('Disable SRv6 counterpoll'):
        disable_srv6_counterpoll(rand_selected_dut)
        verify_srv6_counterpoll_status(rand_selected_dut, 'disable')

    with allure.step('Delete SRv6 Locators and SIDs'):
        for sid_param in MySIDs.MY_SID_LIST:
            locator_name = sid_param[0]
            ip_addr = sid_param[1]
            del_srv6_sid(rand_selected_dut, locator_name, ip_addr)

        for locator_param in MyLocators.my_locator_list:
            locator_name = locator_param[0]
            del_srv6_locator(rand_selected_dut, locator_name)

    with allure.step('Verify the CRM usage of SRv6 SID after the test'):
        used_mysid_num = 0
        available_mysid_num = srv6_crm_total_sids
        wait_until(10, 1, 0, verify_srv6_crm_status, rand_selected_dut, used_mysid_num, available_mysid_num)

    with allure.step('Delete static route for SRv6'):
        rand_selected_dut.command(f"sonic-db-cli CONFIG_DB DEL STATIC_ROUTE\\|default\\|{ROUTE_BASE}::/16")

    rand_selected_dut.shell('sudo config save -y')


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the srv6 reboot tests.
    """
    parser.addoption(
        "--srv6_reboot_type",
        action="store",
        choices=['random', 'reload', 'cold', 'bgp'],
        default='random',
        required=False,
        help="reboot type such as random, reload, cold, bgp"
    )

    parser.addoption(
        "--srv6_packet_type",
        action="store",
        default="srh,no_srh",
        help="SRv6 test parameters, comma separated values, default: srh,no_srh"
    )


def pytest_generate_tests(metafunc):
    if "srv6_packet_type" in metafunc.fixturenames:
        params = metafunc.config.getoption('--srv6_packet_type').split(',')
        metafunc.parametrize("srv6_packet_type", [param.strip() for param in params], scope="class")


@pytest.fixture(scope="class")
def srv6_packet_type(request):
    return request.param
