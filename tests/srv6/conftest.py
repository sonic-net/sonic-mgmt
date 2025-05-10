import pytest
import time
import re
import logging
from tests.common.utilities import wait_until
from tests.common.helpers.ptf_tests_helper import get_stream_ptf_ports
from tests.common.helpers.ptf_tests_helper import select_random_link
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links  # noqa F401
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.srv6_helper import SRv6Packets, create_srv6_locator, del_srv6_locator, create_srv6_sid, \
    del_srv6_sid
from tests.srv6.srv6_utils import MyLocators, MySIDs, get_srv6_mysid_entry_usage, \
    enable_srv6_counterpoll, disable_srv6_counterpoll, set_srv6_counterpoll_interval, verify_srv6_counterpoll_status, \
    verify_srv6_crm_status

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def default_tunnel_mode(rand_selected_dut):
    default_tunnel_mode = rand_selected_dut.shell(
        'sonic-db-cli APPL_DB HGET "TUNNEL_DECAP_TABLE:IPINIP_V6_TUNNEL" "dscp_mode"')["stdout"]
    yield default_tunnel_mode


@pytest.fixture(scope='class')
def prepare_param(rand_selected_dut, tbinfo, mg_facts, downstream_links, upstream_links,  # noqa: F811
                  default_tunnel_mode):  # noqa F811
    prepare_param = {}
    prepare_param['inner_src_ip'] = '1.1.1.1'
    prepare_param['inner_dst_ip'] = '2.2.2.2'
    prepare_param['inner_src_ipv6'] = '2000::1'
    prepare_param['inner_dst_ipv6'] = '3000::2'
    prepare_param['outer_src_ipv6'] = '1000:1000::1'
    prepare_param['packet_num'] = 100
    prepare_param['router_mac'] = rand_selected_dut.facts["router_mac"]
    prepare_param['srv6_packets'] = SRv6Packets.srv6_packets
    prepare_param['srv6_next_header'] = SRv6Packets.srv6_next_header

    downlink = select_random_link(downstream_links)
    uplink_ptf_ports = get_stream_ptf_ports(upstream_links)

    assert downlink, "No downlink found"
    assert uplink_ptf_ports, "No uplink found"
    assert prepare_param['router_mac'], "No router MAC found"

    prepare_param['ptf_downlink_port'] = downlink.get("ptf_port_id")
    prepare_param['ptf_uplink_ports'] = uplink_ptf_ports

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


@pytest.fixture(params=MySIDs.TUNNEL_MODE)
def config_setup(request, rand_selected_dut, srv6_crm_total_sids):
    '''
    Configure 10 instances of SRV6_MY_SIDS
    '''
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
        for locator_param in MyLocators.my_locator_list:
            locator_name = locator_param[0]
            del_srv6_locator(rand_selected_dut, locator_name)

        for sid_param in MySIDs.MY_SID_LIST:
            locator_name = sid_param[0]
            ip_addr = sid_param[1]
            del_srv6_sid(rand_selected_dut, locator_name, ip_addr)

    with allure.step('Verify the CRM usage of SRv6 SID after the test'):
        used_mysid_num = 0
        available_mysid_num = srv6_crm_total_sids
        wait_until(10, 1, 0, verify_srv6_crm_status, rand_selected_dut, used_mysid_num, available_mysid_num)

    rand_selected_dut.shell('sudo config save -y')


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the srv6 reboot tests.
    """
    parser.addoption(
        "--srv6_reboot_type",
        action="store",
        choices=['random', 'reload', 'cold'],
        default='random',
        required=False,
        help="reboot type such as random, reload, cold"
    )
