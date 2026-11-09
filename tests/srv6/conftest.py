import pytest
import time
import re
import logging
import random
from tests.common.utilities import wait_until
from tests.common.helpers.ptf_tests_helper import get_stream_ptf_ports
from tests.common.helpers.ptf_tests_helper import select_random_link
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links  # noqa F401
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.srv6_helper import SRv6Packets, create_srv6_locator, del_srv6_locator, create_srv6_sid, \
    del_srv6_sid
from tests.srv6.srv6_utils import MyLocators, MySIDs, get_srv6_mysid_entry_usage, \
    enable_srv6_counterpoll, disable_srv6_counterpoll, set_srv6_counterpoll_interval, verify_srv6_counterpoll_status, \
    verify_srv6_crm_status, ROUTE_BASE, get_ptf_src_port_and_dut_port_and_neighbor, verify_asic_db_sid_entry_exist

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def prepare_param(rand_selected_dut, srv6_packet_type, downstream_links, upstream_links):  # noqa F811
    prepare_param = {}
    prepare_param['packet_num'] = 100
    prepare_param['router_mac'] = rand_selected_dut.facts["router_mac"]
    prepare_param['srv6_packets'] = SRv6Packets.generate_srv6_packets(MyLocators.my_locator_list, srv6_packet_type)
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


def get_random_uplink_port(duthost, upstream_links, intf_infos):  # noqa F811
    '''
    Get a random uplink port that is used by the ipv6 interface info
    '''
    upstream_ports = set(upstream_links.keys())
    random_port = random.choice(list(upstream_ports))
    portchannels = duthost.show_and_parse('show int portchannel', start_line_index=2)
    for pc in portchannels:
        if random_port in pc['ports']:
            random_port = pc['team dev']
            break

    logger.info(f"Selected uplink port: {random_port}")
    intf_neighbor_map = {intf_info['interface']: intf_info['neighbor ip'] for intf_info in intf_infos}
    return random_port, intf_neighbor_map[random_port]


@pytest.fixture(scope="class", params=MySIDs.TUNNEL_MODE)
def config_setup(request, rand_selected_dut, srv6_crm_total_sids, upstream_links):  # noqa F811
    '''
    Configure 128 instances of SRV6_MY_SIDS
    '''
    with allure.step('Create static route for SRv6'):
        ipv6_intf_info = rand_selected_dut.show_and_parse('show ipv6 interface')
        ifname, nexthop = get_random_uplink_port(rand_selected_dut, upstream_links, ipv6_intf_info)
        logger.info(f"Selected uplink interface and nexthop: {ifname}, nexthop: {nexthop}")
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


@pytest.fixture()
def setup_uN(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_port_ids = []
    for interface in list(mg_facts["minigraph_ptf_indices"].keys()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        ptf_port_ids.append(port_id)

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_asic = duthost.asic_instance(asic_index)
        dut_mac = dut_asic.get_router_mac()
        dut_port, ptf_src_ports, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost.facts["router_mac"]
        dut_port, ptf_src_ports, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(duthost, tbinfo)

    logger.info("Doing test on DUT port {} | PTF ports {}".format(dut_port, ptf_src_ports))

    neighbor_ip = None
    # get neighbor IP
    lines = duthost.command("show ipv6 bgp sum")['stdout'].split("\n")
    for line in lines:
        if neighbor in line:
            neighbor_ip = line.split()[0]
    assert neighbor_ip, "Unable to find neighbor {} IP".format(neighbor)

    # use DUT portchannel if applicable
    pc_info = duthost.command("show int portchannel")['stdout']
    if dut_port in pc_info:
        lines = pc_info.split("\n")
        for line in lines:
            if dut_port in line:
                dut_port = line.split()[1]
                logger.info("Using portchannel interface: {}".format(dut_port))
                break

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    random.seed(time.time())
    # add the static route for IPv6 forwarding towards PTF's uSID and the blackhole route in a random order
    if random.randint(0, 1) == 0:
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                        .format(neighbor_ip, dut_port))
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
    else:
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                        .format(neighbor_ip, dut_port))
    duthost.command("config save -y")
    # Verify that the ASIC DB has the SRv6 SID entries
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB"

    setup_info = {
        "asic_index": asic_index,
        "duthost": duthost,
        "dut_mac": dut_mac,
        "dut_port": dut_port,
        "ptf_src_ports": ptf_src_ports,
        "neighbor_ip": neighbor_ip,
        "cli_options": cli_options,
        "ptf_port_ids": ptf_port_ids
    }

    yield setup_info

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb::/32")
    duthost.command("config save -y")


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

    parser.addoption(
        "--srv6_warmboot_send_interval",
        action="store",
        type=float,
        default=0.01,
        help="Interval in seconds between two SRv6 packets sent during the warm reboot test. "
             "It drives the resolution of the disruption measurement, default: 0.01 (100 pps)"
    )

    parser.addoption(
        "--srv6_warmboot_max_duration",
        action="store",
        type=int,
        default=1200,
        help="Upper bound, in seconds, of the traffic sending phase of the warm reboot test"
    )

    parser.addoption(
        "--srv6_warmboot_settle_time",
        action="store",
        type=int,
        default=60,
        help="Time, in seconds, during which the traffic keeps running after the warm boot "
             "finalizer completed. The SRv6 SID entries are reconciled after the device is "
             "reachable again, so the traffic has to cover that window too"
    )

    parser.addoption(
        "--srv6_warmboot_allowed_disruption",
        action="store",
        type=float,
        default=0.0,
        help="Data plane disruption, in seconds, tolerated over a warm reboot. It defaults to 0 "
             "because a warm reboot is expected to be hitless, which is also the limit used by "
             "the advanced reboot test"
    )

    parser.addoption(
        "--srv6_warmboot_allowed_duplication",
        action="store",
        type=int,
        default=0,
        help="Number of duplicated packets tolerated over a warm reboot"
    )


def pytest_generate_tests(metafunc):
    if "srv6_packet_type" in metafunc.fixturenames:
        params = metafunc.config.getoption('--srv6_packet_type').split(',')
        metafunc.parametrize("srv6_packet_type", [param.strip() for param in params], scope="class")


@pytest.fixture(scope="class")
def srv6_packet_type(request):
    return request.param
