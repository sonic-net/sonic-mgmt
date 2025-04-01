import pytest
from tests.common.helpers.ptf_tests_helper import get_stream_ptf_ports
from tests.common.helpers.ptf_tests_helper import select_random_link
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links  # noqa F401
from tests.srv6.srv6_utils import SRv6Packets, create_srv6_locator, del_srv6_locator, create_srv6_sid, del_srv6_sid, \
    MyLocators, MySIDs


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


@pytest.fixture(params=MySIDs.TUNNEL_MODE)
def config_setup(request, rand_selected_dut):
    '''
    Configure 10 instances of SRV6_MY_SIDS
    '''
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
    rand_selected_dut.shell('sudo config save -y')

    yield dscp_mode

    for locator_param in MyLocators.my_locator_list:
        locator_name = locator_param[0]
        del_srv6_locator(rand_selected_dut, locator_name)

    for sid_param in MySIDs.MY_SID_LIST:
        locator_name = sid_param[0]
        ip_addr = sid_param[1]
        del_srv6_sid(rand_selected_dut, locator_name, ip_addr)
    rand_selected_dut.shell('sudo config save -y')
