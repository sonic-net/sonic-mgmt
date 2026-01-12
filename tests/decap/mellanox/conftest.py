import pytest
import logging
import random
from tests.common.utilities import get_ipv4_loopback_ip
from tests.common.helpers.ptf_tests_helper import get_stream_ptf_ports
from tests.common.helpers.ptf_tests_helper import select_random_link
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links  # noqa F401

logger = logging.getLogger(__name__)

ECN_MODE_LIST = [(2, 3)]


@pytest.fixture(scope='module')
def prepare_param(rand_selected_dut, ptfadapter, downstream_links, upstream_links, request):  # noqa F811
    prepare_param = {}
    prepare_param['outer_dst_mac'] = rand_selected_dut.facts["router_mac"]
    prepare_param['outer_src_ip'] = '100.0.0.1'
    prepare_param['outer_dst_ip'] = get_ipv4_loopback_ip(rand_selected_dut)
    prepare_param['outer_ecn'], prepare_param['inner_ecn'] = random.choice(ECN_MODE_LIST)
    prepare_param['inner_src_ip'] = '1.1.1.1'
    prepare_param['inner_dst_ip'] = '2.2.2.2'
    prepare_param['from_list'] = request.config.getoption('base_image_list')
    prepare_param['to_list'] = request.config.getoption('target_image_list')
    prepare_param['restore_to_image'] = request.config.getoption('restore_to_image')

    downlink = select_random_link(downstream_links)
    uplink_ptf_ports = get_stream_ptf_ports(upstream_links)

    assert downlink, "No downlink found"
    assert uplink_ptf_ports, "No uplink found"
    assert prepare_param['outer_dst_mac'], "No router MAC found"

    prepare_param['ptf_downlink_port'] = downlink.get("ptf_port_id")
    prepare_param['ptf_uplink_ports'] = uplink_ptf_ports

    prepare_param['outer_src_mac'] = ptfadapter.dataplane.get_mac(0, prepare_param['ptf_downlink_port']).decode('utf-8')

    return prepare_param
