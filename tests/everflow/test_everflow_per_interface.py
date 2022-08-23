"""Test cases to support the Everflow Mirroring feature in SONiC."""
import logging
import time
import pytest

import ptf.testutils as testutils
import everflow_test_utilities as everflow_utils

from everflow_test_utilities import BaseEverflowTest
from everflow_test_utilities import TEMPLATE_DIR, EVERFLOW_RULE_CREATE_TEMPLATE, DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE
from tests.common.helpers.assertions import pytest_require, pytest_assert

from everflow_test_utilities import setup_info, EVERFLOW_DSCP_RULES       # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error

pytestmark = [
    pytest.mark.topology("any")
]

EVERFLOW_TABLE_NAME = {
    "ipv4": "EVERFLOW",
    "ipv6": "EVERFLOWV6"
}

EVERFLOW_SESSION_NAME = "everflow_session_per_interface"

logger = logging.getLogger(__file__)

@pytest.fixture(scope="module", autouse=True)
def skip_if_not_supported(tbinfo, rand_selected_dut, ip_ver):

    asic_type = rand_selected_dut.facts["asic_type"]
    unsupported_platforms = ["mellanox", "marvell", "cisco-8000"]
    # Skip ipv6 test on Mellanox platform
    is_mellanox_ipv4 = asic_type == 'mellanox' and ip_ver == 'ipv4'
    # Skip ipv6 test on cisco-8000 platform
    is_cisco_ipv4 = asic_type == 'cisco-8000' and ip_ver == 'ipv4'	
    pytest_require(asic_type not in unsupported_platforms or is_mellanox_ipv4 or is_cisco_ipv4, "Match 'IN_PORTS' is not supported on {} platform".format(asic_type))

def build_candidate_ports(duthost, tbinfo):
    """
    Build candidate ports for testing
    """
    candidate_ports = {}
    unselected_ports = {}
    if tbinfo['topo']['type'] == 't0':
        candidate_neigh_name = 'Server'
    else:
        candidate_neigh_name = 'T0'
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
        ptf_idx = mg_facts["minigraph_ptf_indices"][dut_port]
        if candidate_neigh_name in neigh['name'] and len(candidate_ports) < 4:
            candidate_ports.update({dut_port: ptf_idx})
        if len(unselected_ports) < 4 and dut_port not in candidate_ports:
            unselected_ports.update({dut_port: ptf_idx})
    
    logger.info("Candidate testing ports are {}".format(candidate_ports))
    return candidate_ports, unselected_ports
    

def build_acl_rule_vars(candidate_ports, ip_ver):
    """
    Build vars for generating ACL rule
    """
    config_vars = {}
    config_vars['acl_table_name'] = EVERFLOW_TABLE_NAME[ip_ver]
    config_vars['rules'] = [{'qualifiers': {'input_interface': ','.join(candidate_ports.keys())}}]
    return config_vars


@pytest.fixture(scope='module')
def apply_mirror_session(rand_selected_dut):
    mirror_session_info = BaseEverflowTest.mirror_session_info(EVERFLOW_SESSION_NAME, rand_selected_dut.facts["asic_type"])
    logger.info("Applying mirror session to DUT")
    BaseEverflowTest.apply_mirror_config(rand_selected_dut, mirror_session_info)
    time.sleep(10)
    single_asic_cmd = 'sonic-db-cli STATE_DB hget \"MIRROR_SESSION_TABLE|{}\" \"monitor_port\"'.format(EVERFLOW_SESSION_NAME)
    if rand_selected_dut.is_multi_asic:
        for front_ns in rand_selected_dut.get_frontend_asic_namespace_list():
            cmd = "{} -n {}".format(single_asic_cmd, front_ns)
            monitor_port = rand_selected_dut.shell(cmd=cmd)['stdout']
            pytest_assert(monitor_port != "", "Failed to retrieve monitor_port on multi-asic dut's frontend namespace: {}".format(front_ns))
    else:
        monitor_port = rand_selected_dut.shell(cmd=single_asic_cmd)['stdout']
        pytest_assert(monitor_port != "", "Failed to retrieve monitor_port")

    yield mirror_session_info, monitor_port

    logger.info("Removing mirror session from DUT")
    BaseEverflowTest.remove_mirror_config(rand_selected_dut, EVERFLOW_SESSION_NAME)

@pytest.fixture(scope='module', params=['ipv4', 'ipv6'])
def ip_ver(request):
    return request.param

@pytest.fixture(scope='module')
def apply_acl_rule(rand_selected_dut, tbinfo, apply_mirror_session, ip_ver):
    """
    Apply ACL rule for matching input_ports
    """
    # Check existence of EVERFLOW
    table_name = EVERFLOW_TABLE_NAME[ip_ver]
    output = rand_selected_dut.shell('show acl table {}'.format(table_name))['stdout_lines']
    # Skip if EVERFLOW table doesn't exist
    pytest_require(len(output) > 2, "Skip test since {} dosen't exist".format(table_name))
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    mirror_session_info, monitor_port = apply_mirror_session    
    # Build testing port list
    candidate_ports, unselected_ports = build_candidate_ports(rand_selected_dut, tbinfo)
    pytest_require(len(candidate_ports) >= 1, "Not sufficient ports for testing")

    # Copy and apply ACL rule
    config_vars = build_acl_rule_vars(candidate_ports, ip_ver)
    rand_selected_dut.host.options["variable_manager"].extra_vars.update(config_vars)
    rand_selected_dut.command("mkdir -p {}".format(DUT_RUN_DIR))
    rand_selected_dut.template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_RULE_CREATE_TEMPLATE),
                                dest=os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE))
    logger.info("Applying acl rule config to DUT")
    command = "acl-loader update full {} --table_name {} --session_name {}" \
                      .format(os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE), table_name, EVERFLOW_SESSION_NAME)
    rand_selected_dut.shell(cmd=command)
    ret = {
        "candidate_ports": candidate_ports,
        "unselected_ports": unselected_ports,
        "mirror_session_info": mirror_session_info,
        "monitor_port": {monitor_port: mg_facts["minigraph_ptf_indices"][monitor_port]}
    }
    
    yield ret

    logger.info("Removing acl rule config from DUT")
    BaseEverflowTest.remove_acl_rule_config(rand_selected_dut, table_name)


def generate_testing_packet(ptfadapter, duthost, mirror_session_info, router_mac):
    packet = testutils.simple_tcp_packet(
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            eth_dst=router_mac
        )
    setup = {}
    setup["router_mac"] = router_mac
    exp_packet = BaseEverflowTest.get_expected_mirror_packet(mirror_session_info, setup, duthost, packet, False)
    return packet, exp_packet


def get_uplink_ports(duthost, tbinfo):
    """The collector IP is a destination reachable by default. 
    So we need to collect the uplink ports to do a packet capture
    """
    uplink_ports = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if 't0' == tbinfo['topo']['type']:
        neigh_name = 'T1'
    else:
        neigh_name = 'T2'
    for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
        ptf_idx = mg_facts["minigraph_ptf_indices"][dut_port]
        if neigh_name in neigh['name']:
            uplink_ports.append(ptf_idx)
    return uplink_ports


def send_and_verify_packet(ptfadapter, packet, expected_packet, tx_port, rx_ports, exp_recv):
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=packet, port_id=tx_port)
    if exp_recv:
        testutils.verify_packet_any_port(ptfadapter, pkt=expected_packet, ports=rx_ports, timeout=5)
    else:
        testutils.verify_no_packet_any(ptfadapter, pkt=expected_packet, ports=rx_ports)


def test_everflow_per_interface(ptfadapter, rand_selected_dut, apply_acl_rule, tbinfo):
    """Verify packet ingress from candidate ports are captured by EVERFLOW, while packets
    ingress from unselected ports are not captured
    """
    everflow_config = apply_acl_rule
    packet, exp_packet = generate_testing_packet(ptfadapter, rand_selected_dut, everflow_config['mirror_session_info'], rand_selected_dut.facts["router_mac"])
    uplink_ports = get_uplink_ports(rand_selected_dut, tbinfo)
    # Verify that packet ingressed from INPUT_PORTS (candidate ports) are mirrored
    for port, ptf_idx in everflow_config['candidate_ports'].items():
        logger.info("Verifying packet ingress from {} is mirrored".format(port))
        send_and_verify_packet(ptfadapter, packet, exp_packet, ptf_idx, uplink_ports, True)
    
    # Verify that packet ingressed from unselected ports are not mirrored
    for port, ptf_idx in everflow_config['unselected_ports'].items():
        logger.info("Verifying packet ingress from {} is not mirrored".format(port))
        send_and_verify_packet(ptfadapter, packet, exp_packet, ptf_idx, uplink_ports, False)
   
   
