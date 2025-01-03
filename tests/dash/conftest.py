import logging
import pytest
import random
import json
import time

from ipaddress import ip_interface
from constants import ENI, VM_VNI, VNET1_VNI, VNET2_VNI, REMOTE_CA_IP, LOCAL_CA_IP, REMOTE_ENI_MAC,\
    LOCAL_ENI_MAC, REMOTE_CA_PREFIX, LOOPBACK_IP, DUT_MAC, LOCAL_PA_IP, LOCAL_PTF_INTF, LOCAL_PTF_MAC,\
    REMOTE_PA_IP, REMOTE_PTF_INTF, REMOTE_PTF_MAC, REMOTE_PA_PREFIX, VNET1_NAME, VNET2_NAME, ROUTING_ACTION, \
    ROUTING_ACTION_TYPE, LOOKUP_OVERLAY_IP, ACL_GROUP, ACL_STAGE
from dash_utils import render_template_to_host, apply_swssconfig_file
from gnmi_utils import generate_gnmi_cert, apply_gnmi_cert, recover_gnmi_cert, apply_gnmi_file
from dash_acl import AclGroup, DEFAULT_ACL_GROUP, WAIT_AFTER_CONFIG, DefaultAclRule

logger = logging.getLogger(__name__)

ENABLE_GNMI_API = True


def pytest_addoption(parser):
    """
    Adds pytest options that are used by DASH tests
    """

    parser.addoption(
        "--skip_config",
        action="store_true",
        help="Don't apply configurations on DUT"
    )

    parser.addoption(
        "--config_only",
        action="store_true",
        help="Apply new configurations on DUT without running tests"
    )

    parser.addoption(
        "--skip_cleanup",
        action="store_true",
        help="Skip config cleanup after test"
    )

    parser.addoption(
        "--skip_dataplane_checking",
        action="store_true",
        help="Skip dataplane checking"
    )

    parser.addoption(
        "--vxlan_udp_dport",
        action="store",
        default="random",
        help="The vxlan udp dst port used in the test"
    )

    parser.addoption(
        "--skip_cert_cleanup",
        action="store_true",
        help="Skip certificates cleanup after test"
    )


@pytest.fixture(scope="module")
def config_only(request):
    return request.config.getoption("--config_only")


@pytest.fixture(scope="module")
def skip_config(request):
    return request.config.getoption("--skip_config")


@pytest.fixture(scope="module")
def skip_cleanup(request):
    return request.config.getoption("--skip_cleanup")


@pytest.fixture(scope="module")
def skip_dataplane_checking(request):
    return request.config.getoption("--skip_dataplane_checking")


@pytest.fixture(scope="module")
def skip_cert_cleanup(request):
    return request.config.getoption("--skip_cert_cleanup")


@pytest.fixture(scope="module")
def config_facts(duthost):
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module")
def minigraph_facts(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Fixture to get minigraph facts

    Args:
        duthost: DUT host object

    Returns:
        Dictionary containing minigraph information
    """
    duthost = duthosts[rand_one_dut_hostname]

    return duthost.get_extended_minigraph_facts(tbinfo)


def get_intf_from_ip(local_ip, config_facts):
    for intf, config in list(config_facts["INTERFACE"].items()):
        for ip in config:
            intf_ip = ip_interface(ip)
            if str(intf_ip.ip) == local_ip:
                return intf, intf_ip


@pytest.fixture(params=["no-underlay-route", "with-underlay-route"])
def use_underlay_route(request):
    return request.param == "with-underlay-route"


@pytest.fixture(scope="function")
def dash_config_info(duthost, config_facts, minigraph_facts, tbinfo):
    dash_info = {
        ENI: "F4939FEFC47E",
        VM_VNI: 4321,
        VNET1_VNI: 1000,
        VNET1_NAME: "Vnet1",
        VNET2_VNI: 2000,
        VNET2_NAME: "Vnet2",
        REMOTE_CA_IP: "20.2.2.2",
        LOCAL_CA_IP: "11.1.1.1",
        REMOTE_ENI_MAC: "F9:22:83:99:22:A2",
        LOCAL_ENI_MAC: "F4:93:9F:EF:C4:7E",
        REMOTE_CA_PREFIX: "20.2.2.0/24",
        ACL_GROUP: "group1",
        ACL_STAGE: 5
    }
    loopback_intf_ip = ip_interface(list(list(config_facts["LOOPBACK_INTERFACE"].values())[0].keys())[0])
    dash_info[LOOPBACK_IP] = str(loopback_intf_ip.ip)
    dash_info[DUT_MAC] = config_facts["DEVICE_METADATA"]["localhost"]["mac"]

    neigh_table = duthost.switch_arptable()['ansible_facts']['arptable']
    topo = tbinfo["topo"]["name"]
    for neigh_ip, config in list(config_facts["BGP_NEIGHBOR"].items()):
        # For dpu with 2 ports Pick the first two BGP neighbor IPs since these should already be learned on the DUT
        # Take neighbor 1 as local PA, take neighbor 2 as remote PA
        if ip_interface(neigh_ip).version == 4:
            if LOCAL_PA_IP not in dash_info:
                dash_info[LOCAL_PA_IP] = neigh_ip
                intf, _ = get_intf_from_ip(config['local_addr'], config_facts)
                dash_info[LOCAL_PTF_INTF] = minigraph_facts["minigraph_ptf_indices"][intf]
                dash_info[LOCAL_PTF_MAC] = neigh_table["v4"][neigh_ip]["macaddress"]
                if topo == 'dpu-1' and REMOTE_PA_IP not in dash_info:
                    # For DPU with only one single port, we just have one neighbor (neighbor 1).
                    # So, we take neighbor 1 as the local PA. For the remote PA,
                    # we take the original neighbor 2's IP as the remote PA IP,
                    # and the original neighbor 2's network as the remote PA network.
                    # Take the mac of neighbor 1's mac as the mac of remote PA,
                    # because the BGP route to neighbor 1 is the default route,
                    # and only the mac of neighbor 1 exists in the arp table.
                    # The remote ptf intf will take the value of neighbor 1
                    # because the packet to remote PA will be forwarded to the ptf port corresponding to neighbor 1.
                    fake_neighbor_2_ip = '10.0.2.2'
                    fake_neighbor_2_prefix = "10.0.2.0/24"
                    dash_info[REMOTE_PA_IP] = fake_neighbor_2_ip
                    dash_info[REMOTE_PTF_INTF] = dash_info[LOCAL_PTF_INTF]
                    dash_info[REMOTE_PTF_MAC] = dash_info[LOCAL_PTF_MAC]
                    dash_info[REMOTE_PA_PREFIX] = fake_neighbor_2_prefix
                    break
            elif REMOTE_PA_IP not in dash_info:
                dash_info[REMOTE_PA_IP] = neigh_ip
                intf, intf_ip = get_intf_from_ip(config['local_addr'], config_facts)
                dash_info[REMOTE_PTF_INTF] = minigraph_facts["minigraph_ptf_indices"][intf]
                dash_info[REMOTE_PTF_MAC] = neigh_table["v4"][neigh_ip]["macaddress"]
                dash_info[REMOTE_PA_PREFIX] = str(intf_ip.network)
                break

    return dash_info


@pytest.fixture(scope="function")
def apply_config(localhost, duthost, ptfhost, skip_config, skip_cleanup):
    configs = []
    op = "SET"

    def _apply_config(config_info):
        if skip_config:
            return
        if config_info not in configs:
            configs.append(config_info)

        config = "dash_basic_config"
        template_name = "{}.j2".format(config)
        dest_path = "/tmp/{}.json".format(config)
        render_template_to_host(template_name, duthost, dest_path, config_info, op=op)
        if ENABLE_GNMI_API:
            apply_gnmi_file(localhost, duthost, ptfhost, dest_path)
        else:
            apply_swssconfig_file(duthost, dest_path)

    yield _apply_config

    op = "DEL"
    if not skip_cleanup:
        for config_info in reversed(configs):
            _apply_config(config_info)


@pytest.fixture(scope="function")
def dash_inbound_configs(dash_config_info, use_underlay_route, minigraph_facts):
    if use_underlay_route:
        dash_config_info[LOCAL_PA_IP] = u"30.30.30.30"
        dash_config_info[LOCAL_PTF_INTF] = list(minigraph_facts["minigraph_ptf_indices"].values())
    else:
        dash_config_info[LOCAL_PTF_INTF] = [dash_config_info[LOCAL_PTF_INTF]]

    logger.info("Testing with config {}".format(dash_config_info))
    return dash_config_info


@pytest.fixture(scope="function")
def apply_inbound_configs(dash_inbound_configs, apply_config):
    dash_inbound_configs[ROUTING_ACTION] = "vnet"
    apply_config(dash_inbound_configs)


@pytest.fixture(scope="function")
def dash_outbound_configs(dash_config_info, use_underlay_route, minigraph_facts, tbinfo):
    if use_underlay_route:
        dash_config_info[REMOTE_PA_IP] = u"30.30.30.30"
        dash_config_info[REMOTE_PA_PREFIX] = "30.30.30.30/32"
        if tbinfo["topo"]["name"] == "dpu-1":
            dash_config_info[REMOTE_PTF_INTF] = [dash_config_info[REMOTE_PTF_INTF]]
        else:
            dash_config_info[REMOTE_PTF_INTF] = list(minigraph_facts["minigraph_ptf_indices"].values())
    else:
        dash_config_info[REMOTE_PTF_INTF] = [dash_config_info[REMOTE_PTF_INTF]]

    logger.info("Testing with config {}".format(dash_config_info))
    return dash_config_info


@pytest.fixture(scope="function")
def apply_vnet_configs(dash_outbound_configs, apply_config):
    dash_outbound_configs[ROUTING_ACTION] = "vnet"
    apply_config(dash_outbound_configs)


@pytest.fixture(scope="function")
def apply_vnet_direct_configs(dash_outbound_configs, apply_config):
    dash_outbound_configs[ROUTING_ACTION] = "vnet_direct"
    dash_outbound_configs[ROUTING_ACTION_TYPE] = "maprouting"
    dash_outbound_configs[LOOKUP_OVERLAY_IP] = "1.1.1.1"

    apply_config(dash_outbound_configs)


@pytest.fixture(scope="function")
def apply_direct_configs(dash_outbound_configs, apply_config):
    dash_outbound_configs[ROUTING_ACTION] = "direct"
    del dash_outbound_configs[VNET2_NAME]

    apply_config(dash_outbound_configs)


@pytest.fixture(scope="module", autouse=True)
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost, ptfhost, skip_cert_cleanup):
    if not ENABLE_GNMI_API:
        yield
        return

    duthost = duthosts[rand_one_dut_hostname]
    generate_gnmi_cert(localhost, duthost)
    apply_gnmi_cert(duthost, ptfhost)
    yield
    recover_gnmi_cert(localhost, duthost, skip_cert_cleanup)


@pytest.fixture(scope="function")
def asic_db_checker(duthost):
    def _check_asic_db(tables):
        for table in tables:
            output = duthost.shell("sonic-db-cli ASIC_DB keys 'ASIC_STATE:{}:*'".format(table))
            assert output["stdout"].strip() != "", "No entries found in ASIC_DB table {}".format(table)
    yield _check_asic_db


@pytest.fixture(scope="function", params=['udp', 'tcp', 'echo_request', 'echo_reply'])
def inner_packet_type(request):
    return request.param


def config_vxlan_udp_dport(duthost, port):
    vxlan_port_config = [
        {
            "SWITCH_TABLE:switch": {"vxlan_port": f"{port}"},
            "OP": "SET"
        }
    ]
    config_path = "/tmp/vxlan_port_config.json"
    duthost.copy(content=json.dumps(vxlan_port_config, indent=4), dest=config_path, verbose=False)
    apply_swssconfig_file(duthost, config_path)


@pytest.fixture(scope="function")
def vxlan_udp_dport(request, duthost):
    """
    Test the traffic with specified or randomly generated VxLAN UDP dst port.
    Configuration is applied by swssconfig.
    """
    UDP_PORT_RANGE = range(0, 65536)
    WELL_KNOWN_UDP_PORT_RANGE = range(0, 1024)
    vxlan_udp_dport = request.config.getoption("--vxlan_udp_dport")
    if vxlan_udp_dport == "random":
        port_candidate_list = ["default", 4789, 13330, 1024, 65535]
        while True:
            random_port = random.choice(UDP_PORT_RANGE)
            if random_port not in WELL_KNOWN_UDP_PORT_RANGE and random_port not in port_candidate_list:
                port_candidate_list.append(random_port)
                break
        vxlan_udp_dport = random.choice(port_candidate_list)
    if vxlan_udp_dport != "default":
        logger.info(f"Configure the VXLAN UDP dst port {vxlan_udp_dport} to DPU")
        vxlan_udp_dport = int(vxlan_udp_dport)
        config_vxlan_udp_dport(duthost, vxlan_udp_dport)
    else:
        logger.info("Use the default VXLAN UDP dst port 4789")
        vxlan_udp_dport = 4789

    yield vxlan_udp_dport

    logger.info("Restore the VXLAN UDP dst port to 4789")
    config_vxlan_udp_dport(duthost, 4789)


@pytest.fixture(scope="function")
def acl_default_rule(localhost, duthost, ptfhost, dash_config_info):
    hwsku = duthost.facts['hwsku']
    hwsku_list_with_default_acl_action_deny = ['Nvidia-9009d3b600CVAA-C1', 'Nvidia-9009d3b600SVAA-C1']
    if hwsku in hwsku_list_with_default_acl_action_deny:
        default_acl_group = AclGroup(localhost, duthost, ptfhost, DEFAULT_ACL_GROUP, dash_config_info[ENI])
        default_acl_rule = DefaultAclRule(localhost, duthost, ptfhost, dash_config_info, "allow")

        default_acl_rule.config()
        default_acl_group.bind(1)
        time.sleep(WAIT_AFTER_CONFIG)

    yield

    if hwsku in hwsku_list_with_default_acl_action_deny:
        default_acl_group.unbind()
        default_acl_rule.teardown()
        del default_acl_group
        time.sleep(WAIT_AFTER_CONFIG)
