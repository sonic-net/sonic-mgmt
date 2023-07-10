import logging
import pytest

from ipaddress import ip_interface
from constants import ENI, VM_VNI, VNET1_VNI, VNET2_VNI, REMOTE_CA_IP, LOCAL_CA_IP, REMOTE_ENI_MAC,\
    LOCAL_ENI_MAC, REMOTE_CA_PREFIX, LOOPBACK_IP, DUT_MAC, LOCAL_PA_IP, LOCAL_PTF_INTF, LOCAL_PTF_MAC,\
    REMOTE_PA_IP, REMOTE_PTF_INTF, REMOTE_PTF_MAC, REMOTE_PA_PREFIX, VNET1_NAME, VNET2_NAME, ROUTING_ACTION, \
    ROUTING_ACTION_TYPE, LOOKUP_OVERLAY_IP
from dash_utils import render_template_to_host, apply_swssconfig_file
from gnmi_utils import generate_gnmi_cert, apply_gnmi_cert, recover_gnmi_cert, apply_gnmi_file

logger = logging.getLogger(__name__)

ENABLE_GNMI_API = False


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
    if request.param == "with-underlay-route":
        pytest.skip("Underlay route not supported yet")
    return request.param == "with-underlay-route"


@pytest.fixture(scope="function")
def dash_config_info(duthost, config_facts, minigraph_facts):
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
    }
    loopback_intf_ip = ip_interface(list(list(config_facts["LOOPBACK_INTERFACE"].values())[0].keys())[0])
    dash_info[LOOPBACK_IP] = str(loopback_intf_ip.ip)
    dash_info[DUT_MAC] = config_facts["DEVICE_METADATA"]["localhost"]["mac"]

    neigh_table = duthost.switch_arptable()['ansible_facts']['arptable']
    for neigh_ip, config in list(config_facts["BGP_NEIGHBOR"].items()):
        # Pick the first two BGP neighbor IPs since these should already be learned on the DUT
        if ip_interface(neigh_ip).version == 4:
            if LOCAL_PA_IP not in dash_info:
                dash_info[LOCAL_PA_IP] = neigh_ip
                intf, _ = get_intf_from_ip(config['local_addr'], config_facts)
                dash_info[LOCAL_PTF_INTF] = minigraph_facts["minigraph_ptf_indices"][intf]
                dash_info[LOCAL_PTF_MAC] = neigh_table["v4"][neigh_ip]["macaddress"]
            elif REMOTE_PA_IP not in dash_info:
                dash_info[REMOTE_PA_IP] = neigh_ip
                intf, intf_ip = get_intf_from_ip(config['local_addr'], config_facts)
                dash_info[REMOTE_PTF_INTF] = minigraph_facts["minigraph_ptf_indices"][intf]
                dash_info[REMOTE_PTF_MAC] = neigh_table["v4"][neigh_ip]["macaddress"]
                dash_info[REMOTE_PA_PREFIX] = str(intf_ip.network)
                break

    return dash_info


@pytest.fixture(scope="function")
def apply_config(duthost, localhost, skip_config, skip_cleanup):
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
        if ENABLE_GNMI_API is True:
            apply_gnmi_file(duthost, localhost, dest_path)
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
def dash_outbound_configs(dash_config_info, use_underlay_route, minigraph_facts):
    if use_underlay_route:
        dash_config_info[REMOTE_PA_IP] = u"30.30.30.30"
        dash_config_info[REMOTE_PA_PREFIX] = "30.30.30.30/32"
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
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost):
    if ENABLE_GNMI_API is False:
        yield
        return

    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell("docker exec gnmi rm /usr/local/yang-models/sonic-dash.yang", module_ignore_errors=True)
    generate_gnmi_cert(localhost, duthost)
    apply_gnmi_cert(duthost)
    yield
    recover_gnmi_cert(duthost)
