import logging

import pytest

from ipaddress import ip_interface 
from constants import *
from dash_utils import render_template_to_host, apply_swssconfig_file


logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Adds pytest options that are used by DASH tests
    """

    parser.addoption(
        "--skip_config",
        action="store_true",
        help="Apply new configurations on DUT"
    )

    parser.addoption(
        "--config_only",
        action="store_true",
        help="Apply new configurations on DUT"
    )

@pytest.fixture(scope="module")
def config_only(request):
    return request.config.getoption("--config_only")

@pytest.fixture(scope="module")
def skip_config(request):
    return request.config.getoption("--skip_config")

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


@pytest.fixture(scope="module")
def dash_config_info(duthost, config_facts, minigraph_facts):
    dash_info = {
        ENI: "F4939FEFC47E",
        VM_VNI: 4321,
        VNET1_VNI: 1000,
        VNET2_VNI: 2000,
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
        # Pick the first two BGP neighbor IPs since these should already be
        # learned on the DUT
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

    logger.info("Testing with config {}".format(dash_info))
    return dash_info


@pytest.fixture(scope="module")
def apply_vnet_configs(skip_config, duthost, dash_config_info):
    # TODO: Combine dash_acl_allow_all and dash_bind_acl into a single template once empty group binding issue is fixed/clarified
    config_list = ["dash_basic_config", "dash_acl_allow_all", "dash_bind_acl"]
    if skip_config:
        return

    for config in config_list:
        template_name = "{}.j2".format(config)
        dest_path = "/tmp/{}.json".format(config)
        render_template_to_host(template_name, duthost, dest_path, dash_config_info, op="SET")
        apply_swssconfig_file(duthost, dest_path)
