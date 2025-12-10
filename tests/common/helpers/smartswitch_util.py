import pytest
import logging
import json

logger = logging.getLogger(__name__)


def get_dpu_dataplane_port(duthost, dpu_index):
    platform = duthost.facts["platform"]
    platform_json = json.loads(duthost.shell(f"cat /usr/share/sonic/device/{platform}/platform.json")["stdout"])
    try:
        interface = list(platform_json["DPUS"][f"dpu{dpu_index}"]["interface"].keys())[0]
    except KeyError:
        if_dpu_index = 224 + dpu_index*8
        interface = f"Ethernet{if_dpu_index}"

    logger.info(f"DPU dataplane interface: {interface}")
    return interface


def get_data_port_on_dpu(npu_lldp_info, data_port_on_npu):
    for info in npu_lldp_info:
        if info['localport'] == data_port_on_npu:
            logger.info(f"Found data port on npu: {info['remoteportdescr']}")
            return info['remoteportdescr']
    logger.info(f"Failed to get data port on dpu for {data_port_on_npu}, so returning default port: Ethernet0")
    return 'Ethernet0'


@pytest.fixture(scope="session", autouse=True)
def correlate_dpu_info_with_dpuhost(dpuhosts, duthost):
    npu_ip_intf_facts = duthost.show_ip_interface()['ansible_facts']['ip_interfaces']
    npu_lldp_info = duthost.show_and_parse("show lldp table")
    for dpuhost in dpuhosts:
        dpu_ip_intf_facts = dpuhost.show_ip_interface()['ansible_facts']['ip_interfaces']
        dpuhost_ip = dpu_ip_intf_facts['eth0-midplane']['ipv4']
        dpuhost.dpu_index = int(dpuhost_ip.split(".")[-1]) - 1
        dpuhost.dpu_mgmt_ip = dpuhost_ip
        logger.info(f"dpuhost.dpu_mgmt_ip:{dpuhost.dpu_mgmt_ip}, dpu_index: {dpuhost.dpu_index}")

        data_port_on_npu = get_dpu_dataplane_port(duthost, dpuhost.dpu_index)
        data_port_on_dpu = get_data_port_on_dpu(npu_lldp_info, data_port_on_npu)
        dpuhost.npu_data_port_ip = npu_ip_intf_facts[data_port_on_npu]['ipv4'] if \
            data_port_on_npu in npu_ip_intf_facts else ''
        dpuhost.dpu_data_port_ip = dpu_ip_intf_facts[data_port_on_dpu]['ipv4'] if \
            data_port_on_dpu in dpu_ip_intf_facts else ''

        dpuhost.npu_dataplane_port = data_port_on_npu
        dpuhost.dpu_dataplane_port = data_port_on_dpu
        dpuhost.npu_dataplane_mac = duthost.get_dut_iface_mac(data_port_on_npu)
        dpuhost.dpu_dataplane_mac = dpuhost.get_dut_iface_mac(data_port_on_dpu)

        dpuhost.dataplane_mask_length = 31
        dpuhost.name = f"dpu{dpuhost.dpu_index}"
        logger.info(f"dpuhost.data_port_on_npu: {dpuhost.npu_dataplane_port}, "
                    f"dpuhost.npu_data_port_ip: {dpuhost.npu_data_port_ip}, "
                    f"dpuhost.npu_dataplane_mac: {dpuhost.npu_dataplane_mac}, "
                    f"dpuhost.data_port_on_dpu: {dpuhost.dpu_dataplane_port}, "
                    f"dpuhost.dpu_data_port_ip: {dpuhost.dpu_data_port_ip}, "
                    f"dpuhost.dpu_dataplane_mac: {dpuhost.dpu_dataplane_mac}")
