import pytest
import allure

from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from util import parse_sfp_eeprom_infos, check_sfp_eeprom_info, is_support_dom, get_pci_cr0_path

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

SHOW_EEPOMR_CMDS = ["show interface transceiver eeprom -d", "sudo sfputil show eeprom -d"]


@pytest.fixture(scope="module", autouse=True)
def sfp_test_intfs_to_dom_map(duthosts, rand_one_dut_hostname, conn_graph_facts, xcvr_skip_list): # noqa F811
    '''
    This fixture is to get map sfp test intfs to dom
    '''
    duthost = duthosts[rand_one_dut_hostname]

    ports_map = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']["PORT"]
    port_name_to_index_map = dict([(port, value["index"]) for port, value in ports_map.items()])

    sfp_test_intf_list = conn_graph_facts["device_conn"][duthost.hostname].keys()

    intf_with_dom_dict = {}
    sfp_test_intfs_to_dom_map_dict = {}
    pic_cr0_path = get_pci_cr0_path(duthost)
    for intf in sfp_test_intf_list:
        if intf not in xcvr_skip_list[duthost.hostname]:
            port_index = port_name_to_index_map[intf]
            if port_index in intf_with_dom_dict:
                inft_support_dom = intf_with_dom_dict[port_index]
            else:
                inft_support_dom = is_support_dom(duthost, port_index, pic_cr0_path)
                intf_with_dom_dict[port_index] = inft_support_dom
            sfp_test_intfs_to_dom_map_dict[intf] = inft_support_dom

    return sfp_test_intfs_to_dom_map_dict


@pytest.mark.parametrize("show_eeprom_cmd", SHOW_EEPOMR_CMDS)
def test_check_sfp_eeprom_with_option_dom(duthosts, rand_one_dut_hostname, show_eeprom_cmd, sfp_test_intfs_to_dom_map):
    """This test case is to check result of  transceiver eeprom with option -d is correct or not for every interface .
    It will do below checks for every available interface
        1. Check if all expected keys exist in the the result
        2. When cable support dom, check the corresponding keys related to monitor exist,
           and the the corresponding value has correct format
    """
    duthost = duthosts[rand_one_dut_hostname]

    with allure.step("Run: {} to get transceiver eeprom info".format(show_eeprom_cmd)):
        check_eeprom_dom_output = duthost.command(show_eeprom_cmd)
        assert check_eeprom_dom_output["rc"] == 0, "Failed to read eeprom info for all interfaces"
        sfp_info_dict = parse_sfp_eeprom_infos(check_eeprom_dom_output["stdout"])

    with allure.step("Check results for {}".format(show_eeprom_cmd)):
        for intf, inft_support_dom in sfp_test_intfs_to_dom_map.items():
            if intf in sfp_info_dict:
                with allure.step("Check {}".format(intf)):
                    if sfp_info_dict[intf] == "SFP EEPROM Not detected":
                        allure.step("{}: SFP EEPROM Not detected".format(intf))
                        continue
                    check_sfp_eeprom_info(duthost, sfp_info_dict[intf], inft_support_dom, show_eeprom_cmd)
