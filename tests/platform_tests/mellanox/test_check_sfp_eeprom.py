import pytest
import allure

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
from .util import check_sfp_eeprom_info
from tests.common.platform.transceiver_utils import parse_sfp_eeprom_infos
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import check_pmon_uptime_minutes
from tests.platform_tests.mellanox.conftest import CPO_PORT_TYPE
import logging

pytestmark = [
    pytest.mark.asic('mellanox', 'nvidia-bluefield'),
    pytest.mark.topology('any')
]

SHOW_EEPOMR_CMDS = ["show interface transceiver eeprom -d",
                    "sudo sfputil show eeprom -d"]
SHOW_INTF_STATUS_CMDS = "show interface status"
REDIS_CLI_TRANSCEIVER_TYPE = 'sonic-db-cli STATE_DB hget "TRANSCEIVER_INFO|{}" "type"'


@pytest.fixture(scope="module", autouse=True)
def sfp_test_intfs_to_dom_map(duthosts, rand_one_dut_hostname, conn_graph_facts, xcvr_skip_list,  # noqa: F811
                              get_sw_control_ports, port_list_with_flat_memory):  # noqa: F811
    '''
    This fixture is to get map sfp test intfs to dom
    '''
    duthost = duthosts[rand_one_dut_hostname]

    sfp_test_intf_list = list(
        conn_graph_facts["device_conn"][duthost.hostname].keys())

    if get_sw_control_ports:
        # Exclude get_sw_control_ports from sfp_test_intf_list
        sfp_test_intf_list = [port for port in sfp_test_intf_list if port not in get_sw_control_ports]

    sfp_test_intfs_to_dom_map_dict = {}

    for intf in sfp_test_intf_list:
        if intf not in xcvr_skip_list[duthost.hostname]:
            inft_support_dom = False if intf in port_list_with_flat_memory[duthost.hostname] else True
            sfp_test_intfs_to_dom_map_dict[intf] = inft_support_dom
    logging.info(f"sfp_test_intfs_to_dom_map_dict: {sfp_test_intfs_to_dom_map_dict}")
    return sfp_test_intfs_to_dom_map_dict


@pytest.mark.parametrize("show_eeprom_cmd", SHOW_EEPOMR_CMDS)
def test_check_sfp_eeprom_with_option_dom(duthosts, rand_one_dut_hostname, show_eeprom_cmd, sfp_test_intfs_to_dom_map,
                                          port_list_with_flat_memory, is_cpo_supported):
    """This test case is to check result of  transceiver eeprom with option -d is correct or not for every interface .
    It will do below checks for every available interface
        1. Check if all expected keys exist in the result
        2. When cable support dom, check the corresponding keys related to monitor exist,
           and the the corresponding value has correct format
    """
    duthost = duthosts[rand_one_dut_hostname]

    pytest_assert(wait_until(360, 10, 0, check_pmon_uptime_minutes, duthost),
                  "Pmon docker is not ready for test")

    with allure.step("Run: {} to get transceiver eeprom info".format(show_eeprom_cmd)):
        check_eeprom_dom_output = duthost.command(show_eeprom_cmd)
        sfp_info_dict = parse_sfp_eeprom_infos(
            check_eeprom_dom_output["stdout"])
        assert sfp_info_dict, "No SFP EEPROM info found"

    with allure.step("Check results for {}".format(show_eeprom_cmd)):
        if is_cpo_supported:
            with allure.step("Run: {} to get interface status".format(SHOW_INTF_STATUS_CMDS)):
                intf_status = duthost.show_and_parse(SHOW_INTF_STATUS_CMDS)
                assert intf_status["rc"] == 0, "Failed to read interface status"
                intf_status_dict = {row["interface"]: row for row in intf_status}

        for intf, inft_support_dom in list(sfp_test_intfs_to_dom_map.items()):
            if intf in sfp_info_dict:
                with allure.step("Check {}".format(intf)):
                    if sfp_info_dict[intf] == "SFP EEPROM Not detected":
                        allure.step("{}: SFP EEPROM Not detected".format(intf))
                        continue
                    is_flat_memory = True if intf in port_list_with_flat_memory[duthost.hostname] else False
                    check_sfp_eeprom_info(
                        duthost, sfp_info_dict[intf], inft_support_dom, show_eeprom_cmd, is_flat_memory)

                if is_cpo_supported:
                    with allure.step("Check {} identifier type".format(intf)):
                        cmd = f'sonic-db-cli STATE_DB hget "TRANSCEIVER_INFO|{intf}" "type"'.format(intf)
                        transceiver_type = duthost.command(cmd)["stdout"]
                        assert transceiver_type == CPO_PORT_TYPE, f"Transceiver type in state DBis not {CPO_PORT_TYPE}"
                        assert intf_status_dict[intf]["type"] == CPO_PORT_TYPE, \
                            f"Interface type in show interface status is not {CPO_PORT_TYPE}"
                        assert sfp_info_dict[intf]["Identifier"] == CPO_PORT_TYPE, \
                            f"Identifier type in sfp eeprom is not {CPO_PORT_TYPE}"
