"""
Check SFP status and configure SFP using sfputil.

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/sonic-net/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import time
import copy

import pytest

from .util import parse_eeprom
from .util import parse_output
from .util import get_dev_conn
from tests.common.utilities import skip_release
from tests.common.fixtures.duthost_utils import shutdown_ebgp   # noqa F401
from .conftest import StopXcvrd
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.port_toggle import default_port_toggle_wait_time

cmd_sfp_presence = "sudo sfputil show presence"
cmd_sfp_eeprom = "sudo sfputil show eeprom"
cmd_sfp_reset = "sudo sfputil reset"
cmd_sfp_show_lpmode = "sudo sfputil show lpmode"
cmd_sfp_set_lpmode = "sudo sfputil lpmode"

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]


def test_check_sfputil_presence(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
    """
    @summary: Check SFP presence using 'sfputil show presence'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)

    logging.info("Check output of '{}'".format(cmd_sfp_presence))
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_presence, "Interface is not in output of '{}'".format(cmd_sfp_presence)
            assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"


@pytest.mark.parametrize("cmd_sfp_error_status",
                         ["sudo sfputil show error-status", "sudo sfputil show error-status --fetch-from-hardware"])
def test_check_sfputil_error_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                    enum_frontend_asic_index, conn_graph_facts, cmd_sfp_error_status, xcvr_skip_list):
    """
    @summary: Check SFP error status using 'sfputil show error-status'
              and 'sfputil show error-status --fetch-from-hardware'
              This feature is supported on 202106 and above

    @param: cmd_sfp_error_status: fixture representing the command used to test
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    skip_release(duthost, ["201811", "201911", "202012"])
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)

    logging.info("Check output of '{}'".format(cmd_sfp_error_status))
    sfp_error_status = duthost.command(cmd_sfp_error_status, module_ignore_errors=True)
    if "NOT implemented" in sfp_error_status['stdout']:
        pytest.skip("Skip test as error status isn't supported")
    parsed_presence = parse_output(sfp_error_status["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            if "Not supported" in sfp_error_status['stdout']:
                logger.warning("test_check_sfputil_error_status: Skipping transceiver {} as error status not "
                               "supported on this port)".format(intf))
                continue
            assert intf in parsed_presence, "Interface is not in output of '{}'".format(cmd_sfp_presence)
            assert parsed_presence[intf] == "OK", "Interface error status is not 'OK'"


def test_check_sfputil_eeprom(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
    """
    @summary: Check SFP presence using 'sfputil show presence'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)

    logging.info("Check output of '{}'".format(cmd_sfp_eeprom))
    sfp_eeprom = duthost.command(cmd_sfp_eeprom)
    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_eeprom, "Interface is not in output of 'sfputil show eeprom'"
            assert parsed_eeprom[intf] == "SFP EEPROM detected"


def test_check_sfputil_reset(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                             enum_frontend_asic_index, conn_graph_facts,
                             tbinfo, xcvr_skip_list, shutdown_ebgp):    # noqa F811
    """
    @summary: Check SFP reset using 'sfputil reset'
    """
    def __get_down_ports(expect_up=True):
        """Check and return the down ports"""
        ports_down = duthost.interface_facts(up_ports=ports)["ansible_facts"][
            "ansible_interface_link_down_ports"]
        db_ports_down = duthost.show_interface(command="status", up_ports=ports)["ansible_facts"][
            "ansible_interface_link_down_ports"]
        if expect_up:
            return set(ports_down) | set(db_ports_down)
        else:
            return set(ports_down) & set(db_ports_down)

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)
    tested_physical_ports = set()
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ports = mg_facts["minigraph_ports"]
    stop_xcvrd = StopXcvrd(duthost)
    port_down_wait_time, port_up_wait_time = default_port_toggle_wait_time(duthost, len(ports))
    wait_after_restore_lpmode = 10
    wait_after_restore_xcvrd = 15
    wait_after_ports_up = 60

    # Form cmds to shutdown and startup ports
    cmds_down = []
    cmds_up = []
    for port in ports:
        namespace = '-n {}'.format(mg_facts["minigraph_neighbors"][port]['namespace']) \
            if mg_facts["minigraph_neighbors"][port]['namespace'] else ''
        cmds_down.append("config interface {} shutdown {}".format(namespace, port))
        cmds_up.append("config interface {} startup {}".format(namespace, port))

    # It's needed to shutdown ports before reset and startup ports after reset,
    # to get config/state machine/etc replayed, so that the modules can be fully
    # restored.
    logging.info("Shutdown ports before sfp reset")
    shutdown_ok = False
    shutdown_err_msg = ""
    try:
        duthost.shell_cmds(cmds=cmds_down)

        logging.info("Wait for ports to go down")
        shutdown_ok = wait_until(port_down_wait_time, 5, 0,
                                 lambda: len(__get_down_ports(expect_up=False)) == len(ports))

        if not shutdown_ok:
            up_ports = __get_down_ports(expect_up=True)
            shutdown_err_msg = "Some ports did not go down as expected: {}".format(str(up_ports))
    except Exception as e:
        shutdown_err_msg = "Shutdown ports failed with exception: {}".format(repr(e))
    pytest_assert(shutdown_ok, shutdown_err_msg)

    logging.info("Check output of '{}' before sfp reset".format(cmd_sfp_show_lpmode))
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    original_lpmode = parse_output(lpmode_show["stdout_lines"][2:])

    # Stop xcvrd to avoid race condition with eeprom polling thread in xcvrd
    logging.info("Stop xcvrd before sfp reset")
    stop_xcvrd.setup()
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            phy_intf = portmap[intf][0]
            if phy_intf in tested_physical_ports:
                logging.info(
                    "skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
                continue
            tested_physical_ports.add(phy_intf)
            logging.info("resetting {} physical interface {}".format(intf, phy_intf))
            reset_result = duthost.command("{} {}".format(cmd_sfp_reset, intf))
            assert reset_result["rc"] == 0, "'{} {}' failed".format(cmd_sfp_reset, intf)
            time.sleep(5)
    sleep_time = 60
    if duthost.shell("show interfaces transceiver eeprom | grep 400ZR", module_ignore_errors=True)['rc'] == 0:
        sleep_time = 90

    logging.info("Wait some time for SFP to fully recover after reset")
    time.sleep(sleep_time)

    logging.info("Check sfp presence again after reset")
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_presence, "Interface is not in output of '{}'".format(cmd_sfp_presence)
            assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    # Restore lpmode if needed, because sfp reset will reset lpmode to default
    logging.info("Check output of '{}' after sfp reset".format(cmd_sfp_show_lpmode))
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    after_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    physical_ports_restored_lpmode = set()
    for intf, after_lpmode_state in after_lpmode.items():
        physical_port = portmap[intf][0]
        after_lpmode_state = after_lpmode_state.lower()
        original_lpmode_state = original_lpmode[intf].lower()
        if physical_port not in tested_physical_ports \
            or physical_port in physical_ports_restored_lpmode:
            continue
        if after_lpmode_state == original_lpmode_state:
            continue
        logging.info("Restoring {} physical interface {} to lpmode {}".format(
            intf, physical_port, original_lpmode_state))
        lpmode_set_result = duthost.command("{} {} {}".format(cmd_sfp_set_lpmode, original_lpmode_state, intf))
        assert lpmode_set_result["rc"] == 0, "'{} {} {}' failed".format(cmd_sfp_set_lpmode, original_lpmode_state, intf)
        physical_ports_restored_lpmode.add(physical_port)
    if physical_ports_restored_lpmode:
        time.sleep(wait_after_restore_lpmode)
    else:
        logging.info("No physical ports to restore lpmode")

    # Restore xcvrd
    logging.info("Start xcvrd after sfp reset")
    stop_xcvrd.teardown()
    logging.info("Wait some time for xcvrd to fully recover after restart")
    time.sleep(wait_after_restore_xcvrd)

    logging.info("Startup ports after sfp reset to restore modules")
    startup_ok = False
    startup_err_msg = ""
    try:
        duthost.shell_cmds(cmds=cmds_up)

        logging.info("Wait for ports to come up")
        startup_ok = wait_until(port_up_wait_time, 5, 0, lambda: len(__get_down_ports()) == 0)

        if not startup_ok:
            down_ports = __get_down_ports()
            startup_err_msg = "Some ports did not come up as expected: {}".format(str(down_ports))
    except Exception as e:
        startup_err_msg = "Startup ports failed with exception: {}".format(repr(e))
    pytest_assert(startup_ok, startup_err_msg)

    logging.info("Wait %d seconds for system to stabilize", wait_after_ports_up)
    time.sleep(wait_after_ports_up)


def test_check_sfputil_low_power_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                      enum_frontend_asic_index, conn_graph_facts,
                                      tbinfo, xcvr_skip_list, shutdown_ebgp):   # noqa F811
    """
    @summary: Check SFP low power mode

    This case is to use the sfputil tool command to check and set SFP low power mode
    * sfputil show lpmode
    * sfputil lpmode off
    * sfputil lpmode on
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)

    # Get the interface pertaining to that asic
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)
    global ans_host
    ans_host = duthost
    logging.info("Check output of '{}'".format(cmd_sfp_show_lpmode))
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    original_lpmode = copy.deepcopy(parsed_lpmode)
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_lpmode, "Interface is not in output of '{}'".format(cmd_sfp_show_lpmode)
            assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Try to change SFP lpmode")
    tested_physical_ports = set()

    not_supporting_lpm_physical_ports = set()
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            phy_intf = portmap[intf][0]
            if phy_intf in tested_physical_ports:
                logging.info(
                    "skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
                continue

            sfp_type_cmd = 'redis-cli -n 6 hget "TRANSCEIVER_INFO|{}" type'.format(intf)
            sfp_type_docker_cmd = asichost.get_docker_cmd(sfp_type_cmd, "database")
            sfp_type = duthost.command(sfp_type_docker_cmd)["stdout"]

            power_class_cmd = 'redis-cli -n 6 hget "TRANSCEIVER_INFO|{}" ext_identifier'.format(intf)
            power_class_docker_cmd = asichost.get_docker_cmd(power_class_cmd, "database")
            power_class = duthost.command(power_class_docker_cmd)["stdout"]

            if ("QSFP" not in sfp_type and "OSFP" not in sfp_type) or "Power Class 1" in power_class:
                logging.info("skip testing port {} which doesn't support LPM".format(intf))
                not_supporting_lpm_physical_ports.add(phy_intf)
                continue
            tested_physical_ports.add(phy_intf)
            logging.info("setting {} physical interface {}".format(intf, phy_intf))
            new_lpmode = "off" if original_lpmode[intf].lower() == "on" else "on"
            lpmode_set_result = duthost.command("{} {} {}".format(cmd_sfp_set_lpmode, new_lpmode, intf))
            assert lpmode_set_result["rc"] == 0, "'{} {} {}' failed".format(cmd_sfp_set_lpmode, new_lpmode, intf)
    time.sleep(10)

    if len(tested_physical_ports) == 0:
        pytest.skip("None of the ports supporting LPM, skip the test")

    logging.info("Check SFP lower power mode again after changing SFP lpmode")
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname] and portmap[intf][0] not in not_supporting_lpm_physical_ports:
            assert intf in parsed_lpmode, "Interface is not in output of '{}'".format(cmd_sfp_show_lpmode)
            expected_lpmode = "off" if original_lpmode[intf].lower() == "on" else "on"
            assert parsed_lpmode[intf].lower() == expected_lpmode, \
                "Unexpected SFP lpmode, actual:{}, expected:{}".format(parsed_lpmode[intf].lower(), expected_lpmode)

    logging.info("Try to change SFP lpmode")
    tested_physical_ports = set()
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            phy_intf = portmap[intf][0]
            if phy_intf in not_supporting_lpm_physical_ports:
                logging.info("skip testing port {} which doesn't support LPM".format(intf))
                continue
            if phy_intf in tested_physical_ports:
                logging.info(
                    "skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
                continue
            tested_physical_ports.add(phy_intf)
            logging.info("restoring {} physical interface {}".format(intf, phy_intf))
            new_lpmode = original_lpmode[intf].lower()
            lpmode_set_result = duthost.command("{} {} {}".format(cmd_sfp_set_lpmode, new_lpmode, intf))
            assert lpmode_set_result["rc"] == 0, "'{} {} {}' failed".format(cmd_sfp_set_lpmode, new_lpmode, intf)
    time.sleep(10)

    logging.info("Check SFP lower power mode again after changing SFP lpmode")
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_lpmode, "Interface is not in output of '{}'".format(cmd_sfp_show_lpmode)
            assert parsed_lpmode[intf].lower() == original_lpmode[intf].lower(), \
                "Unexpected SFP lpmode. actual:{}, expected:{}".format(
                    parsed_lpmode[intf].lower(), original_lpmode[intf].lower())

    logging.info("Check sfp presence again after setting lpmode")
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_presence, "Interface is not in output of '{}'".format(cmd_sfp_presence)
            assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check interface status")
    cmd = "show interfaces transceiver eeprom {} | grep 400ZR".format(asichost.cli_ns_option)
    if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
        logging.info("sleeping for 60 seconds for ZR optics to come up")
        time.sleep(60)

    namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    # TODO Remove this logic when minigraph facts supports namespace in multi_asic
    up_ports = mg_facts["minigraph_ports"]
    if enum_frontend_asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        up_ports = {k: v for k, v in list(portmap.items()) if k in mg_facts["minigraph_ports"]}
    intf_facts = duthost.interface_facts(namespace=namespace, up_ports=up_ports)["ansible_facts"]
    assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
        "Some interfaces are down: {}".format(intf_facts["ansible_interface_link_down_ports"])
