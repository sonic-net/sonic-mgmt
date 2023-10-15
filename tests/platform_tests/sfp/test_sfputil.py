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
from tests.common.utilities import wait_until
from tests.common.mellanox_data import is_mellanox_device

cmd_sfp_presence = "sudo sfputil show presence"
cmd_sfp_eeprom = "sudo sfputil show eeprom"
cmd_sfp_reset = "sudo sfputil reset"
cmd_sfp_show_lpmode = "sudo sfputil show lpmode"
cmd_sfp_set_lpmode = "sudo sfputil lpmode"

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
    sfp_error_status = duthost.command(cmd_sfp_error_status)
    for line in sfp_error_status["stdout_lines"][2:]:
        if "Not implemented" in line:
            pytest.skip("Skip test as error status isn't supported")
    parsed_presence = parse_output(sfp_error_status["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
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
                             tbinfo, xcvr_skip_list, shutdown_ebgp, stop_xcvrd):    # noqa F811
    """
    @summary: Check SFP presence using 'sfputil show presence'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)
    tested_physical_ports = set()
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

    logging.info("Check interface status")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    intf_facts = duthost.interface_facts(up_ports=mg_facts["minigraph_ports"])["ansible_facts"]
    assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
        "Some interfaces are down: {}".format(intf_facts["ansible_interface_link_down_ports"])


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
    original_interface_status = duthost.get_interfaces_status()

    logging.info("Check the value of lpmode is correct for all interfaces not in xcvr_skip_list")
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_lpmode, "Interface is not in output of '{}'".format(cmd_sfp_show_lpmode)
            assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Get interfaces which support lpmode")
    tested_lpmode_ports, tested_lpmode_ports_with_admin_up = _get_support_ldpmode_physical_ports(
        duthost, xcvr_skip_list, asichost, dev_conn, portmap, original_interface_status)

    if len(tested_lpmode_ports) == 0:
        pytest.skip("None of the ports supporting LPM, skip the test")

    try:

        if is_mellanox_device(duthost) and len(tested_lpmode_ports_with_admin_up) > 0:
            logging.info("For ports with admin up, set lpmode to on, check ports are still up and lpmode is still off")
            shutdown_ports = list(tested_lpmode_ports_with_admin_up)
            _set_and_check_lpmode(duthost, portmap, tested_lpmode_ports_with_admin_up, original_lpmode,
                                  is_set_orignal_lpmode=False, is_check_orignal_mode=True)
            assert wait_until(60, 1, 0, duthost.links_status_up, shutdown_ports), \
                "ports {} are shutdown after setting lpmode to on".format(shutdown_ports)

            # for nvidia devices, need to shutdown the port before setting the port into lp mode
            logging.info("Shut down ports:{}".format(shutdown_ports))
            duthost.shutdown_multiple(shutdown_ports)
            assert wait_until(60, 1, 0, duthost.links_status_down, shutdown_ports), \
                "ports {} are not all down after shutting down ports".format(shutdown_ports)

        logging.info("Toggle the lpmode and check if the value is correct")
        _set_and_check_lpmode(duthost, portmap, tested_lpmode_ports, original_lpmode,
                              is_set_orignal_lpmode=False, is_check_orignal_mode=False)

        logging.info("Set original lpmode, and check if the value is correct")
        _set_and_check_lpmode(duthost, portmap, tested_lpmode_ports, original_lpmode,
                              is_set_orignal_lpmode=True, is_check_orignal_mode=True)

        logging.info("Check sfp presence again after setting lpmode")
        verify_interface_present(duthost, dev_conn, xcvr_skip_list)

        if is_mellanox_device(duthost) and len(tested_lpmode_ports_with_admin_up) > 0:
            logging.info("Check ports {}: are still down after change lpmode".format(shutdown_ports))
            assert wait_until(60, 1, 0, duthost.links_status_down, shutdown_ports), "ports {} are not all down".format(
                shutdown_ports)

            # for nvidia devices, need to restore the tested ports to up
            logging.info("Startup ports:{}".format(shutdown_ports))
            startup_tested_ports(duthost, shutdown_ports)

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
            # Check if the interfaces of this ASIC is present in conn_graph_facts
            up_ports = {k: v for k, v in list(portmap.items()) if k in mg_facts["minigraph_ports"]}
        intf_facts = duthost.interface_facts(namespace=namespace, up_ports=up_ports)["ansible_facts"]
        assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
            "Some interfaces are down: {}".format(intf_facts["ansible_interface_link_down_ports"])

    except Exception as err:
        raise AssertionError(err)

    finally:
        if is_mellanox_device(duthost) and len(tested_lpmode_ports_with_admin_up) > 0:
            # for nvidia device, need to check if the tested port is restored. If no, we need restore it
            logging.info("Check ports {}: are still down after change lpmode".format(shutdown_ports))
            if not duthost.links_status_up(shutdown_ports):
                logging.info("Recover shutdown ports:{}".format(shutdown_ports))
                startup_tested_ports(duthost, shutdown_ports)


def _get_support_ldpmode_physical_ports(
        duthost, xcvr_skip_list, asichost, dev_conn, portmap, original_interface_status):
    tested_lpmode_physical_ports = set()
    tested_lpmode_ports = set()
    tested_lpmode_ports_with_admin_up = set()
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            phy_intf = portmap[intf][0]
            if phy_intf in tested_lpmode_physical_ports:
                tested_lpmode_ports.add(intf)
                if intf in original_interface_status and original_interface_status[intf]["admin"].lower() == "up":
                    tested_lpmode_ports_with_admin_up.add(intf)
                logging.info(
                    "skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
                continue

            sfp_type_cmd = 'redis-cli -n 6 hget "TRANSCEIVER_INFO|{}" type'.format(intf)
            sfp_type_docker_cmd = asichost.get_docker_cmd(sfp_type_cmd, "database")
            sfp_type = duthost.command(sfp_type_docker_cmd)["stdout"]

            power_class_cmd = 'redis-cli -n 6 hget "TRANSCEIVER_INFO|{}" ext_identifier'.format(intf)
            power_class_docker_cmd = asichost.get_docker_cmd(power_class_cmd, "database")
            power_class = duthost.command(power_class_docker_cmd)["stdout"]

            if "QSFP" not in sfp_type or "Power Class 1" in power_class:
                logging.info("skip testing port {} which doesn't support LPM".format(intf))
                continue
            tested_lpmode_physical_ports.add(phy_intf)
            tested_lpmode_ports.add(intf)
            if intf in original_interface_status and original_interface_status[intf]["admin"].lower() == "up":
                tested_lpmode_ports_with_admin_up.add(intf)

    return tested_lpmode_ports, tested_lpmode_ports_with_admin_up


def _set_and_check_lpmode(
        duthost, portmap, tested_lpmode_ports, original_lpmode, is_set_orignal_lpmode, is_check_orignal_mode):
    logging.info("Try to change SFP lpmode")
    notice_msg = "Notice: please set port admin status to down before setting power mode"

    for intf in tested_lpmode_ports:
        phy_intf = portmap[intf][0]
        logging.info("setting {} physical interface {}".format(intf, phy_intf))
        if is_set_orignal_lpmode:
            new_lpmode = original_lpmode[intf].lower()
        else:
            new_lpmode = "off" if original_lpmode[intf].lower() == "on" else "on"

        lpmode_set_result = duthost.command("{} {} {}".format(cmd_sfp_set_lpmode, new_lpmode, intf))
        if is_mellanox_device(duthost):
            logging.info("Check return msg include some notice info")
            assert notice_msg in lpmode_set_result['stdout'], " Expected notice_msg:{}, actual msg: {} ".format(
                notice_msg, lpmode_set_result['stdout'])

        assert lpmode_set_result["rc"] == 0, "'{} {} {}' failed".format(cmd_sfp_set_lpmode, new_lpmode, intf)

    def check_lpmode():
        lpmode_show = duthost.command(cmd_sfp_show_lpmode)
        parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
        for intf in tested_lpmode_ports:
            assert intf in parsed_lpmode, "Interface is not in output of '{}'".format(cmd_sfp_show_lpmode)
            actual_lpmode = parsed_lpmode[intf].lower()
            if is_check_orignal_mode:
                expected_lpmode = original_lpmode[intf].lower()
            else:
                expected_lpmode = "off" if original_lpmode[intf].lower() == "on" else "on"
            assert actual_lpmode == expected_lpmode, "Unexpected SFP lpmode: actual:{}, expected:{}".format(
                actual_lpmode, expected_lpmode)
        return True

    logging.info("Check SFP lower power mode. set original lpmode:{}".format(is_set_orignal_lpmode))
    assert wait_until(10, 1, 0, check_lpmode), "lpmode is not the expected one"


def startup_tested_ports(duthost, tested_ports):
    duthost.no_shutdown_multiple(tested_ports)
    assert wait_until(120, 5, 0, duthost.links_status_up, tested_ports), "ports {} are not all up".format(
        tested_ports)


def verify_interface_present(duthost, dev_conn, xcvr_skip_list):
    def check_sfp_presence(duthost, dev_conn, xcvr_skip_list):
        logging.info("check sfp presence")
        sfp_presence = duthost.command(cmd_sfp_presence)
        parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
        for intf in dev_conn:
            if intf not in xcvr_skip_list[duthost.hostname]:
                assert intf in parsed_presence, "Interface {} is not in output of '{}'".format(intf, parsed_presence)
                assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"
        return True
    assert wait_until(60, 5, 0, check_sfp_presence, duthost, dev_conn, xcvr_skip_list), \
        "Some interfaces are not present"
