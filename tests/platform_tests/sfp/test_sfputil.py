"""
Check SFP status and configure SFP using sfputil.

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/sonic-net/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import time
import copy
from natsort import natsorted
import pytest

from .util import parse_eeprom
from .util import parse_output
from .util import get_dev_conn
from tests.common.utilities import skip_release, wait_until
from tests.common.fixtures.duthost_utils import shutdown_ebgp   # noqa F401
from tests.common.port_toggle import default_port_toggle_wait_time
from tests.common.platform.interface_utils import get_physical_port_indices

cmd_sfp_presence = "sudo sfputil show presence"
cmd_sfp_eeprom = "sudo sfputil show eeprom"
cmd_sfp_reset = "sudo sfputil reset"
cmd_sfp_show_lpmode = "sudo sfputil show lpmode"
cmd_sfp_set_lpmode = "sudo sfputil lpmode"
cmd_config_intf_dom = "config interface {} transceiver dom {} {}"
cmd_config_intf_action = "config interface {} {} {}"
cmd_intf_startup = "startup"
cmd_intf_shutdown = "shutdown"
cmd_dom_disable = "disable"
cmd_dom_enable = "enable"

I2C_WAIT_TIME_AFTER_SFP_RESET = 5  # in seconds

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]


class LogicalInterfaceDisabler:
    """
    Disable the given logical interface and restore afterwards.
    """
    def __init__(self, duthost, enum_frontend_asic_index, logical_intf, phy_intf,
                 skip_dom_polling_handle=False, skip_lpmode_handle=False):
        self.duthost = duthost
        self.logical_intf = logical_intf
        self.phy_intf = phy_intf
        self.original_lpmode_state = None
        self.skip_dom_polling_handle = skip_dom_polling_handle
        self.skip_lpmode_handle = skip_lpmode_handle
        self.wait_after_dom_config = 5
        self.wait_after_lpmode_set = 3

        self.namespace_cmd_opt = get_namespace_cmd_option(duthost,
                                                          enum_frontend_asic_index)
        self.cmd_down = cmd_config_intf_action.format(self.namespace_cmd_opt,
                                                      cmd_intf_shutdown, logical_intf)
        self.cmd_up = cmd_config_intf_action.format(self.namespace_cmd_opt,
                                                    cmd_intf_startup, logical_intf)
        self.cmd_disable_dom = cmd_config_intf_dom.format(self.namespace_cmd_opt,
                                                          logical_intf, cmd_dom_disable)
        self.cmd_enable_dom = cmd_config_intf_dom.format(self.namespace_cmd_opt,
                                                         logical_intf, cmd_dom_enable)
        self.cmd_sfp_show_lpmode = "{} -p {}".format(cmd_sfp_show_lpmode, logical_intf)
        self.cmd_sfp_presence = "{} -p {}".format(cmd_sfp_presence, logical_intf)

    def disable(self):
        """
        Disable a logical interface by doing below:
            * Disable DOM polling
            * Shutdown port
            * Check and save lpmode
        """
        if not self.skip_dom_polling_handle:
            logging.info("Disable DOM polling to avoid race condition during sfp reset"
                         " for {}".format(self.logical_intf))
            disable_dom_result = self.duthost.command(self.cmd_disable_dom)
            assert disable_dom_result["rc"] == 0, \
                "Disable DOM polling failed for {}".format(self.logical_intf)
            time.sleep(self.wait_after_dom_config)

        # It's needed to shutdown ports before reset and startup ports after reset,
        # to get config/state machine/etc replayed, so that the modules can be fully
        # restored.
        logging.info("Shutdown {} before sfp reset".format(self.logical_intf))
        shutdown_result = self.duthost.command(self.cmd_down)
        assert shutdown_result["rc"] == 0, "Shutdown {} failed".format(self.logical_intf)
        assert check_interface_status(self.duthost, [self.logical_intf], expect_up=False)

        if not self.skip_lpmode_handle:
            logging.info("Check output of '{}' before sfp reset".format(self.cmd_sfp_show_lpmode))
            lpmode_show = self.duthost.command(self.cmd_sfp_show_lpmode)
            self.original_lpmode_state = \
                parse_output(lpmode_show["stdout_lines"][2:])[self.logical_intf].lower()

    def restore(self):
        """
        Restore a logical interface from disabled state by doing below:
            * Check and restore lpmode if needed
            * Startup port
            * Enable DOM polling
        """
        if not self.skip_lpmode_handle:
            # Restore lpmode if needed, because sfp reset will reset lpmode to default
            logging.info("Check output of '{}' after sfp reset".format(self.cmd_sfp_show_lpmode))
            lpmode_show = self.duthost.command(self.cmd_sfp_show_lpmode)
            after_lpmode_state = \
                parse_output(lpmode_show["stdout_lines"][2:])[self.logical_intf].lower()
            if after_lpmode_state != self.original_lpmode_state:
                logging.info("Restoring {} physical interface {} to lpmode {}".format(
                    self.logical_intf, self.phy_intf, self.original_lpmode_state))
                cmd_sfp_set_lpmode_to_original = "{} {} {}".format(cmd_sfp_set_lpmode,
                                                                   self.original_lpmode_state,
                                                                   self.logical_intf)
                lpmode_set_result = self.duthost.command(cmd_sfp_set_lpmode_to_original)
                assert lpmode_set_result["rc"] == 0, \
                    "'{}' failed".format(cmd_sfp_set_lpmode_to_original)
                time.sleep(self.wait_after_lpmode_set)

        logging.info("Startup {} after sfp reset to restore module".format(self.logical_intf))
        startup_result = self.duthost.command(self.cmd_up)
        assert startup_result["rc"] == 0, "Startup {} failed".format(self.logical_intf)
        assert check_interface_status(self.duthost, [self.logical_intf], expect_up=True)

        if not self.skip_dom_polling_handle:
            logging.info("Restore DOM polling after sfp reset for {}".format(self.logical_intf))
            enable_dom_result = self.duthost.command(self.cmd_enable_dom)
            assert enable_dom_result["rc"] == 0, "Enable DOM polling failed for {}".format(self.logical_intf)


class DisablePhysicalInterface:
    """
    Context manager to disable the given physical interface (as wells as its
    logical interfaces if needed) and restore afterwards.

    Disable/enable port includes:
        * Disable/enable DOM polling
        * Shutdown/startup port
        * Check/restore lpmode
    """
    def __init__(self, duthost, enum_frontend_asic_index, phy_intf, logical_intfs_list):
        self.duthost = duthost
        self.phy_intf = phy_intf
        self.original_lpmode_state = None
        self.wait_after_dom_config = 1
        self.wait_after_lpmode_set = 1
        self.logical_intfs_list = logical_intfs_list
        self.namespace_cmd_opt = get_namespace_cmd_option(duthost,
                                                          enum_frontend_asic_index)
        self.skip_lpmode_handle_global = self.skip_lpmode_handle_for_physical_interface()
        self.logical_intf_disablers = \
            [LogicalInterfaceDisabler(duthost=duthost,
                                      enum_frontend_asic_index=enum_frontend_asic_index,
                                      logical_intf=logical_intf,
                                      phy_intf=phy_intf,
                                      skip_dom_polling_handle=(i != 0),
                                      skip_lpmode_handle=(self.skip_lpmode_handle_global or
                                                          i != 0))
             for i, logical_intf in enumerate(logical_intfs_list)]

    def skip_lpmode_handle_for_physical_interface(self):
        cmd = "sonic-db-cli {} STATE_DB HGETALL 'TRANSCEIVER_INFO|{}'".format(self.namespace_cmd_opt,
                                                                              self.logical_intfs_list[0])
        xcvr_info_output = self.duthost.command(cmd)["stdout"]
        is_cmis = "cmis_rev" in xcvr_info_output
        is_power_class_1 = "Power Class 1" in xcvr_info_output

        if is_cmis or is_power_class_1:
            logging.info("Skip lpmode handling for physical interface {} "
                         "as it's CMIS compliant({}) or Power Class 1({})".format(self.phy_intf,
                                                                                  is_cmis,
                                                                                  is_power_class_1))
            return True
        return False

    def __enter__(self):
        """
        Disable a physical port by doing below:
            * Disable DOM polling
            * Shutdown port
            * Check and save lpmode
        """
        for logical_intf_disabler in self.logical_intf_disablers:
            logical_intf_disabler.disable()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Restore a physical port from disabled state by doing below:
            * Check and restore lpmode if needed
            * Startup port
            * Enable DOM polling
        """
        for logical_intf_disabler in self.logical_intf_disablers:
            logical_intf_disabler.restore()


def check_interfaces_up(duthost, namespace, up_ports):
    logging.info("Checking interface status")
    intf_facts = duthost.interface_facts(namespace=namespace, up_ports=up_ports)["ansible_facts"]
    if len(intf_facts["ansible_interface_link_down_ports"]) == 0:
        return True
    else:
        logging.info("Some interfaces are down: {}".format(intf_facts["ansible_interface_link_down_ports"]))
        return False


def get_namespace_cmd_option(duthost, asic_index):
    """Get the namespace option used in the command"""
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    return "-n {}".format(namespace) if namespace else ""


def get_down_ports(duthost, ports):
    """Check and return the down ports among the given ports."""
    return duthost.show_interface(command="status", up_ports=ports)["ansible_facts"][
        "ansible_interface_link_down_ports"]


def is_interface_status_expected(duthost, ports, expect_up=True):
    """Check if the given ports are up or down as expected."""
    if expect_up:
        return len(get_down_ports(duthost, ports)) == 0
    else:
        return len(get_down_ports(duthost, ports)) == len(ports)


def check_interface_status(duthost, ports, expect_up=True, wait_time=None):
    """
    Check if the given ports are up or down as expected.

    Args:
        duthost: DUT host object
        ports: List of ports to check
        expect_up: True if the ports are expected to be up, False if down
        wait_time: Time to wait for the ports to come up or down
    """
    expect_status_str = "up" if expect_up else "down"
    err_msg = ""

    if wait_time is None:
        port_down_wait_time, port_up_wait_time = \
            default_port_toggle_wait_time(duthost, len(ports))
        if expect_up:
            wait_time = port_up_wait_time
        else:
            wait_time = port_down_wait_time

    logging.info("Wait for ports to come {}: {}".format(expect_status_str, ports))
    is_ok = wait_until(wait_time, 5, 0,
                       is_interface_status_expected,
                       duthost, ports, expect_up)

    if not is_ok:
        down_ports = get_down_ports(duthost, ports)
        if expect_up:
            problematic_ports = down_ports
        else:
            problematic_ports = set(ports) - down_ports

        err_msg = "Some ports did not come {} as expected: {}".format(
            expect_status_str, str(problematic_ports))
    return is_ok, err_msg


def get_phy_intfs_to_test_per_asic(duthost,
                                   conn_graph_facts,
                                   enum_frontend_asic_index,
                                   xcvr_skip_list):
    """
    Get the interfaces to test for given asic, excluding the skipped ones.

    return:
        dict of all physical interfaces to test (key: physical port number,
        value: list of logical interfaces under this physical port)
    """
    _, dev_conn = get_dev_conn(duthost,
                               conn_graph_facts,
                               enum_frontend_asic_index)
    physical_port_idx_map = get_physical_port_indices(duthost, logical_intfs=dev_conn)
    phy_intfs_to_test_per_asic = {}
    tmp_dict = {}

    for logical_intf in dev_conn:
        # Skip the interfaces in the skip list
        if logical_intf in xcvr_skip_list[ans_host.hostname]:
            continue
        physical_port_idx = physical_port_idx_map[logical_intf]
        tmp_dict.setdefault(physical_port_idx, []).append(logical_intf)
    # sort physical interfaces
    for phy_intf, logical_intfs_list in sorted(tmp_dict.items()):
        # sort logical interfaces within the same physical interface
        phy_intfs_to_test_per_asic[phy_intf] = natsorted(logical_intfs_list)
    logging.info("Interfaces to test for asic {}: {}".format(enum_frontend_asic_index,
                                                             phy_intfs_to_test_per_asic))
    return phy_intfs_to_test_per_asic


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
    sfp_presence = duthost.command(cmd_sfp_presence, module_ignore_errors=True)

    # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
    if duthost.facts["asic_type"] == "vs" and sfp_presence['rc'] == 2:
        return
    assert sfp_presence['rc'] == 0, "Run command '{}' failed".format(cmd_sfp_presence)

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
    sfp_eeprom = duthost.command(cmd_sfp_eeprom, module_ignore_errors=True)

    # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
    if duthost.facts["asic_type"] == "vs" and sfp_eeprom['rc'] == 2:
        return
    assert sfp_eeprom['rc'] == 0, "Run command '{}' failed".format(cmd_sfp_presence)

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
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    phy_intfs_to_test_per_asic = get_phy_intfs_to_test_per_asic(duthost,
                                                                conn_graph_facts,
                                                                enum_frontend_asic_index,
                                                                xcvr_skip_list)
    for phy_intf, logical_intfs_list in phy_intfs_to_test_per_asic.items():
        logical_intf = logical_intfs_list[0]
        with DisablePhysicalInterface(duthost, enum_frontend_asic_index, phy_intf, logical_intfs_list):
            cmd_sfp_presence_per_intf = cmd_sfp_presence + " -p {}".format(logical_intf)

            cmd_sfp_reset_intf = "{} {}".format(cmd_sfp_reset, logical_intf)
            logging.info("resetting {} physical interface {}".format(logical_intf, phy_intf))
            reset_result = duthost.command(cmd_sfp_reset_intf)
            assert reset_result["rc"] == 0, "'{}' failed".format(cmd_sfp_reset_intf)
            time.sleep(I2C_WAIT_TIME_AFTER_SFP_RESET)

            logging.info("Check sfp presence again after reset")
            sfp_presence = duthost.command(cmd_sfp_presence_per_intf, module_ignore_errors=True)

            # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
            if duthost.facts["asic_type"] == "vs" and sfp_presence['rc'] == 2:
                pass
            else:
                assert sfp_presence['rc'] == 0, \
                    "Run command '{}' failed".format(cmd_sfp_presence_per_intf)

            parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
            assert logical_intf in parsed_presence, \
                "Interface is not in output of '{}'".format(cmd_sfp_presence_per_intf)
            assert parsed_presence[logical_intf] == "Present", \
                "Interface presence is not 'Present' for {}".format(logical_intf)

    # Check interface status for all interfaces in the end just in case
    assert check_interface_status(duthost,
                                  [logical_intf
                                   for logical_intfs_list in phy_intfs_to_test_per_asic.values()
                                   for logical_intf in logical_intfs_list],
                                  expect_up=True)


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
    lpmode_show = duthost.command(cmd_sfp_show_lpmode, module_ignore_errors=True)

    # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
    if duthost.facts["asic_type"] == "vs" and lpmode_show['rc'] == 2:
        pass
    else:
        assert lpmode_show['rc'] == 0, "Run command '{}' failed".format(cmd_sfp_presence)

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
    all_intf_up = wait_until(100, 10, 0, check_interfaces_up, duthost, namespace, up_ports)
    if not all_intf_up:
        intf_facts = duthost.interface_facts(namespace=namespace, up_ports=up_ports)["ansible_facts"]
        assert all_intf_up, "Some interfaces are down: {}".format(intf_facts["ansible_interface_link_down_ports"])
