import logging
import pytest
import random
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_inventory_files, get_host_visible_vars
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from .util import get_field_range, get_fields, get_skip_mod_list, get_skip_logical_module_list

logger = logging.getLogger('__name__')

pytestmark = [
    pytest.mark.topology('t2')
]

CMD_SHOW_CHASSIS_MODULE = "show chassis modules"


@pytest.fixture(scope='module')
def dut_vars(duthosts, enum_rand_one_per_hwsku_hostname, request):
    inv_files = get_inventory_files(request)
    dut_vars = get_host_visible_vars(inv_files, enum_rand_one_per_hwsku_hostname)
    yield dut_vars


def parse_chassis_module(output, expected_headers):
    assert len(output) > 2, (
        "The output of the 'show chassis modules' command is too short ({} lines). "
    ).format(len(output))
    f_ranges = get_field_range(output[1])
    headers = get_fields(output[0], f_ranges)

    for header_v in expected_headers:
        pytest_assert(
            header_v in headers,
            (
                "header {} is not in headers {}"
            ).format(
                header_v, headers
            )
        )

    result = {}
    for a_line in output[2:]:
        field_val = get_fields(a_line, f_ranges)
        mod_idx = field_val[0]
        result[mod_idx] = {}
        cur_field = 1
        for a_header in headers[1:]:
            result[mod_idx][a_header] = field_val[cur_field]
            cur_field += 1

    return result


def test_show_chassis_module_status(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars):
    cmd = " ".join([CMD_SHOW_CHASSIS_MODULE, "status"])
    logger.info("verifying output of cli command {}".format(cmd))
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    exp_headers = ["Name", "Description", "Physical-Slot", "Oper-Status", "Admin-Status"]
    skip_mod_list = get_skip_mod_list(duthost)
    skip_logical_lc_list = get_skip_logical_module_list(duthost)
    """
    Gather expected module slot data from a inventory file if 'module_slot_info' is defined in the inventory
    # Sample inventory with module_slot_info:
    str-sonic-chassis-01-sup:
        ansible_host: 10.251.0.188
        model: SOME-VENDOR-MODEL
        serial: BADC0FFEE123
        base_mac: 38:8a:29:13:45:67
        module_slot_info:
            "FABRIC-CARD0": "1"
            "FABRIC-CARD3": "3"
            "FABRIC-CARD4": "4"
            "LINE-CARD1": "2"
            "LINE-CARD3": "4"
            "SUPERVISOR0": "Y"
    """
    exp_module_slot_info = {}
    if 'module_slot_info' in dut_vars:
        exp_module_slot_info = dut_vars['module_slot_info']

    output = duthost.command(cmd)
    res = parse_chassis_module(output['stdout_lines'], exp_headers)

    # by default will assume all modules should be shown online except in skip_module_list
    for mod_idx in list(res.keys()):
        if mod_idx in skip_mod_list:
            """
               In case the module is part of the skip logical LC which means LC may be physically
               connected while logically is not part of this logical chassis at which case we should
               not check any further and move on
            """
            if mod_idx in skip_logical_lc_list:
                continue
            else:
                pytest_assert(res[mod_idx]['Oper-Status'] == 'Empty',
                              "Oper-status for slot {} should be Empty but it is {}".format(
                                  mod_idx, res[mod_idx]['Oper-Status']))
        else:
            pytest_assert(res[mod_idx]['Oper-Status'] == 'Online',
                          "Oper-status for slot {} should be Online but it is {}".format(
                              mod_idx, res[mod_idx]['Oper-Status']))

            # If inventory contains physical slot info, perform expected slot number check
            if exp_module_slot_info:
                pytest_assert(mod_idx in exp_module_slot_info,
                              "Module {} is expected to be present but it is missing".format(
                                  mod_idx))

                pytest_assert(res[mod_idx]['Physical-Slot'] == exp_module_slot_info[mod_idx],
                              "Module {} expected slot {} not matching show output {}".format(
                                  mod_idx, exp_module_slot_info[mod_idx], res[mod_idx]['Physical-Slot']))
            else:
                # In case Inventory file does not have the slot info, just log it but no need to fail the test
                logger.info("Inventory file has no record of module_slot_info")


def test_show_chassis_module_midplane_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """
       @summary: Verify output of `show chassis-module midplane-status`
    """
    cmd = " ".join([CMD_SHOW_CHASSIS_MODULE, "midplane-status"])
    logger.info("verifying output of cli command {}".format(cmd))
    expected_headers = ["Name", "IP-Address", "Reachability"]

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.command(cmd)
    res_mid_status = parse_chassis_module(output['stdout_lines'], expected_headers)
    mod_key = ['line-cards', 'supervisor']
    skip_mod_list = get_skip_mod_list(duthost, mod_key)

    for mod_idx in res_mid_status:
        mod_mid_status = res_mid_status[mod_idx]['Reachability']
        if mod_idx not in skip_mod_list:
            pytest_assert(
                mod_mid_status == "True",
                (
                    "Midplane reachability of line card {} expected to be True but is {}."
                ).format(
                    mod_idx, mod_mid_status
                )
            )

        else:
            # There are cases where the chassis is logically divided where some LCs belongs to another chassis
            # and needs to be skipped and for those cases we should not assume if skipped means it must be
            # offline.
            if "LINE-CARD" in mod_idx:
                logger.info("skip checking midplane status for {} since it is on skip_mod_list".format(mod_idx))
            else:
                pytest_assert(
                    mod_mid_status == "False",
                    (
                        "Reachability of {} expected to be False but is {}. "
                        "It is not a line card for the current chassis and should be skipped."
                    ).format(
                        mod_idx, mod_mid_status
                    )
                )


def test_show_chassis_module_status_after_docker_restart(duthosts, tbinfo):
    """
    @summary: Verify output of `show chassis-module midplane-status` after `systemctl restart docker`
              to check if it remains consistent.
    """
    is_modular_chassis = random.choice(duthosts.frontend_nodes).get_facts().get("modular_chassis")
    if not is_modular_chassis or tbinfo["topo"]["type"] != "t2" or len(duthosts.supervisor_nodes) == 0:
        pytest.skip("This test is only applicable for the T2 supervisor node")

    suphost = duthosts.supervisor_nodes[0]
    sup_hostname = suphost.hostname
    logger.info(f"Get initial chassis module status on the supervisor node - {sup_hostname}")
    cmd = " ".join([CMD_SHOW_CHASSIS_MODULE, "status"])
    initial_output = suphost.command(cmd)
    exp_headers = ["Name", "Description", "Physical-Slot", "Oper-Status", "Admin-Status"]
    initial_res = parse_chassis_module(initial_output["stdout_lines"], exp_headers)

    linecards_bgp_neighbors = {}
    for linecard in duthosts.frontend_nodes:
        lc_hostname = linecard.hostname
        logger.info(f"Get the established BGP neighbors for the linecard - {lc_hostname}")
        lc_bgp_neighbors = linecard.get_bgp_neighbors_per_asic("established")
        linecards_bgp_neighbors[lc_hostname] = lc_bgp_neighbors

    logger.info(f"Restart docker server on the supervisor node - {sup_hostname}")
    suphost.command("systemctl restart docker")

    logging.info(f"Wait until all critical processes are fully started on the supervisor node - {sup_hostname}")
    wait_critical_processes(suphost)
    pytest_assert(
        wait_until(330, 20, 0, suphost.critical_services_fully_started),
        (
            "All critical services should be fully started on the supervisor node - {}. "
            "One or more critical services failed to start within the expected timeframe."
        ).format(sup_hostname)
    )

    for linecard in duthosts.frontend_nodes:
        lc_hostname = linecard.hostname
        logging.info(f"Ensure BGP sessions are re-established on the linecard - {lc_hostname}")
        pytest_assert(
            wait_until(
                300,
                10,
                0,
                linecard.check_bgp_session_state_all_asics,
                linecards_bgp_neighbors[lc_hostname],
                "established",
            ),
            (
                "BGP session on linecard {} failed to establish within the expected timeframe. "
                "Expected BGP session state to be 'established' for all ASICs."
            ).format(lc_hostname)
        )

    logger.info(f"Get chassis module status after docker restart on the supervisor node - {sup_hostname}")
    final_output = suphost.command(cmd)
    final_res = parse_chassis_module(final_output["stdout_lines"], exp_headers)

    logger.info("Compare initial and final outputs")
    for mod_idx in list(initial_res.keys()):
        pytest_assert(
            initial_res[mod_idx] == final_res[mod_idx],
            "Mismatch in module status for slot {}: initial={} final={}."
            .format(
                mod_idx, initial_res[mod_idx], final_res[mod_idx]
            )
        )

    logger.info(
        f"Chassis module status remains consistent after docker restart on the supervisor node - {sup_hostname}"
    )
