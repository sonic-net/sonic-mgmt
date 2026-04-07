import json
from pathlib import Path
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.cli.util import get_skip_mod_list
from tests.cisco.common.utils import CheckEnvironment
import logging
import re
import time
import random
from tests.cisco.platform_tests.centralized_cli_test import (
    does_result_contain,
    check_output_for_errors,
    get_platform_serial_number,
    find_active_lc_list,
    get_namespace_list_for_lc,
    find_min_namespace_count,
    find_node_name_from_duthost,
    find_duthost_from_node_name,
    save_thread_context,
    compare_thread_contexts,
    update_results,
    print_result_summary,
    save_memory_leak_context,
    compare_memory_usage_contexts,
    save_cpu_utilization_context,
    compare_cpu_usage_contexts,
    prepare_lc_command_for_admin_user,
    parse_additional_parameters,
    reformat_clicmd,
    parse_invalid_linecard_all_option_error,
    parse_missing_n_option_error
)

# Configuration file macro
RP_LC_TESTCASE_CONFIG_FILE = "test_rp_lc_testcase_config.json"
CFG = Path(__file__).with_name(RP_LC_TESTCASE_CONFIG_FILE)


def _load_cases():
    """
    Load testcase configuration from the JSON config file.
    Returns list of testcase dictionaries.
    """
    try:
        with CFG.open("r") as f:
            data = json.load(f)

        testcases = data["testcases"] if isinstance(data, dict) and "testcases" in data else data
        if not isinstance(testcases, list):
            logging.error(f"Invalid testcase config format in {CFG}: expected list or dict with 'testcases'")
            return []

        if not testcases:
            logging.error(f"No testcases found in config file: {CFG}")
            return []

        logging.info(f"Loaded {len(testcases)} testcases from {RP_LC_TESTCASE_CONFIG_FILE}")
        return testcases
    except FileNotFoundError:
        logging.error(f"Config file not found: {CFG}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in config file {CFG}: {str(e)}")
        return []
    except Exception as e:
        logging.error(f"Error loading config file {CFG}: {str(e)}")
        return []


def _case_id(case):
    return case.get("tcname") or case.get("name") or case.get("id") or str(case)


CASES = _load_cases()

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2')
]

@pytest.fixture(autouse=True, scope="module")
def get_parameter(request):
    """
    Fixture to get parameter platform_npu_tc_name
    """
    global platform_npu_tc_name
    # Use getoption with default value to handle missing option gracefully
    platform_npu_tc_name = request.config.getoption("--platform_npu_tc_name", default="all")
    return platform_npu_tc_name


def sup_platform_npu_tests(duthosts, duthost, tc_dict, results):
    """
    Run Platform NPU config tests from Supervisor (RP)
    
    Test execution flow:
    RUN 1: RP local command
        Example: config platform cisco histogram tc -o
    RUN 2: RP to one LC (centralized CLI: positive test)
        Example: config platform cisco fabric -n asic0 -L 1 -a startup -o -l LINE-CARD0
    RUN 3: RP to all LCs with all ASICs (centralized CLI: negative test)
        Example: config platform cisco sdk-debug disable -o -l all
    
    Commands with -l flag use centralized CLI for RP→LC communication
    """

    original_command = tc_dict['command']

    additional_parameters = parse_additional_parameters(tc_dict)
    requires_interface = any(p.startswith('interface_option') for p in additional_parameters)
    requires_active_asic = 'rp_active_asic' in additional_parameters

    # RUN1: SUP local command
    # Reformat command for RP local runs (RUN1) for requires_interface testcases
    if requires_interface:
        if not reformat_clicmd(duthost, tc_dict, results, cli_case="RP"):
            return

    # Reformat command for RP local runs (RUN1) for requires_active_asic testcases
    if requires_active_asic:
        sup_asic_id_list = duthost.get_asic_namespace_list()
        if not sup_asic_id_list:
            skip_msg = "SKIPPED - No active ASIC found for RUN1 rp_active_asic requirement"
            update_results(results, tc_dict["tcname"], "PASSED", skip_msg)
            return
        active_asic = random.choice(sup_asic_id_list)
        command_str = f"{tc_dict['command']} -o -n {active_asic}"
        logging.info(f"[RP-config-cli: {command_str}] - RUN 1: RP local command on one active ASIC")
    else:
        command_str = f"{tc_dict['command']} -o"
        logging.info(f"[RP-config-cli: {command_str}] - RUN 1: RP local command on all active ASICs")

    saved_ctxt_thread_count = []
    current_thread_count = []
    saved_ctxt_thread_count = save_thread_context(duthosts)
    result = duthost.command(command_str, module_ignore_errors=True)
    logging.info(result)
    error_msg = check_output_for_errors(result)
    if error_msg:
        update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if tc_dict['output_match_str'] != 'NO_PATTERN':
        ret = does_result_contain(result, tc_dict['output_match_str'])
        if ret == False:
            error_msg = f"Command output does not contain expected pattern: {tc_dict['output_match_str']}"
            update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
    current_thread_count = save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return


    #RUN2: RC to one LC specific commands
    active_lc_list = []
    lc_namespace_list = []
    lc_command_for_remote = original_command
    rexec_lc_for_check = None
    rexec_interface_for_check = None
    logging.info("=== Starting LC specific command section ===")
    active_lc_list = find_active_lc_list(duthosts)
    logging.info(f"Found {len(active_lc_list)} active LCs: {active_lc_list}")
    
    if not active_lc_list:
        skip_msg = "SKIPPED - No active LCs found for RP->LC commands"
        logging.warning(skip_msg)
        update_results(results, tc_dict["tcname"], "PASSED", skip_msg)
        return

    requires_interface = any(p.startswith('interface_option') for p in additional_parameters)

    lc_tc_dict = dict(tc_dict)
    lc_tc_dict['command'] = original_command

    # Reformat command for RP to LC (RUN2) for requires_interface testcases
    # Specifically, find an active LC and its last UP Ethernet interface, then rewrite
    # the command with that LC/interface pair before executing RP->LC centralized CLI.
    if requires_interface:
        if not reformat_clicmd(
            duthost,
            lc_tc_dict,
            results,
            cli_case="RP-LC",
            lc_target=None,
            active_lc_list=active_lc_list
        ):
            return

        lc_command_for_remote = lc_tc_dict['command']
        rexec_lc_for_check = lc_tc_dict.get('resolved_lc_target')
        rexec_interface_for_check = lc_tc_dict.get('resolved_lc_interface')

        if (not rexec_lc_for_check or not rexec_interface_for_check) or (rexec_lc_for_check not in active_lc_list):
            skip_msg = (
                "SKIPPED - No UP Ethernet interface found for RP-LC"
                if not rexec_lc_for_check or not rexec_interface_for_check
                else f"SKIPPED - Resolved LC target for RUN2 is not active: {rexec_lc_for_check}"
            )
            update_results(results, tc_dict["tcname"], "PASSED", skip_msg)
            return
        lc = rexec_lc_for_check
        logging.info(f"Using resolved LC/interface for RP RUN2/RUN3 checks: {lc}/{rexec_interface_for_check}")
    else:
        lc = active_lc_list[0]
        rexec_lc_for_check = lc
        rexec_interface_for_check = None
        lc_command_for_remote = lc_tc_dict['command']
        logging.info(f"RUN2 no interface requirement; using active LC: {lc}")

    lc_dut = find_duthost_from_node_name(duthosts, lc)
    if not lc_dut:
        update_results(results, tc_dict["tcname"], "PASSED", f"SKIPPED - Unable to resolve duthost for LC {lc}")
        return

    # Reformat command for RP to LC (RUN2) for requires_active_asic testcases
    lc_namespace_list = lc_dut.get_asic_namespace_list()
    if requires_active_asic:
        if not lc_namespace_list:
            skip_msg = f"SKIPPED - No active ASIC found on {lc} for RUN2 rp_active_asic requirement"
            update_results(results, tc_dict["tcname"], "PASSED", skip_msg)
            return
        active_asic = random.choice(lc_namespace_list)
        command_str = f"{lc_command_for_remote} -o -l {lc} -n {active_asic}"
        logging.info(f"[RP-config-cli: {command_str}] - RUN 2: RP to one LC ({lc}) with one active ASIC")
    else:
        command_str = f"{lc_command_for_remote} -o -l {lc}"
        logging.info(f"[RP-config-cli: {command_str}] - RUN 2: RP to one LC ({lc}) on all active ASICs")

    exec_command_str = prepare_lc_command_for_admin_user(duthost, command_str)
    saved_ctxt_thread_count = save_thread_context(duthosts)
    result = duthost.shell(exec_command_str, module_ignore_errors=True)
    logging.info(result)
    error_msg = check_output_for_errors(result)
    if error_msg:
        update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if tc_dict['output_match_str'] != 'NO_PATTERN':
        ret = does_result_contain(result, tc_dict['output_match_str'])
        if ret == False:
            error_msg = f"Command output does not contain expected pattern: {tc_dict['output_match_str']}"
            update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
    current_thread_count = save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return


    # RUN3: RP to all LCs with all active ASICs (currently commented out)
    command_str = f"{lc_command_for_remote} -o -l all"
    exec_command_str = prepare_lc_command_for_admin_user(duthost, command_str)
    logging.info(f"[RP-config-cli: {command_str}] - RUN 3: RP to all LCs with all active ASICs")
    saved_ctxt_thread_count = save_thread_context(duthosts)
    result = duthost.shell(exec_command_str, module_ignore_errors=True)
    logging.info(result)
    error_msg = check_output_for_errors(result)
    if error_msg:
        update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if not parse_invalid_linecard_all_option_error(result):
        error_msg = (
            "RUN 3 expected LINE-CARD input validation message for '-l all', "
            "but it was not found in command output"
        )
        update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    current_thread_count = save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return
    logging.info("All RUNs completed successfully")

    update_results(results, tc_dict["tcname"], "PASSED", "PASSED")
    return

def lc_platform_npu_tests(duthosts, duthost, tc_dict, results):
    """
    Run Platform NPU config tests from Line Card (LC)
    
    Test execution flow:
    RUN 1: LC/T0/T1 local command with specific ASIC targeting
        Example: config platform cisco bfd counter enable -n asic0 -d 1 -o
    RUN 2: LC        local command on all ASICs (negative test)
    RUN 2: T0/T1     local command on all ASICs (skip)
        Example: config platform cisco histogram tc -o
    
    All commands executed locally on LC (no -l flag)
    All commands include -o flag for debug output
    """
    additional_parameters = parse_additional_parameters(tc_dict)
    requires_interface = any(p.startswith('interface_option') for p in additional_parameters)
    requires_skip_generic_cli = 'skip_generic_cli' in additional_parameters

    if requires_interface:
        if not reformat_clicmd(duthost, tc_dict, results, cli_case="LC"):
            return

    # RUN1: LC local commands
    saved_ctxt_thread_count = []
    current_thread_count = []
    active_lc_list = []
    lc_asic_id_list = duthost.get_asic_namespace_list()
    if duthost.facts.get('modular_chassis', False):
        if lc_asic_id_list:
            asic_id = random.choice(lc_asic_id_list)
        else:
            skip_msg = "SKIPPED - No active ASIC found in lc_asic_id_list for RUN1 on modular chassis"
            update_results(results, tc_dict["tcname"], "PASSED", skip_msg)
            return
    else:
        asic_id = "asic0"

    command_str = f"{tc_dict['command']} -o -n {asic_id}"
    logging.info(f"[LC-config-cli: {command_str}] - RUN 1: LC local command on one active ASIC")
    saved_ctxt_thread_count = save_thread_context(duthosts)
    result = duthost.command(command_str, module_ignore_errors=True)
    logging.info(result)
    error_msg = check_output_for_errors(result)
    if error_msg:
        update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if tc_dict['output_match_str'] != 'NO_PATTERN':
        ret = does_result_contain(result, tc_dict['output_match_str'])
        if ret == False:
            error_msg = f"Command output does not contain expected pattern: {tc_dict['output_match_str']}"
            update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
    current_thread_count = save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return
    
    # RUN2: LC local negative test on modular chassis (expect reject without -n)
    # On non-modular T0/T1, skip RUN2 because there is no LC centralized-CLI negative behavior.
    if duthost.facts.get('modular_chassis', False):
        if requires_skip_generic_cli:
            logging.info("RUN 2 skipped by testcase additional_parameters: requires_skip_generic_cli")
        else:
            command_str = f"{tc_dict['command']} -o"
            logging.info(f"[LC-config-cli: {command_str}] - RUN 2: LC local negative test on modular chassis (expect reject without -n)")
            saved_ctxt_thread_count = save_thread_context(duthosts)
            result = duthost.command(command_str, module_ignore_errors=True)
            logging.info(result)

            # Expected negative format for RUN 2:
            # Error: Missing option '-n'.
            if not parse_missing_n_option_error(result):
                error_msg = "RUN 2 expected rejection with 'Missing option -n' on modular chassis LC"
                update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return

            current_thread_count = save_thread_context(duthosts)
            logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
            ret = compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
            if ret == False:
                return
    else:
        logging.info("RUN 2 skipped: non-modular topology (T0/T1)")

    tcname = tc_dict["tcname"]
    update_results(results, tc_dict["tcname"], "PASSED", "PASSED")
    return


def rp_lc_config_platform_npu_testcase(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, tc_dict, results):
    """
    Function to run Platform NPU config tests based on Supervisor or Linecard
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    additional_parameters = parse_additional_parameters(tc_dict)
    if 'skip_vxr_not_support' in additional_parameters and CheckEnvironment.is_sim(duthost):
        update_results(results, tc_dict["tcname"], "PASSED", "vxr SIM environment does not support this testcase")
        return
    
    # Enhanced logging to identify device type and execution context
    device_hostname = duthost.hostname
    if duthost.is_supervisor_node():
        device_type = "SUPERVISOR"
    elif duthost.facts.get('modular_chassis', False):
        device_type = "LINE-CARD"
    else:
        device_type = "NON-CHASSIS"
    logging.info(f"Running PLATFORM NPU Config Test Case: {tc_dict['tcname']} on {device_type} device: {device_hostname}")
    
    # Save initial memory and CPU context before running tests
    logging.info("=== Saving initial memory and CPU contexts ===")
    saved_memory_context = save_memory_leak_context(duthosts)
    saved_cpu_context = save_cpu_utilization_context(duthosts)
    
    try:
        if duthost.is_supervisor_node():
            logging.info(f"Executing SUP tests from Supervisor device: {device_hostname}")
            sup_platform_npu_tests(duthosts, duthost, tc_dict, results)
        else:
            logging.info(f"Executing LC and DUT tests from non-supervisor device: {device_hostname}")
            lc_platform_npu_tests(duthosts, duthost, tc_dict, results)
    
    finally:
        # Always check memory and CPU contexts after test execution
        logging.info("=== Checking memory and CPU contexts after test execution ===")
        current_memory_context = save_memory_leak_context(duthosts)
        current_cpu_context = save_cpu_utilization_context(duthosts)
        
        # Check for memory leaks
        memory_check_result = compare_memory_usage_contexts(duthosts, saved_memory_context, current_memory_context, tc_dict, results)
        if not memory_check_result:
            logging.error("Memory leak detected during test execution!")
        
        # Check for high CPU usage
        cpu_check_result = compare_cpu_usage_contexts(duthosts, saved_cpu_context, current_cpu_context, tc_dict, results)
        if not cpu_check_result:
            logging.error("High CPU usage detected during test execution!")
        
        logging.info("Memory and CPU usage checks completed")


@pytest.mark.parametrize("tc_dict", CASES, ids=_case_id)
def test_rp_lc_config_platform_npu(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, tc_dict):
    """
    Parametrized test case function to run one Platform NPU config testcase per pytest item.
    """
    pytest_assert(platform_npu_tc_name != None, "Test case name argument was not passed!!!")
    results = []

    pytest_assert(len(CASES) != 0, f"Testcase choices input file {RP_LC_TESTCASE_CONFIG_FILE} is empty or not found!!!")
 
    tc_dict = dict(tc_dict)
 
    tc_name = tc_dict.get('tcname')
    if platform_npu_tc_name != "all" and tc_name != platform_npu_tc_name:
        pytest.skip(f"Skipped by --platform_npu_tc_name filter: {platform_npu_tc_name}")

    if 'yes' not in tc_dict.get('supported', []):
        pytest.skip(f"Test case {tc_name} is not supported")

    try:
        rp_lc_config_platform_npu_testcase(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, tc_dict, results)
    except Exception as e:
        error_msg = str(e)
        update_results(results, tc_dict["tcname"], "ERROR", error_msg)

    print_result_summary(results)
