import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.cli.util import get_skip_mod_list
import logging
import re
import time
import centralized_cli_test

CASES = centralized_cli_test.RP_LC_TESTCASE_CHOICES_CASES
_case_id = centralized_cli_test.rp_lc_testcase_choices_case_id
RP_LC_SHOW_TESTCASE_FILE = centralized_cli_test.RP_LC_SHOW_TESTCASE_CHOICES_FILENAME

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.fixture(autouse=True, scope="module")
def get_parameter(request):
    """
    Fixture to get parameter platform_npu_tc_name
    """
    global platform_npu_tc_name
    platform_npu_tc_name = request.config.getoption("--platform_npu_tc_name", default="all")
    return platform_npu_tc_name


def sup_platform_npu_tests(duthosts, duthost, tc_dict, results):
    """
    Function to run Platform NPU tests on Supervisor
    """

    #SUP local commands
    saved_ctxt_used_mem_kb = []
    current_used_mem_kb = []
    saved_ctxt_cpu_pc = []
    current_used_cpu_pc = []
    saved_ctxt_thread_count = []
    current_thread_count = []
    sup_asic_id_list = duthost.get_asic_namespace_list()
    for asic_id in sup_asic_id_list:
        saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
        result = duthost.command(f"{tc_dict['command']} -n {asic_id}", module_ignore_errors=True)
        logging.info(result)
        ret = centralized_cli_test.check_output_for_errors(result)
        if ret == True:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
        if tc_dict['output_match_str'] != 'NO_PATTERN':
            ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
            if ret == False:
                error_msg = "Command output is not complete!!!"
                centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return
        current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
        ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
        if ret == False:
            return
        current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
        ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
        if ret == False:
            return
        current_thread_count = centralized_cli_test.save_thread_context(duthosts)
        logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
        ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
        if ret == False:
            return

    saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
    saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
    saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
    result = duthost.command(f"{tc_dict['command']}")
    logging.info(result)
    ret = centralized_cli_test.check_output_for_errors(result)
    if ret == True:
        error_msg = "Command output is not complete!!!"
        centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if tc_dict['output_match_str'] != 'NO_PATTERN':
        ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
        if ret == False:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
    current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
    logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
    ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
    if ret == False:
        return
    current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
    logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
    ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
    if ret == False:
        return
    current_thread_count = centralized_cli_test.save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return

    #LC specific commands
    active_lc_list = []
    lc_namespace_list = []
    active_lc_list = centralized_cli_test.find_active_lc_list(duthosts)
    for lc in active_lc_list:
        lc_dut = centralized_cli_test.find_duthost_from_node_name(duthosts, lc)
        lc_namespace_list = lc_dut.get_asic_namespace_list()
        for asic_id in lc_namespace_list:
            saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
            saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
            saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
            result = duthost.command(f"{tc_dict['command']} -l {lc} -n {asic_id}", module_ignore_errors=True)
            logging.info(result)    
            ret = centralized_cli_test.check_output_for_errors(result)
            if ret == True:
                error_msg = "Command output is not complete!!!"
                centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return
            if tc_dict['output_match_str'] != 'NO_PATTERN':
                ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
                if ret == False:
                    error_msg = "Command output is not complete!!!"
                    centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                    return
            current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
            logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
            ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
            if ret == False:
                return
            current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
            logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
            ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
            if ret == False:
                return
            current_thread_count = centralized_cli_test.save_thread_context(duthosts)
            logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
            ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
            if ret == False:
                return

        saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
        result = duthost.command(f"{tc_dict['command']} -l {lc}", module_ignore_errors=True)
        logging.info(result)
        ret = centralized_cli_test.check_output_for_errors(result)
        if ret == True:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
        if tc_dict['output_match_str'] != 'NO_PATTERN':
            ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
            if ret == False:
                error_msg = "Command output is not complete!!!"
                centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return
        current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
        ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
        if ret == False:
            return
        current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
        ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
        if ret == False:
            return
        current_thread_count = centralized_cli_test.save_thread_context(duthosts)
        logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
        ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
        if ret == False:
            return

    #SUP - All specific commands
    min_namespace_count = centralized_cli_test.find_min_namespace_count(duthosts)
    min_namespace_list = [f"asic{i}" for i in range(min_namespace_count)]
    for asic_id in min_namespace_list:
        saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
        result = duthost.command(f"{tc_dict['command']} -l all -n {asic_id}", module_ignore_errors=True)
        logging.info(result)
        ret = centralized_cli_test.check_output_for_errors(result)
        if ret == True:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
        if tc_dict['output_match_str'] != 'NO_PATTERN':
            ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
            if ret == False:
                error_msg = "Command output is not complete!!!"
                centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return
        current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
        ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
        if ret == False:
            return
        current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
        ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
        if ret == False:
            return
        current_thread_count = centralized_cli_test.save_thread_context(duthosts)
        logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
        ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
        if ret == False:
            return

    saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
    saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
    saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
    result = duthost.command(f"{tc_dict['command']} -l all", module_ignore_errors=True)
    logging.info(result)
    ret = centralized_cli_test.check_output_for_errors(result)
    if ret == True:
        error_msg = "Command output is not complete!!!"
        centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if tc_dict['output_match_str'] != 'NO_PATTERN':
        ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
        if ret == False:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
    current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
    logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
    ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
    if ret == False:
        return
    current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
    logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
    ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
    if ret == False:
        return
    current_thread_count = centralized_cli_test.save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return

    centralized_cli_test.update_results(results, tc_dict["tcname"], "PASSED", "PASSED")
    return

def lc_platform_npu_tests(duthosts, duthost, tc_dict, results):
    """
    Function to run Platform NPU tests on linecard
    """
    #LC local commands
    saved_ctxt_used_mem_kb = []
    current_used_mem_kb = []
    saved_ctxt_cpu_pc = []
    current_used_cpu_pc = []
    saved_ctxt_thread_count = []
    current_thread_count = []
    active_lc_list = []
    lc_asic_id_list = duthost.get_asic_namespace_list()
    for asic_id in lc_asic_id_list:
        saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
        result = duthost.command(f"{tc_dict['command']} -n {asic_id}", module_ignore_errors=True)
        logging.info(result)    
        ret = centralized_cli_test.check_output_for_errors(result)
        if ret == True:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
        if tc_dict['output_match_str'] != 'NO_PATTERN':
            ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
            if ret == False:
                error_msg = "Command output is not complete!!!"
                centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return
        current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
        logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
        ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
        if ret == False:
            return
        current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
        logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
        ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
        if ret == False:
            return
        current_thread_count = centralized_cli_test.save_thread_context(duthosts)
        logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
        ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
        if ret == False:
            return
    
    saved_ctxt_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
    saved_ctxt_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
    saved_ctxt_thread_count = centralized_cli_test.save_thread_context(duthosts)
    result = duthost.command(f"{tc_dict['command']}", module_ignore_errors=True)
    logging.info(result)
    ret = centralized_cli_test.check_output_for_errors(result)
    if ret == True:
        error_msg = "Command output is not complete!!!"
        centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
        return
    if tc_dict['output_match_str'] != 'NO_PATTERN':
        ret = centralized_cli_test.does_result_contain(result, tc_dict['output_match_str'])
        if ret == False:
            error_msg = "Command output is not complete!!!"
            centralized_cli_test.update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return
    current_used_mem_kb = centralized_cli_test.save_memory_leak_context(duthosts)
    logging.info(f"saved_ctxt_used_mem_kb {saved_ctxt_used_mem_kb} current_used_mem_kb {current_used_mem_kb}")
    ret = centralized_cli_test.compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results)
    if ret == False:
        return
    current_cpu_pc = centralized_cli_test.save_cpu_utilization_context(duthosts)
    logging.info(f"saved_ctxt_cpu_pc {saved_ctxt_cpu_pc} current_cpu_pc {current_cpu_pc}")
    ret = centralized_cli_test.compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results)
    if ret == False:
        return
    current_thread_count = centralized_cli_test.save_thread_context(duthosts)
    logging.info(f"saved_ctxt_thread_count {saved_ctxt_thread_count} current_thread_count {current_thread_count}")
    ret = centralized_cli_test.compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results)
    if ret == False:
        return

    tcname = tc_dict["tcname"]
    centralized_cli_test.update_results(results, tc_dict["tcname"], "PASSED", "PASSED")
    return

def rp_lc_show_platform_npu_testcase(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, tc_dict, results):
    """
    Function to run Platform NPU tests based on Supervisor or Linecard
    """

    logging.info(f"Running PLATFORM NPU Test Case: {tc_dict['tcname']}")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if not duthost.facts['modular_chassis']:
        pytest.skip("Test skipped applicable to modular chassis only")
    if duthost.is_supervisor_node():
        sup_platform_npu_tests(duthosts, duthost, tc_dict, results)
    else:
        lc_platform_npu_tests(duthosts, duthost, tc_dict, results)


@pytest.mark.parametrize("tc_dict", CASES, ids=_case_id)
def test_rp_lc_show_platform_npu(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, tc_dict):
    """
    Parametrized test: one pytest item per JSON testcase (same pattern as test_rp_lc_config_platform_npu).
    """
    pytest_assert(platform_npu_tc_name is not None, "Test case name argument was not passed!!!")
    results = []

    pytest_assert(
        len(CASES) != 0,
        f"Testcase choices input file {RP_LC_SHOW_TESTCASE_FILE} is empty or not found!!!",
    )

    tc_name = tc_dict.get("tcname")
    if platform_npu_tc_name != "all" and tc_name != platform_npu_tc_name:
        pytest.skip(f"Skipped by --platform_npu_tc_name filter: {platform_npu_tc_name}")

    if "yes" not in tc_dict.get("supported", []):
        pytest.skip(f"Test case {tc_name} is not supported")

    try:
        rp_lc_show_platform_npu_testcase(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, tc_dict, results)
    except Exception as e:
        error_msg = str(e)
        centralized_cli_test.update_results(results, tc_dict["tcname"], "ERROR", error_msg)

    centralized_cli_test.print_result_summary(results)
