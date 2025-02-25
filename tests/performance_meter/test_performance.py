import logging
import asyncio
import time
import statistics
import pytest
from contextlib import asynccontextmanager
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from ops import get_op_by_name
from success_criteria import get_success_criteria_by_name
from success_criteria import get_success_criteria_stats_by_name


# This tests is designed to test the performance of certain operation
# on designated devices. The process is separated into 2 test cases.
# test_performance will run N times as designated by user input.
# test_performance_stats will run once to analyze previous run result.
# Each run of test_performance is designed like below:
# 1. Read from config dir and pick config files that apply (fixture)
# 2. Loop though ops sequentially as listed in config files
# 2. Run sanity_check before op to make sure dut is healthy
# 3. Run success_criteria, finish some setup and return checker
#    It doesn't check success_criteria, it only returns the checker
# 4. Run the first part of op setup until yield is hit
# 5. Run success criteria check for success criteria every 1 second
# 6. Run the second part of op cleanup after checker returns True
# 7. Run sanity_check again
# 8. Log result and continue to next op


def filter_vars(my_vars, prefix):
    filter_vars = filter(lambda item: item[0].startswith(prefix), my_vars.items())
    map_vars = map(lambda item: (item[0][len(prefix) + 1:], item[1]), filter_vars)
    return dict(map_vars)


async def check_success_criteria(timeout, delay, checker, result):
    start_time = time.time()
    result["passed"] = wait_until(timeout=timeout, interval=1, delay=delay, condition=checker)
    end_time = time.time()
    result["time_to_pass"] = end_time - start_time


async def async_test_performance(duthosts, rand_one_dut_hostname, call_sanity_check,
                                 reorg_test_config, run_index, store_test_result):
    duthost = duthosts[rand_one_dut_hostname]
    logging.info("Test run {} of performance test on {}".format(run_index, rand_one_dut_hostname))

    single_run_result = {}
    store_test_result[run_index] = single_run_result

    sanity_check_setup, sanity_check_cleanup = call_sanity_check

    # run and test each op one by one
    for op, test_config_for_op in reorg_test_config.items():
        op_test_result = {}
        single_run_result[op] = op_test_result

        # before do_op, check that dut is healthy
        if sanity_check_setup(run_index, op) is False:
            op_test_result["op_precheck_success"] = False
            continue
        op_test_result["op_precheck_success"] = True

        # prior to op, prepare for checking success criteria
        coros = []
        for path, test_config_under_path in test_config_for_op.items():
            path_test_result = {}
            op_test_result[path] = path_test_result
            for test_name, test_config in test_config_under_path.items():
                success_criteria = test_config["success_criteria"]
                filtered_vars = filter_vars(test_config, success_criteria)
                pytest_assert("timeout" in filtered_vars, "{}_timeout variable is not defined for {}"
                                                          .format(success_criteria, success_criteria))
                timeout = filtered_vars["timeout"]
                delay = filtered_vars.get("delay", 0)
                checker = get_success_criteria_by_name(success_criteria)(duthost, **filtered_vars)
                test_result = {}
                path_test_result[test_name] = test_result
                coros.append(check_success_criteria(timeout, delay, checker, test_result))

        # do the op setup, it can block but should NEVER block forever
        # return True on success, False on fail
        # failure will stop test for op
        async with asynccontextmanager(get_op_by_name(op))(duthost) as op_success:
            op_test_result["op_success"] = op_success
            if op_success:
                asyncio.gather(*coros)
            else:
                logging.warning("Test run {} op {} failed".format(run_index, op))
                for coro in coros:
                    coro.close()

        # after op finishes cleanup, check that dut is healthy
        if sanity_check_cleanup(run_index, op) is False:
            op_test_result["op_postcheck_success"] = False
            continue
        op_test_result["op_postcheck_success"] = True

    logging.info("Test run {} result {}".format(run_index, single_run_result))


# Ideally, test_performance should not give errors and only collect results regardless of the
# errors received. Analyzing the result is reserved for test_performance_stats
@pytest.mark.disable_loganalyzer
def test_performance(duthosts, rand_one_dut_hostname, call_sanity_check, reorg_test_config,
                     run_index, store_test_result):     # noqa F811
    asyncio.run(async_test_performance(duthosts, rand_one_dut_hostname, call_sanity_check,
                reorg_test_config, run_index, store_test_result))


def reorg_test_result(test_config, test_result):
    total_run = len(test_result)
    reorged_test_result = {path: {test_name: [None] * total_run
                                  for test_name, _ in config["performance_meter"].items()}
                           for path, config in test_config.items()}
    for run_index, single_run_result in enumerate(test_result):
        if single_run_result is None:
            continue
        for op, op_test_result in single_run_result.items():
            for path, reorged_path_test_result in reorged_test_result.items():
                for test_name, result in reorged_path_test_result.items():
                    if test_config[path]["performance_meter"][test_name]["op"] == op:
                        result[run_index] = {**op_test_result,
                                             **op_test_result.get(path, {}).get(test_name, {})}
    return reorged_test_result


def process_single_test_case(test_config, single_test_result):
    # test environment issue
    success_criteria = test_config["success_criteria"]
    passed_sanity_check = list(filter(lambda item: item is not None, single_test_result))
    logging.warning("{} runs passed sanity check".format(len(passed_sanity_check)))
    passed_op_precheck = list(filter(lambda item: item["op_precheck_success"], passed_sanity_check))
    logging.warning("{} runs passed op precheck".format(len(passed_op_precheck)))
    # test issue
    finished_op = list(filter(lambda item: item["op_success"], passed_op_precheck))
    logging.warning("{} runs finished op".format(len(finished_op)))
    passed_success_criteria = list(filter(lambda result: result["passed"], finished_op))
    logging.warning("{} runs passed {} before timeout".format(len(passed_success_criteria), success_criteria))
    if len(passed_success_criteria) == 0:
        logging.warning("No meaningful result has been collected")
    else:
        time_to_pass = list(map(lambda result: result["time_to_pass"], passed_success_criteria))
        mean = statistics.mean(time_to_pass)
        logging.warning("Mean time to pass: {}".format(mean))
    passed_op_postcheck = list(filter(lambda item: item["op_postcheck_success"], finished_op))
    logging.warning("{} runs passed op postcheck".format(len(passed_op_postcheck)))
    # specific stats check
    if passed_op_precheck and get_success_criteria_stats_by_name(success_criteria):
        return get_success_criteria_stats_by_name(success_criteria)(passed_op_precheck,
                                                                    **filter_vars(test_config,
                                                                                  success_criteria))
    return True


def test_performance_stats(filter_test_config, store_test_result):
    test_result = reorg_test_result(filter_test_config, store_test_result)
    failed_tests = []
    for path, path_test_result in test_result.items():
        logging.warning("Analyzing result for config file {}".format(path))
        for test_name, result in path_test_result.items():
            logging.warning("Analyzing result for test case {}".format(test_name))
            test_config = filter_test_config[path]["performance_meter"][test_name]
            if process_single_test_case(test_config, result) is False:
                failed_tests.append((path, test_name))
            logging.warning("Finished analyzing result for test case {}".format(test_name))
        logging.warning("Finished analyzing result for config file {}".format(path))
    pytest_assert(len(failed_tests) == 0, "{} tests failed: {}".format(len(failed_tests), failed_tests))
