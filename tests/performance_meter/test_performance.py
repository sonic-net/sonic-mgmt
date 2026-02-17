import logging
import asyncio
import time
import statistics
import pytest
from contextlib import asynccontextmanager
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import async_wait_until

from ops import get_op_by_name
from success_criteria import get_success_criteria_by_name
from success_criteria import get_success_criteria_stats_by_name
from success_criteria import filter_vars


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),  # will be invoked manually in test
    pytest.mark.disable_loganalyzer
]


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


async def check_success_criteria(timeout, delay, interval, checker, result):
    start_time = time.time()
    result["passed"] = await async_wait_until(timeout=timeout, interval=interval, delay=delay, condition=checker)
    end_time = time.time()
    result["time_to_pass"] = end_time - start_time


async def run_test_performance_for_op(request, call_sanity_check, reorged_test_config, op, run_index):
    sanity_check_setup, sanity_check_cleanup = call_sanity_check

    single_run_result = {}
    test_config_for_op = reorged_test_config[op]

    # before do_op, check that dut is healthy
    op_precheck_success = sanity_check_setup(run_index, op)
    single_run_result["op_precheck_success"] = op_precheck_success
    if op_precheck_success is False:
        return single_run_result

    # prior to op, prepare for checking success criteria
    coros = []
    for path, test_config_under_path in test_config_for_op.items():
        path_test_result = {}
        single_run_result[path] = path_test_result
        for test_name, test_config in test_config_under_path.items():
            if run_index > test_config["run"]:
                continue
            test_result = {}
            path_test_result[test_name] = test_result
            timeout = test_config["timeout"]
            delay = test_config.get("delay", 0)
            interval = test_config.get("interval", 1)
            success_criteria = test_config["success_criteria"]
            filtered_vars = filter_vars(test_config, success_criteria)
            checker = get_success_criteria_by_name(success_criteria)(request, test_result, **filtered_vars)
            coros.append(check_success_criteria(timeout, delay, interval, checker, test_result))

    # do the op setup, it can block but should NEVER block forever
    # return True on success, False on fail
    # failure will stop test for op
    async with asynccontextmanager(get_op_by_name(op))(request) as op_success:
        single_run_result["op_success"] = op_success
        if op_success:
            await asyncio.gather(*coros)
        else:
            for coro in coros:
                coro.close()

    # after op finishes cleanup, check that dut is healthy
    single_run_result["op_postcheck_success"] = sanity_check_cleanup(run_index, op)
    return single_run_result


async def async_test_performance(request, call_sanity_check, reorged_test_config, store_test_result,
                                 path, test_name, op, success_criteria, run_index):
    if op not in reorged_test_config or path not in reorged_test_config[op]:
        pytest.skip("Test condition run_when does not match")
    logging.info("Running path {} test_name {} op {} success_criteria {} run_index {}"
                 .format(path, test_name, op, success_criteria, run_index))
    if not store_test_result[op][run_index]:
        logging.info("The {}th op {} has not been run, running now".format(run_index, op))
        store_test_result[op][run_index] = await run_test_performance_for_op(request, call_sanity_check,
                                                                             reorged_test_config, op, run_index)
    test_result = store_test_result[op][run_index]
    logging.info("Result of path {} test_name {} op {} success_criteria {} run_index {}: {}"
                 .format(path, test_name, op, success_criteria, run_index, test_result))


# Ideally, test_performance should not give errors and only collect results regardless of the
# errors received. Analyzing the result is reserved for test_performance_stats
def test_performance(request, call_sanity_check, reorged_test_config, store_test_result,
                     path, test_name, op, success_criteria, run_index):     # noqa: F811
    asyncio.run(async_test_performance(request, call_sanity_check, reorged_test_config, store_test_result,
                                       path, test_name, op, success_criteria, run_index))


def process_single_test_case(test_config, single_test_results):
    # test environment issue
    success_criteria = test_config["success_criteria"]
    passed_sanity_check = list(filter(lambda item: item is not None, single_test_results))
    logging.warning("{} runs passed sanity check".format(len(passed_sanity_check)))
    passed_op_precheck = list(filter(lambda item: item["op_precheck_success"], passed_sanity_check))
    logging.warning("{} runs passed op precheck".format(len(passed_op_precheck)))
    # test issue
    finished_op = list(filter(lambda item: item["op_success"], passed_op_precheck))
    logging.warning("{} runs finished op".format(len(finished_op)))
    passed_success_criteria = list(filter(lambda result: result["passed"], finished_op))
    logging.warning("{} runs passed {} before timeout".format(len(passed_success_criteria), success_criteria))
    time_to_pass = list(map(lambda result: result["time_to_pass"], passed_success_criteria))
    if len(passed_success_criteria) > 0:
        mean = statistics.mean(time_to_pass)
        logging.warning("Mean time to pass: {}".format(mean))
    else:
        logging.warning("No meaningful mean has been collected")
    if len(passed_success_criteria) > 1:
        stdev = statistics.stdev(time_to_pass)
        logging.warning("Stdev time to pass: {}".format(stdev))
    else:
        logging.warning("No meaningful stdev has been collected")
    passed_op_postcheck = list(filter(lambda item: item["op_postcheck_success"], finished_op))
    logging.warning("{} runs passed op postcheck".format(len(passed_op_postcheck)))
    # specific stats check
    success_criteria_stats = get_success_criteria_stats_by_name(test_config.get("success_criteria_stats",
                                                                                success_criteria + "_stats"))
    if success_criteria_stats:
        try:
            success_criteria_stats(passed_op_precheck, **filter_vars(test_config, success_criteria))
        except pytest.fail.Exception as e:
            # assertion error, we want to catch this and report this
            return e
        except Exception as e:
            # when unexpected exception happen, it is typically not meaningful result
            # we dont want it to block other tests, so we just log and continue
            logging.warning("Unexpected error occured when processing {}: {}".format(success_criteria_stats, e))
            pass
    return True


def test_performance_stats(filtered_test_config, store_test_result):
    failed_tests = []
    for path, test_config_for_path in filtered_test_config.items():
        logging.warning("Analyzing result for config file {}".format(path))
        for test_name, test_config in test_config_for_path["performance_meter"].items():
            logging.warning("Analyzing result for test case {}".format(test_name))
            single_test_results = map(lambda result: {**result, **result[path][test_name]},
                                      store_test_result[test_config["op"]][:test_config["run"]])
            result = process_single_test_case(test_config, single_test_results)
            if result is not True:
                failed_tests.append((path, test_name, result))
            logging.warning("Finished analyzing result for test case {}".format(test_name))
        logging.warning("Finished analyzing result for config file {}".format(path))
    pytest_assert(len(failed_tests) == 0, "{} tests failed: {}".format(len(failed_tests), failed_tests))
