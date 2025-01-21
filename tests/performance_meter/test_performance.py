import logging
import asyncio
import time
import random
import statistics
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


async def async_command(duthost, command):
    return duthost.command(command)


async def async_command_ignore_errors(duthost, command):
    try:
        return duthost.command(command, module_ignore_errors=True)
    except Exception:
        return


# Defining an op.
# An op is seperated into 2 parts by yield. The first part is setup
# and happens before checking for success criteria, and the second
# part is cleanup and happens after checking for success criteria
# and the goal is to make sure that no change is leftover.
# An op can be blocking or nonblocking, or combined, depending on
# the need. For example, sometimes we want reboot to block until it
# is successfully done before proceeding, or we want reboot to not
# block at all to calculate how much time it takes to reboot.
# If an op does not have yield in it, it will be treated as blocking.
# Timing will only start after the first blocking part of operation
# is over. The op should make sure op is started correctly and ended
# correctly. If either part is unsuccessful, op should yeild False and
# log the error, otherwise yielding True is expected.


async def noop(duthost):
    yield True


async def bad_op(duthost):
    yield False


async def reboot_by_cmd(duthost):
    command = asyncio.create_task(async_command_ignore_errors(duthost, "reboot"))
    yield True
    await command


# Defining a success criteria and its stats.
# A success criteria is a function defined in this module that
# returns a function that returns True or False. It takes a duthost
# and all variables defined in config that starts with the
# name of said criteria, as keyword args. If we have "bgp_up",
# then it will take "bgp_up_timeout", "bgp_up_delay", "bgp_up_foo",
# etc as kwargs. A timeout is expected because we don't test to hang
# forever. A delay is to not run the check for said time, default
# to 0. Because each test run is separate, the function cannot
# process results of all runs, so there could be a success criteria
# stats function, named with a "_stats" suffix, taking the same
# variables as its single run version, like "bgp_up_stats". It will
# take all results that passed op precheck.


def random_success_20_perc(duthost, **kwarg):
    return lambda: random.random() < 0.2


def random_success_20_perc_stats(passed_op_precheck, **kwarg):
    logging.warning("Foo is {}".format(kwarg["foo"]))


def bgp_up(duthost, **kwarg):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {}).keys()
    return lambda: duthost.check_bgp_session_state(bgp_neighbors)


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

    # run and test each op one by one
    for op, test_config_for_op in reorg_test_config.items():
        op_test_result = {}
        single_run_result[op] = op_test_result

        # before do_op, check that dut is healthy
        try:
            for sanity_check in call_sanity_check():
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
                        checker = globals()[success_criteria](duthost, **filtered_vars)
                        test_result = {}
                        path_test_result[test_name] = test_result
                        coros.append(check_success_criteria(timeout, delay, checker, test_result))

                # do the op setup, it can block but should NEVER block forever
                # return True on success, False on fail
                # failure will stop test for op
                async for op_success in globals()[op](duthost):
                    op_test_result["op_success"] = op_success
                    if op_success:
                        asyncio.gather(*coros)
                    else:
                        logging.warning("Test run {} op {} failed".format(run_index, op))
                        for coro in coros:
                            coro.close()

        except Exception as e:
            if "op_success" in op_test_result:
                logging.warning("Test run {} op {} postcheck failed on {}".format(run_index, op, e))
                op_test_result["op_precheck_success"] = True
                op_test_result["op_postcheck_success"] = False
            else:
                logging.warning("Test run {} op {} precheck failed on {}".format(run_index, op, e))
                op_test_result["op_precheck_success"] = False
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
    success_criteria_stats = success_criteria + "_stats"
    if success_criteria_stats in globals():
        return globals()[success_criteria_stats](passed_op_precheck, **filter_vars(test_config, success_criteria))
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
