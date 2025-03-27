import logging
import random
import statistics
import datetime
from tests.common.helpers.assertions import pytest_assert


# find success criteria function by exact name match
def get_success_criteria_by_name(success_criteria):
    return globals()[success_criteria]


# find succes criteria stats function
# it is always expected to end in stats to distinguish from others
def get_success_criteria_stats_by_name(name):
    if name.endswith("_stats"):
        return globals().get(name, None)
    else:
        return globals().get(name + "_stats", None)


def suppress_exception(func):
    def inner():
        try:
            return func()
        except Exception:
            return False
    return inner


# Defining a success criteria and its stats.
# A success criteria is a function defined in this module that
# returns a function that returns True or False. It takes a duthost
# and all variables defined in config that starts with the
# name of said criteria, as keyword args. If we have "bgp_up",
# then it will take "bgp_up_timeout", "bgp_up_delay", "bgp_up_foo",
# etc, and have "timeout", "delay", "foo" etc, as kwargs. kwargs can
# be used to pass any additional arguments and limitations
# from config file to the success criteria function. Additionally a
# timeout is always expected in config file because test can't hang
# forever. A delay is to not run the check for said time, default
# to 0. It is ok to throw exception as it will be handled, but it
# prints to the console, which could be a lot.


# sample success criteria function, returns True 20% of times.
def random_success_20_perc(duthost, test_result, **kwargs):
    return lambda: random.random() < 0.2


# Because each test run is separate, success criteria function cannot
# process results of all runs, so there could be an optional success
# criteria stats function, named with a "_stats" suffix, like
# "bgp_up_stats", taking all the same kwargs variables as its single run
# version. Unlike the single test run counter part, it takes
# passed_op_precheck which is the test result of all test runs that
# passed pre op sanity_check. The passed_op_precheck is a list of test
# results. Test result has the following format:
# {
#   "op_precheck_success": True/False,
#   "op_success": True/False,
#   "op_postcheck_success": True/False,
#   "passed": True/False,
#   "time_to_pass": DURATION,
# }
# When one stage fails, the following stages will not have an entry.
# Test results have been filtered to have op_precheck_success == True.


# sample success criteria stats
def random_success_20_perc_stats(passed_op_precheck, **kwargs):
    finished_op = list(filter(lambda item: item["op_success"], passed_op_precheck))
    if "success_rate_op" in kwargs:
        success_rate_op = len(finished_op) / len(passed_op_precheck)
        logging.warning("Success rate of op is {}".format(success_rate_op))
        pytest_assert(success_rate_op >= kwargs["success_rate_op"],
                      "Success rate of op {} is less than expected {}".format(success_rate_op,
                                                                              kwargs["success_rate_op"]))
    passed_success_criteria = list(filter(lambda result: result["passed"], finished_op))
    if "success_rate" in kwargs:
        success_rate = len(passed_success_criteria) / len(finished_op)
        logging.warning("Success rate is {}".format(success_rate))
        pytest_assert(success_rate >= kwargs["success_rate"],
                      "Success rate {} is less than expected {}".format(success_rate, kwargs["success_rate"]))
    all_time_to_pass = list(map(lambda item: item["time_to_pass"], passed_success_criteria))
    if "max" in kwargs:
        max_time_to_pass = max(all_time_to_pass)
        logging.warning("Max time_to_pass is {}".format(max_time_to_pass))
        pytest_assert(max_time_to_pass <= kwargs["max"],
                      "Max time_to_pass {} is more than defined max {}".format(max_time_to_pass, kwargs["max"]))
    if "min" in kwargs:
        min_time_to_pass = min(all_time_to_pass)
        logging.warning("Min time_to_pass is {}".format(min_time_to_pass))
        pytest_assert(min_time_to_pass >= kwargs["min"],
                      "Min time_to_pass {} is less than defined min {}".format(min_time_to_pass, kwargs["min"]))
    if "mean" in kwargs:
        mean_time_to_pass = statistics.mean(all_time_to_pass)
        logging.warning("Mean time_to_pass is {}".format(mean_time_to_pass))
        pytest_assert(mean_time_to_pass <= kwargs["mean"],
                      "Mean time_to_pass {} is more than defined mean {}".format(mean_time_to_pass, kwargs["mean"]))
    if "stdev" in kwargs:
        stdev_time_to_pass = statistics.stdev(all_time_to_pass)
        logging.warning("Stdev time_to_pass is {}".format(stdev_time_to_pass))
        pytest_assert(stdev_time_to_pass <= kwargs["stdev"],
                      "Stdev time_to_pass {} is more than defined stdev {}".format(stdev_time_to_pass, kwargs["stdev"]))
    logging.warning("Foo is {}".format(kwargs["foo"]))


def display_variable_stats(passed_op_precheck, **kwargs):
    finished_op = list(filter(lambda item: item["op_success"], passed_op_precheck))
    success_rate_op = len(finished_op) / len(passed_op_precheck)
    logging.warning("Success rate of op is {}".format(success_rate_op))
    passed_success_criteria = list(filter(lambda result: result["passed"], finished_op))
    success_rate = len(passed_success_criteria) / len(finished_op)
    logging.warning("Success rate is {}".format(success_rate))
    if "display_variable" in kwargs:
        display_variable = kwargs["display_variable"]
        all_display_variable = list(map(lambda item: item[display_variable], passed_success_criteria))
        max_display_variable = max(all_display_variable)
        logging.warning("Max {} is {}".format(display_variable, max_display_variable))
        min_display_variable = min(all_display_variable)
        logging.warning("Min {} is {}".format(display_variable, min_display_variable))
        mean_display_variable = statistics.mean(all_display_variable)
        logging.warning("Mean {} is {}".format(display_variable, mean_display_variable))
        stdev_display_variable = statistics.stdev(all_display_variable)
        logging.warning("Stdev {} is {}".format(display_variable, stdev_display_variable))


def bgp_up(duthost, test_result, **kwargs):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    bgp_neighbors = config_facts.get("BGP_NEIGHBOR", {}).keys()
    return suppress_exception(lambda: duthost.check_bgp_session_state(bgp_neighbors))


def _extract_timestamp(duthost, line):
    timestamp = line[:line.index(duthost.hostname) - 1]
    formats = ["%Y %b %d %H:%M:%S.%f", "%b %d %H:%M:%S.%f", "%b %d %H:%M:%S"]
    for f in formats:
        try:
            return datetime.datetime.strptime(timestamp, f)
        except ValueError:
            continue
    raise ValueError("Unable to parse {}".format(timestamp))


def _get_last_timestamp(duthost):
    stdout = duthost.shell("show logging | tail -n 1")["stdout"]
    return _extract_timestamp(duthost, stdout)


def swss_up(duthost, test_result, **kwargs):
    last_timestamp = _get_last_timestamp(duthost)
    cur_swss_start = None
    swss_start_cmd = "show logging | grep 'docker cmd: start for swss' | grep -v ansible | tail -n 1"
    swss_started_cmd = "show logging | grep 'Feature swss is enabled and started' | grep -v ansible | tail -n 1"

    @suppress_exception
    def swss_up_checker():
        nonlocal cur_swss_start
        if cur_swss_start is None:
            stdout = duthost.shell(swss_start_cmd)["stdout"]
            swss_start = _extract_timestamp(duthost, stdout)
            if swss_start > last_timestamp:
                cur_swss_start = swss_start
        if cur_swss_start is not None:
            stdout = duthost.shell(swss_started_cmd)["stdout"]
            swss_started = _extract_timestamp(duthost, stdout)
            if swss_started > cur_swss_start:
                test_result["swss_start_time"] = (swss_started - cur_swss_start).seconds
                return True
        return False
    return swss_up_checker


def startup_mem_usage_after_bgp_up(duthost, test_result, **kwargs):
    bgp_up_checker = bgp_up(duthost, test_result, **kwargs)

    @suppress_exception
    def checker():
        if bgp_up_checker():
            cmd = "cat /proc/meminfo | grep MemAvailable | egrep -o '[0-9]+'"
            test_result["mem_available"] = int(duthost.shell(cmd)["stdout"])
            return True
        return False
    return checker
