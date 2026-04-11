import logging
import random
import statistics
import datetime
import pandas as pd
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


def filter_vars(my_vars, prefix):
    filter_vars = filter(lambda item: item[0].startswith(prefix + "_"), my_vars.items())
    map_vars = map(lambda item: (item[0][len(prefix) + 1:], item[1]), filter_vars)
    return dict(map_vars)


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
def random_success_20_perc(request, test_result, **kwargs):
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


# function for printing out collected stats on display_variable/s provided through config
# this variable should have been collected by success_criteria and stored in test results
def display_variable_stats(passed_op_precheck, **kwargs):
    finished_op = list(filter(lambda item: item["op_success"], passed_op_precheck))
    success_rate_op = len(finished_op) / len(passed_op_precheck)
    logging.warning("Success rate of op is {}".format(success_rate_op))
    passed_success_criteria = list(filter(lambda result: result["passed"], finished_op))
    success_rate = len(passed_success_criteria) / len(finished_op)
    logging.warning("Success rate is {}".format(success_rate))
    display_variables = kwargs.get("display_variables", [])
    display_variable_stats = {}
    if "display_variable" in kwargs:
        display_variables.append(kwargs["display_variable"])
    for display_variable in display_variables:
        all_display_variable = list(map(lambda item: item[display_variable], passed_success_criteria))
        max_display_variable = max(all_display_variable)
        logging.warning("Max {} is {}".format(display_variable, max_display_variable))
        min_display_variable = min(all_display_variable)
        logging.warning("Min {} is {}".format(display_variable, min_display_variable))
        mean_display_variable = statistics.mean(all_display_variable)
        logging.warning("Mean {} is {}".format(display_variable, mean_display_variable))
        stdev_display_variable = statistics.stdev(all_display_variable)
        logging.warning("Stdev {} is {}".format(display_variable, stdev_display_variable))
        display_variable_stats[display_variable] = {"max": max_display_variable,
                                                    "min": min_display_variable,
                                                    "mean": mean_display_variable,
                                                    "stdev": stdev_display_variable,
                                                    }
        extra_vars = filter_vars(kwargs, display_variable)
        if "quantile" in extra_vars:
            quantile = extra_vars["quantile"]
            series = pd.Series(all_display_variable)
            result = series.quantile(quantile)
            logging.warning("Quantile {} of {} is {}".format(quantile, display_variable, result))
            display_variable_stats[display_variable]["quantile"] = quantile
            display_variable_stats[display_variable]["quantile_result"] = result
    return display_variable_stats


def bgp_up(request, test_result, **kwargs):
    duthost = request.getfixturevalue("duthost")
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    bgp_neighbors = config_facts.get("BGP_NEIGHBOR", {}).keys()
    return suppress_exception(lambda: duthost.check_bgp_session_state(bgp_neighbors))


# utility function to extract timestamp from syslog line
def _extract_timestamp(duthost, line):
    timestamp = line[:line.index(duthost.hostname) - 1]
    formats = ["%Y %b %d %H:%M:%S.%f", "%b %d %H:%M:%S.%f", "%b %d %H:%M:%S"]
    for f in formats:
        try:
            return datetime.datetime.strptime(timestamp, f)
        except ValueError:
            continue
    raise ValueError("Unable to parse {}".format(timestamp))


# utility function to get last syslog timestamp
def _get_last_timestamp(duthost):
    stdout = duthost.shell("show logging | tail -n 1")["stdout"]
    return _extract_timestamp(duthost, stdout)


def success_criteria_by_syslog(request, test_result, **kwargs):
    duthost = request.getfixturevalue("duthost")
    last_timestamp = _get_last_timestamp(duthost)
    syslog_start = None
    syslog_start_cmd = kwargs["syslog_start_cmd"]
    syslog_end_cmd = kwargs["syslog_end_cmd"]

    @suppress_exception
    def syslog_checker():
        nonlocal syslog_start
        if syslog_start is None:
            stdout = duthost.shell(syslog_start_cmd)["stdout"]
            timestamp = _extract_timestamp(duthost, stdout)
            if timestamp > last_timestamp:
                syslog_start = timestamp
        if syslog_start is not None:
            stdout = duthost.shell(syslog_end_cmd)["stdout"]
            timestamp = _extract_timestamp(duthost, stdout)
            if timestamp > syslog_start:
                test_result[kwargs["result_variable"]] = (timestamp - syslog_start).seconds
                return True
        return False
    return syslog_checker


def swss_up(request, test_result, **kwargs):
    swss_start_cmd = "show logging | grep 'docker cmd: start for swss' | grep -v ansible | tail -n 1"
    swss_end_cmd = "show logging | grep 'Feature swss is enabled and started' | grep -v ansible | tail -n 1"
    extra_vars = {"syslog_start_cmd": swss_start_cmd,
                  "syslog_end_cmd": swss_end_cmd,
                  "result_variable": "swss_start_time"}
    return success_criteria_by_syslog(request, test_result, **{**kwargs, **extra_vars})


def swss_create_switch(request, test_result, **kwargs):
    start_mark = "create: request switch create with context 0"
    start_cmd = "show logging | grep '{}' | grep -v ansible | tail -n 1".format(start_mark)
    end_mark = "main: Create a switch, id:"
    end_cmd = "show logging | grep '{}' | grep -v ansible | tail -n 1".format(end_mark)
    extra_vars = {"syslog_start_cmd": start_cmd,
                  "syslog_end_cmd": end_cmd,
                  "result_variable": "swss_create_switch_start_time"}
    return success_criteria_by_syslog(request, test_result, **{**kwargs, **extra_vars})


def swss_create_switch_stats(passed_op_precheck, **kwargs):
    variable_stats = display_variable_stats(passed_op_precheck,
                                            **{**kwargs,
                                               "display_variable": "swss_create_switch_start_time",
                                               "swss_create_switch_start_time_quantile": 1})
    start_time_stats = variable_stats["swss_create_switch_start_time"]
    pytest_assert(start_time_stats["mean"] < kwargs["mean"],
                  "swss_create_switch_start_time mean {} is not lower than target mean {}"
                  .format(start_time_stats["mean"], kwargs["mean"]))
    pytest_assert(start_time_stats["quantile_result"] < kwargs["p100"],
                  "swss_create_switch_start_time p100 {} is not lower than target p100 {}"
                  .format(start_time_stats["quantile_result"], kwargs["p100"]))


# utility function to read /proc/meminfo item
def read_meminfo(duthost, item):
    cmd = "cat /proc/meminfo | grep {} | egrep -o '[0-9]+'".format(item)
    return int(duthost.shell(cmd)["stdout"])


def startup_mem_usage_after_bgp_up(request, test_result, **kwargs):
    bgp_up_checker = bgp_up(request, test_result, **kwargs)
    duthost = request.getfixturevalue("duthost")
    mem_total = read_meminfo(duthost, "MemTotal")

    @suppress_exception
    def checker():
        if bgp_up_checker():
            mem_available = read_meminfo(duthost, "MemAvailable")
            test_result["mem_available"] = mem_available
            test_result["mem_used_perc"] = 1 - mem_available / mem_total
            return True
        return False
    return checker


def startup_mem_usage_after_bgp_up_stats(passed_op_precheck, **kwargs):
    variable_stats = display_variable_stats(passed_op_precheck,
                                            **{**kwargs,
                                               "display_variables": ["time_to_pass", "mem_used_perc"],
                                               "time_to_pass_quantile": 0.90,
                                               "mem_used_perc_quantile": 0.90})
    bgp_up_stats = variable_stats["time_to_pass"]
    target_bgp_up_stats = filter_vars(kwargs, "bgp_up")
    pytest_assert(bgp_up_stats["mean"] < target_bgp_up_stats["mean"],
                  "bgp_up mean {} is not lower than target mean {}".format(bgp_up_stats["mean"],
                                                                           target_bgp_up_stats["mean"]))
    pytest_assert(bgp_up_stats["quantile_result"] < target_bgp_up_stats["p90"],
                  "bgp_up p90 {} is not lower than target p90 {}".format(bgp_up_stats["quantile_result"],
                                                                         target_bgp_up_stats["p90"]))
    mem_used_perc_stats = variable_stats["mem_used_perc"]
    target_mem_used_perc_stats = filter_vars(kwargs, "mem_used_perc")
    pytest_assert(mem_used_perc_stats["mean"] < target_mem_used_perc_stats["mean"],
                  "mem_used_perc mean {} is not lower than target mem_used_perc mean {}"
                  .format(mem_used_perc_stats["mean"], target_mem_used_perc_stats["mean"]))
    pytest_assert(mem_used_perc_stats["quantile_result"] < target_mem_used_perc_stats["p90"],
                  "mem_used_perc p90 {} is not lower than target mem_used_perc p90 {}"
                  .format(mem_used_perc_stats["quantile_result"], target_mem_used_perc_stats["p90"]))
