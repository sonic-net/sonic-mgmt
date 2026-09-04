import collections
import logging
import random
import shlex
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
    hostname_index = line.find(duthost.hostname)
    if hostname_index <= 0:
        raise ValueError("No hostname in syslog line: {}".format(line))
    timestamp = line[:hostname_index - 1]
    formats = ["%Y %b %d %H:%M:%S.%f", "%b %d %H:%M:%S.%f", "%b %d %H:%M:%S"]
    for f in formats:
        try:
            return datetime.datetime.strptime(timestamp, f)
        except ValueError:
            continue
    raise ValueError("Unable to parse {}".format(timestamp))


def _syslog_duration(start, end):
    """Seconds between two syslog timestamps, rejecting an inverted pair.

    timedelta.seconds truncates the fraction and wraps a negative delta to about
    86400, so an out of order pair looks like a plausible result. Fail instead.
    """
    duration = (end - start).total_seconds()
    if duration < 0:
        raise ValueError("End marker {} precedes start marker {}".format(end, start))
    return duration


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
                test_result[kwargs["result_variable"]] = _syslog_duration(syslog_start, timestamp)
                return True
        return False
    return syslog_checker


DEFAULT_SYSLOG_PATH = "/var/log/syslog"
START_POLICIES = ("first", "last")

SyslogWindow = collections.namedtuple(
    "SyslogWindow", ["start", "end", "start_count", "end_count"])


def _read_syslog_position(duthost, syslog_path):
    """Inode and byte length of syslog, so later reads can skip what is already there."""
    stat = duthost.shell("stat -c '%i %s' {}".format(shlex.quote(syslog_path)))["stdout"]
    inode, size = stat.split()
    return int(inode), int(size)


def _appended_lines_command(syslog_path, inode, size, marks):
    """Shell command yielding marker lines appended to syslog since (inode, size).

    Replaces "show logging", which concatenates the rotated and current logs in
    full on every call. Falls back to both files if the log rotated meanwhile.
    """
    path = shlex.quote(syslog_path)
    rotated = shlex.quote(syslog_path + ".1")
    patterns = " ".join("-e {}".format(shlex.quote(mark)) for mark in marks)

    not_rotated = '[ "$(stat -c %i {} 2>/dev/null)" = "{}" ]'.format(path, inode)
    read_appended = "tail -c +{} {}".format(size + 1, path)
    read_both_files = "cat {} {}".format(rotated, path)

    return ("if {}; then {}; elif [ -f {} ]; then {}; else cat {}; fi"
            " | grep -F {} | grep -v ansible || true").format(
                not_rotated, read_appended, rotated, read_both_files, path, patterns)


def _select_syslog_window(duthost, output, baseline, start_mark, end_mark, start_policy):
    """Pick the measurement window from collected marker lines, or None if incomplete.

    A single reload can log more than one start marker, so start_policy decides
    which one pairs with the final end marker rather than leaving it to read order.
    """
    starts = []
    ends = []
    for line in output.splitlines():
        if start_mark not in line and end_mark not in line:
            continue
        try:
            timestamp = _extract_timestamp(duthost, line)
        except ValueError:
            logging.debug("Skipping unparsable syslog line %s", line)
            continue
        if timestamp <= baseline:
            continue
        if start_mark in line:
            starts.append(timestamp)
        if end_mark in line:
            ends.append(timestamp)

    if not starts or not ends:
        return None
    end = max(ends)
    candidates = sorted(timestamp for timestamp in starts if timestamp <= end)
    if not candidates:
        return None
    start = candidates[0] if start_policy == "first" else candidates[-1]
    return SyslogWindow(start, end, len(candidates), len(ends))


def success_criteria_by_bounded_syslog(request, test_result, **kwargs):
    """success_criteria_by_syslog, but each poll reads only newly appended syslog.

    The result comes from timestamps the DUT wrote itself, so work done while
    polling lands inside the interval being measured and inflates it.
    """
    duthost = request.getfixturevalue("duthost")
    start_mark = kwargs["syslog_start_mark"]
    end_mark = kwargs["syslog_end_mark"]
    result_variable = kwargs["result_variable"]

    start_policy = kwargs.get("start_policy", "last")
    if start_policy not in START_POLICIES:
        raise ValueError("start_policy must be one of {}, got {}".format(
            START_POLICIES, start_policy))

    syslog_path = kwargs.get("syslog_path", DEFAULT_SYSLOG_PATH)
    baseline = _get_last_timestamp(duthost)
    inode, size = _read_syslog_position(duthost, syslog_path)
    command = _appended_lines_command(syslog_path, inode, size, [start_mark, end_mark])

    @suppress_exception
    def syslog_checker():
        output = duthost.shell(command)["stdout"]
        window = _select_syslog_window(
            duthost, output, baseline, start_mark, end_mark, start_policy)
        if window is None:
            return False
        test_result[result_variable] = _syslog_duration(window.start, window.end)
        test_result[result_variable + "_start_count"] = window.start_count
        test_result[result_variable + "_end_count"] = window.end_count
        return True
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
    end_mark = "main: Create a switch, id:"
    result_variable = "swss_create_switch_start_time"

    if kwargs.get("log_read_mode") == "bounded":
        return success_criteria_by_bounded_syslog(request, test_result, **dict(
            kwargs,
            syslog_start_mark=start_mark,
            syslog_end_mark=end_mark,
            result_variable=result_variable))

    show_logging = "show logging | grep '{}' | grep -v ansible | tail -n 1"
    return success_criteria_by_syslog(request, test_result, **dict(
        kwargs,
        syslog_start_cmd=show_logging.format(start_mark),
        syslog_end_cmd=show_logging.format(end_mark),
        result_variable=result_variable))


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
