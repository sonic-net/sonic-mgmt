import logging
import random
import statistics
from tests.common.helpers.assertions import pytest_assert


def get_success_criteria_by_name(success_criteria):
    return globals()[success_criteria]


def get_success_criteria_stats_by_name(success_criteria):
    return globals().get(success_criteria + "_stats", None)


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
# etc, and have "timeout", "delay", "foo" etc, as kwargs. kwarg can
# be used to pass any additional arguments and limitations
# from config file to the success criteria function. Additionally a
# timeout is always expected in config file because test can't hang
# forever. A delay is to not run the check for said time, default
# to 0. It is ok to throw exception as it will be handled, but it
# prints to the console, which could be a lot.


# sample success criteria function, returns True 20% of times.
def random_success_20_perc(duthost, **kwarg):
    return lambda: random.random() < 0.2


# Because each test run is separate, success criteria function cannot
# process results of all runs, so there could be an optional success
# criteria stats function, named with a "_stats" suffix, like
# "bgp_up_stats", taking all the same kwarg variables as its single run
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
def random_success_20_perc_stats(passed_op_precheck, **kwarg):
    finished_op = list(filter(lambda item: item["op_success"], passed_op_precheck))
    if "success_rate_op" in kwarg:
        success_rate_op = len(finished_op) / len(passed_op_precheck)
        logging.warning("Success rate of op is {}".format(success_rate_op))
        pytest_assert(success_rate_op >= kwarg["success_rate_op"],
                      "Success rate of op {} is less than expected {}".format(success_rate_op,
                                                                              kwarg["success_rate_op"]))
    passed_success_criteria = list(filter(lambda result: result["passed"], finished_op))
    if "success_rate" in kwarg:
        success_rate = len(passed_success_criteria) / len(finished_op)
        logging.warning("Success rate is {}".format(success_rate))
        pytest_assert(success_rate >= kwarg["success_rate"],
                      "Success rate {} is less than expected {}".format(success_rate, kwarg["success_rate"]))
    if "max" in kwarg:
        max_time_to_pass = max(map(lambda item: item["time_to_pass"], passed_success_criteria))
        logging.warning("Max time_to_pass is {}".format(max_time_to_pass))
        pytest_assert(max_time_to_pass <= kwarg["max"],
                      "Max time_to_pass {} is more than defined max {}".format(max_time_to_pass, kwarg["max"]))
    if "min" in kwarg:
        min_time_to_pass = min(map(lambda item: item["time_to_pass"], passed_success_criteria))
        logging.warning("Min time_to_pass is {}".format(min_time_to_pass))
        pytest_assert(min_time_to_pass >= kwarg["min"],
                      "Min time_to_pass {} is less than defined min {}".format(min_time_to_pass, kwarg["min"]))
    if "mean" in kwarg:
        mean_time_to_pass = statistics.mean(map(lambda item: item["time_to_pass"], passed_success_criteria))
        logging.warning("Mean time_to_pass is {}".format(mean_time_to_pass))
        pytest_assert(mean_time_to_pass <= kwarg["mean"],
                      "Mean time_to_pass {} is more than defined mean {}".format(mean_time_to_pass, kwarg["mean"]))
    logging.warning("Foo is {}".format(kwarg["foo"]))


def bgp_up(duthost, **kwarg):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {}).keys()
    return suppress_exception(lambda: duthost.check_bgp_session_state(bgp_neighbors))
