import logging
import random


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
