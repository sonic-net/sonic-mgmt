
import logging
import copy
import json

import pytest

from inspect import getmembers, isfunction
from collections import defaultdict

from tests.common.plugins.sanity_check import constants
from tests.common.plugins.sanity_check import checks
from tests.common.plugins.sanity_check.checks import *
from tests.common.plugins.sanity_check.recover import recover
from tests.common.plugins.sanity_check.constants import STAGE_PRE_TEST, STAGE_POST_TEST
from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


def is_check_item(member):
    '''
    Function to filter for valid check items

    Used in conjunction with inspect.getmembers to make sure that only valid check functions/fixtures executed

    Valid check items must meet the following criteria:
    - Is a function
    - Is defined directly in sanity_checks/checks.py, NOT imported from another file
    - Begins with the string 'check_'

    Args:
        member (object): The object to checked
    Returns:
        (bool) True if 'member' is a valid check function, False otherwise
    '''
    if isfunction(member):
        in_check_file = member.__module__ == 'tests.common.plugins.sanity_check.checks'
        starts_with_check = member.__name__.startswith('check_')
        return in_check_file and starts_with_check
    else:
        return False


SUPPORTED_CHECKS = [member[0].replace('check_', '') for member in getmembers(checks, is_check_item)]


def _item2fixture(item):
    return 'check_' + item


def _update_check_items(old_items, new_items, supported_items):
    """
    @summary: Update the items to be performed in sanity check
    @param old_items: Existing items to be checked. Should be a Set.
    @param new_items: Iterable. Items to be added or removed.
    @param supported_items: The sanity check items that are currently supported.
    """
    updated_items = copy.deepcopy(old_items)
    for new_item in new_items:
        if not new_item:
            continue
        if new_item[0] in ["_", "-"]:      # Skip a check item
            new_item = new_item[1:]
            if new_item in updated_items:
                logger.info("Skip checking '%s'" % new_item)
                updated_items.remove(new_item)
        else:                       # Add a check item
            if new_item[0] == "+":
                new_item = new_item[1:]
            if new_item in supported_items :
                if new_item not in updated_items:
                    logger.info("Add checking '{}'".format(new_item))
                    updated_items.add(new_item)
            else:
                logger.warning('Check item "{}" no in supported check items: {}'.format(new_item, supported_items))
    return updated_items


def print_logs(duthosts):
    for dut in duthosts:
        logger.info("Run commands to print logs")

        cmds = constants.PRINT_LOGS.values()
        results = dut.shell_cmds(cmds=cmds, module_ignore_errors=True, verbose=False)['results']
        outputs = []
        for res in results:
            res.pop('stdout')
            res.pop('stderr')
            outputs.append(res)
        logger.info(json.dumps(outputs, indent=4))


def filter_check_items(tbinfo, check_items):
    filtered_check_items = copy.deepcopy(check_items)

    # ignore BGP check for particular topology type
    if tbinfo['topo']['type'] == 'ptf' and 'bgp' in filtered_check_items:
        filtered_check_items.remove('bgp')

    if 'dualtor' not in tbinfo['topo']['name'] and 'mux_simulator' in filtered_check_items:
        filtered_check_items.remove('mux_simulator')

    return filtered_check_items


def do_checks(request, check_items, *args, **kwargs):
    check_results = []
    for item in check_items:
        check_fixture = request.getfixturevalue(_item2fixture(item))
        results = check_fixture(*args, **kwargs)
        if results and isinstance(results, list):
            check_results.extend(results)
        elif results:
            check_results.append(results)
    return check_results


@pytest.fixture(scope="module", autouse=True)
def sanity_check(localhost, duthosts, request, fanouthosts, tbinfo):
    logger.info("Prepare sanity check")

    skip_sanity = False
    allow_recover = False
    recover_method = "adaptive"
    pre_check_items = set(copy.deepcopy(SUPPORTED_CHECKS))  # Default check items
    post_check = False

    customized_sanity_check = None
    for m in request.node.iter_markers():
        logger.info("Found marker: m.name=%s, m.args=%s, m.kwargs=%s" % (m.name, m.args, m.kwargs))
        if m.name == "sanity_check":
            customized_sanity_check = m
            break

    if customized_sanity_check:
        logger.info("Process marker {} in script. m.args={}, m.kwargs={}"
            .format(customized_sanity_check.name, customized_sanity_check.args, customized_sanity_check.kwargs))
        skip_sanity = customized_sanity_check.kwargs.get("skip_sanity", False)
        allow_recover = customized_sanity_check.kwargs.get("allow_recover", False)
        recover_method = customized_sanity_check.kwargs.get("recover_method", "adaptive")
        if allow_recover and recover_method not in constants.RECOVER_METHODS:
            pytest.warning("Unsupported recover method")
            logger.info("Fall back to use default recover method 'config_reload'")
            recover_method = "config_reload"

        pre_check_items = _update_check_items(
            pre_check_items,
            customized_sanity_check.kwargs.get("check_items", []),
            SUPPORTED_CHECKS)

        post_check = customized_sanity_check.kwargs.get("post_check", False)

    if request.config.option.skip_sanity:
        skip_sanity = True
    if skip_sanity:
        logger.info("Skip sanity check according to command line argument or configuration of test script.")
        yield
        return

    if request.config.option.allow_recover:
        allow_recover = True

    if request.config.option.post_check:
        post_check = True

    cli_check_items = request.config.getoption("--check_items")
    cli_post_check_items = request.config.getoption("--post_check_items")

    if cli_check_items:
        logger.info('Fine tune pre-test check items based on CLI option --check_items')
        cli_items_list=str(cli_check_items).split(',')
        pre_check_items = _update_check_items(pre_check_items, cli_items_list, SUPPORTED_CHECKS)

    pre_check_items = filter_check_items(tbinfo, pre_check_items)  # Filter out un-supported checks.

    if post_check:
        # Prepare post test check items based on the collected pre test check items.
        post_check_items = copy.copy(pre_check_items)
        if customized_sanity_check:
            post_check_items = _update_check_items(
                post_check_items,
                customized_sanity_check.kwargs.get("post_check_items", []),
                SUPPORTED_CHECKS)

        if cli_post_check_items:
            logger.info('Fine tune post-test check items based on CLI option --post_check_items')
            cli_post_items_list = str(cli_post_check_items).split(',')
            post_check_items = _update_check_items(post_check_items, cli_post_items_list, SUPPORTED_CHECKS)

        post_check_items = filter_check_items(tbinfo, post_check_items)  # Filter out un-supported checks.
    else:
        post_check_items = set()

    logger.info("Sanity check settings: skip_sanity=%s, pre_check_items=%s, allow_recover=%s, recover_method=%s, post_check=%s, post_check_items=%s" % \
        (skip_sanity, pre_check_items, allow_recover, recover_method, post_check, post_check_items))

    for item in pre_check_items.union(post_check_items):
        request.fixturenames.append(_item2fixture(item))

        # Workaround for pytest requirement.
        # Each possibly used check fixture must be executed in setup phase. Otherwise there could be teardown error.
        request.getfixturevalue(_item2fixture(item))

    if pre_check_items:
        logger.info("Start pre-test sanity checks")

        # Dynamically attach selected check fixtures to node
        for item in set(pre_check_items):
            request.fixturenames.append(_item2fixture(item))

        print_logs(duthosts)

        check_results = do_checks(request, pre_check_items, stage=STAGE_PRE_TEST)
        logger.debug("Pre-test sanity check results:\n%s" % json.dumps(check_results, indent=4))

        failed_results = [result for result in check_results if result['failed']]
        if failed_results:
            if not allow_recover:
                pt_assert(False, "!!!!!!!!!!!!!!!!Pre-test sanity check failed: !!!!!!!!!!!!!!!!\n{}"\
                    .format(json.dumps(failed_results, indent=4)))
            else:
                dut_failed_results = defaultdict(list)
                for failed_result in failed_results:
                    if 'host' in failed_result:
                        dut_failed_results[failed_result['host']].append(failed_result)
                for dut_name, dut_results in dut_failed_results.items():
                    recover(duthosts[dut_name], localhost, fanouthosts, dut_results, recover_method)

                logger.info("Run sanity check again after recovery")
                new_check_results = do_checks(request, pre_check_items, stage=STAGE_PRE_TEST, after_recovery=True)
                logger.debug("Pre-test sanity check after recovery results:\n%s" % json.dumps(new_check_results, indent=4))

                new_failed_results = [result for result in new_check_results if result['failed']]
                if new_failed_results:
                    pt_assert(False, "!!!!!!!!!!!!!!!! Pre-test sanity check after recovery failed: !!!!!!!!!!!!!!!!\n{}"\
                        .format(json.dumps(new_failed_results, indent=4)))

        logger.info("Done pre-test sanity check")
    else:
        logger.info('No pre-test sanity check item, skip pre-test sanity check.')

    yield

    if not post_check:
        logger.info("No post-test check is required. Done post-test sanity check")
        return

    if post_check_items:
        logger.info("Start post-test sanity check")
        post_check_results = do_checks(request, post_check_items, stage=STAGE_POST_TEST)
        logger.debug("Post-test sanity check results:\n%s" % json.dumps(post_check_results, indent=4))

        post_failed_results = [result for result in post_check_results if result['failed']]
        if post_failed_results:
            pt_assert(False, "!!!!!!!!!!!!!!!! Post-test sanity check failed: !!!!!!!!!!!!!!!!\n{}"\
                .format(json.dumps(post_failed_results, indent=4)))

        logger.info("Done post-test sanity check")
    else:
        logger.info('No post-test sanity check item, skip post-test sanity check.')
