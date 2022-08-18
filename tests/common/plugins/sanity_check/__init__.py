
import logging
import copy
import json

import pytest

from collections import defaultdict

from tests.common.plugins.sanity_check import constants
from tests.common.plugins.sanity_check import checks
from tests.common.plugins.sanity_check.checks import *
from tests.common.plugins.sanity_check.recover import recover
from tests.common.plugins.sanity_check.recover import neighbor_vm_restore
from tests.common.plugins.sanity_check.constants import STAGE_PRE_TEST, STAGE_POST_TEST
from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)

SUPPORTED_CHECKS = checks.CHECK_ITEMS


def pytest_sessionfinish(session, exitstatus):
    if session.config.cache.get("sanity_check_failed", None):
        session.config.cache.set("sanity_check_failed", None)
        session.exitstatus = constants.SANITY_CHECK_FAILED_RC


def fallback_serializer(_):
    """
    Fallback serializer for non JSON serializable objects

    Used for json.dumps
    """
    return '<not serializable>'


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
                    updated_items.append(new_item)
            else:
                logger.warning('Check item "{}" no in supported check items: {}'.format(new_item, supported_items))
    return updated_items


def print_logs(duthosts, print_dual_tor_logs=False):
    for dut in duthosts:
        logger.info("Run commands to print logs")

        cmds = list(constants.PRINT_LOGS.values())

        if print_dual_tor_logs is False:
            cmds.remove(constants.PRINT_LOGS['mux_status'])
            cmds.remove(constants.PRINT_LOGS['mux_config'])

        results = dut.shell_cmds(cmds=cmds, module_ignore_errors=True, verbose=False)['results']
        outputs = []
        for res in results:
            res.pop('stdout')
            res.pop('stderr')
            outputs.append(res)
        logger.info("dut={}, cmd_outputs={}".format(dut.hostname,json.dumps(outputs, indent=4)))


def filter_check_items(tbinfo, check_items):
    filtered_check_items = copy.deepcopy(check_items)

    # ignore BGP check for particular topology type
    if tbinfo['topo']['type'] == 'ptf' and 'check_bgp' in filtered_check_items:
        filtered_check_items.remove('check_bgp')

    if 'dualtor' not in tbinfo['topo']['name'] and 'check_mux_simulator' in filtered_check_items:
        filtered_check_items.remove('check_mux_simulator')

    return filtered_check_items


def do_checks(request, check_items, *args, **kwargs):
    check_results = []
    for item in check_items:
        check_fixture = request.getfixturevalue(item)
        results = check_fixture(*args, **kwargs)
        logger.debug("check results of each item {}".format(results))
        if results and isinstance(results, list):
            check_results.extend(results)
        elif results:
            check_results.append(results)
    return check_results


@pytest.fixture(scope="module", autouse=True)
def sanity_check(localhost, duthosts, request, fanouthosts, nbrhosts, tbinfo):
    logger.info("Prepare sanity check")

    skip_sanity = False
    allow_recover = False
    recover_method = "adaptive"
    pre_check_items = copy.deepcopy(SUPPORTED_CHECKS)  # Default check items
    post_check = False
    enable_macsec = False

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

    if request.config.option.recover_method:
        recover_method = request.config.getoption("--recover_method")

    if request.config.option.post_check:
        post_check = True

    if request.config.option.enable_macsec:
        enable_macsec = True
        startup_macsec = request.getfixturevalue("startup_macsec")
        start_macsec_service = request.getfixturevalue("start_macsec_service")

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

    pre_post_check_items = pre_check_items + [item for item in post_check_items if item not in pre_check_items]
    for item in pre_post_check_items:
        request.fixturenames.append(item)

        # Workaround for pytest requirement.
        # Each possibly used check fixture must be executed in setup phase. Otherwise there could be teardown error.
        request.getfixturevalue(item)

    if pre_check_items:
        logger.info("Start pre-test sanity checks")

        # Dynamically attach selected check fixtures to node
        for item in set(pre_check_items):
            request.fixturenames.append(item)
        dual_tor = 'dualtor' in tbinfo['topo']['name']
        print_logs(duthosts, print_dual_tor_logs=dual_tor)

        check_results = do_checks(request, pre_check_items, stage=STAGE_PRE_TEST)
        logger.debug("Pre-test sanity check results:\n%s" % json.dumps(check_results, indent=4, default=fallback_serializer))

        failed_results = [result for result in check_results if result['failed']]
        if failed_results:
            if not allow_recover:
                request.config.cache.set("sanity_check_failed", True)
                pt_assert(False, "!!!!!!!!!!!!!!!!Pre-test sanity check failed: !!!!!!!!!!!!!!!!\n{}"\
                    .format(json.dumps(failed_results, indent=4, default=fallback_serializer)))
            else:
                dut_failed_results = defaultdict(list)
                infra_recovery_actions= []
                for failed_result in failed_results:
                    if 'host' in failed_result:
                        dut_failed_results[failed_result['host']].append(failed_result)
                    if 'hosts' in failed_result:
                        for hostname in failed_result['hosts']:
                            dut_failed_results[hostname].append(failed_result)
                    if failed_result['check_item'] in constants.INFRA_CHECK_ITEMS:
                        if 'action' in failed_result and failed_result['action'] is not None \
                            and callable(failed_result['action']):
                            infra_recovery_actions.append(failed_result['action'])
                for dut_name, dut_results in dut_failed_results.items():
                    # Attempt to restore DUT state
                    recover(duthosts[dut_name], localhost, fanouthosts, dut_results, recover_method)
                    # Attempt to restore neighbor VM state
                    neighbor_vm_restore(duthosts[dut_name], nbrhosts, tbinfo)
                for action in infra_recovery_actions:
                    action()

                if enable_macsec:
                    start_macsec_service()
                    startup_macsec()

                logger.info("Run sanity check again after recovery")
                new_check_results = do_checks(request, pre_check_items, stage=STAGE_PRE_TEST, after_recovery=True)
                logger.debug("Pre-test sanity check after recovery results:\n%s" % json.dumps(new_check_results, indent=4, default=fallback_serializer))

                new_failed_results = [result for result in new_check_results if result['failed']]
                if new_failed_results:
                    request.config.cache.set("sanity_check_failed", True)
                    pt_assert(False, "!!!!!!!!!!!!!!!! Pre-test sanity check after recovery failed: !!!!!!!!!!!!!!!!\n{}"\
                        .format(json.dumps(new_failed_results, indent=4, default=fallback_serializer)))

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
        logger.debug("Post-test sanity check results:\n%s" % json.dumps(post_check_results, indent=4, default=fallback_serializer))

        post_failed_results = [result for result in post_check_results if result['failed']]
        if post_failed_results:
            request.config.cache.set("sanity_check_failed", True)
            pt_assert(False, "!!!!!!!!!!!!!!!! Post-test sanity check failed: !!!!!!!!!!!!!!!!\n{}"\
                .format(json.dumps(post_failed_results, indent=4, default=fallback_serializer)))

        logger.info("Done post-test sanity check")
    else:
        logger.info('No post-test sanity check item, skip post-test sanity check.')
