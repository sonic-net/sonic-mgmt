
import logging
import random
import copy
import json

import pytest

import constants
from checks import do_checks, print_logs
from recover import recover
from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


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
        if new_item[0] == "-":      # Remove default check item
            new_item = new_item[1:]
            if new_item in updated_items:
                logger.info("Skip checking '%s'" % new_item)
                updated_items.remove(new_item)
        else:                       # Add a check item
            if new_item[0] == "+":
                new_item = new_item[1:]
            if new_item in supported_items:
                logger.info("Add checking '%s'" % new_item)
                updated_items.add(new_item)
            else:
                logger.warning("Unsupported sanity checking: '%s'" % new_item)
    return updated_items


@pytest.fixture(scope="module", autouse=True)
def sanity_check(localhost, duthosts, request, fanouthosts, tbinfo):
    logger.info("Start pre-test sanity check")

    skip_sanity = False
    allow_recover = False
    recover_method = "adaptive"
    check_items = set(copy.deepcopy(constants.DEFAULT_CHECK_ITEMS))  # Default check items
    post_check = False

    customized_sanity_check = None
    for m in request.node.iter_markers():
        logger.info("Found marker: m.name=%s, m.args=%s, m.kwargs=%s" % (m.name, m.args, m.kwargs))
        if m.name == "sanity_check":
            customized_sanity_check = m
            break

    if customized_sanity_check:
        logger.info("Process marker %s in script. m.args=%s, m.kwargs=%s" % (m.name, str(m.args), str(m.kwargs)))
        skip_sanity = customized_sanity_check.kwargs.get("skip_sanity", False)
        allow_recover = customized_sanity_check.kwargs.get("allow_recover", False)
        recover_method = customized_sanity_check.kwargs.get("recover_method", "adaptive")
        if allow_recover and recover_method not in constants.RECOVER_METHODS:
            pytest.warning("Unsupported recover method")
            logger.info("Fall back to use default recover method 'config_reload'")
            recover_method = "config_reload"

        check_items = _update_check_items(check_items,
                                          customized_sanity_check.kwargs.get("check_items", []),
                                          constants.SUPPORTED_CHECK_ITEMS)
        post_check = customized_sanity_check.kwargs.get("post_check", False)

    if request.config.option.skip_sanity:
        skip_sanity = True
    if request.config.option.allow_recover:
        allow_recover = True
    items = request.config.getoption("--check_items")
    if items:
        items_array=str(items).split(',')
        check_items = _update_check_items(check_items, items_array, constants.SUPPORTED_CHECK_ITEMS)

    # ignore BGP check for particular topology type
    if tbinfo['topo']['type'] == 'ptf' and 'bgp' in check_items:
        check_items.remove('bgp')

    logger.info("Sanity check settings: skip_sanity=%s, check_items=%s, allow_recover=%s, recover_method=%s, post_check=%s" % \
        (skip_sanity, check_items, allow_recover, recover_method, post_check))

    if skip_sanity:
        logger.info("Skip sanity check according to command line argument or configuration of test script.")
        yield
        return

    if not check_items:
        logger.info("No sanity check item is specified, no pre-test sanity check")
        yield
        logger.info("No sanity check item is specified, no post-test sanity check")
        return

    print_logs(duthosts, constants.PRINT_LOGS)
    check_results = do_checks(duthosts, check_items)
    logger.info("!!!!!!!!!!!!!!!! Pre-test sanity check results: !!!!!!!!!!!!!!!!\n%s" % \
                json.dumps(check_results, indent=4))

    pre_sanity_failed = False
    for a_dutname, a_dut_results in check_results.items():
        if any([result["failed"] for result in a_dut_results]):
            pre_sanity_failed = True
            if not allow_recover:
                failed_items = json.dumps([result for result in a_dut_results if result["failed"]], indent=4)
                logger.error("On {}, failed pre-sanity check items with allow_recover=False:\n{}".format(a_dutname, failed_items))
            else:
                logger.info("Pre-test sanity check failed on %s, try to recover, recover_method=%s" % (a_dutname, recover_method))
                recover(duthosts[a_dutname], localhost, fanouthosts, a_dut_results, recover_method)

    pt_assert(allow_recover or not pre_sanity_failed, "Pre-test sanity check failed on DUTs, allow_recover=False:{}".format(check_results))

    if allow_recover and pre_sanity_failed:
        logger.info("Run sanity check again after recovery")
        new_check_results = do_checks(duthosts, check_items)
        logger.info("!!!!!!!!!!!!!!!! Pre-test sanity check after recovery results: !!!!!!!!!!!!!!!!\n%s" % \
                    json.dumps(new_check_results, indent=4))
        pre_sanity_failed_after_recover = False
        for a_dutname, a_dut_new_results in new_check_results.items():
            if any([result["failed"] for result in a_dut_new_results]):
                pre_sanity_failed_after_recover = True
                failed_items = json.dumps([result for result in a_dut_new_results if result["failed"]], indent=4)
                logger.error("On {}, failed check items after recover:\n{}".format(a_dutname, failed_items))

        pt_assert(not pre_sanity_failed_after_recover, "Pre-test sanity check failed on DUTs after recover:\n{}".format(new_check_results))

    logger.info("Done pre-test sanity check")

    yield

    logger.info("Start post-test sanity check")

    if not post_check:
        logger.info("No post-test check is required. Done post-test sanity check")
        return

    post_check_results = do_checks(duthosts, check_items)
    logger.info("!!!!!!!!!!!!!!!! Post-test sanity check results: !!!!!!!!!!!!!!!!\n%s" % \
                json.dumps(post_check_results, indent=4))
    post_sanity_failed = False
    for a_dutname, a_dut_post_results in post_check_results.items():
        if any([result["failed"] for result in a_dut_post_results]):
            post_sanity_failed = True
            failed_items = json.dumps([result for result in a_dut_new_results if result["failed"]], indent=4)
            logger.error("On {}, failed check items after recover:\n{}".format(a_dutname, failed_items))

    pt_assert(not post_sanity_failed, "Post-test sanity check failed on DUTs after recover:\n{}".format(post_check_results))

    logger.info("Done post-test sanity check")
    return
