"""
Tests for the `counterpoll queue/watermark/pg-drop ...` commands in SONiC
"""

import allure
import logging
import random

import pytest

from tests.common.config_reload import config_reload
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import redis_get_keys
from tests.common.utilities import get_inventory_files, get_host_visible_vars
from tests.common.utilities import skip_release
from tests.common.reboot import reboot
from .counterpoll_constants import CounterpollConstants
from .counterpoll_helper import ConterpollHelper

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

ENABLE = CounterpollConstants.COUNTERPOLL_ENABLE.split(' ')[-1]
DISABLE = CounterpollConstants.COUNTERPOLL_DISABLE.split(' ')[-1]

MAPS_LONG_PREFIX = 'COUNTERS_{}_*_MAP'

MAPS = 'maps'
QUEUE_MAPS = {'prefix': 'QUEUE', MAPS: ['COUNTERS_QUEUE_NAME_MAP', 'COUNTERS_QUEUE_INDEX_MAP',
                                        'COUNTERS_QUEUE_TYPE_MAP', 'COUNTERS_QUEUE_PORT_MAP']}

PG_MAPS = {'prefix': 'PG', MAPS: ['COUNTERS_PG_INDEX_MAP', 'COUNTERS_PG_PORT_MAP', 'COUNTERS_PG_NAME_MAP']}

MAPS_PREFIX_FOR_ALL_COUNTERPOLLS = [QUEUE_MAPS['prefix'], PG_MAPS['prefix']]

FLEX_COUNTER_PREFIX = 'FLEX_COUNTER_TABLE:'
RELEVANT_COUNTERPOLLS = [CounterpollConstants.QUEUE, CounterpollConstants.WATERMARK, CounterpollConstants.PG_DROP]
RELEVANT_MAPS = {CounterpollConstants.QUEUE: {MAPS: [QUEUE_MAPS], CounterpollConstants.TYPE:
                                                    [CounterpollConstants.QUEUE_STAT_TYPE]},
                 CounterpollConstants.WATERMARK: {MAPS: [QUEUE_MAPS, PG_MAPS],
                                                  CounterpollConstants.TYPE:
                                                      [CounterpollConstants.QUEUE_WATERMARK_STAT_TYPE,
                                                       CounterpollConstants.PG_WATERMARK_STAT_TYPE]},
                 CounterpollConstants.PG_DROP: {MAPS: [PG_MAPS],
                                                CounterpollConstants.TYPE: [CounterpollConstants.PG_DROP_STAT_TYPE]}
                 }

WATERMARK_COUNTERS_DB_STATS_TYPE = ['USER_WATERMARKS', 'PERSISTENT_WATERMARKS', 'PERIODIC_WATERMARKS']


@pytest.fixture(scope='module')
def dut_vars(duthosts, enum_rand_one_per_hwsku_hostname, request):
    inv_files = get_inventory_files(request)
    dut_vars = get_host_visible_vars(inv_files, enum_rand_one_per_hwsku_hostname)
    yield dut_vars


def test_counterpoll_queue_watermark_pg_drop(duthosts, localhost, enum_rand_one_per_hwsku_hostname, dut_vars,
                                             backup_and_restore_config_db):     # noqa F811
    """
    @summary: Verify FLEXCOUNTERS_DB and COUNTERS_DB content after `counterpoll queue/watermark/queue enable`

    this test runs the following steps once with config reload between counterpolls enabled,
     and once with switch reboot:
    1. Disable the counter polling for all counters
    2. save and reboot or reload configuration (randomized)
    3. run one of the (type[watermark,queue,pg-drop]) (randomized)
        a. queue: enable the queue counter polling, check whether queue map is generated in COUNTERS_DB,
           no WATERMARK or PG-DROP stats in FLEX_COUNTER_DB
        b. watermark: enable the watermark counter polling, check whether PG and queue maps are generated in COUNTER_DB
           and both PG and QUEUE WATERMARK stats exists in FLEX_COUNTER_DB, without any QUEUE or PG-DROP stats
           for watermark also check WATERMARK stats in COUNTERS_DB (USER/PERSISTENT/PERIODIC WATERMARKS)
        c. pg-drop: enable the pg-drop counter polling, check whether PG map is generated in COUNTERS_DB
           no WATERMARK or QUEUE stats in FLEX_COUNTER_DB
    4. enables all three counterpolls (queue,watermark,pg-drop) and count stats per type
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["202205", "202111", "202106", "202012", "201911", "201811", "201803"])

    counted_dict = {}
    # choosing only one between reload / reboot due to test duration limitations
    with allure.step("choosing random config apply method"):
        config_apply_method = random.choice(["config reload", "switch reboot"])
    with allure.step("disabling all counterpolls"):
        ConterpollHelper.disable_counterpoll(duthost, list(CounterpollConstants.COUNTERPOLL_MAPPING.values()))

    # verify relevant counterpolls (queue/watermark/pg-drop) are disabled
    with allure.step("Verifying initial output of {} on {} ..."
                     .format(CounterpollConstants.COUNTERPOLL_SHOW, duthost.hostname)):
        verify_all_counterpoll_status(duthost, DISABLE)

    with allure.step("saving config on dut {} after counterpoll disable...".format(duthost.hostname)):
        duthost.shell('config save -y')

    # choosing only one counterpoll to test due to test duration limitaions
    tested_counterpoll = random.choice(RELEVANT_COUNTERPOLLS)
    # need reload or reboot after disabling counterpolls to clean DB stats, this is by design
    with allure.step(config_apply_method + " dut {} ...".format(duthost.hostname)):
        if 'reload' in config_apply_method:
            config_reload(duthost)
        elif 'reboot' in config_apply_method:
            reboot(duthost, localhost)
    # verify all counterpolls are disabled after reload or reboot
    with allure.step("Verifying output of {} on {} after {} ..."
                     .format(CounterpollConstants.COUNTERPOLL_SHOW, duthost.hostname, config_apply_method)):
        verify_all_counterpoll_status(duthost, DISABLE)
    # enable the selected counterpoll queue/watermark/pg-drop
    with allure.step("enabling and verify randomly selected counterpoll {} on {} ..."
                     .format(duthost.hostname, [tested_counterpoll])):
        ConterpollHelper.enable_counterpoll(duthost, [tested_counterpoll])
        verify_counterpoll_status(duthost, [tested_counterpoll], ENABLE)

    # verify QUEUE or PG maps are generated into COUNTERS_DB after enabling relevant counterpoll
    with allure.step("Verifying MAPS in COUNTERS_DB on {}...".format(duthost.hostname)):
        maps_dict = RELEVANT_MAPS[tested_counterpoll]
        maps_to_verify = maps_dict[MAPS]
        for map_to_verify in maps_to_verify:
            map_prefix = map_to_verify['prefix']
            maps = map_to_verify[MAPS]
            map_output = redis_get_keys(duthost, 'COUNTERS_DB', MAPS_LONG_PREFIX.format(map_prefix))
            map = []
            failed = ""
            for map_entry in maps:
                map.append(map_entry)
            msg = "no {} maps found in COUNTERS_DB".format(map_prefix)
            pytest_assert(map_output, msg)
            for line in map_output:
                try:
                    map.remove(line)
                except ValueError:
                    failed = "MAP {} was not found in {} MAPS list".format(line, map_prefix)
            pytest_assert("" == failed, failed)
            pytest_assert(len(map) == 0, "{} maps mismatch, one or more queue was not found in redis COUNTERS_DB"
                          .format(map_prefix))

    failed_list = []
    with allure.step("Verifying {} STATS in FLEX_COUNTER_DB on {}...".format(tested_counterpoll, duthost.hostname)):
        stats_output = redis_get_keys(duthost, 'FLEX_COUNTER_DB', '*{}*'.format(map_prefix))
        counted = 0
        # build expected counterpoll stats vs unexpected
        expected_types = []
        unexpected_types = []
        for counterpoll, v in list(RELEVANT_MAPS.items()):
            types_to_check = v[CounterpollConstants.TYPE]
            if counterpoll in tested_counterpoll:
                for type in types_to_check:
                    expected_types.append(FLEX_COUNTER_PREFIX + type)
            else:
                for type in types_to_check:
                    unexpected_types.append(FLEX_COUNTER_PREFIX + type)
        logging.info("expected types for for counterpoll {}:\n{}".format(tested_counterpoll, expected_types))
        logging.info("unexpected types for for counterpoll {}:\n{}".format(tested_counterpoll, unexpected_types))
        for line in stats_output:
            for expected in expected_types:
                if expected in line:
                    counted += 1
            for unexpected in unexpected_types:
                if unexpected in line:
                    failed_list.append("found for {} unexpected stat counter in FLEX_COUNTER_DB: {}"
                                       .format(tested_counterpoll, line))
        logging.info("counted {} {} STATs type in FLEX_COUNTER_DB on {}..."
                     .format(counted, tested_counterpoll, duthost.hostname))
        pytest_assert(len(failed_list) == 0, failed_list)
        pytest_assert(counted > 0, "counted {} for {}".format(counted, tested_counterpoll))

    # for watermark only, also count stats with actual values in COUNTERS_DB
    if CounterpollConstants.WATERMARK in tested_counterpoll:
        with allure.step("counting {} STATS in FLEX_COUNTER_DB on {}...".format(tested_counterpoll, duthost.hostname)):
            count_watermark_stats_in_counters_db(duthost)

    pytest_assert([] == failed_list, failed_list)

    # no need for reload or reboot when enabling all queue/watermark/pg-drop counterpolls
    with allure.step("enable and verify all {} counterpolls on {} ..."
                     .format(RELEVANT_COUNTERPOLLS, duthost.hostname)):
        ConterpollHelper.enable_counterpoll(duthost, RELEVANT_COUNTERPOLLS)
        verify_counterpoll_status(duthost, RELEVANT_COUNTERPOLLS, ENABLE)
    # count FLEXCOUNTER_DB countrpolls and put in results dict key per countrpoll
    with allure.step("check all counterpolls {} results on {} ...".format(RELEVANT_COUNTERPOLLS, duthost.hostname)):
        for counterpoll in RELEVANT_COUNTERPOLLS:
            counted_dict[counterpoll] = 0
        for map_prefix in MAPS_PREFIX_FOR_ALL_COUNTERPOLLS:
            stats_output = redis_get_keys(duthost, 'FLEX_COUNTER_DB', '*{}*'.format(map_prefix))
            for line in stats_output:
                for counterpoll, v in list(RELEVANT_MAPS.items()):
                    types_to_check = v[CounterpollConstants.TYPE]
                    for type in types_to_check:
                        if type in line:
                            counted_dict[counterpoll] += 1
        logging.info("counted_dict {}".format(counted_dict))
    # verify each queue/watermark/pg-drop counterpoll has stats in FLEX_COUNTER_DB
    for counterpoll in RELEVANT_COUNTERPOLLS:
        pytest_assert(counted_dict[counterpoll] > 0)
    # for watermark only, also count stats with actual values in COUNTERS_DB
    with allure.step("counting watermark STATS in FLEX_COUNTER_DB on {}...".format(duthost.hostname)):
        count_watermark_stats_in_counters_db(duthost)


def verify_all_counterpoll_status(duthost, expected):
    verify_counterpoll_status(duthost, RELEVANT_COUNTERPOLLS, expected)


def verify_counterpoll_status(duthost, counterpoll_list, expected):
    with allure.step("verifying {} for {} in output of {} on {}..."
                     .format(expected, counterpoll_list, CounterpollConstants.COUNTERPOLL_SHOW, duthost.hostname)):
        counterpoll_output = ConterpollHelper.get_counterpoll_show_output(duthost)
        pytest_assert(len(counterpoll_output) > 0, "cmd {} returns no output"
                      .format(CounterpollConstants.COUNTERPOLL_SHOW))

        verified_output_dict = {}
        for counterpoll_parsed_dict in counterpoll_output:
            for k, v in list(CounterpollConstants.COUNTERPOLL_MAPPING.items()):
                if k in counterpoll_parsed_dict[CounterpollConstants.TYPE]:
                    verified_output_dict[v] = counterpoll_parsed_dict[CounterpollConstants.STATUS]

        # Validate all of the relevant keys are disabled - QUEUE/WATERMARK/PG-DROP
        for counterpoll in counterpoll_list:
            pytest_assert(expected in verified_output_dict[counterpoll], "{} is {}. expected to be {}"
                          .format(counterpoll, verified_output_dict[counterpoll], expected))


def count_watermark_stats_in_counters_db(duthost):
    watermark_stats_output = redis_get_keys(duthost, 'COUNTERS_DB', '*{}*'
                                            .format(CounterpollConstants.WATERMARK.upper()))
    watermark_stats = {}
    for watermark_type in WATERMARK_COUNTERS_DB_STATS_TYPE:
        watermark_stats[watermark_type] = 0
        for line in watermark_stats_output:
            if watermark_type in line:
                watermark_stats[watermark_type] += 1
    logging.info("watermark_stats {}".format(watermark_stats))
    for k, v in list(watermark_stats.items()):
        pytest_assert(v > 0, "watermark_stats {} in COUNTERS_DB: {}, expected > 0".format(k, v))
