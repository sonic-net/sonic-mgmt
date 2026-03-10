import re
import math
import time
import pytest
import logging
import datetime
import functools

from tests.common.helpers.assertions import pytest_assert
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance


logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]

QUIET = 'QUIET'
SHORT_WAIT = 'SHORT_WAIT'
LONG_WAIT = 'LONG_WAIT'
PENDING_REGEX = re.compile(r'Pending, due in (\d+) msec')
RUN_REGEX = re.compile(r'Still runs for (\d+) msec')


@pytest.fixture(scope="module", autouse=True)
def isis_set_isis_ietf_spf_params(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key_list = ['spf_init_delay', 'spf_short_delay', 'spf_long_delay', 'spf_hold_down', 'spf_time_to_learn']
    config_dict = {'spf_init_delay': '1000',
                   'spf_short_delay': '25000',
                   'spf_long_delay': '35000',
                   'spf_hold_down': '50000',
                   'spf_time_to_learn': '40000'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, config_key_list)
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def get_isis_level2_spf_facts(dut_host):
    isis_facts = dut_host.isis_facts()["ansible_facts"]['isis_facts']
    isis_facts['spf_delay_ietf'][isis_instance]['Level-2'].update(isis_facts['summary'][isis_instance]['level_2'])
    return isis_facts['spf_delay_ietf'][isis_instance]['Level-2']


def trigger_lsp_update(nbr_host, nbr_port):
    nbr_host.set_isis_metric(nbr_port, '1000')
    nbr_host.no_isis_metric(nbr_port)


def wait_for_quiet_state(dut_host):
    spf_facts = get_isis_level2_spf_facts(dut_host)
    if spf_facts['spf_delay_status'] == 'Not scheduled' and spf_facts['state'] == QUIET:
        return spf_facts

    pending_time = holddown_time = 0
    if PENDING_REGEX.match(spf_facts['spf_delay_status']):
        pending_time = PENDING_REGEX.match(spf_facts['spf_delay_status']).group(1)

    if RUN_REGEX.match(spf_facts['holddown_state']):
        holddown_time = RUN_REGEX.match(spf_facts['holddown_state']).group(1)

    wait_time = math.ceil(max(int(pending_time), int(holddown_time)) / 1000.0)
    time.sleep(wait_time)

    spf_facts = get_isis_level2_spf_facts(dut_host)

    pytest_assert(spf_facts['spf_delay_status'] == 'Not scheduled',
                  'IS-IS spf delay status {} is not "Not scheduled".'.format(spf_facts['spf_delay_status']))
    pytest_assert(spf_facts['state'] == QUIET,
                  'IS-IS spf state {} is not {}.'.format(spf_facts['state'], QUIET))
    return spf_facts


def wait_for_short_wait_state(dut_host, nbr_host, nbr_port):
    spf_facts = get_isis_level2_spf_facts(dut_host)
    if spf_facts['state'] == SHORT_WAIT and PENDING_REGEX.match(spf_facts['spf_delay_status']) is None:
        return spf_facts
    wait_for_quiet_state(dut_host)
    trigger_lsp_update(nbr_host, nbr_port)
    spf_facts = get_isis_level2_spf_facts(dut_host)
    # if spf_facts['state'] is in LONG_WAIT, it means time_to_learn is timeout
    # because the two operation caused too much time.
    pytest_assert(spf_facts['state'] == SHORT_WAIT,
                  'IS-IS spf state {} is not {}.'.format(spf_facts['state'], SHORT_WAIT))
    return spf_facts


def wait_for_long_wait_state(dut_host, nbr_host, nbr_port):
    spf_facts = get_isis_level2_spf_facts(dut_host)
    if spf_facts['state'] == LONG_WAIT:
        return spf_facts
    # 1. Short wait but time to learn still run, wait for time_to_learn expire
    if spf_facts['state'] == SHORT_WAIT:
        pytest_assert(spf_facts['timetolearn_state'] != 'Inactive',
                      'IS-IS spf timetolearn is in not in running state.')
        wait_time = math.ceil(int(RUN_REGEX.match(spf_facts['timetolearn_state']).group(1)) / 1000.0)
    else:
        # 2. Wait for quiet state, trigger lsp update and wait time to learn to expire
        wait_for_quiet_state(dut_host)
        trigger_lsp_update(nbr_host, nbr_port)
        wait_time = math.ceil(int(spf_facts['timetolearn_timer']) / 1000.0)
    time.sleep(wait_time)
    spf_facts = get_isis_level2_spf_facts(dut_host)
    pytest_assert(spf_facts['state'] == LONG_WAIT,
                  'IS-IS spf state {} is not {}.'.format(spf_facts['state'], LONG_WAIT))
    return spf_facts


@pytest.mark.parametrize("spf_state", [QUIET, SHORT_WAIT, LONG_WAIT])
def test_isis_spf_ietf_delay_igp_event(isis_common_setup_teardown, spf_state):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    if spf_state == QUIET:
        wait_for_quiet_state(dut_host)
    elif spf_state == SHORT_WAIT:
        pre_spf_facts = wait_for_short_wait_state(dut_host, nbr_host, nbr_port)
    elif spf_state == LONG_WAIT:
        pre_spf_facts = wait_for_long_wait_state(dut_host, nbr_host, nbr_port)

    start_time = datetime.datetime.now()

    trigger_lsp_update(nbr_host, nbr_port)
    spf_facts = get_isis_level2_spf_facts(dut_host)

    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    time_diff = time_diff.total_seconds() * 1000

    # with IGP event, timer should start in all state
    pytest_assert(spf_facts['spf_delay_status'] != 'Not scheduled',
                  'IS-IS spf timer is not start in {} state: {}.'.format(spf_state, spf_facts['spf_delay_status']))
    if spf_state == QUIET:
        pytest_assert(spf_facts['state'] == SHORT_WAIT,
                      'IS-IS spf state {} is not {}.'.format(spf_facts['state'], SHORT_WAIT))
        pytest_assert(RUN_REGEX.match(spf_facts['holddown_state']),
                      'IS-IS spf holddown state: {} and timer is not start.'.format(spf_facts['holddown_state']))
        pytest_assert(RUN_REGEX.match(spf_facts['timetolearn_state']),
                      'IS-IS spf timetolearn state: {} and timer is not start.'.format(spf_facts['timetolearn_state']))

    if spf_state == SHORT_WAIT or spf_state == LONG_WAIT:
        pytest_assert(spf_facts['state'] == spf_state,
                      'IS-IS spf state {} is not {}'.format(spf_facts['state'], spf_state))
        pytest_assert(RUN_REGEX.match(pre_spf_facts['holddown_state']),
                      'IS-IS spf holddown timer is not running in {}.'.format(spf_state))
        pytest_assert(RUN_REGEX.match(spf_facts['holddown_state']),
                      'IS-IS spf holddown timer is not running in {}.'.format(spf_state))
        pre_holddown_time = int(RUN_REGEX.match(pre_spf_facts['holddown_state']).group(1))
        holddown_time = int(RUN_REGEX.match(spf_facts['holddown_state']).group(1))
        pytest_assert(holddown_time > pre_holddown_time - time_diff,
                      'IS-IS spf holddown timer is not refreshed.')


@pytest.mark.parametrize("spf_state", [QUIET, SHORT_WAIT, LONG_WAIT])
def test_isis_spf_ietf_delay_timeout(isis_common_setup_teardown, spf_state):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    if spf_state == QUIET:
        pre_spf_facts = wait_for_quiet_state(dut_host)
    elif spf_state == SHORT_WAIT:
        pre_spf_facts = wait_for_short_wait_state(dut_host, nbr_host, nbr_port)
    elif spf_state == LONG_WAIT:
        pre_spf_facts = wait_for_long_wait_state(dut_host, nbr_host, nbr_port)

    if pre_spf_facts['spf_delay_status'] == 'Not scheduled':
        trigger_lsp_update(nbr_host, nbr_port)
        pre_spf_facts = get_isis_level2_spf_facts(dut_host)

    pytest_assert(PENDING_REGEX.match(pre_spf_facts['spf_delay_status']),
                  'IS-IS spf timer is not running in {}.'.format(spf_state))

    wait_time = math.ceil(int(PENDING_REGEX.match(pre_spf_facts['spf_delay_status']).group(1)) / 1000.0)
    time.sleep(wait_time)
    spf_facts = get_isis_level2_spf_facts(dut_host)

    pre_run_cnt = int(pre_spf_facts['IPv4']['run_count'])
    run_cnt = int(spf_facts['IPv4']['run_count'])
    pytest_assert(run_cnt == pre_run_cnt+1,
                  'IS-IS spf run count is not correct. pre count: {}, current count{}'.format(pre_run_cnt, run_cnt))


def test_isis_spf_ietf_delay_learn_timer_expire(isis_common_setup_teardown):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    spf_facts = wait_for_short_wait_state(dut_host, nbr_host, nbr_port)
    pytest_assert(RUN_REGEX.match(spf_facts['timetolearn_state']),
                  'IS-IS spf timetolearn timer is not running. {}'.format(spf_facts['timetolearn_state']))

    wait_time = math.ceil(int(RUN_REGEX.match(spf_facts['timetolearn_state']).group(1)) / 1000.0)
    time.sleep(wait_time)

    spf_facts = get_isis_level2_spf_facts(dut_host)
    pytest_assert(spf_facts['state'] == LONG_WAIT,
                  'IS-IS spf is not in LONG_WAIT state after timetolearn timer exipre.')


@pytest.mark.parametrize("spf_state", [SHORT_WAIT, LONG_WAIT])
def test_isis_spf_ietf_delay_holddown_expire(isis_common_setup_teardown, spf_state):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    if spf_state == SHORT_WAIT:
        spf_facts = wait_for_short_wait_state(dut_host, nbr_host, nbr_port)
    elif spf_state == LONG_WAIT:
        spf_facts = wait_for_long_wait_state(dut_host, nbr_host, nbr_port)

    pytest_assert(RUN_REGEX.match(spf_facts['holddown_state']),
                  'IS-IS spf holddown timer is not in running state. holddown state: {}'
                  .format(spf_facts['holddown_state']))
    wait_time = math.ceil(int(RUN_REGEX.match(spf_facts['holddown_state']).group(1)) / 1000.0)
    time.sleep(wait_time)

    spf_facts = get_isis_level2_spf_facts(dut_host)
    pytest_assert(spf_facts['state'] == QUIET,
                  'IS-IS spf {} is not QUIET state'.format(spf_facts['state']))
    pytest_assert(spf_facts['holddown_state'] == 'Inactive',
                  'IS-IS spf holddown state: {} is not Inactive.'.format(spf_facts['holddown_state']))
    pytest_assert(spf_facts['timetolearn_state'] == 'Inactive',
                  'IS-IS spf timetolearn state: {} is not Inactive.'.format(spf_facts['timetolearn_state']))
    pytest_assert(spf_facts['spf_delay_status'] == 'Not scheduled',
                  'IS-IS spf delay status {} is not "Not scheduled".'.format(spf_facts['spf_delay_status']))
