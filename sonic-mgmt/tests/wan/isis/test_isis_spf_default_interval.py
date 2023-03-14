import re
import time
import pytest
import logging
import functools

from tests.common.helpers.assertions import pytest_assert
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance


logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]

SPF_INTERVAL = 20


@pytest.fixture(scope="module", autouse=True)
def isis_set_default_isis_interval(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "spf_minimum_interval"
    config_dict = {config_key: SPF_INTERVAL}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def get_isis_spf_summary(dut_host):
    isis_facts = dut_host.isis_facts()["ansible_facts"]['isis_facts']
    return isis_facts['summary'][isis_instance]['level_2']


def get_isis_spf_last_run_elapsed(spf_summary):
    regex_time = re.compile(r'(\d+):(\d+):(\d+)')
    match = regex_time.match(spf_summary['IPv4']['last_run_elapsed'])
    return int(match.group(3))


def wait_isis_spf_stable(dut_host):
    spf_summary = get_isis_spf_summary(dut_host)
    last_run_elapsed = get_isis_spf_last_run_elapsed(spf_summary)

    wait_time = SPF_INTERVAL if spf_summary['spf_pending'] else 0
    if last_run_elapsed < SPF_INTERVAL:
        wait_time += SPF_INTERVAL - last_run_elapsed
    if wait_time:
        time.sleep(wait_time)


def check_isis_post_spf_cnt(spf_summary, pre_run_cnt):
    # Check spf count added by neighbor metric trigger
    pytest_assert(pre_run_cnt+1 == int(spf_summary['IPv4']['run_count']),
                  'IS-IS SPF count number ({}) is not correct ({}+1).'
                  .format(spf_summary['IPv4']['run_count'], pre_run_cnt))


def test_isis_spf_default_interval(isis_common_setup_teardown):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    # Get the 'last run elapsed' field to check whether this value exceed configured interval.
    # a. If it exceeds configured interval, when changing nbr metric, spf will run immediately.
    # b. If not, spf will pending, and when it exceeds configured interval, spf will run.

    wait_isis_spf_stable(dut_host)
    spf_summary = get_isis_spf_summary(dut_host)

    run_cnt = int(spf_summary['IPv4']['run_count'])
    # 1. trigger the first time, spf will run immediately
    nbr_host.set_isis_metric(nbr_port, '1000')

    spf_summary = get_isis_spf_summary(dut_host)

    check_isis_post_spf_cnt(spf_summary, run_cnt)

    # Check spf elapsed time refresh from 0
    last_run_elapsed = get_isis_spf_last_run_elapsed(spf_summary)
    pytest_assert(last_run_elapsed < SPF_INTERVAL,
                  'IS-IS SPF last run elapsed is not refreshed ({}).'
                  .format(last_run_elapsed))

    run_cnt = int(spf_summary['IPv4']['run_count'])
    # 2. trigger the second time, spf will in pending state
    nbr_host.no_isis_metric(nbr_port)
    nbr_host.set_isis_metric(nbr_port, '1000')
    nbr_host.no_isis_metric(nbr_port)

    spf_summary = get_isis_spf_summary(dut_host)
    pytest_assert(spf_summary['spf_pending'], 'IS-IS spf is not in pending state')

    # spf cnt will remain the same
    pytest_assert(run_cnt == int(spf_summary['IPv4']['run_count']),
                  'IS-IS SPF count number changed in pending state.(Pre: {}, Post: {})'
                  .format(spf_summary['IPv4']['run_count'], run_cnt))

    wait_isis_spf_stable(dut_host)
    check_isis_post_spf_cnt(get_isis_spf_summary(dut_host), run_cnt)
