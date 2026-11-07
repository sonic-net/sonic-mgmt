"""Runner lifecycle hooks and legacy-mode acceptance."""
import os

import pytest

from tests.common.plugins.redis_protection.control import prepare, restore, verify_mode
from tests.common.reboot import reboot

pytestmark = [pytest.mark.topology('any')]


def lifecycle(request, action):
    mode = request.config.getoption('--redis-protection-mode')
    if mode is None or os.environ.get('SONIC_REDIS_MODE_ACTION') != action:
        pytest.skip('Redis mode lifecycle is selected explicitly by run_tests.sh')
    path = os.environ.get('SONIC_REDIS_MODE_STATE')
    assert path, 'Missing controller-side Redis restoration record path'
    return mode, path


@pytest.mark.disable_loganalyzer
@pytest.mark.sanity_check(skip_sanity=True)
def test_prepare_redis_mode(duthosts, localhost, request):
    mode, path = lifecycle(request, 'prepare')
    prepare(list(duthosts), lambda dut: reboot(dut, localhost, safe_reboot=True), path, mode,
            request.config.getoption('--redis-allow-tcp-exceptions'))


def test_redis_legacy_mode(duthosts, request):
    if request.config.getoption('--redis-protection-mode') != 'legacy':
        pytest.skip('Legacy acceptance requires the legacy test plan')
    assert list(duthosts), 'Legacy acceptance requires at least one DUT'
    for dut in duthosts:
        verify_mode(dut, 'legacy')


@pytest.mark.disable_loganalyzer
@pytest.mark.sanity_check(skip_sanity=True)
def test_restore_redis_mode(duthosts, localhost, request):
    _, path = lifecycle(request, 'restore')
    restore(list(duthosts), lambda dut: reboot(dut, localhost, safe_reboot=True), path)
