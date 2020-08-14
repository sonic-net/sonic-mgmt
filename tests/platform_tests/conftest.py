import pytest

from .args.advanced_reboot_args import add_advanced_reboot_args
from .args.cont_warm_reboot_args import add_cont_warm_reboot_args


@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(duthost):
    platform = duthost.facts["platform"]
    if "simx" in platform:
        pytest.skip('skipped on this platform: {}'.format(platform))


# Platform pytest arguments
def pytest_addoption(parser):
    add_advanced_reboot_args(parser)
    add_cont_warm_reboot_args(parser)


def pytest_generate_tests(metafunc):
    if 'power_off_delay' in metafunc.fixturenames:
        delays = metafunc.config.getoption('power_off_delay')
        if not delays:
            # if power_off_delay option is not present, set it to default [5, 15] for backward compatible
            metafunc.parametrize('power_off_delay', [5, 15])
        else:
            metafunc.parametrize('power_off_delay', delays)
