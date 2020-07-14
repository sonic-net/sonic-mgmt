import pytest

from tests.common.fixtures.advanced_reboot import get_advanced_reboot
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