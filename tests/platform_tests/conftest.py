import pytest

from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from .args.advanced_reboot_args import add_advanced_reboot_args
from .args.cont_warm_reboot_args import add_cont_warm_reboot_args
from .args.normal_reboot_args import add_normal_reboot_args
from .args.api_sfp_args import add_api_sfp_args


@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    if "simx" in platform:
        pytest.skip('skipped on this platform: {}'.format(platform))


@pytest.fixture()
def bring_up_dut_interfaces(request, duthosts, rand_one_dut_hostname, tbinfo):
    """
    Bring up outer interfaces on the DUT.

    Args:
        request: pytest request object
        duthost: Fixture for interacting with the DUT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    yield
    if request.node.rep_call.failed:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = mg_facts['minigraph_ports'].keys()

        # Enable outer interfaces
        for port in ports:
            duthost.no_shutdown(ifname=port)


def pytest_addoption(parser):
    add_advanced_reboot_args(parser)
    add_cont_warm_reboot_args(parser)
    add_normal_reboot_args(parser)
    add_api_sfp_args(parser)


def pytest_generate_tests(metafunc):
    if 'power_off_delay' in metafunc.fixturenames:
        delays = metafunc.config.getoption('power_off_delay')
        default_delay_list = [5, 15]
        if not delays:
            # if power_off_delay option is not present, set it to default [5, 15] for backward compatible
            metafunc.parametrize('power_off_delay', default_delay_list)
        else:
            try:
                delay_list = [int(delay.strip()) for delay in delays.split(',')]
                metafunc.parametrize('power_off_delay', delay_list)
            except ValueError:
                metafunc.parametrize('power_off_delay', default_delay_list)
