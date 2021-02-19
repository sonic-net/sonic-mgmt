import pytest
import json
import os
import logging
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

@pytest.fixture(scope="module")
def xcvr_skip_list(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts['platform']
    hwsku = duthost.facts['hwsku']
    f_path = os.path.join('/usr/share/sonic/device', platform, hwsku, 'hwsku.json')
    intf_skip_list = []
    try:
        out = duthost.command("cat {}".format(f_path))
        hwsku_info = json.loads(out["stdout"])
        for int_n in hwsku_info['interfaces']:
            if hwsku_info['interfaces'][int_n]['port_type'] == "RJ45":
                intf_skip_list.append(int_n)

    except Exception:
        # hwsku.json does not exist will return empty skip list
        logging.debug(
            "hwsku.json absent or port_type for interfaces not included for hwsku {}".format(hwsku))

    return intf_skip_list

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
