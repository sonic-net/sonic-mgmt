import pytest
import logging
import functools

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_lsp_refresh_20(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_generation_interval"
    config_dict = {config_key: '10'}
    config_key1 = "lsp_refresh_interval"
    config_dict1 = {config_key1: '20'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        add_dev_isis_attr(dut_host, config_dict1)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


@pytest.fixture(scope="function")
def isis_setup_teardown_lsp_refresh_30(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_generation_interval"
    config_dict = {config_key: '20'}
    config_key1 = "lsp_refresh_interval"
    config_dict1 = {config_key1: '30'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        add_dev_isis_attr(dut_host, config_dict1)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_lsp_refresh_interval(duthost, last_cnt):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']

    if isis_facts['summary']['test']['tx_cnt']['l2_lsp'] - last_cnt >= 1:
        return True

    return False


def test_isis_lsp_refresh_20(isis_common_setup_teardown, isis_setup_teardown_lsp_refresh_20):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    isis_facts = dut_host.isis_facts()["ansible_facts"]['isis_facts']
    last_counter = isis_facts['summary']['test']['tx_cnt']['l2_lsp']

    pytest_assert(wait_until(20, 1, 0, check_isis_lsp_refresh_interval, dut_host, last_counter),
                  "LSP didn't get re-sent!")


def test_isis_lsp_refresh_30(isis_common_setup_teardown, isis_setup_teardown_lsp_refresh_30):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    isis_facts = dut_host.isis_facts()["ansible_facts"]['isis_facts']
    last_counter = isis_facts['summary']['test']['tx_cnt']['l2_lsp']

    pytest_assert(wait_until(30, 1, 0, check_isis_lsp_refresh_interval, dut_host, last_counter),
                  "LSP didn't get re-sent!")
