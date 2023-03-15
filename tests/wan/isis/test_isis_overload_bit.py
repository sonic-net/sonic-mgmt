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
def isis_setup_teardown_set_overload_bit(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "isis_overload_bit"
    config_dict = {config_key: 'true'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


@pytest.fixture(scope="function")
def isis_setup_teardown_unset_overload_bit(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "isis_overload_bit"
    config_dict = {config_key: 'false'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_overload_bit(duthost, enabled):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']

    for lsp, _ in isis_facts['database']['test'].items():
        if duthost.hostname in lsp:
            overload = isis_facts['database']['test'][lsp]['overload']
            if int(overload) == enabled:
                return True

    return False


def test_isis_set_overload_bit(isis_common_setup_teardown, isis_setup_teardown_set_overload_bit):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(30, 2, 0, check_isis_overload_bit, dut_host, 1),
                  "Overload bit doesn't set!")


def test_isis_unset_overload_bit(isis_common_setup_teardown, isis_setup_teardown_unset_overload_bit):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(30, 2, 0, check_isis_overload_bit, dut_host, 0),
                  "Overload bit doesn't unset!")
