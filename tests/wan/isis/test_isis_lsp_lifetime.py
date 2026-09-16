import pytest
import logging
import functools

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance

MAX_LSP_LIFETIME = 2000
MIN_LSP_LIFETIME = 1500

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_lsp_long_lifetime(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_maximum_lifetime"
    config_dict = {config_key: MAX_LSP_LIFETIME}
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
def isis_setup_teardown_lsp_short_lifetime(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_maximum_lifetime"
    config_dict = {config_key: MIN_LSP_LIFETIME}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_lsp_lifetime(duthost, long):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']

    for lsp, _ in list(isis_facts['database'][isis_instance].items()):
        if duthost.hostname in lsp:
            lifetime = isis_facts['database'][isis_instance][lsp]['holdtime']
            if int:
                lifetime_offset = MAX_LSP_LIFETIME - int(lifetime)
            else:
                lifetime_offset = MIN_LSP_LIFETIME - int(lifetime)

            if lifetime_offset < 200:
                return True
            else:
                return False

    return False


def test_isis_lsp_long_lifetime(isis_common_setup_teardown, isis_setup_teardown_lsp_long_lifetime):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(60, 2, 0, check_isis_lsp_lifetime, dut_host, 1),
                  "LSP lifetime dosen't correct!")


def test_isis_lsp_short_lifetime(isis_common_setup_teardown, isis_setup_teardown_lsp_short_lifetime):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(60, 2, 0, check_isis_lsp_lifetime, dut_host, 0),
                  "LSP lifetime dosen't correct!")
