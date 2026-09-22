import pytest
import logging
import functools

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_lsp_fragment(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_mtu_size"
    config_dict = {config_key: '250'}
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
def isis_setup_teardown_no_lsp_fragment(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "lsp_mtu_size"
    config_dict = {config_key: '1497'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_lsp_fragment(duthost):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']
    lsp_cnt = 0

    for lsp, _ in list(isis_facts['database'][isis_instance].items()):
        if duthost.hostname in lsp:
            lsp_cnt = lsp_cnt + 1
    if lsp_cnt > 1:
        return True

    return False


def check_isis_no_lsp_fragment(duthost):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']
    lsp_cnt = 0

    for lsp, _ in list(isis_facts['database'][isis_instance].items()):
        if duthost.hostname in lsp:
            lsp_cnt = lsp_cnt + 1
    if lsp_cnt > 1:
        return False

    return True


def test_isis_lsp_fragment(isis_common_setup_teardown, isis_setup_teardown_lsp_fragment):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(60, 2, 0, check_isis_lsp_fragment, dut_host),
                  "LSP doesn't fragment!")


def test_isis_no_lsp_fragment(isis_common_setup_teardown, isis_setup_teardown_no_lsp_fragment):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(60, 2, 0, check_isis_no_lsp_fragment, dut_host),
                  "LSP fragment!")
