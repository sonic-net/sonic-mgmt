import pytest
import logging
import functools

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance

MAX_LSP_LIFETIME = 1200

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_basic_config(isis_common_setup_teardown, request):
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


def check_isis_route(duthost):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']

    if "1.1.0.0/16" in list(isis_facts['route'][isis_instance]['ipv4'].keys()):
        return True

    return False


def config_isis_redistribute(duthost):
    isis_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router isis test' "
        "-c 'redistribute ipv4 static level-2' "
        "-c 'exit' "
        "-c 'ip route 1.1.1.1 255.255.0.0 blackhole' "
        "-c 'exit' "
    )
    duthost.shell(isis_config)


def test_isis_redistribute(isis_common_setup_teardown, isis_setup_teardown_basic_config):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    config_isis_redistribute(dut_host)

    pytest_assert(wait_until(60, 2, 0, check_isis_route, dut_host),
                  "No route redistribute into is-is!")
