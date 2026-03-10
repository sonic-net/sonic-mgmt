import pytest
import logging
import functools

from tests.common.helpers.assertions import pytest_assert
from isis_helpers import get_device_systemid
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_no_intf_passive(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "isis_passive"
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


@pytest.fixture(scope="function")
def isis_setup_teardown_intf_passive(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "isis_passive"
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


def test_isis_no_intf_passive(isis_common_setup_teardown, isis_setup_teardown_no_intf_passive):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    output = dut_host.shell("sudo tcpdump -A -i {} -c 10 | grep 'IS-IS, p2p IIH, src-id {}'".
                            format(dut_port, get_device_systemid(dut_host)))
    pytest_assert(output['stdout_lines'] != [], "None IIH had sent out!")


def test_isis_intf_passive(isis_common_setup_teardown, isis_setup_teardown_intf_passive):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    output = dut_host.shell("sudo tcpdump -A -i {} -c 10 | grep 'IS-IS, p2p IIH, src-id {}'"
                            .format(dut_port, get_device_systemid(dut_host)),
                            module_ignore_errors=True)
    pytest_assert(output['stdout_lines'] == [], "IIH had sent out!")
