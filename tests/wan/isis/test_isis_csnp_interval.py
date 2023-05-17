import pytest
import logging
import functools
import re

from tests.common.helpers.assertions import pytest_assert
from isis_helpers import get_device_systemid
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="function")
def isis_setup_teardown_csnp_interval(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "csnp_interval"
    config_dict = {config_key: '15'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def test_isis_csnp_interval(isis_common_setup_teardown, isis_setup_teardown_csnp_interval):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    output = dut_host.shell("sudo tcpdump -i {} -c 50 -tt | grep 'IS-IS, L2 CSNP, src-id {}'".
                            format(dut_port, get_device_systemid(dut_host)))
    timestamp_new = int(re.match(r'(\d+).*$', output['stdout_lines'][-1]).group(1))
    timestamp_old = int(re.match(r'(\d+).*$', output['stdout_lines'][-2]).group(1))

    pytest_assert(timestamp_new - timestamp_old < 15, "CSNP interval larger then interval")
