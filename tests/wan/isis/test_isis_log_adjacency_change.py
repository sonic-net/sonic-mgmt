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
def isis_setup_teardown_log_adjacency_change(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "log_adjacency_changes"
    config_dict = {config_key: 'True'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_log_adjacency_change(duthost, status):
    output = duthost.shell("tail -n 1000 /var/log/syslog\
                           |grep -e '.*%ADJCHANGE: Adjacency to.*to {}'\
                           |grep -v grep".format(status),
                           module_ignore_errors=True)
    if output['stdout'] != '':
        return True
    else:
        return False


def test_isis_log_adjacency_change(isis_common_setup_teardown, isis_setup_teardown_log_adjacency_change):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, peer_host, peer_port) = selected_connections[0]

    peer_host.shutdown(peer_port)
    pytest_assert(wait_until(10, 2, 0, check_isis_log_adjacency_change, dut_host, "Down"),
                  "No adjacency change logs!")

    peer_host.no_shutdown(peer_port)
    pytest_assert(wait_until(10, 2, 0, check_isis_log_adjacency_change, dut_host, "Up"),
                  "No adjacency change logs!")
