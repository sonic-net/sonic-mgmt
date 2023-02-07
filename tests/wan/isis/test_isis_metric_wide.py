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
def isis_setup_teardown_wide_metric(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "wide_metric"
    config_dict = {config_key: '16777215'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_wide_metric(duthost):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']
    for lsp, metric in isis_facts['database_detail']['test'].items():
        if duthost.hostname in lsp:
            for _, value in metric.items():
                if int(value) == 16777215:
                    return True
    return False


def test_isis_wide_metric(isis_common_setup_teardown, isis_setup_teardown_wide_metric):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, _, _) = selected_connections[0]

    pytest_assert(wait_until(90, 2, 0, check_isis_wide_metric, dut_host),
                  "Max wide metric doesn't set!")
