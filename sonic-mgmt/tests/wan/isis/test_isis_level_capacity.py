import pytest
import logging
import functools

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance
from isis_helpers import get_nbr_name
from isis_helpers import config_device_isis
from isis_helpers import add_dev_isis_attr, del_dev_isis_attr

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('wan-com'),
]


@pytest.fixture(scope="module")
def isis_setup_teardown_l12(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "level_capability"
    config_dict = {config_key: 'level-1-2'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


@pytest.fixture(scope="module")
def isis_setup_teardown_l1(isis_common_setup_teardown, request):
    target_devices = []
    selected_connections = isis_common_setup_teardown

    config_key = "level_capability"
    config_dict = {config_key: 'level-1'}
    for (dut_host, _, _, _) in selected_connections:
        add_dev_isis_attr(dut_host, config_dict)
        target_devices.append(dut_host)
        config_device_isis(dut_host)

    def revert_isis_config(devices):
        for device in devices:
            del_dev_isis_attr(dut_host, [config_key])
            config_device_isis(device)

    request.addfinalizer(functools.partial(revert_isis_config, target_devices))


def check_isis_neighbor_l12(duthost, nbr_name, state):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']
    if isis_instance not in isis_facts['neighbors'].keys():
        logger.info("Failed to isis instance {} in dut {}.".format(isis_instance, duthost.hostname))
        return False

    if state == 'Up' and nbr_name not in isis_facts['neighbors'][isis_instance].keys():
        return False

    if state == 'Up' and isis_facts['neighbors'][isis_instance][nbr_name]['state'] == 'Up':
        return True

    if state == 'Down' and nbr_name not in isis_facts['neighbors'][isis_instance].keys():
        return True

    logger.info("Failed to nbr {} in dut {}.".format(nbr_name, duthost.hostname))
    return False


def check_isis_neighbor_l1(duthost, nbr_name, state):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']
    if isis_instance not in isis_facts['neighbors'].keys():
        logger.info("Failed to isis instance {} in dut {}.".format(isis_instance, duthost.hostname))
        return False

    if state == 'Down' and nbr_name not in isis_facts['neighbors'][isis_instance].keys():
        return True

    logger.info("Failed to nbr {} in dut {}.".format(nbr_name, duthost.hostname))
    return False


def test_isis_neighbor_l12(isis_common_setup_teardown, isis_setup_teardown_l12, nbrhosts):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    nbr_name = get_nbr_name(nbrhosts, nbr_host)
    pytest_assert(wait_until(10, 2, 0, check_isis_neighbor_l12, dut_host, nbr_name, 'Up'),
                  "ISIS Neighbor {} is not Up state".format(nbr_name))

    # Shutdown PortChannel in neighbor device
    nbr_host.shutdown(nbr_port)
    pytest_assert(wait_until(10, 2, 1, check_isis_neighbor_l12, dut_host, nbr_name, 'Down'),
                  "ISIS Neighbor {} is not Down state".format(nbr_name))

    # No Shutdown PortChannel in neighbor device
    nbr_host.no_shutdown(nbr_port)
    pytest_assert(wait_until(10, 2, 1, check_isis_neighbor_l12, dut_host, nbr_name, 'Up'),
                  "ISIS Neighbor {} is not Up state".format(nbr_name))

    # Shutdown PortChannel in dut device
    dut_host.shutdown(dut_port)
    pytest_assert(wait_until(10, 2, 1, check_isis_neighbor_l12, dut_host, nbr_name, 'Down'),
                  "ISIS Neighbor {} is not Down state".format(nbr_name))

    # No Shutdown PortChannel in dut device
    dut_host.no_shutdown(dut_port)
    pytest_assert(wait_until(10, 2, 1, check_isis_neighbor_l12, dut_host, nbr_name, 'Up'),
                  "ISIS Neighbor {} is not Up state".format(nbr_name))


def test_isis_neighbor_l1(isis_common_setup_teardown, isis_setup_teardown_l1, nbrhosts):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]

    nbr_name = get_nbr_name(nbrhosts, nbr_host)
    pytest_assert(wait_until(10, 2, 0, check_isis_neighbor_l1, dut_host, nbr_name, 'Down'),
                  "ISIS Neighbor {} is not Down state".format(nbr_name))
