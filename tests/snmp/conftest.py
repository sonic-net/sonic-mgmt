import pytest
import logging
from tests.common.utilities import wait_until

logger = logging.getLogger('__name__')

@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(duthosts):
    for duthost in duthosts:
        assert wait_until(300, 20, duthost.is_service_fully_started, "snmp"), "SNMP service is not running"

@pytest.fixture(scope="module", autouse=True)
def setup_enable_counters(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info('Enabling all counters on DUT')
    counters = ['PORT', 'PORT_BUFFER_DROP', 'QUEUE', 'PG_WATERMARK', 'RIF']
    for counter in counters:
        return_value = duthost.shell("sudo redis-cli -n 4 hset 'FLEX_COUNTER_TABLE|{}' 'FLEX_COUNTER_STATUS' 'enable'".format(counter),
                                module_ignore_errors=True)['rc']
        assert return_value == 0, 'Failed to enable counter: {}'.format(counter)

def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the snmp tests.
    """
    parser.addoption(
                    "--percentage",
                    action="store",
                    default=False,
                    help="Set percentage difference for snmp test",
                    type=int)
