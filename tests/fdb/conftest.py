import logging
import pytest
from .args.fdb_args import add_fdb_mac_expire_args
from tests.common.utilities import wait

logger = logging.getLogger(__name__)

CRM_POLLING_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300


# FDB pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to FDB pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_fdb_mac_expire_args(parser)


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthost):
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))
    wait(wait_time, "Waiting {} sec for CRM counters to become updated".format(wait_time))

    yield

    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    wait(wait_time, "Waiting {} sec for CRM counters to become updated".format(wait_time))


@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")
