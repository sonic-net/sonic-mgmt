import pytest
import logging
from tests.common.helpers.assertions import pytest_require

class CheckEnvironment:
    _is_sim = None

    @staticmethod
    def is_sim(duthost):
        if CheckEnvironment._is_sim is None:
            result = duthost.command("dmidecode")
            if 'QEMU' in result:
                CheckEnvironment._is_sim = True
                logging.info("In simulation env")
            else:
                CheckEnvironment._is_sim = False
                logging.info("In hardware env")
        return CheckEnvironment._is_sim


@pytest.fixture(scope='module')
def skip_if_sim(duthosts, enum_rand_one_per_hwsku_hostname ):
    """
    Skip the test if its a simulation environment
    """
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    pytest_require(not CheckEnvironment.is_sim(duthost),
                   'Test not supported in SIM environment')
