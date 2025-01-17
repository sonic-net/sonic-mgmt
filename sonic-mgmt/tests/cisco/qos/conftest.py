import logging
import pytest
from tests.common.errors import RunAnsibleModuleFail
from tests.qos.args.qos_sai_args import add_qos_sai_args

# QoS pytest arguments


def pytest_addoption(parser):
    '''
        Adds option to QoS pytest
        Args:
            parser: pytest parser object
        Returns:
            None
    '''
    add_qos_sai_args(parser)


@pytest.fixture(scope="module")
def verify_cmd(duthost):
    ''' Wrapper '''
    def wrapper(cmd):
        logging.info("Running command: {}".format(cmd))
        try:
            # Throws exception when RC is non-zero. Parse for easier reading.
            results = duthost.command(cmd)
        except RunAnsibleModuleFail as e:
            results = e.results
            rc = results['rc']
            pytest.fail("Command '{}' failed with RC {}".format(cmd, rc))
        return results['stdout']
    return wrapper
