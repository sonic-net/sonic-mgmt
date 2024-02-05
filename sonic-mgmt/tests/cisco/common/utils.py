import pytest
import logging
from tests.common.helpers.assertions import pytest_require


class CheckEnvironment:
    _is_sim = None

    @staticmethod
    def is_sim(duthost):
        if CheckEnvironment._is_sim is None:
            result = duthost.command("dmidecode")
            if 'QEMU' in result["stdout"]:
                CheckEnvironment._is_sim = True
                logging.info("In simulation env")
            else:
                CheckEnvironment._is_sim = False
                logging.info("In hardware env")
        return CheckEnvironment._is_sim


@pytest.fixture(scope='module')
def skip_if_sim(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Skip the test if its a simulation environment
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    pytest_require(not CheckEnvironment.is_sim(duthost),
                   'Test not supported in SIM environment')


@pytest.fixture(scope='module')
def skip_if_not_sim(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Skip the test if its not simulation environment
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    pytest_require(CheckEnvironment.is_sim(duthost),
                   'Test is supported only in SIM environment')


def verify_command_result(result, cmd):
    # Raise an AssertionError if "stdout" is empty
    assert result["stdout"], "No output for {}".format(cmd)

    # Check if "Traceback" is present in result["stdout"]
    traceback_found = "Traceback" in result["stdout"]
    # Raise an AssertionError if "Traceback" is found
    assert not traceback_found, "Traceback found in {}".format(cmd)
