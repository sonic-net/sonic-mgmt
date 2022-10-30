import pytest
import logging

from sai_infra import *  # noqa: F403 F401
from conftest import *  # noqa: F403 F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


"""
Use this script to setup the test environment
"""


def test_sai_env_setup(sai_testbed, creds, duthost, ptfhost, request):
    """
    Setup the sai test environment.
    Replay the fixture setup in sequence, sai_testbed, sai_test_env_check

    Args:
        sai_testbed: Fixture which can help prepare the sai testbed.
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Setup SAI test environment.")


def test_sai_env_teardown(sai_testbed, creds, duthost, ptfhost, request):
    """
    Remove the sai test env.

    Args:
        sai_testbed: Fixture which can help prepare the sai testbed.
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Remove SAI test environment.")
