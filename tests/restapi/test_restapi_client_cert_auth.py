import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from helper import set_trusted_client_cert_subject_name
from restapi_operations import Restapi


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer
]

CLIENT_CERT = 'restapiclient.crt'
CLIENT_KEY = 'restapiclient.key'

restapi = Restapi(CLIENT_CERT, CLIENT_KEY)


@pytest.fixture
def restore_default_trusted_subject_name(duthosts, rand_one_dut_hostname):
    """
    Fixture restore the original trusted client cert subject name after test.
    """
    yield
    duthost = duthosts[rand_one_dut_hostname]
    # Restore cert config
    set_trusted_client_cert_subject_name(duthost, "test.client.restapi.sonic")


def check_client_cert_auth(construct_url, duthost, new_subject_name=None, expect_failure=False):
    """
    Helper function to set a new trusted client cert subject name and
    check if client cert auth with the RESTAPI server is successful.
    """
    if new_subject_name:
        logger.info(f"Setting trusted client cert subject name to '{new_subject_name}'...")
        set_trusted_client_cert_subject_name(duthost, new_subject_name)
    status_code = restapi.heartbeat(construct_url, assert_success=False)
    if expect_failure:
        pytest_assert(status_code == 401, f"Unexpected status code from the RESTAPI server: {status_code}")
    else:
        pytest_assert(status_code == 200, f"Client cert auth failed with status code {status_code}.")


def test_client_cert_subject_name_matching(construct_url, duthosts, rand_one_dut_hostname,
                                           restore_default_trusted_subject_name):  # noqa F811
    duthost = duthosts[rand_one_dut_hostname]

    # The client cert's subject name: test.client.restapi.sonic
    # Initially, the trusted client cert subject name is also set to test.client.restapi.sonic.
    logger.info("Expecting client cert auth success (exact match)...")
    check_client_cert_auth(construct_url, duthost)

    # Set trusted client cert subject name to a value that is different from the client cert's subject name.
    logger.info("Expecting client cert auth failure (exact match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="random.client.restapi.sonic", expect_failure=True)

    # Set trusted client cert subject name to a value that is different from the client cert's subject name.
    logger.info("Expecting client cert auth failure (exact match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="test.client.restapi.com", expect_failure=True)

    # Set trusted client cert subject name to a matching wildcard CN.
    logger.info("Expecting client cert auth success (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.client.restapi.sonic")

    # Set trusted client cert subject name to a matching wildcard CN.
    logger.info("Expecting client cert auth success (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.restapi.sonic")

    # Set trusted client cert subject name to a matching wildcard CN.
    logger.info("Expecting client cert auth success (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.sonic")

    # Set trusted client cert subject name to a non-matching wildcard CN.
    logger.info("Expecting client cert auth failure (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.test.client.restapi.sonic", expect_failure=True)

    # Set trusted client cert subject name to a non-matching wildcard CN.
    logger.info("Expecting client cert auth failure (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.client.restapi", expect_failure=True)

    # Set trusted client cert subject name to a non-matching wildcard CN.
    logger.info("Expecting client cert auth failure (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.example.sonic", expect_failure=True)

    # Set trusted client cert subject name to an invalid wildcard CN.
    logger.info("Expecting client cert auth failure (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*test.client.restapi.sonic", expect_failure=True)

    # Set trusted client cert subject name to an invalid wildcard CN.
    logger.info("Expecting client cert auth failure (wildcard match)...")
    check_client_cert_auth(construct_url, duthost, new_subject_name="*.", expect_failure=True)
