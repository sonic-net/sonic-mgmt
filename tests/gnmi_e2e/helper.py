
import pytest
import logging

from tests.common.helpers.gnmi_utils import add_gnmi_client_common_name, \
                                            del_gnmi_client_common_name, \
                                            GNMI_CERT_NAME


logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"
INVALID_CERT_NAME = "invalid.cname"

def telemetry_enabled(duthost):
    containers = duthost.get_all_containers()
    logger.warning("running containers: {}".format(containers))
    return TELEMETRY_CONTAINER in containers


@pytest.fixture(scope="function")
def setup_invalid_client_cert_cname(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    del_gnmi_client_common_name(duthost, GNMI_CERT_NAME)
    add_gnmi_client_common_name(duthost, INVALID_CERT_NAME)

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: {}".format(keys))

    yield

    del_gnmi_client_common_name(duthost, INVALID_CERT_NAME)
    add_gnmi_client_common_name(duthost, GNMI_CERT_NAME)
