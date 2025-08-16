
import pytest
import logging

from tests.common.helpers.gnmi_utils import add_gnmi_client_common_name, \
                                            del_gnmi_client_common_name


logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"


TELEMETRY_PORT = "50052"
TELEMETRY_CONTAINER = "telemetry"
TELEMETRY_PROGRAM = "telemetry"


def telemetry_enabled(duthost):
    containers = duthost.get_all_containers()
    logger.warning("running containers: {}".format(containers))
    return TELEMETRY_CONTAINER in containers


@pytest.fixture(scope="function")
def setup_invalid_client_cert_cname(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "invalid.cname")

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: {}".format(keys))

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
