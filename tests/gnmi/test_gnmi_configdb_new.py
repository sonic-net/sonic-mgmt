import logging
import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    setup_gnoi_tls_server, ptf_grpc
)
from .helper import gnmi_get
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnoi_tls_server",
                            "setup_legacy_cert_paths", "check_dut_timestamp")
]


def test_gnmi_configdb_get_metadata(duthosts, rand_one_dut_hostname, ptfhost):
    """
    Verify gNMI Get for CONFIG_DB DEVICE_METADATA using new TLS fixture.
    """
    duthost = duthosts[rand_one_dut_hostname]
    path_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"]
    msg_list = gnmi_get(duthost, ptfhost, path_list)
    pytest_assert(len(msg_list) > 0, "No response from gNMI Get")
    result = msg_list[0]
    pytest_assert("bgp_asn" in result, "bgp_asn not found in GetResponse: %s" % result)
