import pytest
import logging
import re
from datetime import datetime, timezone
from dateutil import parser

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.grpc_config import grpc_config

logger = logging.getLogger(__name__)

CERT_VALIDITY_DAYS = 4800

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp"),
]


@pytest.mark.parametrize(
    "gnmi_tls",
    [{"transport": "tls", "validity_days": CERT_VALIDITY_DAYS}],
    indirect=True,
)
def test_gnmi_capabilities_2038(
        duthosts, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify certificate after 2038 year problem
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Verify certificate date on DUT
    check_cert_date_on_dut(duthost)

    # Verify GNMI capabilities to validate functionality
    result = gnmi_tls.pygnmi_client.capabilities()
    models = {model.get("name") for model in result.get("supported_models", [])}
    assert "sonic-db" in models, result
    encodings = [encoding.lower() for encoding in result.get("supported_encodings", [])]
    assert "json_ietf" in encodings, result


def check_cert_date_on_dut(duthost):
    ca_path = "{}/{}".format(grpc_config.DUT_CERT_DIR, grpc_config.CA_CERT)
    cmd = "openssl x509 -in {} -text".format(ca_path)
    output = duthost.shell(cmd, module_ignore_errors=True)
    not_after_line = re.search(r"Not After\s*:\s*(.*)", output['stdout'])
    if not_after_line:
        not_after_date_str = not_after_line.group(1).strip()
        # Convert the date string to a datetime object
        expiry_date = parser.parse(not_after_date_str)
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        # comparison date is January 20, 2038, after the 2038 problem
        after_2038_problem_date = datetime(2038, 1, 20, tzinfo=timezone.utc)

        if expiry_date < after_2038_problem_date:
            raise Exception("The expiry date {} is not after 2038 problem date".format(expiry_date))
        else:
            logger.info("The expiry date {} is after January 20, 2038.".format(expiry_date))
    else:
        raise Exception("The 'Not After' line with expiry date was not found")
