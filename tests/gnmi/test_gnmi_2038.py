import pytest
import logging
import re
from datetime import datetime, timezone
from dateutil import parser

from tests.common.helpers.gnmi_utils import gnmi_capabilities, prepare_root_cert, prepare_server_cert, \
    prepare_client_cert, copy_certificate_to_dut, copy_certificate_to_ptf
from .helper import apply_cert_config

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

ROOT_CERT_DAYS = 4850
SERVER_CERT_DAYS = 4800
CLIENT_CERT_DAYS = 4800


def test_gnmi_capabilities_2038(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Verify certificate after 2038 year problem
    '''
    duthost = duthosts[rand_one_dut_hostname]

    prepare_root_cert(localhost, days=ROOT_CERT_DAYS)
    prepare_server_cert(duthost, localhost, days=SERVER_CERT_DAYS)
    prepare_client_cert(localhost, days=CLIENT_CERT_DAYS)

    copy_certificate_to_dut(duthost)
    copy_certificate_to_ptf(ptfhost)

    apply_cert_config(duthost)

    # Verify certificate date on DUT
    check_cert_date_on_dut(duthost)

    # Verify GNMI capabilities to validate functionality
    ret, msg = gnmi_capabilities(duthost, localhost)
    assert ret == 0, msg
    assert "sonic-db" in msg, msg
    assert "JSON_IETF" in msg, msg


def check_cert_date_on_dut(duthost):
    cmd = "openssl x509 -in /etc/sonic/telemetry/gnmiCA.pem -text"
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
