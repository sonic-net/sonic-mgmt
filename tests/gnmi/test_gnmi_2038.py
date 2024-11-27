import pytest
import logging

from .helper import gnmi_capabilities, prepare_root_cert, prepare_server_cert, prepare_client_cert, \
    copy_certificate_to_dut, copy_certificate_to_ptf, apply_cert_config, cert_date_on_dut

logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_capabilities(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Verify certificate after 2038 year problem
    '''
    duthost = duthosts[rand_one_dut_hostname]

    prepare_root_cert(localhost, days="4850")
    prepare_server_cert(duthost, localhost, days="4810")
    prepare_client_cert(localhost, days="4810")

    copy_certificate_to_dut(duthost)
    copy_certificate_to_ptf(ptfhost)

    apply_cert_config(duthost)

    # Verify certificate date on DUT
    cert_date_on_dut(duthost)

    # Verify GNMI capabilities to validate functionality
    ret, msg = gnmi_capabilities(duthost, localhost)
    assert ret == 0, msg
    assert "sonic-db" in msg, msg
    assert "JSON_IETF" in msg, msg
