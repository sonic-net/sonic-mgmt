import pytest
import logging
import re
import shutil
from datetime import datetime, timezone
from functools import partial
from dateutil import parser

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.grpc_config import grpc_config
from tests.common.helpers.gnmi_utils import prepare_root_cert, prepare_server_cert, prepare_client_cert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]

ROOT_CERT_DAYS = 4850
SERVER_CERT_DAYS = 4800
CLIENT_CERT_DAYS = 4800


def test_gnmi_capabilities_2038(duthosts, rand_one_dut_hostname, localhost, ptfhost,
                                gnmi_tls, tmp_path, monkeypatch):  # noqa: F811
    '''
    Verify certificate after 2038 year problem
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Keep the legacy validity periods, but install into the managed TLS paths.
    with monkeypatch.context() as patch:
        patch.chdir(tmp_path)
        patch.setattr(localhost, "shell", partial(localhost.shell, chdir=str(tmp_path)))
        prepare_root_cert(localhost, days=ROOT_CERT_DAYS)
        prepare_server_cert(duthost, localhost, days=SERVER_CERT_DAYS)
        prepare_client_cert(localhost, days=CLIENT_CERT_DAYS)

    client = gnmi_tls.pygnmi_client
    shutil.copyfile(tmp_path / "gnmiCA.pem", client.ca_cert)
    shutil.copyfile(tmp_path / "gnmiclient.crt", client.client_cert)
    shutil.copyfile(tmp_path / "gnmiclient.key", client.client_key)
    dut_cert_paths = grpc_config.get_dut_cert_paths()
    duthost.copy(src=str(tmp_path / "gnmiCA.pem"), dest=dut_cert_paths['ca_cert'])
    duthost.copy(src=str(tmp_path / "gnmiserver.crt"), dest=dut_cert_paths['server_cert'])
    duthost.copy(src=str(tmp_path / "gnmiserver.key"), dest=dut_cert_paths['server_key'])
    ptfhost.copy(src=client.ca_cert, dest=gnmi_tls.cert_paths.ca_cert)
    ptfhost.copy(src=client.client_cert, dest=gnmi_tls.cert_paths.client_cert)
    ptfhost.copy(src=client.client_key, dest=gnmi_tls.cert_paths.client_key)
    gnmi_tls.reconfigure_after_reboot()

    # Verify certificate date on DUT
    check_cert_date_on_dut(duthost)

    # Verify GNMI capabilities to validate functionality
    msg = gnmi_tls.pygnmi_client.capabilities()
    assert any(model["name"] == "sonic-db" for model in msg["supported_models"]), msg
    assert "json_ietf" in msg["supported_encodings"], msg


def check_cert_date_on_dut(duthost):
    cmd = "openssl x509 -in /etc/sonic/telemetry/gnmiCA.cer -text"
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
