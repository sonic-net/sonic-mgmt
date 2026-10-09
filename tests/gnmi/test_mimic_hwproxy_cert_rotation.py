import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import PygnmiClient
from tests.common.utilities import wait_until
from tests.common.helpers.gnmi_utils import GNMIEnvironment, delete_gnmi_certs, \
    prepare_root_cert, prepare_server_cert, prepare_client_cert, copy_certificate_to_ptf, \
    create_revoked_cert_and_crl, copy_certificate_to_dut
from tests.common.utilities import get_image_type


def _rotate_gnmi_certs(duthost, localhost, ptfhost):
    """Regenerate the GNMI PKI and push the fresh certs to the DUT and ptf."""
    prepare_root_cert(localhost)
    prepare_server_cert(duthost, localhost)
    prepare_client_cert(localhost)
    copy_certificate_to_ptf(ptfhost)
    create_revoked_cert_and_crl(localhost, ptfhost)
    copy_certificate_to_dut(duthost)


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def test_mimic_hwproxy_cert_rotation(duthosts, rand_one_dut_hostname, localhost, ptfhost, gnmi_tls):  # noqa: F811
    """Verify gnmi cert rotation across a feature restart: disable the gnmi feature,
    rotate the server cert and rewrite the GNMI cert config, re-enable the feature,
    and confirm the server comes back and serves (gnmi capabilities succeed).
    Complements test_gnmi_cert_rotation.py::test_gnmi_cert_rotate, which hot-rotates
    certs on a running server (no feature restart) and checks a data GET."""
    duthost = duthosts[rand_one_dut_hostname]

    # Use bash -c to run the pipeline properly
    cmd_feature = (
        'bash -c "show feature status | awk \'$1==\\"gnmi\\" {print $1, $2}\'"'
    )
    logging.debug("show feature status command is: {}".format(cmd_feature))

    result = duthost.command(cmd_feature, module_ignore_errors=True)
    output = result["stdout"]

    gnmi_enabled = False

    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2:
            feature, state = parts
            if feature == "gnmi" and state == "enabled":
                gnmi_enabled = True

    if get_image_type(duthost) != "public":
        pytest_assert(
            gnmi_enabled,
            "Internal image does not have the gnmi feature enabled"
        )

    if gnmi_enabled:
        cmd_feature = "docker images | grep 'docker-sonic-gnmi'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result["stdout"].strip():
            # disable feature
            disable_feature = 'sudo config feature state gnmi disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            try:
                # rotate gnmi cert
                _rotate_gnmi_certs(duthost, localhost, ptfhost)
                duthost.copy(src="gnmiCA.pem", dest="/etc/sonic/telemetry/gnmiCA.cer")
                duthost.copy(src="gnmiserver.crt", dest="/etc/sonic/telemetry/gnmiserver.cer")
                # set gnmi table
                env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
                port = env.gnmi_port
                set_table = (
                    f'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" '
                    f'client_auth "true" '
                    f'log_level "2" '
                    f'port "{port}"'
                )
                duthost.command(set_table, module_ignore_errors=True)
                set_table_cert = 'sonic-db-cli CONFIG_DB hset "GNMI|certs"   \
                    ca_crt "/etc/sonic/telemetry/gnmiCA.cer"   \
                    server_crt "/etc/sonic/telemetry/gnmiserver.cer"   \
                    server_key "/etc/sonic/telemetry/gnmiserver.key"'
                duthost.command(set_table_cert, module_ignore_errors=True)
                # enable feature
                enable_feature = 'sudo config feature state gnmi enabled'
                duthost.command(enable_feature, module_ignore_errors=True)
                assert wait_until(60, 3, 0, check_gnmi_status, duthost), "GNMI service failed to start"
                client = PygnmiClient(gnmi_tls.host, port,
                                      ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
                                      client_key="gnmiclient.key", connect=False)
                msg = client.capabilities()
                assert "sonic-db" in [model["name"] for model in msg["supported_models"]], msg
                assert "json_ietf" in msg["supported_encodings"], msg
            finally:
                delete_gnmi_certs(localhost)
