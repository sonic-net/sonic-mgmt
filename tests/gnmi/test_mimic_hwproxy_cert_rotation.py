import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.gu_utils import create_checkpoint, rollback
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
    dut_command = "docker exec gnmi supervisorctl status gnmi-native"
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def check_telemetry_status(duthost, env):
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def test_mimic_hwproxy_cert_rotation(
        duthosts, rand_one_dut_hostname, localhost, ptfhost, request, loganalyzer):
    duthost = duthosts[rand_one_dut_hostname]

    # Use bash -c to run the pipeline properly
    cmd_feature = (
        'bash -c "show feature status | awk \'$1==\\"gnmi\\" || $1==\\"telemetry\\" {print $1, $2}\'"'
    )
    logging.debug("show feature status command is: {}".format(cmd_feature))

    result = duthost.command(cmd_feature, module_ignore_errors=True)
    output = result["stdout"]

    gnmi_enabled = False
    telemetry_enabled = False
    gnmi_certs_rotated = False

    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2:
            feature, state = parts
            if feature == "gnmi" and state == "enabled":
                gnmi_enabled = True
            elif feature == "telemetry" and state == "enabled":
                telemetry_enabled = True

    if get_image_type(duthost) != "public":
        pytest_assert(
            gnmi_enabled or telemetry_enabled,
            "Internal image has neither gnmi nor telemetry feature enabled"
        )

    if gnmi_enabled:
        gnmi_tls = request.getfixturevalue("gnmi_tls")  # noqa: F811
    if telemetry_enabled:
        # Resolve the telemetry endpoint before stopping its container.
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        assert env.gnmi_container == "telemetry", "Telemetry container is not running"
        if not gnmi_enabled:
            create_checkpoint(duthost, "hwproxy_telemetry_rotation")

    try:
        if gnmi_enabled:
            cmd_feature = "docker images | grep 'docker-sonic-gnmi'"
            result = duthost.shell(cmd_feature, module_ignore_errors=True)
            if result["stdout"].strip():
                unit_file_state = duthost.command(
                    "systemctl show gnmi.service --property=UnitFileState --value")["stdout"].strip()
                # disable feature
                disable_feature = 'sudo config feature state gnmi disabled'
                duthost.command(disable_feature, module_ignore_errors=True)
                # rotate gnmi cert
                _rotate_gnmi_certs(duthost, localhost, ptfhost)
                duthost.copy(src="gnmiCA.pem", dest="/etc/sonic/telemetry/gnmiCA.cer")
                duthost.copy(src="gnmiserver.crt", dest="/etc/sonic/telemetry/gnmiserver.cer")
                gnmi_certs_rotated = True
                # set gnmi table
                port = gnmi_tls.port
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
                if loganalyzer and unit_file_state == "generated":
                    # featured logs enable failure for generated units even when start succeeds.
                    loganalyzer[duthost.hostname].ignore_regex.append(
                        r" ERR featured: \['sudo', 'systemctl', 'enable', 'gnmi\.service'\]"
                        r" - failed: return code - 1, output:\s*$")

        if telemetry_enabled:
            cmd_feature = "docker images | grep 'docker-sonic-telemetry'"
            result = duthost.shell(cmd_feature, module_ignore_errors=True)
            if result["stdout"].strip():
                port = env.gnmi_port
                # disable feature
                disable_feature = 'sudo config feature state telemetry disabled'
                duthost.command(disable_feature, module_ignore_errors=True)
                # rotate telemetry cert
                # Both services share the server key path; reuse this test's fresh PKI.
                if not gnmi_certs_rotated:
                    _rotate_gnmi_certs(duthost, localhost, ptfhost)
                    duthost.copy(src="gnmiCA.pem", dest="/etc/sonic/telemetry/gnmiCA.cer")
                    duthost.copy(src="gnmiserver.crt", dest="/etc/sonic/telemetry/gnmiserver.cer")
                # set telemetry table
                set_table = (
                    f'sonic-db-cli CONFIG_DB hset "TELEMETRY|gnmi" '
                    f'client_auth "true" '
                    f'log_level "2" '
                    f'port "{port}"'
                )
                duthost.command(set_table, module_ignore_errors=True)
                set_table_cert = 'sonic-db-cli CONFIG_DB hset "TELEMETRY|certs"   \
                    ca_crt "/etc/sonic/telemetry/gnmiCA.cer"   \
                    server_crt "/etc/sonic/telemetry/gnmiserver.cer"   \
                    server_key "/etc/sonic/telemetry/gnmiserver.key"'
                duthost.command(set_table_cert, module_ignore_errors=True)
                # enable feature
                enable_feature = 'sudo config feature state telemetry enabled'
                duthost.command(enable_feature, module_ignore_errors=True)
                assert wait_until(60, 3, 0, check_telemetry_status, duthost, env), "TELEMETRY service failed to start"
    finally:
        delete_gnmi_certs(localhost)
        # gnmi_tls owns the checkpoint when gNMI is enabled, including dual-service tests.
        if telemetry_enabled and not gnmi_enabled:
            output = rollback(duthost, "hwproxy_telemetry_rotation")
            assert output['rc'] == 0 and "Config rolled back successfully" in output['stdout'], output
            duthost.service(name="telemetry", state="restarted")
            assert wait_until(60, 3, 0, check_telemetry_status, duthost, env), \
                "TELEMETRY service failed to recover"
