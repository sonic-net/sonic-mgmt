import pytest
import logging

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from .helper import telemetry_enabled, TELEMETRY_PORT, TELEMETRY_CONTAINER
from .helper import setup_invalid_client_cert_cname # noqa: F401

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def telemetry_capabilities(duthost, localhost):
    ip = duthost.mgmt_ip
    # Connect to Telemetry service port 50052
    cmd = "docker exec %s gnmi_cli -client_types=gnmi "
    cmd += "-a %s:%s " % (TELEMETRY_CONTAINER, ip, TELEMETRY_PORT)
    cmd += "-client_crt /etc/sonic/telemetry/gnmiclient.crt "
    cmd += "-client_key /etc/sonic/telemetry/gnmiclient.key "
    cmd += "-ca_crt /etc/sonic/telemetry/gnmiCA.pem "
    cmd += "-logtostderr -capabilities"
    output = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("telemetry_capabilities: {} output: {}".format(cmd, output))
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def test_telemetry_authorize_passed_with_valid_cname(duthosts,
                                                     rand_one_dut_hostname,
                                                     localhost):
    '''
    Verify telemetry authorization using a valid certificate to ensure secure access
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not telemetry_enabled(duthost):
        pytest.skip("Skipping because telemetry not enabled")

    ret, msg = telemetry_capabilities(duthost, localhost)
    logger.debug("test_telemetry_authorize_passed_with_valid_cname: {}".format(msg))

    assert "Unauthenticated" not in msg, (
        "'Unauthenticated' error message found in Telemetry response. "
        "- Actual message: '{}'"
    ).format(msg)


def test_telemetry_authorize_failed_with_invalid_cname(duthosts,
                                                       rand_one_dut_hostname,
                                                       localhost,
                                                       setup_invalid_client_cert_cname):
    '''
    Verify telemetry authorization using an invalid certificate to confirm rejection behavior
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not telemetry_enabled(duthost):
        pytest.skip("Skipping because telemetry not enabled")

    ret, msg = telemetry_capabilities(duthost, localhost)
    logger.debug("test_telemetry_authorize_failed_with_invalid_cname: {}".format(msg))

    assert "Unauthenticated" in msg, (
        "'Unauthenticated' error message not found in Telemetry response. "
        "- Actual message: '{}'"
    ).format(msg)
