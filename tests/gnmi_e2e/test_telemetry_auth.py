import pytest
import logging

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.gnmi_e2e.helper import telemetry_enabled
from tests.gnmi_e2e.helper import setup_invalid_client_cert_cname     # noqa: F401
from tests.common.helpers.gnmi_utils import GNMIEnvironment

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def ptf_telemetry_get(duthost, ptfhost):
    output = ptfhost.shell("whoami", module_ignore_errors=True)
    logger.error("whoami: {}".format(output))

    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = '/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/gnmiCA.pem '
    cmd += '-pkey /root/gnmiclient.key '
    cmd += '-cchain /root/gnmiclient.crt '
    cmd += '-m get -x DEVICE_METADATA/localhost -xt CONFIG_DB'
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    logger.debug("ptf_telemetry_capabilities: {} output: {}".format(cmd, output))
    return output['failed'], "\n".join(output['stdout_lines'])


def test_telemetry_authorize_passed_with_valid_cname(duthosts,
                                                     rand_one_dut_hostname,
                                                     ptfhost):
    '''
    Verify telemetry authorization using a valid certificate to ensure secure access
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not telemetry_enabled(duthost):
        pytest.skip("Skipping because telemetry not enabled")

    failed, msg = ptf_telemetry_get(duthost, ptfhost)
    logger.debug("test_telemetry_authorize_passed_with_valid_cname: {}".format(msg))

    assert not failed, ("Telemetry 'get' command failed to execute: {}").format(msg)

    assert "Unauthenticated" not in msg, (
        "'Unauthenticated' error message found in Telemetry response. "
        "- Actual message: '{}'"
    ).format(msg)


def test_telemetry_authorize_failed_with_invalid_cname(duthosts,
                                                       rand_one_dut_hostname,
                                                       ptfhost,
                                                       setup_invalid_client_cert_cname):    # noqa: F811
    '''
    Verify telemetry authorization using an invalid certificate to confirm rejection behavior
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not telemetry_enabled(duthost):
        pytest.skip("Skipping because telemetry not enabled")

    failed, msg = ptf_telemetry_get(duthost, ptfhost)
    logger.debug("test_telemetry_authorize_failed_with_invalid_cname: {}".format(msg))

    assert failed, ("Telemetry 'get' command executed successfully: {}").format(msg)

    assert "Unauthenticated" in msg, (
        "'Unauthenticated' error message not found in Telemetry response. "
        "- Actual message: '{}'"
    ).format(msg)
