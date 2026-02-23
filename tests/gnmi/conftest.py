import pytest
import logging

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.gnmi.helper import gnmi_container, apply_cert_config, recover_cert_config
from tests.gnmi.helper import GNMI_SERVER_START_WAIT_TIME, check_ntp_sync_status
from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.helpers.gnmi_utils import create_revoked_cert_and_crl, create_gnmi_certs, \
    delete_gnmi_certs, prepare_root_cert, prepare_server_cert, prepare_client_cert, copy_certificate_to_dut, \
    copy_certificate_to_ptf
from tests.common.helpers.ntp_helper import setup_ntp_context


logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"


@pytest.fixture(scope="module")
def setup_gnmi_ntp_client_server(duthosts, rand_one_dut_hostname, ptfhost):
    """Auto-setup NTP for all gNMI tests using existing helper."""
    duthost = duthosts[rand_one_dut_hostname]

    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        logger.info("check_system_time_sync is skipped for this platform, so skip ntp setup")
        yield
        return

    if check_ntp_sync_status(duthost) is True:
        logger.info("DUT is already in sycn with NTP server, so skip ntp setup")
        yield
        return

    with setup_ntp_context(ptfhost, duthost, False):
        yield


@pytest.fixture(scope="module")
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Setup GNMI server with client certificates
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if GNMI is enabled on the device
    pyrequire(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!")

    create_gnmi_certs(duthost, localhost, ptfhost)

    create_checkpoint(duthost, SETUP_ENV_CP)
    apply_cert_config(duthost)

    yield

    delete_gnmi_certs(localhost)

    # Rollback configuration
    rollback(duthost, SETUP_ENV_CP)
    # Save the configuration
    cmd = "config save -y"
    duthost.shell(cmd, module_ignore_errors=True)
    recover_cert_config(duthost)


@pytest.fixture(scope="module")
def setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Create GNMI client certificates
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if GNMI is enabled on the device
    pyrequire(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!"
    )
    prepare_root_cert(localhost)
    prepare_server_cert(duthost, localhost)
    prepare_client_cert(localhost)
    copy_certificate_to_ptf(ptfhost)
    create_revoked_cert_and_crl(localhost, ptfhost)
    copy_certificate_to_dut(duthost)


@pytest.fixture(scope="module")
def check_dut_timestamp(duthosts, rand_one_dut_hostname, localhost):
    '''
    Check DUT time to detect NTP issue
    '''
    duthost = duthosts[rand_one_dut_hostname]
    # Seconds since 1970-01-01 00:00:00 UTC
    time_cmd = "date +%s"
    dut_res = duthost.shell(time_cmd, module_ignore_errors=True)
    local_res = localhost.shell(time_cmd, module_ignore_errors=True)
    local_time = int(local_res["stdout"])
    dut_time = int(dut_res["stdout"])
    logger.info("Local time %d, DUT time %d" % (local_time, dut_time))
    time_diff = local_time - dut_time
    if time_diff >= GNMI_SERVER_START_WAIT_TIME:
        logger.warning("DUT time is wrong (%d), please check NTP" % (-time_diff))
