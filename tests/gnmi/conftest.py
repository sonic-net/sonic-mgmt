import pytest
import shutil
import logging

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.gnmi.helper import gnmi_container, apply_cert_config, recover_cert_config, create_ext_conf
from tests.gnmi.helper import GNMI_SERVER_START_WAIT_TIME
from tests.generic_config_updater.gu_utils import create_checkpoint, rollback

logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"


@pytest.fixture(scope="function", autouse=True)
def skip_non_x86_platform(duthosts, rand_one_dut_hostname):
    """
    Skip the current test if DUT is not x86_64 platform.
    """
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    if 'x86_64' not in platform:
        pytest.skip("Test not supported for current platform. Skipping the test")


@pytest.fixture(scope="module", autouse=True)
def download_gnmi_client(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    for file in ["gnmi_cli", "gnmi_set", "gnmi_get", "gnoi_client"]:
        duthost.shell("docker cp %s:/usr/sbin/%s /tmp" % (gnmi_container(duthost), file))
        ret = duthost.fetch(src="/tmp/%s" % file, dest=".")
        gnmi_bin = ret.get("dest", None)
        shutil.copyfile(gnmi_bin, "gnmi/%s" % file)
        localhost.shell("sudo chmod +x gnmi/%s" % file)


@pytest.fixture(scope="module", autouse=True)
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Create GNMI client certificates
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if GNMI is enabled on the device
    pyrequire(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!")

    # Create Root key
    local_command = "openssl genrsa -out gnmiCA.key 2048"
    localhost.shell(local_command)

    # Create Root cert
    local_command = "openssl req \
                        -x509 \
                        -new \
                        -nodes \
                        -key gnmiCA.key \
                        -sha256 \
                        -days 1825 \
                        -subj '/CN=test.gnmi.sonic' \
                        -out gnmiCA.pem"
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out gnmiserver.key 2048"
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key gnmiserver.key \
                        -subj '/CN=test.server.gnmi.sonic' \
                        -out gnmiserver.csr"
    localhost.shell(local_command)

    # Sign server certificate
    create_ext_conf(duthost.mgmt_ip, "extfile.cnf")
    local_command = "openssl x509 \
                        -req \
                        -in gnmiserver.csr \
                        -CA gnmiCA.pem \
                        -CAkey gnmiCA.key \
                        -CAcreateserial \
                        -out gnmiserver.crt \
                        -days 825 \
                        -sha256 \
                        -extensions req_ext -extfile extfile.cnf"
    localhost.shell(local_command)

    # Create client key
    local_command = "openssl genrsa -out gnmiclient.key 2048"
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key gnmiclient.key \
                        -subj '/CN=test.client.gnmi.sonic' \
                        -out gnmiclient.csr"
    localhost.shell(local_command)

    # Sign client certificate
    local_command = "openssl x509 \
                        -req \
                        -in gnmiclient.csr \
                        -CA gnmiCA.pem \
                        -CAkey gnmiCA.key \
                        -CAcreateserial \
                        -out gnmiclient.crt \
                        -days 825 \
                        -sha256"
    localhost.shell(local_command)

    # Copy CA certificate, server certificate and client certificate over to the DUT
    duthost.copy(src='gnmiCA.pem', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.key', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiclient.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiclient.key', dest='/etc/sonic/telemetry/')
    # Copy CA certificate and client certificate over to the PTF
    ptfhost.copy(src='gnmiCA.pem', dest='/root/')
    ptfhost.copy(src='gnmiclient.crt', dest='/root/')
    ptfhost.copy(src='gnmiclient.key', dest='/root/')

    create_checkpoint(duthost, SETUP_ENV_CP)
    apply_cert_config(duthost)

    yield
    # Delete all created certs
    local_command = "rm \
                        extfile.cnf \
                        gnmiCA.* \
                        gnmiserver.* \
                        gnmiclient.*"
    localhost.shell(local_command)

    # Rollback configuration
    rollback(duthost, SETUP_ENV_CP)
    recover_cert_config(duthost)


@pytest.fixture(scope="module", autouse=True)
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
