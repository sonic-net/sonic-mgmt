import pytest
import shutil

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.gnmi.helper import GNMI_CONTAINER_NAME, apply_cert_config, create_ext_conf
from tests.generic_config_updater.gu_utils import create_checkpoint, rollback

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
        duthost.shell("docker cp %s:/usr/sbin/%s /tmp" % (GNMI_CONTAINER_NAME, file))
        ret = duthost.fetch(src="/tmp/%s" % file, dest=".")
        gnmi_bin = ret.get("dest", None)
        shutil.copyfile(gnmi_bin, "gnmi/%s" % file)
        localhost.shell("sudo chmod +x gnmi/%s" % file)


@pytest.fixture(scope="module", autouse=True)
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost):
    '''
    Create GNMI client certificates
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if GNMI is enabled on the device
    pyrequire(
        check_container_state(duthost, GNMI_CONTAINER_NAME, should_be_running=True),
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

    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src='gnmiCA.pem', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.key', dest='/etc/sonic/telemetry/')

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
    duthost.shell("systemctl restart %s" % GNMI_CONTAINER_NAME)
