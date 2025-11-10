import pytest
import logging
import os
import glob
import grpc

from grpc_tools import protoc

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.gnmi.helper import gnmi_container, apply_cert_config, recover_cert_config
from tests.gnmi.helper import GNMI_SERVER_START_WAIT_TIME, check_ntp_sync_status
from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.helpers.gnmi_utils import GNMIEnvironment, create_revoked_cert_and_crl, create_gnmi_certs, \
    delete_gnmi_certs, prepare_root_cert, prepare_server_cert, prepare_client_cert, copy_certificate_to_dut, \
    copy_certificate_to_ptf
from tests.common.helpers.ntp_helper import setup_ntp_context


logger = logging.getLogger(__name__)
SETUP_ENV_CP = "test_setup_checkpoint"


@pytest.fixture(scope="module", autouse=True)
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


@pytest.fixture(scope="module", autouse=True)
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


@pytest.fixture(scope="module", autouse=True)
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


def compile_protos(proto_files, proto_root):
    """Compile all .proto files using grpc_tools.protoc."""
    for proto_file in proto_files:

        # Command arguments for protoc
        args = [
            "grpc_tools.protoc",
            f"--proto_path={proto_root}",  # Root directory for proto imports
            f"--python_out={proto_root}",     # Output for message classes
            f"--grpc_python_out={proto_root}",  # Output for gRPC stubs
            proto_file                     # Input .proto file
        ]

        print(f"Compiling: {proto_file}")
        ret_code = protoc.main(args)
        if ret_code != 0:
            raise Exception(f"Failed to compile {proto_file} with return code {ret_code}")


def cleanup_generated_files():
    """Remove all generated proto .py files."""
    generated_files = glob.glob("gnmi/protos/**/*.py")
    for file in generated_files:
        os.remove(file)


@pytest.fixture(scope="module", autouse=True)
def setup_and_cleanup_protos():
    """Compile proto files before running tests and remove them afterward."""
    PROTO_ROOT = "gnmi/protos"
    PROTO_FILES = ["gnmi/protos/gnoi/system/system.proto"]

    # Compile proto files into Python gRPC stubs
    compile_protos(PROTO_FILES, PROTO_ROOT)

    # Run tests, then clean up
    yield
    cleanup_generated_files()


@pytest.fixture(scope="function")
def grpc_channel(duthosts, rand_one_dut_hostname):
    """
    Fixture to set up a gRPC channel with secure credentials.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get DUT gRPC server address and port
    if ":" in duthost.mgmt_ip and not duthost.mgmt_ip.startswith('['):
        ip = f"[{duthost.mgmt_ip}]"
    else:
        ip = duthost.mgmt_ip
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    port = env.gnmi_port
    target = f"{ip}:{port}"

    # Load the TLS certificates
    with open("gnmiCA.pem", "rb") as f:
        root_certificates = f.read()
    with open("gnmiclient.crt", "rb") as f:
        client_certificate = f.read()
    with open("gnmiclient.key", "rb") as f:
        client_key = f.read()

    # Create SSL credentials
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=client_key,
        certificate_chain=client_certificate,
    )

    # Create gRPC channel
    logging.info("Creating gRPC secure channel to %s", target)
    channel = grpc.secure_channel(target, credentials)

    try:
        grpc.channel_ready_future(channel).result(timeout=10)
        logging.info("gRPC channel is ready")
    except grpc.FutureTimeoutError as e:
        logging.error("Error: gRPC channel not ready: %s", e)
        pytest.fail("Failed to connect to gRPC server")

    yield channel

    # Close the channel
    channel.close()
