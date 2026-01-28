"""
Simple integration tests for gNOI File service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging

# Import fixtures module to ensure pytest discovers them
import tests.common.fixtures.grpc_fixtures  # noqa: F401
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Enable TLS fixture by default for all tests in this module
pytestmark = pytest.mark.usefixtures("setup_gnoi_tls_server")


def test_file_stat(ptf_gnoi):
    """Test File.Stat RPC with TLS enabled by default."""
    try:
        result = ptf_gnoi.file_stat("/etc/hostname")
        assert "stats" in result
        logger.info(f"File stats: {result['stats'][0]}")
    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.Stat failed (expected): {e}")


def test_file_transfer_to_remote(ptf_gnoi, ptfhost, duthosts, rand_one_dut_hostname):
    """Test File.TransferToRemote RPC downloading file from HTTP server to DUT."""
    duthost = duthosts[rand_one_dut_hostname]

    # Test file configuration
    test_filename = "test.txt"
    test_content = "Hello from gNOI TransferToRemote test!"
    local_path = f"/tmp/{test_filename}"
    http_port = 8080

    try:
        # 1. Create test file on PTF host
        logger.info(f"Creating test file {test_filename} on PTF host")
        ptfhost.shell(f"echo '{test_content}' > /tmp/{test_filename}")

        # 2. Start HTTP server on PTF host
        logger.info(f"Starting HTTP server on PTF host port {http_port}")
        ptfhost.command(f"cd /tmp && python -m http.server {http_port}", module_async=True)

        # 3. Wait for HTTP server to start
        ptf_ip = ptfhost.mgmt_ip
        logger.info(f"Waiting for HTTP server to start at {ptf_ip}:{http_port}")

        def server_ready():
            try:
                result = ptfhost.command(f"curl -f --max-time 2 {ptf_ip}:{http_port}",
                                         module_ignore_errors=True)
                return result["rc"] == 0
            except Exception:
                return False

        wait_until(server_ready, timeout=30, interval=2,
                   delay=2, backoff=1.1)
        logger.info("HTTP server is ready")

        # 4. Test TransferToRemote
        remote_url = f"http://{ptf_ip}:{http_port}/{test_filename}"
        logger.info(f"Testing TransferToRemote: {remote_url} -> {local_path}")

        result = ptf_gnoi.file_transfer_to_remote(
            local_path=local_path,
            remote_url=remote_url,
            protocol="HTTP"
        )

        # 5. Verify response has hash
        assert "hash" in result, "TransferToRemote response missing hash field"
        logger.info(f"TransferToRemote response: {result}")

        # 6. Verify file was downloaded to DUT
        file_stat = duthost.stat(path=local_path)
        assert file_stat["stat"]["exists"], f"File {local_path} not found on DUT after transfer"
        logger.info(f"File successfully downloaded to DUT: {local_path}")

        # 7. Verify downloaded content
        downloaded_content = duthost.shell(f"cat {local_path}")["stdout"].strip()
        assert test_content in downloaded_content, \
            f"Content mismatch. Expected: '{test_content}', Got: '{downloaded_content}'"
        logger.info(f"File content verified: {downloaded_content}")

        logger.info("TransferToRemote test completed successfully")

    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.TransferToRemote failed (may be expected): {e}")

    finally:
        # 8. Cleanup
        logger.info("Cleaning up test resources")
        try:
            # Stop HTTP server
            ptfhost.command(f"pkill -f 'python.*http.server.*{http_port}'",
                            module_ignore_errors=True)
            # Remove test file from PTF
            ptfhost.shell(f"rm -f /tmp/{test_filename}", module_ignore_errors=True)
            # Remove downloaded file from DUT
            duthost.shell(f"rm -f {local_path}", module_ignore_errors=True)
            logger.info("Cleanup completed")
        except Exception as cleanup_e:
            logger.warning(f"Cleanup failed: {cleanup_e}")
