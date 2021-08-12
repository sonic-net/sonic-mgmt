import os
import pytest
import time
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

SONIC_SSH_PORT = 22
SONIC_SSH_REGEX = "OpenSSH_[\\w\\.]+ Debian"
HTTP_PORT = "8080"

TEST_FILE_NAME = "test_file.bin"

@pytest.fixture
def setup_teardown(duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Copies http server files to ptf
    ptfhost.copy(src="http/start_http_server.py", dest="/tmp/start_http_server.py")
    ptfhost.copy(src="http/stop_http_server.py", dest="/tmp/stop_http_server.py")

    yield

    # Perform cleanup on DUT
    duthost.file(path="./{}".format(TEST_FILE_NAME), state="absent")

    # Confirm cleanup occured succesfuly
    file_stat = duthost.stat(path="./{}".format(TEST_FILE_NAME))

    # Delete files off ptf and Ensure that files were removed
    files_to_remove = ["./{}".format(TEST_FILE_NAME), "/tmp/start_http_server.py", "/tmp/stop_http_server.py"]

    for file in files_to_remove:
        ptfhost.file(path=file, state="absent")


def test_http_copy(duthosts, rand_one_dut_hostname, ptfhost, setup_teardown):
    """Test that HTTP (copy) can be used to download objects to the DUT"""

    duthost = duthosts[rand_one_dut_hostname]
    ptf_ip = ptfhost.mgmt_ip

    # Starts the http server on the ptf
    ptfhost.command("python /tmp/start_http_server.py", module_async=True)

    # Validate HTTP Server has started
    started = False
    tries = 0
    while not started and tries < 10:
        if os.system("curl {}:8080".format(ptf_ip)) == 0:
            started = True
        tries += 1
        time.sleep(1)

    pytest_assert(started, "HTTP Server could not be started")

    # Generate the file from /dev/urandom
    ptfhost.command(("dd if=/dev/urandom of=./{} count=1 bs=1000000000 iflag=fullblock".format(TEST_FILE_NAME)))

    # Ensure that file was downloaded
    file_stat = ptfhost.stat(path="./{}".format(TEST_FILE_NAME))

    pytest_assert(file_stat["stat"]["exists"], "Test file was not found on DUT after attempted http get")

    # Generate MD5 checksum to compare with the sent file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    orig_checksum = output.split()[0]

    # Have DUT request file from http server
    duthost.command("curl -O {}:{}/{}".format(ptf_ip, HTTP_PORT, TEST_FILE_NAME))

    # Validate file was received
    file_stat = duthost.stat(path="./{}".format(TEST_FILE_NAME))

    pytest_assert(file_stat["stat"]["exists"], "Test file was not found on DUT after attempted http get")

    # Get MD5 checksum of received file
    output = duthost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    new_checksum = output.split()[0]

    # Confirm that the received file is identical to the original file
    pytest_assert(orig_checksum == new_checksum, "Original file differs from file sent to the DUT")

    # Stops http server
    ptfhost.command("python /tmp/stop_http_server.py")

    # Ensure that HTTP server was closed
    started = True
    tries = 0
    while started and tries < 10:
        if os.system("curl {}:8080".format(ptf_ip)) != 0:
            started = False
        tries += 1
        time.sleep(1)

    pytest_assert(not started, "HTTP Server could not be stopped.")
