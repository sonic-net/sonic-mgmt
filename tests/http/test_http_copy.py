import os
import pytest
import time
import tempfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.devices.multi_asic import MultiAsicSonicHost


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
]


SONIC_SSH_PORT = 22
SONIC_SSH_REGEX = "OpenSSH_[\\w\\.]+ Debian"
HTTP_PORT = "8080"
TEST_FILE_NAME = ""

LOCAL_START_SERVER_FILENAME = "http/start_http_server.py"
LOCAL_START_SERVER_FILENAME_IPV6 = "http/start_http_server_ipv6.py"
PTF_START_SERVER_FILENAME = "/tmp/start_http_server.py"
LOCAL_STOP_SERVER_FILENAME = "http/stop_http_server.py"
PTF_STOP_SERVER_FILENAME = "/tmp/stop_http_server.py"


def mgmt_ip_is_v6(duthost: MultiAsicSonicHost) -> bool:
    return duthost.get_mgmt_ip()['version'] == 'v6'


@pytest.fixture(autouse=True)
def setup_teardown(ptfhost, duthost):
    global TEST_FILE_NAME

    # Copies http server files to ptf
    local_start_server_filename = LOCAL_START_SERVER_FILENAME_IPV6 if mgmt_ip_is_v6(duthost) else LOCAL_START_SERVER_FILENAME
    ptfhost.copy(src=local_start_server_filename, dest=PTF_START_SERVER_FILENAME)
    ptfhost.copy(src=LOCAL_STOP_SERVER_FILENAME, dest=PTF_STOP_SERVER_FILENAME)

    with tempfile.NamedTemporaryFile(prefix="http_copy_test_file", suffix=".bin") as test_file:
        TEST_FILE_NAME = os.path.basename(test_file.name)

        # this 'yield' is inside the scope of the with-statment so that the temporary binary will be in scope for the
        # test but will be automatically deleted when the test is done
        yield

        # Delete files off ptf and ensure that files were removed
        files_to_remove = [PTF_START_SERVER_FILENAME, PTF_STOP_SERVER_FILENAME]

        for file in files_to_remove:
            ptfhost.file(path=file, state="absent")


def test_http_copy(duthosts, rand_one_dut_hostname, ptfhost):
    """Test that HTTP (copy) can be used to download objects to the DUT"""

    duthost = duthosts[rand_one_dut_hostname]

    if mgmt_ip_is_v6(duthost):
        ptf_ip = ptfhost.mgmt_ipv6
        curl_check_server_cmd = f"curl -6 [{ptf_ip}]:8080"
        curl_copy_cmd = f"curl -O -6 [{ptf_ip}]:{HTTP_PORT}/{TEST_FILE_NAME}"
    else:
        ptf_ip = ptfhost.mgmt_ip
        curl_check_server_cmd = f"curl {ptf_ip}:8080"
        curl_copy_cmd = f"curl -O {ptf_ip}:{HTTP_PORT}/{TEST_FILE_NAME}"

    # Starts the http server on the ptf
    ptfhost.command(f"python {PTF_START_SERVER_FILENAME}", module_async=True)

    # Validate HTTP Server has started
    started = False
    tries = 0
    while not started and tries < 10:
        if os.system(curl_check_server_cmd) == 0:
            started = True
        tries += 1
        time.sleep(1)

    pytest_assert(started, "HTTP Server could not be started")

    # Generate the file from /dev/urandom
    ptfhost.command(("dd if=/dev/urandom of=./{} count=1 bs=1000000 iflag=fullblock".format(TEST_FILE_NAME)))

    # Ensure that file was downloaded
    file_stat = ptfhost.stat(path="./{}".format(TEST_FILE_NAME))

    pytest_assert(file_stat["stat"]["exists"], "Test file was not found on DUT after attempted http get")

    # Generate MD5 checksum to compare with the sent file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    orig_checksum = output.split()[0]

    # Have DUT request file from http server
    duthost.command(curl_copy_cmd)

    # Validate file was received
    file_stat = duthost.stat(path="./{}".format(TEST_FILE_NAME))

    pytest_assert(file_stat["stat"]["exists"], "Test file was not found on DUT after attempted http get")

    # Get MD5 checksum of received file
    output = duthost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    new_checksum = output.split()[0]

    # Confirm that the received file is identical to the original file
    pytest_assert(orig_checksum == new_checksum, "Original file differs from file sent to the DUT")

    # Stops http server
    ptfhost.command(f"python {PTF_STOP_SERVER_FILENAME}")

    # Ensure that HTTP server was closed
    started = True
    tries = 0
    while started and tries < 10:
        if os.system(curl_check_server_cmd) != 0:
            started = False
        tries += 1
        time.sleep(1)

    pytest_assert(not started, "HTTP Server could not be stopped.")
