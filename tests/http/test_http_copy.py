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

def test_http_copy(duthosts, rand_one_dut_hostname, ptfhost):
    """Test that HTTP (copy) can be used to download objects to the DUT"""

    pytest.skip("---- test doesn't clean up the files in /tmp, it will cause the subsequent cases in /tmp fail,"
                "skipping until the issue is addressed ----")
    duthost = duthosts[rand_one_dut_hostname]
    ptf_ip = ptfhost.mgmt_ip

    test_file_name = "test_file.bin"

    # Copies http server files to ptf
    ptfhost.copy(src="http/start_http_server.py", dest="/tmp/start_http_server.py")
    ptfhost.copy(src="http/stop_http_server.py", dest="/tmp/stop_http_server.py")

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
    ptfhost.command(("dd if=/dev/urandom of=./{} count=1 bs=1000000000 iflag=fullblock".format(test_file_name)))

    # Ensure that file was downloaded
    file_stat = ptfhost.stat(path="./{}".format(test_file_name))

    pytest_assert(file_stat["stat"]["exists"], "Test file was not found on DUT after attempted http get")

    # Generate MD5 checksum to compare with the sent file
    output = ptfhost.command("md5sum ./{}".format(test_file_name))["stdout"]
    orig_checksum = output.split()[0]

    # Have DUT request file from http server
    duthost.command("curl -O {}:{}/{}".format(ptf_ip, HTTP_PORT, test_file_name))

    # Validate file was received
    file_stat = duthost.stat(path="./{}".format(test_file_name))

    pytest_assert(file_stat["stat"]["exists"], "Test file was not found on DUT after attempted http get")

    # Get MD5 checksum of received file
    output = duthost.command("md5sum ./{}".format(test_file_name))["stdout"]
    new_checksum = output.split()[0]

    # Confirm that the received file is identical to the original file
    pytest_assert(orig_checksum == new_checksum, "Original file differs from file sent to the DUT")

    # Perform cleanup on DUT
    duthost.command("sudo rm ./{}".format(test_file_name))

    # Confirm cleanup occured succesfuly
    file_stat = duthost.stat(path="./{}".format(test_file_name))

    pytest_assert(not file_stat["stat"]["exists"], "DUT container could not be cleaned.")

    # Delete file off ptf
    ptfhost.command(("rm ./{}".format(test_file_name)))

    # Ensure that file was removed correctly
    file_stat = ptfhost.stat(path="./{}".format(test_file_name))

    pytest_assert(not file_stat["stat"]["exists"], "PTF container could not be cleaned.")

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
