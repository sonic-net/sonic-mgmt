import os
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
import logging
import pwd

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

SCP_PORT = 22
TEST_FILE_NAME = "test_file.bin"
TEST_FILE_2_NAME = "test_file_2.bin"

@pytest.fixture
def setup_teardown(duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Copies script to DUT
    duthost.copy(src="scp/perform_scp.py", dest="/home/admin/perform_scp.py")

    yield

    files_to_remove = ["./{}".format(TEST_FILE_NAME), "/home/admin/perform_scp.py"]
    for file in files_to_remove:
        duthost.file(path=file, state="absent")

    files_to_remove_2 = ["./{}".format(TEST_FILE_NAME),"./{}".format(TEST_FILE_2_NAME)]
    for file in files_to_remove_2:
        ptfhost.file(path=file, state="absent")

def test_scp_copy(duthosts, rand_one_dut_hostname, ptfhost, setup_teardown):
    duthost = duthosts[rand_one_dut_hostname]
    ptf_ip = ptfhost.mgmt_ip

    duthost.copy(src="scp/perform_scp.py", dest="/home/admin/perform_scp.py")

    # Generate the file from /dev/urandom
    ptfhost.command(("dd if=/dev/urandom of=./{} count=1 bs=1000000000 iflag=fullblock".format(TEST_FILE_NAME)))

    # Ensure that file was downloaded
    res = ptfhost.command("ls -ltr ./{}".format(TEST_FILE_NAME), module_ignore_errors=True)["rc"]
    pytest_assert(res==0, "Test file was not downloaded on the DUT")

    # Generate MD5 checksum to compare with the sent file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    #output = os.system("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    orig_checksum = output.split()[0]

    duthost.command("python3 perform_scp.py y {} /root/{} /home/admin root".format(ptf_ip, TEST_FILE_NAME))

    # Validate file was received
    res = duthost.command("ls -ltr ./{}".format(TEST_FILE_NAME), module_ignore_errors=True)["rc"]

    pytest_assert(res==0, "Test file was not found on DUT after attempted scp get")

    # Get MD5 checksum of received file
    output = duthost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    new_checksum = output.split()[0]

    # Confirm that the received file is identical to the original file
    pytest_assert(orig_checksum == new_checksum, "Original file differs from file sent to the DUT")

    # Use scp to copy the file into the PTF
    duthost.command("python3 perform_scp.py n {} /home/admin/{} /root/{} root".format(ptf_ip, TEST_FILE_NAME, TEST_FILE_2_NAME))

    # Validate that the file copied is now present in the PTF
    res = ptfhost.command("ls -ltr ./{}".format(TEST_FILE_2_NAME), module_ignore_errors=True)["rc"]
    pytest_assert(res==0, "Test file was not found on PTF after attempted scp put")

    # Get MD5 checksum of copied file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_2_NAME))["stdout"]
    fin_checksum = output.split()[0]

    pytest_assert(new_checksum == fin_checksum, "Copied file on PTF differs from copied DUT file")
