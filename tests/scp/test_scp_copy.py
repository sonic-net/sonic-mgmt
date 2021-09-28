import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

SCP_PORT = 22
TEST_FILE_NAME = "test_file.bin"
TEST_FILE_2_NAME = "test_file_2.bin"
BLOCK_SIZE = 500000000

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

def test_scp_copy(duthosts, rand_one_dut_hostname, ptfhost, setup_teardown, creds):
    duthost = duthosts[rand_one_dut_hostname]
    ptf_ip = ptfhost.mgmt_ip

    # Generate the file from /dev/urandom
    ptfhost.command(("dd if=/dev/urandom of=./{} count=1 bs={} iflag=fullblock"\
            .format(TEST_FILE_NAME, BLOCK_SIZE)))

    # Ensure that file was downloaded
    res = ptfhost.command("ls -ltr ./{}".format(TEST_FILE_NAME), module_ignore_errors=True)["rc"]
    pytest_assert(res==0, "Test file was not created on the DUT")

    # Generate MD5 checksum to compare with the sent file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    orig_checksum = output.split()[0]

    duthost.command("python3 perform_scp.py in {} /root/{} /home/admin {} {}"\
        .format(ptf_ip, TEST_FILE_NAME, creds["ptf_host_user"], creds["ptf_host_pass"]))

    # Validate file was received
    res = duthost.command("ls -ltr ./{}".format(TEST_FILE_NAME), module_ignore_errors=True)["rc"]

    pytest_assert(res==0, "Test file was not found on DUT after attempted scp get")

    # Get MD5 checksum of received file
    output = duthost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    new_checksum = output.split()[0]

    # Confirm that the received file is identical to the original file
    pytest_assert(orig_checksum == new_checksum,
            "PTF file ({}) checksum ({}) differs from DUT file({}) checksum ({})"\
            .format(TEST_FILE_NAME, orig_checksum, TEST_FILE_NAME, new_checksum))

    # Use scp to copy the file into the PTF
    duthost.command("python3 perform_scp.py out {} /home/admin/{} /root/{} {} {}"\
            .format(ptf_ip, TEST_FILE_NAME, TEST_FILE_2_NAME, creds["ptf_host_user"], creds["ptf_host_pass"]))

    # Validate that the file copied is now present in the PTF
    res = ptfhost.command("ls -ltr ./{}".format(TEST_FILE_2_NAME), module_ignore_errors=True)["rc"]
    pytest_assert(res==0, "Test file was not found on PTF after attempted scp put")

    # Get MD5 checksum of copied file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_2_NAME))["stdout"]
    fin_checksum = output.split()[0]

    pytest_assert(new_checksum == fin_checksum, 
            "Checksum ({}) of new file({}) on PTF differs from checksum ({}) of file ({}) on DUT"\
            .format(fin_checksum, TEST_FILE_2_NAME, new_checksum, TEST_FILE_NAME))
