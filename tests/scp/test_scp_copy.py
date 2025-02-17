import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_dut_current_passwd

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
]

SCP_PORT = 22
TEST_FILE_NAME = "test_file.bin"
TEST_FILE_2_NAME = "test_file_2.bin"
BLOCK_SIZE = 500000000


@pytest.fixture
def setup_teardown(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Copies script to DUT
    duthost.copy(src="scp/perform_scp.py", dest="/home/{}/perform_scp.py".format(creds['sonicadmin_user']))

    yield

    files_to_remove = [
        "./{}".format(TEST_FILE_NAME), "/home/{}/perform_scp.py".format(creds['sonicadmin_user'])]
    for file in files_to_remove:
        duthost.file(path=file, state="absent")

    files_to_remove_2 = [
        "./{}".format(TEST_FILE_NAME), "./{}".format(TEST_FILE_2_NAME)]
    for file in files_to_remove_2:
        ptfhost.file(path=file, state="absent")


def _gather_passwords(ptfhost, duthost):

    ptfhostvars = duthost.host.options['variable_manager']._hostvars[ptfhost.hostname]
    passwords = []
    alt_passwords = ptfhostvars.get("ansible_altpasswords", [])
    if alt_passwords:
        passwords.extend(alt_passwords)

    for key in ["ansible_password", "ptf_host_pass", "ansible_altpassword"]:
        if key in ptfhostvars:
            value = ptfhostvars.get(key, None)
            if value:
                passwords.append(value)

    return passwords


def test_scp_copy(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_teardown, creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    ptf_ip = ptfhost.mgmt_ip

    # After PTF default password rotation is supported, need to figure out which password is currently working
    _passwords = _gather_passwords(ptfhost, duthost)
    logger.warn("_password: " + str(_passwords))
    current_password = get_dut_current_passwd(ptf_ip, "", creds["ptf_host_user"], _passwords)

    # Generate the file from /dev/urandom
    ptfhost.command(("dd if=/dev/urandom of=./{} count=1 bs={} iflag=fullblock"
                     .format(TEST_FILE_NAME, BLOCK_SIZE)))

    # Ensure that file was downloaded
    res = ptfhost.command(
        "ls -ltr ./{}".format(TEST_FILE_NAME), module_ignore_errors=True)["rc"]
    pytest_assert(res == 0, "Test file was not created on the DUT")

    # Generate MD5 checksum to compare with the sent file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    orig_checksum = output.split()[0]

    python_version = "python3"
    p3_pexp_exists = duthost.command(
        "python3 -c 'import pexpect'", module_ignore_errors=True)["rc"]
    if p3_pexp_exists != 0:
        python_version = "python"

    duthost.command("{} perform_scp.py in {} /root/{} /home/{} {} {}"
                    .format(python_version, ptf_ip, TEST_FILE_NAME,
                            creds['sonicadmin_user'], creds["ptf_host_user"], current_password))

    # Validate file was received
    res = duthost.command(
        "ls -ltr ./{}".format(TEST_FILE_NAME), module_ignore_errors=True)["rc"]

    pytest_assert(
        res == 0, "Test file was not found on DUT after attempted scp get")

    # Get MD5 checksum of received file
    output = duthost.command("md5sum ./{}".format(TEST_FILE_NAME))["stdout"]
    new_checksum = output.split()[0]

    # Confirm that the received file is identical to the original file
    pytest_assert(orig_checksum == new_checksum,
                  "PTF file ({}) checksum ({}) differs from DUT file({}) checksum ({})"
                  .format(TEST_FILE_NAME, orig_checksum, TEST_FILE_NAME, new_checksum))

    # Use scp to copy the file into the PTF
    duthost.command("{} perform_scp.py out {} /home/{}/{} /root/{} {} {}"
                    .format(python_version, ptf_ip, creds['sonicadmin_user'], TEST_FILE_NAME, TEST_FILE_2_NAME,
                            creds["ptf_host_user"], current_password))

    # Validate that the file copied is now present in the PTF
    res = ptfhost.command(
        "ls -ltr ./{}".format(TEST_FILE_2_NAME), module_ignore_errors=True)["rc"]
    pytest_assert(
        res == 0, "Test file was not found on PTF after attempted scp put")

    # Get MD5 checksum of copied file
    output = ptfhost.command("md5sum ./{}".format(TEST_FILE_2_NAME))["stdout"]
    fin_checksum = output.split()[0]

    pytest_assert(new_checksum == fin_checksum,
                  "Checksum ({}) of new file({}) on PTF differs from checksum ({}) of file ({}) on DUT"
                  .format(fin_checksum, TEST_FILE_2_NAME, new_checksum, TEST_FILE_NAME))
