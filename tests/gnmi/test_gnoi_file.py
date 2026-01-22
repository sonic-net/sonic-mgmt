import logging
import pytest

from .helper import gnoi_request, extract_gnoi_response, gnoi_exec
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]


"""
This module contains tests for the gNOI File API.
"""


@pytest.mark.disable_loganalyzer
def test_gnoi_file_get(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify gNOI File.Get returns method unimplemented error as expected.

    """

    duthost = duthosts[rand_one_dut_hostname]
    request_json = '{"remote_file": "/etc/hostfile.txt"}'
    ret, msg = gnoi_request(duthost, localhost, "File", "Get", request_json)
    pytest_assert(ret == -1, "File.Get RPC failed: rc = {}, msg = {}".format(ret, msg))
    if not msg:
        pytest.fail("Failed to extract gnoi response for File.Get RPC")

    logging.info("File.Get Response: {}" .format(msg))
    pytest_assert("Method file.Get is unimplemented" in msg, "Expected Method Unimplemented error")


@pytest.mark.disable_loganalyzer
def test_gnoi_file_stat(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify gNOI File.Stat returns the statistcis of the specified file as follows
    {stats : {<path, lastmodified, size(in bytes), permissions, umask> }}

    """

    duthost = duthosts[rand_one_dut_hostname]
    request_json = '{"path": "/etc/hostname"}'
    ret, msg = gnoi_request(duthost, localhost, "File", "Stat", request_json)
    pytest_assert(ret == 0, "File.Stat RPC failed: rc = {}, msg = {}".format(ret, msg))

    msg_json = extract_gnoi_response(msg)
    if not msg_json:
        pytest.fail("Failed to extract gnoi response for File.Stat RPC")

    logging.info("File.stat Response: {}" .format(msg_json))
    pytest_assert("File Stat" in msg, "Expected File Stat")


@pytest.mark.disable_loganalyzer
def test_gnoi_file_remove_invalid_file(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify gNOI File.Remove returns file not found error for invalid files.
    """

    duthost = duthosts[rand_one_dut_hostname]
    request_json = '{"remote_file":"/tmp/test_remove"}'
    ret, msg = gnoi_request(duthost, localhost, "File", "Remove", request_json)
    pytest_assert(ret == -1, "File.Remove RPC failed: rc = {}, msg = {}".format(ret, msg))

    if not msg:
        pytest.fail("Failed to extract gnoi response for File.Remove RPC")

    logging.info("File.Remove Response: {}" .format(msg))
    pytest_assert('File not found' in msg, "No such file. Failed to remove'")


@pytest.mark.disable_loganalyzer
def test_gnoi_file_transfertoremote(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify gNOI File.TransferToRemote returns method unimplemented error as expected.
    """

    duthost = duthosts[rand_one_dut_hostname]
    request_json = (
        '{'
        '"local_path": "/etc/config.txt", '
        '"remote_download": {'
        '"protocol": 1, '
        '"remote_url": "scp://user@remotehost:/path/to/destination", '
        '"username": "********", '
        '"password": "********"'
        '}'
        '}'
    )

    ret, msg = gnoi_request(duthost, localhost, "File", "TransferToRemote", request_json)
    pytest_assert(ret == -1, "File.TransferToRemote RPC failed: rc = {}, msg = {}".format(ret, msg))

    if not msg:
        pytest.fail("Failed to extract gnoi response for File.TransferToRemote RPC")

    logging.info("File.TransferToRemote Response: {}" .format(msg))
    pytest_assert('unimplemented' in msg, "Expected Method Unimplemented error")


@pytest.mark.disable_loganalyzer
def test_gnoi_file_remove(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify gNOI File.Remove removes the specified file on the target successfully.
    """

    duthost = duthosts[rand_one_dut_hostname]
    dut_cmd = "touch /tmp/test_remove"
    duthost.shell(dut_cmd, module_ignore_errors=True)

    request_json = '{"remote_file":"/tmp/test_remove"}'
    ret, msg = gnoi_request(duthost, localhost, "File", "Remove", request_json)

    pytest_assert(ret == 0, "File.Remove RPC failed: rc = {}, msg = {}".format(ret, msg))

    if not msg:
        pytest.fail("Failed to extract gnoi response for File.Remove RPC")

    logging.info("File.Remove Response: {}" .format(msg))
    pytest_assert('File Remove' in msg, "Expected 'File Remove' message not found in response")


@pytest.mark.disable_loganalyzer
def test_gnoi_file_put(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify gNOI File.Put returns method unimplemented error as expected.
    """

    duthost = duthosts[rand_one_dut_hostname]
    val = gnoi_exec(duthost, "touch /tmp/sample.bin")
    pytest_assert(val == 0, "Failed to open the file")

    request_json = '{"remote_file":"/tmp/test.bin","permissions":644}'
    input_data = ' -input_file="/tmp/sample.bin"'

    ret, msg = gnoi_request(duthost, localhost, "File", "Put", request_json, input_data)
    pytest_assert(ret == -1, "File.Put RPC failed: rc = {}, msg = {}".format(ret, msg))

    val = gnoi_exec(duthost, "rm -rf /tmp/sample.bin")
    pytest_assert(val == 0, "Failed to remove the file")

    if not msg:
        pytest.fail("Failed to extract gnoi response for File.Put RPC")

    logging.info("File.Put Response: {}" .format(msg))
    pytest_assert('unimplemented' in msg, "Expected Method Unimplemented error")
