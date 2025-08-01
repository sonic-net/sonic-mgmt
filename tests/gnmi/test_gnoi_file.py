import logging
import pytest
import time

from .helper import gnoi_request, extract_gnoi_response
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
