import pytest
import time
import logging
import json

from tests.common import config_reload
from tests.common.reboot import reboot, REBOOT_TYPE_FAST
from tests.common.helpers.assertions import pytest_assert as pyassert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.restapi_helper import generate_cert, apply_cert_config, RESTAPI_CONTAINER_NAME
from helper import reboot_and_wait_for_fips, set_fips_by_patch

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


'''
This test checks for reset status and sets it
'''

VERIFY_PYTHON_FIPS = """
import os, ssl, time
rand_byte = ssl.RAND_bytes(1)
time.sleep(1)
with open(os.path.join("/proc", str(os.getpid()), "maps")) as f:
  print(f.read())
"""

def enable_fips(duthost, is_enable=False):
    enable_value = '0'
    if is_enable:
         enable_value = '1'
    dut_command = "sudo mkdir -p /etc/fips && echo {} | sudo tee /etc/fips/fips_enable".format(enable_value)
    duthost.shell(dut_command)

def enable_fips_restapi(duthost, is_enable=False):
    enable_fips(duthost, is_enable)
    enable_value = '0'
    if is_enable:
         enable_value = '1'
    dut_command = "docker inspect {} | grep /etc/fips/enable_fips || docker exec {} bash -c 'mkdir -p /etc/fips && echo {} > /etc/fips/fips_enable'".format(RESTAPI_CONTAINER_NAME, RESTAPI_CONTAINER_NAME, enable_value)
    duthost.shell(dut_command)

    # Restart RESTAPI server with the updated config
    dut_command = "sudo systemctl restart restapi"
    duthost.shell(dut_command)
    time.sleep(15)

def enforce_fips(duthost, is_enforce=False):
    enable_value = '0'
    if is_enable:
         enable_value = '1'
    dut_command = "sudo mkdir -p /etc/fips && echo {} | sudo tee /etc/fips/fips_enable".format(enable_value)
    duthost.shell(dut_command)

def check_fips_status(duthost, process_id, is_enabled):
    dut_command = "sudo cat /proc/{}/maps".format(process_id)
    output = duthost.shell(dut_command)['stdout']
    if is_enabled:
        pyassert("symcrypt" in output)
    else:
        pyassert("symcrypt" not in output)

def test_fips_enable_for_python(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Stop hostcfgd
    duthost.shell("sudo systemctl stop hostcfgd")

    # Disable FIPS and verify FIPS disabled
    enable_fips(duthost, False)
    dut_command = "sudo python3 -c '{}'".format(VERIFY_PYTHON_FIPS)
    output = duthost.shell(dut_command)['stdout']
    pyassert("symcrypt" not in output)

    # Enable FIPS and verify FIPS enabled
    enable_fips(duthost, True)
    dut_command = "sudo python3 -c '{}'".format(VERIFY_PYTHON_FIPS)
    output = duthost.shell(dut_command)['stdout']
    pyassert("symcrypt" in output)

    # Start hostcfgd
    duthost.shell("sudo systemctl start hostcfgd")

def test_fips_enable_for_golang(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    pyrequire(check_container_state(duthost, RESTAPI_CONTAINER_NAME, should_be_running=True),
                          "Test was not supported on devices which do not support RESTAPI!")

    # Setup Restapi certificate 
    generate_cert(duthost, localhost)
    apply_cert_config(duthost)

    # Stop hostcfgd
    duthost.shell("sudo systemctl stop hostcfgd")

    # Disable Fips
    enable_fips_restapi(duthost, False)

    # Verify the FIPS status
    process_id = duthost.shell('pgrep -f go-server-server | head -n 1')['stdout'].strip()
    check_fips_status(duthost, process_id, False)

    # Enable Fips
    enable_fips_restapi(duthost, True)

    # Verify the FIPS status
    process_id = duthost.shell('pgrep -f go-server-server | head -n 1')['stdout'].strip()
    check_fips_status(duthost, process_id, True)

    # Start hostcfgd
    duthost.shell("sudo systemctl start hostcfgd")

def test_fips_enable_for_db(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Check if test supported
    dut_command = "sudo ls /usr/local/yang-models/"
    output = duthost.shell(dut_command)['stdout']
    pyrequire("sonic-fips" in output, "Test was not supported on devices which do not support sonic-fips yang model!")

    # Make sure hostcfgd started
    duthost.shell("sudo systemctl start hostcfgd")
    time.sleep(5)

    # Apply the patch to enable FIPS
    set_fips_by_patch(duthost, True, False)
    time.sleep(10)

    # Check the FIPS enabled by openssl engine
    dut_command = "sudo openssl engine -vv"
    output = duthost.shell(dut_command)['stdout']
    pyassert("symcrypt" in output)

    # Restart the procdockerstatsd, only to update the state db quickly, it will need to wait for 120 seconds if not restart
    dut_command = "sudo systemctl restart procdockerstatsd"
    duthost.shell(dut_command)
    time.sleep(10)

    # Check the State DB
    dut_command = "redis-cli -n 6 hget 'FIPS_STATS|state' enabled"
    output = duthost.shell(dut_command)['stdout']
    pyassert("True" in output)

    dut_command = "redis-cli -n 6 hget 'FIPS_STATS|state' enforced"
    output = duthost.shell(dut_command)['stdout']
    pyassert("False" in output)

    # Apply the patch to disable FIPS
    set_fips_by_patch(duthost, False, False)
    time.sleep(5)

    # Check the FIPS enabled by openssl engine
    dut_command = "sudo openssl engine -vv"
    output = duthost.shell(dut_command)['stdout']
    if "symcrypt" in output:
        import pdb; pdb.set_trace()
    pyassert("symcrypt" not in output)

    # Restart the procdockerstatsd, only to update the state db quickly, it will need to wait for 120 seconds if not restart
    dut_command = "sudo systemctl restart procdockerstatsd"
    duthost.shell(dut_command)
    time.sleep(5)
 
    # Check the State DB
    dut_command = "redis-cli -n 6 hget 'FIPS_STATS|state' enabled"
    output = duthost.shell(dut_command)['stdout']
    pyassert("False" in output)


def test_fips_enforce(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Check if test supported
    dut_command = "sudo ls /usr/local/yang-models/"
    output = duthost.shell(dut_command)['stdout']
    pyrequire("sonic-fips" in output, "Test was not supported on devices which do not support sonic-fips yang model!")

    # Make sure hostcfgd started
    duthost.shell("sudo systemctl start hostcfgd")

    # Check the dut FIPS status
    set_fips_by_patch(duthost, False, False)
    dut_command = "sudo cat /proc/cmdline"
    output = duthost.shell(dut_command)['stdout']
    enforced = " fips=1" in output or " sonic_fips=1" in output
    if enforced:
        reboot_and_wait_for_fips(duthost, localhost, False)

    # Verify the FIPS not enforced
    set_fips_by_patch(duthost, False, False)
    dut_command = "sudo cat /proc/cmdline"
    output = duthost.shell(dut_command)['stdout']
    assert "fips=1" not in output

    # Apply the patch to enable FIPS
    set_fips_by_patch(duthost, True, True)
    time.sleep(10)

    # Restart the procdockerstatsd, only to update the state db quickly, it will need to wait for 120 seconds if not restart
    dut_command = "sudo systemctl restart procdockerstatsd"
    duthost.shell(dut_command)
    time.sleep(5)

    # Verify FIPS is not enforced in the State DB
    dut_command = "redis-cli -n 6 hget 'FIPS_STATS|state' enforced"
    output = duthost.shell(dut_command)['stdout']
    pyassert("False" in output)

    # Verify FIPS is enforced in the next reboot
    dut_command = "sudo sonic-installer get-fips"
    output = duthost.shell(dut_command)['stdout']
    assert "enabled" in output

    # Reboot
    reboot_and_wait_for_fips(duthost, localhost, True)

    # Verify the FIPS enforced
    dut_command = "sudo cat /proc/cmdline"
    output = duthost.shell(dut_command)['stdout']
    if "fips=1" not in output:
        import pdb; pdb.set_trace()
    assert "fips=1" in output

    # Verify the symcrypt loaded in openssl
    dut_command = "sudo openssl engine -vv"
    output = duthost.shell(dut_command)['stdout']
    assert "symcrypt" in output

    # Verify FIPS is enforced in the State DB
    dut_command = "redis-cli -n 6 hget 'FIPS_STATS|state' enforced"
    output = duthost.shell(dut_command)['stdout']
    pyassert("True" in output)

    # Dut run into enforced state, if adding more tests, please add the tests before test_fips_enforce,
    # or uncomment the following lines to restore the original state.
    # In the conftest.py, it will restore the old state automatically, uncomment the following lines will impact the test performance.
    # if not enforced:
    #     set_fips_by_patch(duthost, False, False)
    #     dut_command = "sudo sonic-installer set-fips --disable-fips"
    #     reboot_and_wait_for_fips(duthost, localhost, True)
