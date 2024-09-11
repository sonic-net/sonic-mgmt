"""
Helper script for DPU  operations
"""
import logging
import pytest
from tests.common.devices.sonic import *  # noqa: F403, F401


@pytest.fixture(scope='function')
def skip_test_smartswitch(duthost):
    """
    Checks whethere given testbed is smartswitch or not
    If not smartswitch, then skip tests
    else, checks for darkmode of dpus
    If dpus are in dark mode, then skip tests
    else, proceeds to run test cases scripts

    Args:
        duthost : Host handle
    """

    python_script_smartswitch = '''
    python -c 'import json
    import subprocess
    cmd = "cat /host/machine.conf | grep onie_platform | cut -d '=' -f 2"
    pin = subprocess.Popen(cmd,
                           shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    id = pin.communicate()[0]
    id = id.strip()
    platform_file = "/usr/share/sonic/device/" +
                    id.decode() +
                    "/platform.json"
    fp = open(platform_file, "r")
    data = json.load(fp)
    fp.close()
    print("DPUS" in data)'
    '''

    python_script_dark_mode = '''
    python -c 'import json
    fp = open("/etc/sonic/config_db.json", "r")
    data = json.load(fp)
    fp.close()
    data_dict = [(key,value) for key, value in data["CHASSIS_MODULE"].items()]
    dpus = [x[1]  for x in data_dict]
    admin_status = ([(dpu["admin_status"]=="down") for dpu in dpus])
    print(admin_status.count(admin_status[0]) == len(admin_status))'
    '''

    output_smartswitch = duthost.command(python_script_smartswitch)

    if output_smartswitch["stdout"] is False:
        pytest.skip("It is not a smartswitch")
    else:
        output_dark_mode = duthost.command(python_script_dark_mode)
        if output_dark_mode["stdout"] is True:
            pytest.skip("Smartswitch is in darkmode")

    logging.info("Testbed is smartswitch and not in dark mode")


def check_dpu_ping_status(duthost, ip_address_list):
    """
    Executes ping to all DPUs
    Args:
        duthost : Host handle
        ip_address_list (list): List of all DPU ip addresses
    Returns:
        Returns True or False based on Ping is successfull or not to all DPUs
    """

    ping_count = 0
    for ip_address in ip_address_list:
        output_ping = duthost.command("ping -c 3 %s" % (ip_address))
        if "0% packet loss" in output_ping["stdout"]:
            ping_count += 1

    return ping_count == len(ip_address_list)


def check_dpu_module_status(duthost, power_status, dpu_name):
    """
    Check status of given DPU module against given option on/off
    Args:
        duthost : Host handle
        power_status: on/off status of dpu
        dpu_name: name of the dpu module
    Returns:
        Returns True or False based on status of given DPU module
    """

    output_dpu_status = duthost.command(
            'show chassis module status | grep %s' % (dpu_name))

    if "Offline" in output_dpu_status["stdout"]:
        if power_status == "off":
            logging.info("'{}' is offline ...".format(dpu_name))
            return True
        else:
            logging.info("'{}' is online ...".format(dpu_name))
            return False
    else:
        if power_status == "on":
            logging.info("'{}' is online ...".format(dpu_name))
            return True
        else:
            logging.info("'{}' is offline ...".format(dpu_name))
            return False


def check_dpu_reboot_cause(duthost, dpu_name):
    """
    Check reboot cause of all DPU modules
    Args:
        duthost : Host handle
        dpu_name: name of the dpu module
    Returns:
        Returns True or False based on reboot cause of all DPU modules
    """

    output_reboot_cause = duthost.command(
            'show reboot-cause all | grep %s' % (dpu_name))

    if 'Unknown' in output_reboot_cause["stdout"]:
        # Checking for Unknown as of now and
        # implementation for other reasons are not in place now
        # TODO: Needs to be extend the function for other reasons
        logging.info("'{}' - reboot cause is Unkown...".format(dpu_name))
        return True

    return False


def count_dpu_modules_in_system_health_cli(duthost):
    """
    Checks and returns number of dpu modules listed  in show system-health DPU
    Args:
        duthost : Host handle
    Returns:
        Returns number of DPU modules that displays system-health status
    """

    num_dpu_health_status = 0
    output_dpu_health_cmd = duthost.show_and_parse("show system-health DPU")

    for index in range(len(output_dpu_health_cmd)):
        parse_output = output_dpu_health_cmd[index]
        if 'DPU' in parse_output['name']:
            num_dpu_health_status += 1

    return num_dpu_health_status
