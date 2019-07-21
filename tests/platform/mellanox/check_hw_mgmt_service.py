"""
Helper function for checking the hw-management service
"""
import logging
import re

from utilities import wait_until


def fan_speed_set_to_default(dut):
    fan_speed_setting = dut.command("cat /var/run/hw-management/thermal/pwm1")["stdout"].strip()
    return fan_speed_setting == "153"


def wait_until_fan_speed_set_to_default(dut):
    wait_until(300, 10, fan_speed_set_to_default, dut)


def check_hw_management_service(dut):
    """This function is to check the hw management service and related settings.
    """
    logging.info("Check service status using systemctl")
    hw_mgmt_service_state = dut.command("systemctl -p ActiveState -p SubState show hw-management")
    assert hw_mgmt_service_state["stdout"].find("ActiveState=active") >= 0, "The hw-management service is not active"
    assert hw_mgmt_service_state["stdout"].find("SubState=exited") >= 0, "The hw-management service is not exited"

    logging.info("Check the thermal control process")
    tc_pid = dut.command("pgrep -f /usr/bin/hw-management-thermal-control.sh")
    assert re.match(r"\d+", tc_pid["stdout"]), "The hw-management-thermal-control process is not running"

    logging.info("Check thermal control status")
    tc_suspend = dut.command("cat /var/run/hw-management/config/suspend")
    assert tc_suspend["stdout"] == "1", "Thermal control is not suspended"

    logging.info("Check fan speed setting")
    fan_speed_setting = dut.command("cat /var/run/hw-management/thermal/pwm1")
    assert fan_speed_setting["stdout"] == "153", "Fan speed is not default to 60%. 153/255=60%"

    logging.info("Check dmesg")
    dmesg = dut.command("sudo dmesg")
    error_keywords = ["crash", "Out of memory", "Call Trace", "Exception", "panic"]
    for err_kw in error_keywords:
        assert not re.match(err_kw, dmesg["stdout"], re.I), \
            "Found error keyword %s in dmesg: %s" % (err_kw, dmesg["stdout"])
