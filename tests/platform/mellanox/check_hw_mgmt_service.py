"""
Helper function for checking the hw-management service
"""
import logging
import re
import time

from common.utilities import wait_until


def fan_speed_set_to_default(dut):
    fan_speed_setting = dut.command("cat /var/run/hw-management/thermal/pwm1")["stdout"].strip()
    return fan_speed_setting == "153"


def wait_until_fan_speed_set_to_default(dut, timeout=300, interval=10):
    wait_until(timeout, interval, fan_speed_set_to_default, dut)


def check_hw_management_service(dut):
    """This function is to check the hw management service and related settings.
    """
    logging.info("Check fan speed setting")
    # In current hw-mgmt implementation, it set the fan speed to default
    # value when suspending thermal control algorithm, but it takes some time
    # to take effect. During this period, algorithm could change speed value
    # back and hw-mgmt will set it to default again, so it's possible that
    # although at some point the speed value is default but it could be changed
    # after some time. So we just wait for 300 secs to make sure fan speed is
    # set to default value instead of check every 10s.
    time.sleep(300)
    assert fan_speed_set_to_default(dut), \
        "Fan speed is not default to 60 percent in 5 minutes. 153/255=60%"

    logging.info("Check service status using systemctl")
    hw_mgmt_service_state = dut.get_service_props("hw-management")
    assert hw_mgmt_service_state["ActiveState"] == "active", "The hw-management service is not active"
    assert hw_mgmt_service_state["SubState"] == "exited", "The hw-management service is not exited"

    logging.info("Check the thermal control process")
    tc_pid = dut.command("pgrep -f /usr/bin/hw-management-thermal-control.sh")
    assert re.match(r"\d+", tc_pid["stdout"]), "The hw-management-thermal-control process is not running"

    logging.info("Check thermal control status")
    tc_suspend = dut.command("cat /var/run/hw-management/config/suspend")
    assert tc_suspend["stdout"] == "1", "Thermal control is not suspended"

    logging.info("Check dmesg")
    dmesg = dut.command("sudo dmesg")
    error_keywords = ["crash", "Out of memory", "Call Trace", "Exception", "panic"]
    for err_kw in error_keywords:
        assert not re.match(err_kw, dmesg["stdout"], re.I), \
            "Found error keyword %s in dmesg: %s" % (err_kw, dmesg["stdout"])
