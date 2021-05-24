"""
Helper function for checking the hw-management service
"""
import logging
import re


def check_hw_management_service(dut):
    """This function is to check the hw management service and related settings.
    """
    logging.info("Check service status using systemctl")
    hw_mgmt_service_state = dut.get_service_props("hw-management")
    assert hw_mgmt_service_state["ActiveState"] == "active", "The hw-management service is not active"
    assert hw_mgmt_service_state["SubState"] == "exited", "The hw-management service is not exited"

    logging.info("Check dmesg")
    dmesg = dut.command("sudo dmesg")
    error_keywords = ["crash", "Out of memory", "Call Trace", "Exception", "panic"]
    for err_kw in error_keywords:
        assert not re.match(err_kw, dmesg["stdout"], re.I), \
            "Found error keyword %s in dmesg: %s" % (err_kw, dmesg["stdout"])
