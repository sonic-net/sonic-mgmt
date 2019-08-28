"""
Helper script for checking status of sysfs.

This script contains re-usable functions for checking status of hw-management related sysfs.
"""
import logging

from check_hw_mgmt_service import wait_until_fan_speed_set_to_default

def check_sysfs(dut):
    """
    @summary: Check various hw-management related sysfs under /var/run/hw-management
    """
    logging.info("Check broken symbolinks")
    broken_symbolinks = dut.command("find /var/run/hw-management -xtype l")
    assert len(broken_symbolinks["stdout_lines"]) == 0, \
        "Found some broken symbolinks: %s" % str(broken_symbolinks["stdout_lines"])

    logging.info("Check content of some key files")

    assert not wait_until_fan_speed_set_to_default(dut, timeout=120), \
        "Content of /var/run/hw-management/thermal/pwm1 should be 153"

    file_suspend = dut.command("cat /var/run/hw-management/config/suspend")
    assert file_suspend["stdout"] == "1", "Content of /var/run/hw-management/config/suspend should be 1"

    file_asic = dut.command("cat /var/run/hw-management/thermal/asic")
    try:
        asic_temp = float(file_asic["stdout"]) / 1000
        assert asic_temp > 0 and asic_temp < 85, "Abnormal ASIC temperature: %s" % file_asic["stdout"]
    except:
        assert False, "Bad content in /var/run/hw-management/thermal/asic: %s" % file_asic["stdout"]

    dut_hwsku = dut.facts["hwsku"]
    from common.mellanox_data import SWITCH_MODELS
    fan_count = SWITCH_MODELS[dut_hwsku]["fans"]["number"]

    if SWITCH_MODELS[dut_hwsku]["fans"]["hot_swappable"]:
        fan_status_list = ["/var/run/hw-management/thermal/fan%d_status" % fan_id for fan_id in range(1, fan_count + 1)]
        for fan_status in fan_status_list:
            fan_status_content = dut.command("cat %s" % fan_status)
            assert fan_status_content["stdout"] == "1", "Content of %s is not 1" % fan_status

    fan_fault_list = ["/var/run/hw-management/thermal/fan%d_fault" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_fault in fan_fault_list:
        fan_fault_content = dut.command("cat %s" % fan_fault)
        assert fan_fault_content["stdout"] == "0", "Content of %s is not 0" % fan_fault

    fan_min_list = ["/var/run/hw-management/thermal/fan%d_min" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_min in fan_min_list:
        try:
            fan_min_content = dut.command("cat %s" % fan_min)
            fan_min_speed = int(fan_min_content["stdout"])
            assert fan_min_speed > 0, "Bad fan minimum speed: %s" % str(fan_min_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_min, repr(e))

    fan_max_list = ["/var/run/hw-management/thermal/fan%d_max" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_max in fan_max_list:
        try:
            fan_max_content = dut.command("cat %s" % fan_max)
            fan_max_speed = int(fan_max_content["stdout"])
            assert fan_max_speed > 10000, "Bad fan maximum speed: %s" % str(fan_max_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_max, repr(e))

    fan_speed_get_list = ["/var/run/hw-management/thermal/fan%d_speed_get" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_speed_get in fan_speed_get_list:
        try:
            fan_speed_get_content = dut.command("cat %s" % fan_speed_get)
            fan_speed = int(fan_speed_get_content["stdout"])
            assert fan_speed > 1000, "Bad fan speed: %s" % str(fan_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_speed_get, repr(e))

    fan_speed_set_list = ["/var/run/hw-management/thermal/fan%d_speed_set" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_speed_set in fan_speed_set_list:
        fan_speed_set_content = dut.command("cat %s" % fan_speed_set)
        assert fan_speed_set_content["stdout"] == "153", "Fan speed should be set to 60%, 153/255"
