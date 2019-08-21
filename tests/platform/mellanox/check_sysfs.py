"""
Helper script for checking status of sysfs.

This script contains re-usable functions for checking status of hw-management related sysfs.
"""
import logging
import json


def check_sysfs_broken_symbolinks(dut):
    logging.info("Check broken symbolinks")
    excludes = [
        "/bsp/thermal_zone/thermal_zone2-x86_pkg_temp/mode",
        "/bsp/environment/voltmon1",
        "/bsp/environment/voltmon2",
        "/bsp/led/",
        "/bsp/qsfp/"
    ]

    broken_symbolinks = dut.command("find /bsp -xtype l")["stdout_lines"]
    broken_symbolinks = [line for line in broken_symbolinks if not any([line.startswith(ex) for ex in excludes])]
    assert len(broken_symbolinks) == 0, \
        "Found some broken symbolinks: %s" % str(broken_symbolinks)

def check_sysfs_thermal(dut):
    logging.info("Check thermal")
    file_asic = dut.command("cat /bsp/thermal/asic")
    try:
        asic_temp = float(file_asic["stdout"]) / 1000
        assert asic_temp > 0 and asic_temp < 85, "Abnormal ASIC temperature: %s" % file_asic["stdout"]
    except:
        assert False, "Bad content in /bsp/thermal/asic: %s" % file_asic["stdout"]


def check_sysfs_fan(dut):
    logging.info("Check fan")

    from common.mellanox_data import SWITCH_MODELS
    fan_count = SWITCH_MODELS[dut.facts["hwsku"]]["fans"]["number"]

    if SWITCH_MODELS[dut.facts["hwsku"]]["fans"]["hot_swappable"]:
        fan_status_list = ["/bsp/module/fan%d_status" % fan_id for fan_id in range(1, fan_count + 1)]
        for fan_status in fan_status_list:
            fan_status_content = dut.command("cat %s" % fan_status)
            assert fan_status_content["stdout"] == "1", "Content of %s is not 1" % fan_status

    fan_min_list = ["/bsp/fan/fan%d_min" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_min in fan_min_list:
        try:
            fan_min_content = dut.command("cat %s" % fan_min)
            fan_min_speed = int(fan_min_content["stdout"])
            assert fan_min_speed > 0, "Bad fan minimum speed: %s" % str(fan_min_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_min, repr(e))

    fan_max_list = ["/bsp/fan/fan%d_max" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_max in fan_max_list:
        try:
            fan_max_content = dut.command("cat %s" % fan_max)
            fan_max_speed = int(fan_max_content["stdout"])
            assert fan_max_speed > 10000, "Bad fan maximum speed: %s" % str(fan_max_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_max, repr(e))

    fan_speed_get_list = ["/bsp/fan/fan%d_speed_get" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_speed_get in fan_speed_get_list:
        try:
            fan_speed_get_content = dut.command("cat %s" % fan_speed_get)
            fan_speed = int(fan_speed_get_content["stdout"])
            assert fan_speed > 1000, "Bad fan speed: %s" % str(fan_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_speed_get, repr(e))

    fan_speed_set_list = ["/bsp/fan/fan%d_speed_set" % fan_id for fan_id in range(1, fan_count + 1)]
    for fan_speed_set in fan_speed_set_list:
        fan_speed_set_content = dut.command("cat %s" % fan_speed_set)
        assert fan_speed_set_content["stdout"] == "153", "Fan speed should be set to 60%, 153/255"


def check_sysfs_psu(dut):
    logging.info("Check psu")

    from common.mellanox_data import SWITCH_MODELS
    psu_count = SWITCH_MODELS[dut.facts["hwsku"]]["psus"]["number"]

    if SWITCH_MODELS[dut.facts["hwsku"]]["psus"]["hot_swappable"]:
        psu_status_list = ["/bsp/module/psu%d_status" % psu_id for psu_id in range(1, psu_count + 1)]
        for psu_status in psu_status_list:
            psu_status_content = dut.command("cat %s" % psu_status)
            assert psu_status_content["stdout"] == "1", "Content of %s is not 1" % psu_status


def check_sysfs_qsfp(dut, interfaces):
    logging.info("Check qsfp status")
    ports_config = json.loads(dut.command("sonic-cfggen -d --var-json PORT")["stdout"])

    for intf in interfaces:
        intf_lanes = ports_config[intf]["lanes"]
        sfp_id = int(intf_lanes.split(",")[0])/4 + 1
        qsfp_status_file = "/bsp/qsfp/qsfp%d_status" % sfp_id
        assert dut.command("cat %s" % qsfp_status_file)["stdout"] == "1", \
            "Content of %s should be '1'" % qsfp_status_file


def check_sysfs(dut, interfaces):
    """
    @summary: Check various hw-management related sysfs under /var/run/hw-management
    """
    check_sysfs_broken_symbolinks(dut)

    check_sysfs_thermal(dut)

    check_sysfs_fan(dut)

    check_sysfs_psu(dut)

    check_sysfs_qsfp(dut, interfaces)
