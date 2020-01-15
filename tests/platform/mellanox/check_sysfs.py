"""
Helper script for checking status of sysfs.

This script contains re-usable functions for checking status of hw-management related sysfs.
"""
import logging
import json
import re


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
        assert 0 < asic_temp < 85, "Abnormal ASIC temperature: %s" % file_asic["stdout"]
    except Exception as e:
        assert False, "Bad content in /bsp/thermal/asic: %s, exception: %s" % (file_asic["stdout"], repr(e))


def check_sysfs_fan(dut):
    logging.info("Check fan")

    from common.mellanox_data import SWITCH_MODELS
    fan_count = SWITCH_MODELS[dut.facts["hwsku"]]["fans"]["number"]

    fan_speed = 0
    fan_min_speed = 0
    fan_max_speed = 0
    fan_set_speed = 0
    for fan_id in range(1, fan_count + 1):
        if SWITCH_MODELS[dut.facts["hwsku"]]["fans"]["hot_swappable"]:
            fan_status = "/bsp/module/fan{}_status".format(fan_id)
            try:
                fan_status_content = dut.command("cat %s" % fan_status)
                assert fan_status_content["stdout"] == "1", "Content of %s is not 1" % fan_status
            except Exception as e:
                assert False, "Get content from %s failed, exception: %s" % (fan_status, repr(e))

        fan_min = "/bsp/fan/fan{}_min".format(fan_id)
        try:
            fan_min_content = dut.command("cat %s" % fan_min)
            fan_min_speed = int(fan_min_content["stdout"])
            assert fan_min_speed > 0, "Bad fan minimum speed: %s" % str(fan_min_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_min, repr(e))

        fan_max = "/bsp/fan/fan{}_max".format(fan_id)
        try:
            fan_max_content = dut.command("cat %s" % fan_max)
            fan_max_speed = int(fan_max_content["stdout"])
            assert fan_max_speed > 10000, "Bad fan maximum speed: %s" % str(fan_max_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_max, repr(e))

        fan_speed_get = "/bsp/fan/fan{}_speed_get".format(fan_id)
        try:
            fan_speed_get_content = dut.command("cat %s" % fan_speed_get)
            fan_speed = int(fan_speed_get_content["stdout"])
            assert fan_speed > 1000, "Bad fan speed: %s" % str(fan_speed)
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_speed_get, repr(e))

        assert fan_min_speed < fan_speed < fan_max_speed, \
            "Fan speed out of range: min speed: %d, speed: %d, max speed: %d" \
            % (fan_min_speed, fan_speed, fan_max_speed)

        fan_speed_set = "/bsp/fan/fan{}_speed_set".format(fan_id)
        try:
            fan_speed_set_content = dut.command("cat %s" % fan_speed_set)
            assert fan_speed_set_content["stdout"] == "153", "Fan speed should be set to 60%, 153/255"
            fan_set_speed = int(fan_speed_set_content["stdout"])
        except Exception as e:
            assert False, "Get content from %s failed, exception: %s" % (fan_speed_set, repr(e))

        max_tolerance_speed = ((float(fan_set_speed) / 256) * fan_max_speed) * (1 + 0.3)
        min_tolerance_speed = ((float(fan_set_speed) / 256) * fan_max_speed) * (1 - 0.3)
        assert min_tolerance_speed < fan_speed < max_tolerance_speed, "Speed out of tolerance speed range (%d, %d)" \
                                                                      % (min_tolerance_speed, max_tolerance_speed)


def check_sysfs_cpu(dut):
    logging.info("Check cpu")
    from common.mellanox_data import SWITCH_MODELS
    cpu_pack_count = SWITCH_MODELS[dut.facts["hwsku"]]["cpu_pack"]["number"]
    if cpu_pack_count != 0:
        cpu_pack_temp_file = "/bsp/thermal/cpu_pack"
        cpu_pack_temp_file_output = dut.command("cat %s" % cpu_pack_temp_file)
        cpu_pack_temp = float(cpu_pack_temp_file_output["stdout"])/1000

        cpu_pack_max_temp_file = "/bsp/thermal/cpu_pack_max"
        cpu_pack_max_temp_file_output = dut.command("cat %s" % cpu_pack_max_temp_file)
        cpu_pack_max_temp = float(cpu_pack_max_temp_file_output["stdout"])/1000

        cpu_pack_crit_temp_file = "/bsp/thermal/cpu_pack_crit"
        cpu_pack_crit_temp_file_output = dut.command("cat %s" % cpu_pack_crit_temp_file)
        cpu_pack_crit_temp = float(cpu_pack_crit_temp_file_output["stdout"])/1000

        assert cpu_pack_max_temp <= cpu_pack_crit_temp, "Bad CPU pack max temp or critical temp, %s, %s " \
                                                        % (str(cpu_pack_max_temp), str(cpu_pack_crit_temp))
        assert cpu_pack_temp < cpu_pack_max_temp, "CPU pack overheated, temp: %s" % (str(cpu_pack_temp))

    cpu_core_count = SWITCH_MODELS[dut.facts["hwsku"]]["cpu_cores"]["number"]
    for core_id in range(0, cpu_core_count):
        cpu_core_temp_file = "/bsp/thermal/cpu_core{}".format(core_id)
        cpu_core_temp_file_output = dut.command("cat %s" % cpu_core_temp_file)
        cpu_core_temp = float(cpu_core_temp_file_output["stdout"])/1000

        cpu_core_max_temp_file = "/bsp/thermal/cpu_core{}_max".format(core_id)
        cpu_core_max_temp_file_output = dut.command("cat %s" % cpu_core_max_temp_file)
        cpu_core_max_temp = float(cpu_core_max_temp_file_output["stdout"])/1000

        cpu_core_crit_temp_file = "/bsp/thermal/cpu_core{}_crit".format(core_id)
        cpu_core_crit_temp_file_output = dut.command("cat %s" % cpu_core_crit_temp_file)
        cpu_core_crit_temp = float(cpu_core_crit_temp_file_output["stdout"])/1000

        assert cpu_core_max_temp <= cpu_core_crit_temp, "Bad CPU core%d max temp or critical temp, %s, %s " \
                                                        % (core_id, str(cpu_core_max_temp), str(cpu_core_crit_temp))
        assert cpu_core_temp < cpu_core_max_temp, "CPU core%d overheated, temp: %s" % (core_id, str(cpu_core_temp))


def check_psu_status_sysfs_consistency(dut, psu_id, psu_state):
    """
    @summary: Check psu related sysfs under /bsp/module against psu_state
    """
    psu_exist = "/bsp/module/psu%s_status" % psu_id
    if psu_state == "NOT PRESENT":
        psu_exist_content = dut.command("cat %s" % psu_exist)
        logging.info("PSU state %s file %s read %s" % (psu_state, psu_exist, psu_exist_content["stdout"]))
        assert psu_exist_content["stdout"] == "0", "CLI returns NOT PRESENT while %s contains %s" %  \
                    (psu_exist, psu_exist_content["stdout"])
    else:
        from common.mellanox_data import SWITCH_MODELS
        dut_hwsku = dut.facts["hwsku"]
        hot_swappabe = SWITCH_MODELS[dut_hwsku]["psus"]["hot_swappable"]
        if hot_swappabe:
            psu_exist_content = dut.command("cat %s" % psu_exist)
            logging.info("PSU state %s file %s read %s" % (psu_state, psu_exist, psu_exist_content["stdout"]))
            assert psu_exist_content["stdout"] == "1", "CLI returns %s while %s contains %s" %  \
                        (psu_state, psu_exist, psu_exist_content["stdout"])

        psu_pwr_state = "/bsp/module/psu%s_pwr_status" % psu_id
        psu_pwr_state_content = dut.command("cat %s" % psu_pwr_state)
        logging.info("PSU state %s file %s read %s" % (psu_state, psu_pwr_state, psu_pwr_state_content["stdout"]))
        assert (psu_pwr_state_content["stdout"] == "1" and psu_state == "OK") \
                or (psu_pwr_state_content["stdout"] == "0" and psu_state == "NOT OK"),\
            "sysfs content %s mismatches with psu_state %s" % (psu_pwr_state_content["stdout"], psu_state)


def check_sysfs_psu(dut):
    logging.info("Check psu")

    from common.mellanox_data import SWITCH_MODELS
    psu_count = SWITCH_MODELS[dut.facts["hwsku"]]["psus"]["number"]

    CMD_PLATFORM_PSUSTATUS = "show platform psustatus"
    logging.info("Get PSU status using '%s', hostname: %s" % (CMD_PLATFORM_PSUSTATUS, dut.hostname))
    psu_status = dut.command(CMD_PLATFORM_PSUSTATUS)
    psu_status_lines = psu_status["stdout_lines"][2:]
    assert len(psu_status_lines) == psu_count, "PSU status output does not match PSU count"

    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")
    for psu_id in range(1, psu_count + 1):
        psu_status_line = psu_status_lines[psu_id - 1]
        psu_state = psu_line_pattern.match(psu_status_line).group(1)
        check_psu_status_sysfs_consistency(dut, psu_id, psu_state)


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

    check_sysfs_cpu(dut)

    check_sysfs_psu(dut)

    check_sysfs_qsfp(dut, interfaces)
