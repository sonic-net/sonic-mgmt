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
        assert 0 < asic_temp < 85, "Abnormal ASIC temperature: %s" % file_asic["stdout"]
    except Exception as e:
        assert False, "Bad content in /var/run/hw-management/thermal/asic: %s" % repr(e)

    dut_hwsku = dut.facts["hwsku"]
    from common.mellanox_data import SWITCH_MODELS
    fan_count = SWITCH_MODELS[dut_hwsku]["fans"]["number"]

    fan_speed = 0
    fan_min_speed = 0
    fan_max_speed = 0
    for fan_id in range(1, fan_count + 1):
        if SWITCH_MODELS[dut_hwsku]["fans"]["hot_swappable"]:
            fan_status = "/var/run/hw-management/thermal/fan{}_status".format(fan_id)
            fan_status_content = dut.command("cat %s" % fan_status)
            assert fan_status_content["stdout"] == "1", "Content of %s is not 1" % fan_status

        fan_fault = "/var/run/hw-management/thermal/fan{}_fault".format(fan_id)
        fan_fault_content = dut.command("cat %s" % fan_fault)
        assert fan_fault_content["stdout"] == "0", "Content of %s is not 0" % fan_fault

        fan_min = "/var/run/hw-management/thermal/fan{}_min".format(fan_id)
        try:
            fan_min_content = dut.command("cat %s" % fan_min)
            fan_min_speed = int(fan_min_content["stdout"])
            assert fan_min_speed > 0, "Bad fan minimum speed: %s" % str(fan_min_speed)
        except Exception as e:
            assert "Get content from %s failed, exception: %s" % (fan_min, repr(e))

        fan_max = "/var/run/hw-management/thermal/fan{}_max".format(fan_id)
        try:
            fan_max_content = dut.command("cat %s" % fan_max)
            fan_max_speed = int(fan_max_content["stdout"])
            assert fan_max_speed > 10000, "Bad fan maximum speed: %s" % str(fan_max_speed)
        except Exception as e:
            assert "Get content from %s failed, exception: %s" % (fan_max, repr(e))

        fan_speed_set = "/var/run/hw-management/thermal/fan{}_speed_set".format(fan_id)
        fan_speed_set_content = dut.command("cat %s" % fan_speed_set)
        assert fan_speed_set_content["stdout"] == "153", "Fan speed should be set to 60%, 153/255"
        fan_set_speed = int(fan_speed_set_content["stdout"])

        fan_speed_get = "/var/run/hw-management/thermal/fan{}_speed_get".format(fan_id)
        try:
            fan_speed_get_content = dut.command("cat %s" % fan_speed_get)
            fan_speed = int(fan_speed_get_content["stdout"])
            assert fan_min_speed < fan_speed < fan_max_speed, "Bad fan speed: %s" % str(fan_speed)
        except Exception as e:
            assert "Get content from %s failed, exception: %s" % (fan_speed_get, repr(e))

        max_tolerance_speed = ((float(fan_set_speed)/256)*fan_max_speed)*(1 + 0.3)
        min_tolerance_speed = ((float(fan_set_speed)/256)*fan_max_speed)*(1 - 0.3)
        assert min_tolerance_speed < fan_speed < max_tolerance_speed, "Speed out of tolerance speed range (%d, %d)" \
                                                                      % (min_tolerance_speed, max_tolerance_speed)

    cpu_pack_count = SWITCH_MODELS[dut_hwsku]["cpu_pack"]["number"]
    if cpu_pack_count != 0:
        cpu_pack_temp_file = "/var/run/hw-management/thermal/cpu_pack"
        cpu_pack_temp_file_output = dut.command("cat %s" % cpu_pack_temp_file)
        cpu_pack_temp = float(cpu_pack_temp_file_output["stdout"])/1000

        cpu_pack_max_temp_file = "/var/run/hw-management/thermal/cpu_pack_max"
        cpu_pack_max_temp_file_output = dut.command("cat %s" % cpu_pack_max_temp_file)
        cpu_pack_max_temp = float(cpu_pack_max_temp_file_output["stdout"])/1000

        cpu_pack_crit_temp_file = "/var/run/hw-management/thermal/cpu_pack_crit"
        cpu_pack_crit_temp_file_output = dut.command("cat %s" % cpu_pack_crit_temp_file)
        cpu_pack_crit_temp = float(cpu_pack_crit_temp_file_output["stdout"])/1000

        assert cpu_pack_max_temp <= cpu_pack_crit_temp, "Bad CPU pack max temp or critical temp, %s, %s " \
                                                        % (str(cpu_pack_max_temp), str(cpu_pack_crit_temp))
        assert cpu_pack_temp < cpu_pack_max_temp, "CPU pack overheated, temp: %s" % (str(cpu_pack_temp))

    cpu_core_count = SWITCH_MODELS[dut_hwsku]["cpu_cores"]["number"]
    for core_id in range(0, cpu_core_count):
        cpu_core_temp_file = "/var/run/hw-management/thermal/cpu_core{}".format(core_id)
        cpu_core_temp_file_output = dut.command("cat %s" % cpu_core_temp_file)
        cpu_core_temp = float(cpu_core_temp_file_output["stdout"])/1000

        cpu_core_max_temp_file = "/var/run/hw-management/thermal/cpu_core{}_max".format(core_id)
        cpu_core_max_temp_file_output = dut.command("cat %s" % cpu_core_max_temp_file)
        cpu_core_max_temp = float(cpu_core_max_temp_file_output["stdout"])/1000

        cpu_core_crit_temp_file = "/var/run/hw-management/thermal/cpu_core{}_crit".format(core_id)
        cpu_core_crit_temp_file_output = dut.command("cat %s" % cpu_core_crit_temp_file)
        cpu_core_crit_temp = float(cpu_core_crit_temp_file_output["stdout"])/1000

        assert cpu_core_max_temp <= cpu_core_crit_temp, "Bad CPU core%d max temp or critical temp, %s, %s " \
                                                        % (core_id, str(cpu_core_max_temp), str(cpu_core_crit_temp))
        assert cpu_core_temp < cpu_core_max_temp, "CPU core%d overheated, temp: %s" % (core_id, str(cpu_core_temp))

    psu_count = SWITCH_MODELS[dut_hwsku]["psus"]["number"]
    for psu_id in range(1, psu_count + 1):
        if SWITCH_MODELS[dut_hwsku]["psus"]["hot_swappable"]:

            # If the PSU is poweroff, all PSU thermal related sensors are not available.
            # In that case, just skip the following tests
            psu_status_file = "/var/run/hw-management/thermal/psu{}_status".format(psu_id)
            psu_status_output = dut.command("cat %s" % psu_status_file)
            psu_status = int(psu_status_output["stdout"])
            if not psu_status:
                logging.info("PSU %d doesn't exist, skipped" % psu_id)
                continue

            psu_pwr_status_file = "/var/run/hw-management/thermal/psu{}_pwr_status".format(psu_id)
            psu_pwr_status_output = dut.command("cat %s" % psu_pwr_status_file)
            psu_pwr_status = int(psu_pwr_status_output["stdout"])
            if not psu_pwr_status:
                logging.info("PSU %d isn't poweron, skipped" % psu_id)
                continue

            psu_temp_file = "/var/run/hw-management/thermal/psu{}_temp".format(psu_id)
            psu_temp_file_output = dut.command("cat %s" % psu_temp_file)
            psu_temp = float(psu_temp_file_output["stdout"])/1000

            psu_max_temp_file = "/var/run/hw-management/thermal/psu{}_temp_max".format(psu_id)
            psu_max_temp_file_output = dut.command("cat %s" % psu_max_temp_file)
            psu_max_temp = float(psu_max_temp_file_output["stdout"])/1000

            assert psu_temp < psu_max_temp, "PSU%d overheated, temp: %s" % (psu_id, str(psu_temp))

            psu_max_temp_alarm_file = "/var/run/hw-management/thermal/psu{}_temp_max_alarm".format(psu_id)
            psu_max_temp_alarm_file_output = dut.command("cat %s" % psu_max_temp_alarm_file)
            assert psu_max_temp_alarm_file_output["stdout"] == '0', "PSU{} temp alarm set".format(psu_id)

            psu_fan_speed_get = "/var/run/hw-management/thermal/psu{}_fan1_speed_get".format(psu_id)
            try:
                psu_fan_speed_get_content = dut.command("cat %s" % psu_fan_speed_get)
                psu_fan_speed = int(psu_fan_speed_get_content["stdout"])
                assert psu_fan_speed > 1000, "Bad fan speed: %s" % str(psu_fan_speed)

            except Exception as e:
                assert "Get content from %s failed, exception: %s" % (psu_fan_speed_get, repr(e))

    sfp_count = SWITCH_MODELS[dut_hwsku]["ports"]["number"]
    for sfp_id in range(1, sfp_count + 1):
        sfp_temp_fault_file = "/var/run/hw-management/thermal/module{}_temp_fault".format(sfp_id)
        sfp_temp_fault_file_output = dut.command("cat %s" % sfp_temp_fault_file)
        assert sfp_temp_fault_file_output["stdout"] == '0', "SFP%d temp fault" % sfp_id

        sfp_temp_file = "/var/run/hw-management/thermal/module{}_temp_input".format(sfp_id)
        sfp_temp_file_output = dut.command("cat %s" % sfp_temp_file)
        if sfp_temp_file_output["stdout"] != '0':
            sfp_temp = float(sfp_temp_file_output["stdout"])/1000
        else:
            sfp_temp = 0

        sfp_temp_crit_file = "/var/run/hw-management/thermal/module{}_temp_crit".format(sfp_id)
        sfp_temp_crit_file_output = dut.command("cat %s" % sfp_temp_crit_file)
        if sfp_temp_crit_file_output["stdout"] != '0':
            sfp_temp_crit = float(sfp_temp_crit_file_output["stdout"])/1000
        else:
            sfp_temp_crit = 0

        sfp_temp_emergency_file = "/var/run/hw-management/thermal/module{}_temp_emergency".format(sfp_id)
        sfp_temp_emergency_file_output = dut.command("cat %s" % sfp_temp_emergency_file)
        if sfp_temp_emergency_file_output["stdout"] != '0':
            sfp_temp_emergency = float(sfp_temp_emergency_file_output["stdout"])/1000
        else:
            sfp_temp_emergency = 0

        if sfp_temp_crit != 0:
            assert sfp_temp < sfp_temp_crit, "SFP%d overheated, temp%s" % (sfp_id, str(sfp_temp))
            assert sfp_temp_crit < sfp_temp_emergency, "Wrong SFP critical temp or emergency temp, " \
                                                       "critical temp: %s emergency temp: %s" \
                                                       % (str(sfp_temp_crit), str(sfp_temp_emergency))

def check_psu_sysfs(dut, psu_id, psu_state):
    """
    @summary: Check psu related sysfs under /var/run/hw-management/thermal against psu_state
    """
    psu_exist = "/var/run/hw-management/thermal/psu%s_status" % psu_id
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

        psu_pwr_state = "/var/run/hw-management/thermal/psu%s_pwr_status" % psu_id
        psu_pwr_state_content = dut.command("cat %s" % psu_pwr_state)
        logging.info("PSU state %s file %s read %s" % (psu_state, psu_pwr_state, psu_pwr_state_content["stdout"]))
        assert (psu_pwr_state_content["stdout"] == "1" and psu_state == "OK") \
                or (psu_pwr_state_content["stdout"] == "0" and psu_state == "NOT OK"),\
            "sysfs content %s mismatches with psu_state %s" % (psu_pwr_state_content["stdout"], psu_state)
