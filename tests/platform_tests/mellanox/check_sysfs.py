"""
Helper script for checking status of sysfs.

This script contains re-usable functions for checking status of hw-management related sysfs.
"""
import logging
import re
from pkg_resources import parse_version
from tests.common.mellanox_data import get_hw_management_version, get_platform_data, is_ld_system
from tests.common.utilities import wait_until

MAX_FAN_SPEED_THRESHOLD = 0.15


def sysfs_get(value, cmd_meta, name, conv=None):
    """
    @summary: Assert a sysfs node was read successfully and is non-empty,
              optionally convert the value, and return it
    """
    assert cmd_meta['rc'] == 0, "{}: read failed (rc={}, stderr={!r}, stdout={!r})".format(
        name, cmd_meta['rc'], cmd_meta['stderr'], value)
    assert value != '', "{}: read succeeded but value is empty (rc=0, stderr={!r})".format(
        name, cmd_meta['stderr'])
    return conv(value) if conv is not None else value


def check_asic_thermal_sysfs(sysfs_facts, sysfs_meta):
    """
    @summary: Check asic thermal related sysfs under /var/run/hw-management/thermal
    """
    asic_temp_raw = sysfs_get(sysfs_facts['asic_info']['temp'],
                              sysfs_meta['asic_info']['temp'], 'ASIC temp')
    asic_temp = float(asic_temp_raw) / 1000
    assert 0 < asic_temp < 105, "Abnormal ASIC temperature: {}".format(
        asic_temp_raw)


def skip_ignored_broken_symbolinks(broken_symbolinks):
    """
    @summary: Check all the broken symbol links found, remove the expected ones
    examples for the expected broken symbol links:
      /var/run/hw-management/led/led_psu2_green_delay_off
      /var/run/hw-management/led/led_uid_blue_delay_on
      /var/run/hw-management/led/led_fan_green_delay_on
      /var/run/hw-management/led/led_status_red_delay_on
    """
    # Currently some led blinking related sysfs are expected to be broken after system boot up,
    # so skip and remove them from the check list.
    broken_symbolinks_updated = []
    pattern = re.compile(".*led_.*_delay_(off|on)")

    logging.info("broken_symbolinks: {}".format(broken_symbolinks))

    for symbolink in broken_symbolinks.splitlines():
        if not pattern.match(symbolink):
            broken_symbolinks_updated.append(symbolink)
        else:
            logging.info("ignore expected broken link: {}".format(symbolink))

    return broken_symbolinks_updated


def check_sysfs(dut, expected_module_temp_fault_value=['0']):
    """
    @summary: Check various hw-management related sysfs under /var/run/hw-management
    """
    platform_data = get_platform_data(dut)
    sysfs_config = generate_sysfs_config(dut, platform_data)
    logging.info("Collect mellanox sysfs facts")
    result = dut.sysfs_facts(config=sysfs_config)
    sysfs_facts = result['ansible_facts']
    sysfs_meta = result['sysfs_metadata']

    logging.info("Check broken symbolinks")
    broken_symbolinks = sysfs_facts['symbolink_info']['broken_links']
    broken_meta = sysfs_meta['symbolink_info']['broken_links']
    assert broken_meta['rc'] == 0, "broken symbolinks: find failed (rc={}, stderr={!r}, stdout={!r})".format(
        broken_meta['rc'], broken_meta['stderr'], broken_symbolinks)
    broken_symbolinks_updated = skip_ignored_broken_symbolinks(
        broken_symbolinks)
    assert len(broken_symbolinks_updated) == 0, \
        "Found some broken symbolinks: {}".format(
            str(broken_symbolinks_updated))

    logging.info("Check ASIC related sysfs")
    try:
        if not is_ld_system(dut):
            check_asic_thermal_sysfs(sysfs_facts, sysfs_meta)
        else:
            logging.info("LD system, skipping ASIC thermal sysfs check")
    except Exception as e:
        assert False, "Bad content in /var/run/hw-management/thermal/asic: {}".format(
            repr(e))

    logging.info("Check fan related sysfs")
    for fan_id, fan_info in list(sysfs_facts['fan_info'].items()):
        fan_meta = sysfs_meta['fan_info'][fan_id]
        if platform_data["fans"].get("hot_swappable"):
            fan_status = sysfs_get(fan_info['status'], fan_meta['status'],
                                   "Fan {} status".format(fan_id))
            assert fan_status == '1', "Fan {} status {} is not 1".format(
                fan_id, fan_status)

        fan_fault = sysfs_get(fan_info['fault'], fan_meta['fault'],
                              "Fan {} fault status".format(fan_id))
        assert fan_fault == '0', "Fan {} fault status {} is not 0".format(
            fan_id, fan_fault)

    if not _is_fan_speed_in_range(sysfs_facts, sysfs_meta):
        sysfs_fan_config = [generate_sysfs_fan_config(platform_data)]
        assert wait_until(30, 5, 0, _check_fan_speed_in_range,
                          dut, sysfs_fan_config), "Fan speed not in range"

    logging.info("Check CPU related sysfs")
    cpu_temp_high_counter = 0
    cpu_temp_list = []
    cpu_crit_temp_list = []
    cpu_pack_count = platform_data["cpu_pack"]["number"]
    if cpu_pack_count > 0:
        cpu_pack_info = sysfs_facts['cpu_pack_info']
        cpu_pack_meta = sysfs_meta['cpu_pack_info']
        cpu_pack_temp = sysfs_get(cpu_pack_info['temp'], cpu_pack_meta['temp'],
                                  'CPU pack temp', conv=float) / 1000
        cpu_pack_max_temp = sysfs_get(cpu_pack_info['max_temp'], cpu_pack_meta['max_temp'],
                                      'CPU pack max temp', conv=float) / 1000
        cpu_pack_crit_temp = sysfs_get(cpu_pack_info['crit_temp'], cpu_pack_meta['crit_temp'],
                                       'CPU pack crit temp', conv=float) / 1000
        assert cpu_pack_max_temp <= cpu_pack_crit_temp, "Bad CPU pack max temp or critical temp, {}, {} ".format(
            str(cpu_pack_max_temp),
            str(cpu_pack_crit_temp))
        if cpu_pack_temp >= cpu_pack_crit_temp:
            cpu_temp_high_counter += 1
        cpu_temp_list.append(cpu_pack_temp)
        cpu_crit_temp_list.append(cpu_pack_crit_temp)

    for core_id, cpu_info in list(sysfs_facts['cpu_core_info'].items()):
        cpu_meta = sysfs_meta['cpu_core_info'][core_id]
        cpu_core_temp = sysfs_get(cpu_info["temp"], cpu_meta["temp"],
                                  "CPU core{} temp".format(core_id), conv=float) / 1000
        cpu_core_max_temp = sysfs_get(cpu_info["max_temp"], cpu_meta["max_temp"],
                                      "CPU core{} max temp".format(core_id), conv=float) / 1000
        cpu_core_crit_temp = sysfs_get(cpu_info["crit_temp"], cpu_meta["crit_temp"],
                                       "CPU core{} crit temp".format(core_id), conv=float) / 1000
        assert cpu_core_max_temp <= cpu_core_crit_temp, "Bad CPU core{} max temp or critical temp, {}, {} ".format(
            core_id,
            str(cpu_core_max_temp),
            str(cpu_core_crit_temp))
        if cpu_core_temp >= cpu_core_crit_temp:
            cpu_temp_high_counter += 1
        cpu_temp_list.append(cpu_core_temp)
        cpu_crit_temp_list.append(cpu_core_crit_temp)

    if cpu_temp_high_counter > 0:
        logging.info("CPU temperatures {}".format(cpu_temp_list))
        logging.info("CPU critical temperatures {}".format(cpu_crit_temp_list))
        assert False, "At least {} of the CPU cores or pack is overheated".format(
            cpu_temp_high_counter)

    logging.info("Check PSU related sysfs")
    if platform_data["psus"].get("hot_swappable"):
        for psu_id, psu_info in list(sysfs_facts['psu_info'].items()):
            psu_meta = sysfs_meta['psu_info'][psu_id]
            psu_id = int(psu_id)
            psu_status = sysfs_get(psu_info["status"], psu_meta["status"],
                                   "PSU{} status".format(psu_id), conv=int)
            if not psu_status:
                logging.info("PSU {} doesn't exist, skipped".format(psu_id))
                continue

            psu_pwr_status = sysfs_get(psu_info["pwr_status"], psu_meta["pwr_status"],
                                       "PSU{} pwr_status".format(psu_id), conv=int)
            if not psu_pwr_status:
                logging.info("PSU {} isn't power on, skipped".format(psu_id))
                continue

            psu_temp = sysfs_get(psu_info["temp"], psu_meta["temp"],
                                 "PSU{} temp".format(psu_id), conv=float) / 1000
            psu_max_temp = sysfs_get(psu_info["max_temp"], psu_meta["max_temp"],
                                     "PSU{} max temp".format(psu_id), conv=float) / 1000
            assert psu_temp < psu_max_temp, "PSU{} overheated, temp: {}".format(
                psu_id, str(psu_temp))
            psu_max_temp_alarm = sysfs_get(psu_info["max_temp_alarm"], psu_meta["max_temp_alarm"],
                                           "PSU{} temp alarm".format(psu_id))
            assert psu_max_temp_alarm == '0', "PSU{} temp alarm set".format(
                psu_id)
            psu_fan_speed_raw = sysfs_get(psu_info["fan_speed"], psu_meta["fan_speed"],
                                          "PSU{} fan speed".format(psu_id))
            try:
                psu_fan_speed = int(psu_fan_speed_raw)
                assert psu_fan_speed > 1000, "Bad fan speed: {}".format(
                    str(psu_fan_speed))
            except Exception as e:
                assert False, "Invalid PSU fan speed value {} for PSU {}, exception: {}".format(
                    psu_fan_speed_raw, psu_id, e)

            if "201911" not in dut.sonic_release and "202012" not in dut.sonic_release:
                # Check consistency between voltage capability and sysfs
                all_capabilities = platform_data["psus"].get("capabilities")
                if all_capabilities:
                    for capabilities in all_capabilities:
                        psu_cmd_prefix = 'cat /var/run/hw-management/power/{}_'.format(
                            capabilities.format(psu_id))
                        psu_capability = dut.command(
                            psu_cmd_prefix + 'capability')['stdout'].split()
                        for capability in psu_capability:
                            # Each capability should exist
                            output = dut.command(
                                psu_cmd_prefix + capability)['stdout']
                            assert output, "PSU capability {} doesn't not exist".format(
                                capability)
            else:
                logging.info("PSU sensors' capability checking ignored")

    logging.info("Check SFP related sysfs")
    for sfp_id, sfp_info in list(sysfs_facts['sfp_info'].items()):
        # Skip when the sfp is missing
        if not sfp_info["temp_fault"]:
            continue

        sfp_meta = sysfs_meta['sfp_info'][sfp_id]
        sfp_temp_fault = sysfs_get(sfp_info["temp_fault"], sfp_meta["temp_fault"],
                                   "SFP{} temp fault".format(sfp_id))
        assert sfp_temp_fault in expected_module_temp_fault_value, "SFP%d temp fault" % int(sfp_id)
        sfp_temp_raw = sysfs_get(sfp_info['temp'], sfp_meta['temp'],
                                 "SFP{} temp".format(sfp_id))
        sfp_crit_temp_raw = sysfs_get(sfp_info['crit_temp'], sfp_meta['crit_temp'],
                                      "SFP{} crit temp".format(sfp_id))
        sfp_emergency_temp_raw = sysfs_get(sfp_info['emergency_temp'], sfp_meta['emergency_temp'],
                                           "SFP{} emergency temp".format(sfp_id))
        sfp_temp = float(sfp_temp_raw) if sfp_temp_raw != '0' else 0
        sfp_temp_crit = float(sfp_crit_temp_raw) if sfp_crit_temp_raw != '0' else 0
        sfp_temp_emergency = float(
            sfp_emergency_temp_raw) if sfp_emergency_temp_raw != '0' else 0
        if sfp_temp_crit != 0:
            assert sfp_temp < sfp_temp_crit, "SFP{} overheated, temp{}".format(
                sfp_id, str(sfp_temp))
            assert sfp_temp_crit < sfp_temp_emergency, "Wrong SFP critical temp or emergency temp, " \
                                                       "critical temp: {} emergency temp: {}".format(
                                                           str(sfp_temp_crit), str(sfp_temp_emergency))

    logging.info("Check liquid cooling leakage related sysfs")
    check_liquid_cooling_leakage_sysfs(dut, sysfs_facts)

    logging.info("Finish checking sysfs")


def check_psu_sysfs(dut, psu_id, psu_state):
    """
    @summary: Check psu related sysfs under /var/run/hw-management/thermal against psu_state
    """
    psu_exist = "/var/run/hw-management/thermal/psu{}_status".format(psu_id)
    if psu_state == "NOT PRESENT":
        psu_exist_content = dut.command("cat {}".format(psu_exist))
        logging.info("PSU state {} file {} read {}".format(
            psu_state, psu_exist, psu_exist_content["stdout"]))
        assert psu_exist_content["stdout"] == "0", "CLI returns NOT PRESENT while {} contains {}".format(
                                                   psu_exist, psu_exist_content["stdout"])
    else:
        platform_data = get_platform_data(dut)
        hot_swappable = platform_data["psus"].get("hot_swappable")
        if hot_swappable:
            psu_exist_content = dut.command("cat {}".format(psu_exist))
            logging.info("PSU state {} file {} read {}".format(
                psu_state, psu_exist, psu_exist_content["stdout"]))
            assert psu_exist_content["stdout"] == "1", "CLI returns {} while {} contains {}".format(
                                                       psu_state, psu_exist, psu_exist_content["stdout"])

        psu_pwr_state = "/var/run/hw-management/thermal/psu{}_pwr_status".format(
            psu_id)
        psu_pwr_state_content = dut.command("cat {}".format(psu_pwr_state))
        logging.info("PSU state {} file {} read {}".format(
            psu_state, psu_pwr_state, psu_pwr_state_content["stdout"]))
        assert (psu_pwr_state_content["stdout"] == "1" and psu_state == "OK") \
            or (psu_pwr_state_content["stdout"] == "0" and psu_state == "NOT OK"), \
            "sysfs content {} mismatches with psu_state {}".format(
                psu_pwr_state_content["stdout"], psu_state)


def _check_fan_speed_in_range(dut, config):
    result = dut.sysfs_facts(config=config)
    sysfs_facts = result['ansible_facts']
    sysfs_meta = result['sysfs_metadata']

    return _is_fan_speed_in_range(sysfs_facts, sysfs_meta)


def _is_fan_speed_in_range(sysfs_facts, sysfs_meta):
    for fan_id, fan_info in list(sysfs_facts['fan_info'].items()):
        fan_meta = sysfs_meta['fan_info'][fan_id]
        fan_min_speed_raw = sysfs_get(fan_info["min_speed"], fan_meta["min_speed"],
                                      "Fan {} min speed".format(fan_id))
        fan_max_speed_raw = sysfs_get(fan_info["max_speed"], fan_meta["max_speed"],
                                      "Fan {} max speed".format(fan_id))
        fan_speed_set_raw = sysfs_get(fan_info["speed_set"], fan_meta["speed_set"],
                                      "Fan {} speed set".format(fan_id))
        fan_speed_get_raw = sysfs_get(fan_info["speed_get"], fan_meta["speed_get"],
                                      "Fan {} speed get".format(fan_id))
        try:
            fan_min_speed = int(fan_min_speed_raw)
            fan_max_speed = int(
                int(fan_max_speed_raw) * (1 + MAX_FAN_SPEED_THRESHOLD))
            fan_speed_set = int(fan_speed_set_raw)
            fan_speed_get = int(fan_speed_get_raw)
        except Exception as e:
            assert False, 'Invalid fan speed: actual speed={}, set speed={}, min={}, max={}, exception={}'.format(
                fan_info["speed_get"],
                fan_info["speed_set"],
                fan_info["min_speed"],
                fan_info["max_speed"],
                e
            )

        assert fan_min_speed > 0 and fan_max_speed > 10000, \
            'Invalid fan {} min/max speed: {}, {}'.format(
                fan_id, fan_min_speed, fan_max_speed)

        low_threshold = ((float(fan_speed_set) / 255) *
                         fan_min_speed) * (1 - 0.5)
        high_threshold = ((float(fan_speed_set) / 255) *
                          fan_max_speed) * (1 + 0.5)

        if not low_threshold < fan_speed_get < high_threshold:
            logging.warning(
                'Fan {} speed {} not in range: [{}, {}], '
                'min_speed={}, max_speed={}, speed_set={}, speed_get={}'.format(
                    fan_id, fan_speed_get, low_threshold, high_threshold,
                    fan_info["min_speed"],
                    fan_info["max_speed"],
                    fan_info["speed_set"],
                    fan_info["speed_get"]))
            return False

    return True


def generate_sysfs_config(dut, platform_data):
    config = list()
    config.append(generate_sysfs_symbolink_config())
    config.append(generate_sysfs_asic_config())
    if platform_data["cpu_pack"]["number"] > 0:
        config.append(generate_sysfs_cpu_pack_config())
    config.append(generate_sysfs_cpu_core_config(platform_data))
    config.append(generate_sysfs_fan_config(platform_data))
    if platform_data['psus'].get("hot_swappable"):
        config.append(generate_sysfs_psu_config(dut, platform_data))
    config.append(generate_sysfs_sfp_config(platform_data))
    if 'liquid_cooling_leakage' in platform_data and platform_data['leak_sensors']['number'] > 0:
        config.append(generate_sysfs_leakage_config(platform_data))
    return config


def generate_sysfs_symbolink_config():
    return {
        'name': 'symbolink_info',
        'type': 'single',
        'properties': [
            {
                'name': 'broken_links',
                'cmd_pattern': 'find /var/run/hw-management -xtype l'
            }
        ]
    }


def generate_sysfs_asic_config():
    return {
        'name': 'asic_info',
        'type': 'single',
        'properties': [
            {
                'name': 'temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/asic'
            }
        ]
    }


def generate_sysfs_fan_config(platform_data):
    fan_config = {
        'name': 'fan_info',
        'start': 1,
        'count': platform_data['fans']['number'],
        'type': 'increment',
        'properties': [
            {
                'name': 'status',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/fan{}_status',
            },
            {
                'name': 'fault',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/fan{}_fault',
            },
            {
                'name': 'min_speed',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/fan{}_min',
            },
            {
                'name': 'max_speed',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/fan{}_max',
            },
            {
                'name': 'speed_set',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/fan{}_speed_set',
            },
            {
                'name': 'speed_get',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/fan{}_speed_get',
            }
        ]
    }
    if not platform_data['fans'].get("hot_swappable"):
        fan_config['properties'] = fan_config['properties'][1:]
    return fan_config


def generate_sysfs_cpu_pack_config():
    return {
        'name': 'cpu_pack_info',
        'type': 'single',
        'properties': [
            {
                'name': 'temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/cpu_pack'
            },
            {
                'name': 'max_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/cpu_pack_max'
            },
            {
                'name': 'crit_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/cpu_pack_crit'
            }
        ]
    }


def generate_sysfs_cpu_core_config(platform_data):
    return {
        'name': 'cpu_core_info',
        'start': 0,
        'count': platform_data['cpu_cores']['number'],
        'type': 'increment',
        'properties': [
            {
                'name': 'temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/cpu_core{}',
            },
            {
                'name': 'max_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/cpu_core{}_max',
            },
            {
                'name': 'crit_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/cpu_core{}_crit',
            }
        ]
    }


def generate_sysfs_psu_config(dut, platform_data):
    data = {
        'name': 'psu_info',
        'start': 1,
        'count': platform_data['psus']['number'],
        'type': 'increment',
        'properties': [
            {
                'name': 'status',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_status',
            },
            {
                'name': 'pwr_status',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_pwr_status',
            },
            {
                'name': 'temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_temp1',
            },
            {
                'name': 'max_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_temp1_max',
            },
            {
                'name': 'max_temp_alarm',
                'cmd_pattern': 'cat /var/run/hw-management/alarm/psu{}_temp1_max_alarm',
            },
            {
                'name': 'fan_speed',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_fan1_speed_get',
            }
        ]
    }
    hw_mgmt_version = get_hw_management_version(dut)
    if parse_version(hw_mgmt_version) < parse_version('7.0030.2003'):
        data['properties'][2]['cmd_pattern'] = 'cat /var/run/hw-management/thermal/psu{}_temp'
        data['properties'][3]['cmd_pattern'] = 'cat /var/run/hw-management/thermal/psu{}_temp_max'
        data['properties'][4]['cmd_pattern'] = 'cat /var/run/hw-management/thermal/psu{}_temp_max_alarm'
    return data


def generate_sysfs_sfp_config(platform_data):
    return {
        'name': 'sfp_info',
        'start': 1,
        'count': platform_data['ports']['number'],
        'type': 'increment',
        'properties': [
            {
                'name': 'temp_fault',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/module{}_temp_fault',
            },
            {
                'name': 'temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/module{}_temp_input',
            },
            {
                'name': 'crit_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/module{}_temp_crit',
            },
            {
                'name': 'emergency_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/module{}_temp_emergency',
            }
        ]
    }


def generate_sysfs_leakage_config(platform_data):
    return {
        'name': 'leakage_info',
        'start': 1,
        'count': platform_data['leak_sensors']['number'],
        'type': 'increment',
        'properties': [
            {
                'name': 'status',
                'cmd_pattern': 'cat /var/run/hw-management/system/leakage{}',
            }
        ]
    }


def check_liquid_cooling_leakage_sysfs(dut, sysfs_facts):
    """
    @summary: Check liquid cooling leakage related sysfs under /var/run/hw-management/system/leakage
    """
    leak_sensors_num = sysfs_facts['leakage_info']['count'] if 'leakage_info' in sysfs_facts else 0
    if leak_sensors_num == 0:
        logging.info("Skip checking leakage related sysfs because no liquid cooling leakage sensors found on device")
        return
    actual_leak_sensors_num = int(len(
        dut.command("ls /var/run/hw-management/system/leakage* |wc -l")['stdout']))
    assert leak_sensors_num <= actual_leak_sensors_num, \
        f"liquid cooling leakage sensors number mismatch, \
            expected: {leak_sensors_num}, actual: {actual_leak_sensors_num}"

    logging.info("Check liquid cooling leakage should be ok")
    for i in range(leak_sensors_num):
        leak_sensor_status = sysfs_facts['leakage_info']['status'][i]
        assert leak_sensor_status == "1", f"Leak sensor {i} is not leak. leak_sensor_status: {leak_sensor_status}"
