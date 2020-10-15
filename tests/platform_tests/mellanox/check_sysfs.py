"""
Helper script for checking status of sysfs.

This script contains re-usable functions for checking status of hw-management related sysfs.
"""
import logging
from tests.common.mellanox_data import get_platform_data
from tests.common.utilities import wait_until


def check_sysfs(dut):
    """
    @summary: Check various hw-management related sysfs under /var/run/hw-management
    """
    platform_data = get_platform_data(dut)
    sysfs_config = generate_sysfs_config(platform_data)
    logging.info("Collect mellanox sysfs facts")
    sysfs_facts = dut.sysfs_facts(config=sysfs_config)['ansible_facts']

    logging.info("Check broken symbolinks")
    broken_symbolinks = sysfs_facts['symbolink_info']['broken_links']
    assert len(broken_symbolinks) == 0, \
        "Found some broken symbolinks: {}".format(str(broken_symbolinks))

    logging.info("Check ASIC related sysfs")
    try:
        asic_temp = float(sysfs_facts['asic_info']['temp']) / 1000
        assert 0 < asic_temp < 105, "Abnormal ASIC temperature: {}".format(sysfs_facts['asic_info']['temp'])
    except Exception as e:
        assert False, "Bad content in /var/run/hw-management/thermal/asic: {}".format(repr(e))

    logging.info("Check fan related sysfs")
    for fan_id, fan_info in sysfs_facts['fan_info'].items():
        if platform_data["fans"]["hot_swappable"]:
            assert fan_info['status'] == '1', "Fan {} status {} is not 1".format(fan_id, fan_info['status'])

        assert fan_info['fault'] == '0', "Fan {} fault status {} is not 1".format(fan_id, fan_info['fault'])

    if not _is_fan_speed_in_range(sysfs_facts):
        sysfs_fan_config = [generate_sysfs_fan_config(platform_data)]
        assert wait_until(30, 5, _check_fan_speed_in_range, dut, sysfs_fan_config), "Fan speed not in range"

    logging.info("Check CPU related sysfs")
    cpu_temp_high_counter = 0
    cpu_temp_list = []
    cpu_crit_temp_list = []
    cpu_pack_count = platform_data["cpu_pack"]["number"]
    if cpu_pack_count > 0:
        cpu_pack_temp = float(sysfs_facts['cpu_pack_info']['temp']) / 1000
        cpu_pack_max_temp = float(sysfs_facts['cpu_pack_info']['max_temp']) / 1000
        cpu_pack_crit_temp = float(sysfs_facts['cpu_pack_info']['crit_temp']) / 1000
        assert cpu_pack_max_temp <= cpu_pack_crit_temp, "Bad CPU pack max temp or critical temp, {}, {} ".format(
                                                    str(cpu_pack_max_temp), 
                                                    str(cpu_pack_crit_temp))
        if cpu_pack_temp >= cpu_pack_crit_temp:
            cpu_temp_high_counter += 1
        cpu_temp_list.append(cpu_pack_temp)
        cpu_crit_temp_list.append(cpu_pack_crit_temp)

    for core_id, cpu_info in sysfs_facts['cpu_core_info'].items():
        cpu_core_temp = float(cpu_info["temp"]) / 1000
        cpu_core_max_temp = float(cpu_info["max_temp"]) / 1000
        cpu_core_crit_temp = float(cpu_info["crit_temp"]) / 1000
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
        assert False, "At least {} of the CPU cores or pack is overheated".format(cpu_temp_high_counter)

    logging.info("Check PSU related sysfs")
    if platform_data["psus"]["hot_swappable"]:
        for psu_id, psu_info in sysfs_facts['psu_info'].items():
            psu_id = int(psu_id)
            psu_status = int(psu_info["status"])
            if not psu_status:
                logging.info("PSU {} doesn't exist, skipped".format(psu_id))
                continue

            psu_pwr_status = int(psu_info["pwr_status"])
            if not psu_pwr_status:
                logging.info("PSU {} isn't power on, skipped".format(psu_id))
                continue

            psu_temp = float(psu_info["temp"]) / 1000
            psu_max_temp = float(psu_info["max_temp"]) / 1000
            assert psu_temp < psu_max_temp, "PSU{} overheated, temp: {}".format(psu_id, str(psu_temp))
            assert psu_info["max_temp_alarm"] == '0', "PSU{} temp alarm set".format(psu_id)
            try:
                psu_fan_speed = int(psu_info["fan_speed"])
                assert psu_fan_speed > 1000, "Bad fan speed: {}".format(str(psu_fan_speed))
            except Exception as e:
                assert "Invalid PSU fan speed value {} for PSU {}, exception: {}".format(psu_info["fan_speed"],
                                                                                         psu_id, e)

    logging.info("Check SFP related sysfs")
    for sfp_id, sfp_info in sysfs_facts['sfp_info'].items():
        assert sfp_info["temp_fault"] == '0', "SFP%d temp fault" % sfp_id
        sfp_temp = float(sfp_info['temp']) if sfp_info['temp'] != '0' else 0
        sfp_temp_crit = float(sfp_info['crit_temp']) if sfp_info['crit_temp'] != '0' else 0
        sfp_temp_emergency = float(sfp_info['emergency_temp']) if sfp_info['emergency_temp'] != '0' else 0
        if sfp_temp_crit != 0:
            assert sfp_temp < sfp_temp_crit, "SFP{} overheated, temp{}".format(sfp_id, str(sfp_temp))
            assert sfp_temp_crit < sfp_temp_emergency, "Wrong SFP critical temp or emergency temp, " \
                                                       "critical temp: {} emergency temp: {}".format(
                                                           str(sfp_temp_crit), str(sfp_temp_emergency))
    logging.info("Finish checking sysfs")


def check_psu_sysfs(dut, psu_id, psu_state):
    """
    @summary: Check psu related sysfs under /var/run/hw-management/thermal against psu_state
    """
    psu_exist = "/var/run/hw-management/thermal/psu{}_status".format(psu_id)
    if psu_state == "NOT PRESENT":
        psu_exist_content = dut.command("cat {}".format(psu_exist))
        logging.info("PSU state {} file {} read {}".format(psu_state, psu_exist, psu_exist_content["stdout"]))
        assert psu_exist_content["stdout"] == "0", "CLI returns NOT PRESENT while {} contains {}".format(
                                                   psu_exist, psu_exist_content["stdout"])
    else:
        platform_data = get_platform_data(dut)
        hot_swappable = platform_data["psus"]["hot_swappable"]
        if hot_swappable:
            psu_exist_content = dut.command("cat {}".format(psu_exist))
            logging.info("PSU state {} file {} read {}".format(psu_state, psu_exist, psu_exist_content["stdout"]))
            assert psu_exist_content["stdout"] == "1", "CLI returns {} while {} contains {}".format(
                                                       psu_state, psu_exist, psu_exist_content["stdout"])

        psu_pwr_state = "/var/run/hw-management/thermal/psu{}_pwr_status".format(psu_id)
        psu_pwr_state_content = dut.command("cat {}".format(psu_pwr_state))
        logging.info("PSU state {} file {} read {}".format(psu_state, psu_pwr_state, psu_pwr_state_content["stdout"]))
        assert (psu_pwr_state_content["stdout"] == "1" and psu_state == "OK") \
               or (psu_pwr_state_content["stdout"] == "0" and psu_state == "NOT OK"), \
            "sysfs content {} mismatches with psu_state {}".format(psu_pwr_state_content["stdout"], psu_state)


def _check_fan_speed_in_range(dut, config):
    sysfs_facts = dut.sysfs_facts(config=config)['ansible_facts']

    return _is_fan_speed_in_range(sysfs_facts)


def _is_fan_speed_in_range(sysfs_facts):
    for fan_id, fan_info in sysfs_facts['fan_info'].items():
        try:
            fan_min_speed = int(fan_info["min_speed"])
            fan_max_speed = int(fan_info["max_speed"])
            fan_speed_set = int(fan_info["speed_set"])
            fan_speed_get = int(fan_info["speed_get"])

            assert fan_min_speed > 0 and fan_max_speed > 10000, 'Invalid fan min/max speed: {}, {}'.format(
                fan_min_speed,
                fan_max_speed)
            assert fan_min_speed < fan_speed_get < fan_max_speed, 'Fan speed {} not in range: [{}, {}]'.format(
                fan_speed_get, fan_min_speed, fan_max_speed
            )

            low_threshold = ((float(fan_speed_set) / 255) * fan_max_speed) * (1 - 0.5)
            high_threshold = ((float(fan_speed_set) / 255) * fan_max_speed) * (1 + 0.5)
            return low_threshold < fan_speed_get < high_threshold
        except Exception as e:
            assert False, 'Invalid fan speed: actual speed={}, set speed={}, min={}, max={}, exception={}'.format(
                fan_info["speed_get"],
                fan_info["speed_set"],
                fan_info["min_speed"],
                fan_info["max_speed"],
                e
            )


def generate_sysfs_config(platform_data):
    config = list()
    config.append(generate_sysfs_symbolink_config())
    config.append(generate_sysfs_asic_config())
    if platform_data["cpu_pack"]["number"] > 0:
        config.append(generate_sysfs_cpu_pack_config())
    config.append(generate_sysfs_cpu_core_config(platform_data))
    config.append(generate_sysfs_fan_config(platform_data))
    if platform_data['psus']['hot_swappable']:
        config.append(generate_sysfs_psu_config(platform_data))
    config.append(generate_sysfs_sfp_config(platform_data))
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
    if not platform_data['fans']['hot_swappable']:
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


def generate_sysfs_psu_config(platform_data):
    return {
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
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_temp',
            },
            {
                'name': 'max_temp',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_temp_max',
            },
            {
                'name': 'max_temp_alarm',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_temp_max_alarm',
            },
            {
                'name': 'fan_speed',
                'cmd_pattern': 'cat /var/run/hw-management/thermal/psu{}_fan1_speed_get',
            }
        ]
    }


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
