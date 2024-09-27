"""
Tests for verifying the configuration on the DUT
to match the expected WRED probability configuration
"""

import logging
import time
import pytest
from tests.common.cisco_data import is_cisco_device
import json


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def enable_serviceability_cli(duthost, show_cmd):

    output = duthost.command(show_cmd)['stdout']

    # Check if "cisco sdk-debug enable" is present in stdout
    dshell_disabled = "cisco sdk-debug enable" in output

    if not dshell_disabled:
        logging.info("Dshell is already enabled")
        return

    asic_facts = get_asic_facts(duthost)
    asics = []
    asics = list(asic_facts.keys()) if duthost.is_multi_asic else ['']

    logging.info("Enabling dshell client")
    for asic in asics:
        cmd = "docker exec syncd{} supervisorctl start dshell_client".format(asic)
        result = duthost.command(cmd)
        verify_command_result(result, cmd)
        if "already started" in result["stdout"]:
            cmd = "docker exec syncd{} supervisorctl restart dshell_client".format(asic)
            result = duthost.command(cmd)
            verify_command_result(result, cmd)

    time.sleep(20)

    output = duthost.command(show_cmd)['stdout']

    # Check if "cisco sdk-debug enable" is present in stdout
    dshell_disabled = "cisco sdk-debug enable" in output

    if not dshell_disabled:
        logging.info("Dshell started successfully")
        return

    time.sleep(60)

    output = duthost.command(show_cmd)['stdout']

    # Check if "cisco sdk-debug enable" is present in stdout
    dshell_disabled = "cisco sdk-debug enable" in output

    if dshell_disabled:
        pytest.fail(
            "This test failed since debug shell server is not running for command: {}".format(show_cmd))


def get_asic_facts(duthost):
    asic_ports_dict = {}

    def get_ports_with_status(config_facts):
        status_dict = {}
        for p, v in config_facts['PORT'].items():
            status = v.get('admin_status', None)
            if status not in status_dict.keys():
                status_dict[status] = []
            status_dict[status].append(p)
        return status_dict

    if duthost.is_multi_asic:
        for asic in duthost.frontend_asics:
            asic_cfg_facts = asic.config_facts(
                        host=duthost.hostname,
                        source="running",
                        namespace=asic.namespace
                    )['ansible_facts']
            asic_ports_dict[asic.namespace] = get_ports_with_status(asic_cfg_facts)
    else:
        cfg_facts = duthost.get_running_config_facts()
        asic_ports_dict['asic0'] = get_ports_with_status(cfg_facts)

    return asic_ports_dict


def verify_command_result(result, cmd):
    # Raise an AssertionError if "stdout" is empty
    assert result["stdout"], "No output for {}".format(cmd)

    # Check if "Traceback" is present in result["stdout"]
    traceback_found = "Traceback" in result["stdout"]
    # Raise an AssertionError if "Traceback" is found
    assert not traceback_found, "Traceback found in {}".format(cmd)


def test_verify_ecn_marking_config(duthosts, rand_one_dut_hostname, request):
    """
    @summary: Verify output of `show platform npu voq cgm_profile with wred_profile drop probability`
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not is_cisco_device(duthost):
        pytest.skip("Skipping as not a Cisco device")

    cmd = "show platform npu rx cgm_global -d"

    enable_serviceability_cli(duthost, cmd)

    result = duthost.command(cmd)
    verify_command_result(result, cmd)

    json_str = result["stdout"].strip()
    data = None
    try:
        data = json.loads(json_str)
    except Exception as e:
        logging.info("JSon load error: {}".format(e))
    if not data or 'hbm_usage' in data:
        pytest.skip("Skipping as a HBM based device")

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    asics = []

    asics = list(asic_facts.keys()) if duthost.is_multi_asic else ['']

    for asic in asics:
        if not asic:
            asic_namespace_string = ''
            asic = 'asic0'
        else:
            asic_namespace_string = " -n " + str(asic)

        up_ports = None
        if 'up' in asic_facts[asic].keys():
            up_ports = asic_facts[asic]['up']

        down_ports = None
        if None in asic_facts[asic].keys():
            down_ports = asic_facts[asic][None]

        if up_ports and down_ports:
            # Combine both Up and Down
            all_ports = up_ports + down_ports
        elif up_ports:
            all_ports = up_ports
        elif down_ports:
            all_ports = down_ports
        else:
            pytest.skip("No ports available")

        port_qos_map_command = "sonic-cfggen -d{} --var-json PORT_QOS_MAP"
        logging.info("Fetching PORT_QOS_MAP for asic: {}".format(asic))
        cmd = port_qos_map_command.format(asic_namespace_string)
        result = duthost.command(cmd)
        verify_command_result(result, cmd)

        json_str = result["stdout"].strip()
        try:
            port_qos_map_data = json.loads(json_str)
        except Exception as e:
            logging.info("JSon load error: {}".format(e))
            continue

        show_command = "sudo show platform npu voq cgm_profile -i {} -t {}{} -d"

        for port in all_ports:

            # if pfc_enable is empty or not present, then PFC is not configured on the interface hence skip the check
            if port not in port_qos_map_data or "pfc_enable" not in port_qos_map_data[port] or \
              not port_qos_map_data[port]['pfc_enable']:
                logging.info("PFC is not enabled on {}".format(port))
                continue

            for pg_to_test in port_qos_map_data[port]['pfc_enable'].split(','):
                logging.info("Checking Port: {} pg {}".format(port, pg_to_test))
                cmd = show_command.format(port, pg_to_test, asic_namespace_string)
                result = duthost.command(cmd)
                verify_command_result(result, cmd)

                json_str = result["stdout"].strip()
                try:
                    data = json.loads(json_str)
                except Exception as e:
                    logging.info("JSon load error: {}".format(e))
                    continue
                voq_mark_data = None
                if "voq_mark_prob_g" in data:
                    voq_mark_data = data["voq_mark_prob_g"]
                    if voq_mark_data:
                        sms_quant_len = len(voq_mark_data)
                        voq_quant_len = len(voq_mark_data[0])
                        age_quant_len = len(voq_mark_data[0][1])
                else:
                    logging.info("Marking data unavailable for Port {} PG {}."
                                 " Please check if PFC is enabled".format(port, pg_to_test))
                    continue

                voq_drop_data = None
                if "voq_drop_prob_g" in data:
                    voq_drop_data = data["voq_drop_prob_g"]
                    if not voq_mark_data and voq_drop_data:
                        sms_quant_len = len(voq_drop_data)
                        voq_quant_len = len(voq_drop_data[0])
                        age_quant_len = len(voq_drop_data[0][1])

                if voq_mark_data:
                    for g_idx in range(sms_quant_len):
                        for voq_idx in range(voq_quant_len):
                            for age_idx in range(age_quant_len):
                                actual_value = round(voq_mark_data[g_idx][voq_idx][age_idx], 2)
                                if age_idx == 0:
                                    mark_level = 0
                                elif (voq_idx >= 1 and age_idx == 1):
                                    mark_level = 1
                                elif (voq_idx >= 1 and age_idx == 2):
                                    mark_level = 2
                                elif (voq_idx >= 1 and age_idx >= 3):
                                    mark_level = 3
                                else:
                                    mark_level = 0
                                expected_value = round(data["wm_prob"][mark_level], 2)
                                assert (
                                        actual_value == expected_value
                                ), '''
                                        Marking Probability not as expected for Port {} PG {}
                                        at SMS/VoQ/Age region {}/{}/{} Expected: {} Actual: {}
                                     '''.format(port, pg_to_test, g_idx, voq_idx,
                                                age_idx, expected_value, actual_value)

                ''' Verify drop is 7 for last quant only'''
                if voq_drop_data:
                    for g_idx in range(sms_quant_len):
                        for voq_idx in range(voq_quant_len):
                            for age_idx in range(age_quant_len):
                                actual_value = voq_drop_data[g_idx][voq_idx][age_idx]
                                expected_value = 7 if voq_idx == (voq_quant_len - 1) else 0
                                assert (
                                        actual_value == expected_value
                                ), '''
                                        Drop Probability not as expected for Port {} PG {} at
                                        SMS/VoQ/Age region {}/{}/{} Expected: {} Actual: {}
                                     '''.format(port, pg_to_test, g_idx, voq_idx,
                                                age_idx, expected_value, actual_value)
