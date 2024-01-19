"""
Tests for verifying the configuration on the DUT for CPU port
to match the expected configuration
"""

import logging
import pytest
from tests.common.cisco_data import is_cisco_device
import json


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def get_asic_facts(duthost):
    asic_namespace_list = []

    if duthost.is_multi_asic:
        for asic in duthost.frontend_asics:
            asic_namespace_list.append(asic.namespace)
    else:
        asic_namespace_list.append('asic0')

    return asic_namespace_list


def verify_command_result(result, cmd):
    # Raise an AssertionError if "stdout" is empty
    assert result["stdout"], "No output for {}".format(cmd)

    # Check if "cisco sdk-debug enable" is present in result["stdout"]
    dshell_disabled = "cisco sdk-debug enable" in result["stdout"]
    # Raise an AssertionError if "cisco sdk-debug enable" is found
    assert not dshell_disabled, "debug shell server is not running for command: {}".format(cmd)

    # Check if "Traceback" is present in result["stdout"]
    traceback_found = "Traceback" in result["stdout"]
    # Raise an AssertionError if "Traceback" is found
    assert not traceback_found, "Traceback found in {}".format(cmd)


@pytest.mark.parametrize("pg_to_test", [0, 3])
def test_verify_cpu_port_config(duthosts, rand_one_dut_hostname, pg_to_test, request):
    """
    @summary: Verify output of `show platform npu voq cgm_profile with expected default drop probability`
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not is_cisco_device(duthost):
        pytest.skip("Skipping as not a Cisco device")

    cmd = "show platform npu rx cgm_global -d"
    result = duthost.command(cmd)
    verify_command_result(result, cmd)

    json_str = result["stdout"].strip()
    data = None
    try:
        data = json.loads(json_str)
    except Exception as e:
        pytest.fail("JSON load error: {}".format(e))

    hbm_present = False
    if 'hbm_usage' in data:
        hbm_present = True

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    asics = []

    asics = asic_facts if duthost.is_multi_asic else ['']

    for asic in asics:
        if not asic:
            asic_namespace_string = ''
            asic = 'asic0'
        else:
            asic_namespace_string = " -n " + str(asic)

        show_command = "sudo show platform npu voq cgm_profile -i CPU -t {}{} -d"

        logging.info("Checking CPU Port")
        cmd = show_command.format(pg_to_test, asic_namespace_string)
        result = duthost.command(cmd)
        verify_command_result(result, cmd)

        json_str = result["stdout"].strip()
        try:
            data = json.loads(json_str)
        except Exception as e:
            pytest.fail("JSON load error: {}".format(e))

        voq_drop_data = None
        if "voq_drop_prob_g" in data:
            voq_drop_data = data["voq_drop_prob_g"]
            if voq_drop_data:
                sms_quant_len = len(voq_drop_data)
                voq_quant_len = len(voq_drop_data[0])
                age_quant_len = len(voq_drop_data[0][1])

        if hbm_present:
            voq_evict_data = None
            if "voq_evict_prob_g" not in data:
                logging.info("Eviction data unavailable for CPU Port PG {}."
                             " Please check".format(pg_to_test))
            else:
                voq_evict_data = data["voq_evict_prob_g"]
                if not voq_drop_data and voq_evict_data:
                    sms_quant_len = len(voq_evict_data)
                    voq_quant_len = len(voq_evict_data[0])
                    age_quant_len = len(voq_evict_data[0][1])

                    ''' Verify evict is 0 for all quant'''
                    if voq_drop_data:
                        for g_idx in range(sms_quant_len):
                            for voq_idx in range(voq_quant_len):
                                for age_idx in range(age_quant_len):
                                    actual_value = voq_evict_data[g_idx][voq_idx][age_idx]
                                    expected_value = 0
                                    assert (
                                            actual_value == expected_value
                                    ), '''
                                            Eviction not expected for CPU Port PG {} at
                                            SMS/VoQ/Age region {}/{}/{} Expected: {} Actual: {}
                                         '''.format(pg_to_test, g_idx, voq_idx,
                                                    age_idx, expected_value, actual_value)

        ''' Verify drop is 7 for last quant only'''
        DROP_PROB_100 = 7
        if voq_drop_data:
            for g_idx in range(sms_quant_len):
                for voq_idx in range(voq_quant_len):
                    for age_idx in range(age_quant_len):
                        actual_value = voq_drop_data[g_idx][voq_idx][age_idx]
                        expected_value = DROP_PROB_100 if voq_idx == (voq_quant_len - 1) else 0
                        assert (
                                actual_value == expected_value
                        ), '''
                                Drop Probability not as expected for CPU Port PG {} at
                                SMS/VoQ/Age region {}/{}/{} Expected: {} Actual: {}
                             '''.format(pg_to_test, g_idx, voq_idx,
                                        age_idx, expected_value, actual_value)
