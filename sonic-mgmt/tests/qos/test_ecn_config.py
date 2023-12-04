"""
Tests for verifying the configuration on the DUT 
to match the expected WRED probability configuration
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.cisco_data import is_cisco_device
import json


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

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
            asic_cfg_facts = asic.config_facts(host=duthost.hostname, source="running", namespace=asic.namespace)['ansible_facts']
            asic_ports_dict[asic.namespace] = get_ports_with_status(asic_cfg_facts)
    else:
        cfg_facts = duthost.get_running_config_facts()
        asic_ports_dict['asic0'] = get_ports_with_status(cfg_facts)
    for asic in asic_ports_dict.keys():
        up_ports = asic_ports_dict[asic]['up']
        intf_facts = duthost.interface_facts(up_ports=up_ports)['ansible_facts']
        up_ports = filter(lambda p: p not in intf_facts['ansible_interface_link_down_ports'], up_ports)
        assert up_ports, "No ports with Admin, Open state UP found"
    return asic_ports_dict

@pytest.mark.parametrize("pg_to_test", [3,4])        
def test_verify_ecn_marking_config(duthosts, rand_one_dut_hostname, pg_to_test, request):
    """
    @summary: Verify output of `show platform npu voq cgm_profile with wred_profile drop probability`
    """
    duthost = duthosts[rand_one_dut_hostname] 
		if not is_cisco_device(duthost):
		 pytest.skip("Skipping as not a Cisco device")

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']
    for asic in asics:
        if not asic:
            asic_namespace_string = asic
            asic = 'asic0'
        else:
            asic_namespace_string = " -n " + str(asic)

        up_ports = asic_facts[asic]['up']

        selected_down_ports = None
        if None in asic_facts[asic].keys():
            down_ports = asic_facts[asic][None]

        #Combine both Up and Down
        up_ports.extend(down_ports)    

        show_command = "sudo show platform npu voq cgm_profile -i {} -t {} -d"

        for port in up_ports:
            logging.info("Checking Port: {}".format(port))
            result = duthost.command(show_command.format(port, pg_to_test))
            traceback_found = "Traceback" in result["stdout"]
            assert not traceback_found, "Traceback found in show platform npu voq for UP Port"
            assert result["stdout"], "No output for this CLI"
            json_str = result["stdout"].strip()
            try:
              data = json.loads(json_str)
            except json.JSONDecodeError as e:
              logging.info("JSon load error: {}".format(e))
              continue
            voq_mark_data=None
            if "voq_mark_prob_g" in data:
              voq_mark_data=data["voq_mark_prob_g"]
              if voq_mark_data:
                sms_quant_len=len(voq_mark_data)
                voq_quant_len=len(voq_mark_data[0])
                age_qaunt_len=len(voq_mark_data[0][1])
            
            voq_drop_data=None
            if "voq_drop_prob_g" in data:
              voq_drop_data=data["voq_drop_prob_g"]
              if not voq_mark_data and voq_drop_data:
                sms_quant_len=len(voq_drop_data)
                voq_quant_len=len(voq_drop_data[0])
                age_qaunt_len=len(voq_drop_data[0][1])

            if voq_mark_data:
              for g_idx in range(sms_quant_len):
                for voq_idx in range(voq_quant_len):
                  for age_idx in range(age_qaunt_len):
                    rounded_actual_value = round(voq_mark_data[g_idx][voq_idx][age_idx],2)
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
                    expected_actual_value = round(data["wm_prob"][mark_level],2)
                    assert (
                        rounded_actual_value == expected_actual_value
                    ), '''
                        Marking Probability not as expected at SMS/VoQ/Age region {}/{}/{} Expected: {} Actual: {}
                       '''.format(g_idx,voq_idx,age_idx,expected_actual_value, rounded_actual_value)

            ''' Verify drop is 7 for last quant'''
            if voq_drop_data:
              for g_idx in range(sms_quant_len):
                for age_idx in range(age_qaunt_len):
                  actual_value = voq_drop_data[g_idx][voq_quant_len-1][age_idx]
                  assert (
                      actual_value == 7
                  ), '''
                      Drop Probability not 100% at SMS/VoQ/Age region {}/{}/{} Expected: 7 Actual: {}
                     '''.format(g_idx,voq_quant_len-1,age_idx,actual_value)
