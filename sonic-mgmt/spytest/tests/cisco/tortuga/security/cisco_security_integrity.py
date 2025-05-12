'''
'''

import re
import yaml
from spytest import st
from collections import Counter
from cisco_security_uefi_key_plugin import basic_cli_output_string_check_helper, run_cmd_w_status_helper, cmd_exec_status_check_helper

cli_command = "show platform security {} > /dev/null 2>&1; echo $?"


def pcr_eventlog_output_helper(dut):
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Helper function to fetch the PCR eventlog using the TPM2 utility and parse
    the YAML-based output.
    '''
    eventlog_output = st.config(dut, "sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements")
    eventlog_output = st.remove_prompt(dut, eventlog_output)
    return yaml.safe_load(eventlog_output)

def pcr_tamcli_output_helper(dut, cmd_component):
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Helper function to fetch PCR-related data using tamcli.
    '''
    command = "/opt/cisco/crypto/bin/tamcli {}".format(cmd_component)
    tamcli_output = st.config(dut, command)
    tamcli_output = st.remove_prompt(dut, tamcli_output)
    return tamcli_output

def extract_pcr_info_helper(pcr_output_data):
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)
    
    Process the PCR output data from tamcli and extract the PCR index, hash values and the 
    extension counters, required for the tests. 
    '''
    pcr_dict = {}
    for output_line in pcr_output_data:
        value_dict = {
            'index':-1,
            'sha256_hash':'',
            'extension_counter':-1
        }
        pattern = r"PCR (\d{1,2}): ([0-9a-fA-F]{64}) \(len \d+, pcr extend counter (\d+)\)"
        match = re.match(pattern, output_line)
        
        if match:
            # Extract matched groups
            value_dict['index'] = int(match.group(1))
            value_dict['sha256_hash'] = match.group(2)
            value_dict['extension_counter'] = int(match.group(3))
            pcr_dict[int(match.group(1))] = value_dict
    return pcr_dict

def pcr_sha256_hash_comparer(value_mode, reference_pcr_index_list, pcr_values, inverse_cond=False):
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Helper function to check whether the supplied PCR indices have the correct 
    hash values that match/dont match the expected value (0000... or ffff...)
    inverse_cond helps to check if the supplied PCR indices do not match the 
    template values.
    '''
    if str(value_mode) == '0':
        reference_value = '%064d' % 0
    elif str(value_mode) == 'f':
        reference_value = 'f'*64

    incorrect_counter_flag = 0
    for pcr_ind in reference_pcr_index_list:
        if (pcr_values[pcr_ind] != reference_value) != inverse_cond:
            incorrect_counter_flag += 1 

    return incorrect_counter_flag

def test_security_integrity_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check presence of integrity commands.
    '''
    command = cli_command.format("integrity -h")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_security_integrity_pcr_value_reporting_sha256():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if CLI returns PCR sha256 hashes successfully for PCRs 0-23.
    '''
    command = cli_command.format("integrity pcr 0-23 sha256")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_security_integrity_pcr_value_reporting_sha1():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if CLI returns PCR sha1 hashes successfully for PCRs 0-23.
    '''
    command = cli_command.format("integrity pcr 0-23 sha1")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_security_integrity_pcr_value_reporting_comma_hyphen_separated_range_sha256():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if CLI returns PCR sha256 hashes successfully for PCRs 0,1,2-6,7,8-23. 
    For values delimited by commas and hyphens.
    '''
    command = cli_command.format("integrity pcr 0,1,2-6,7,8-23 sha256")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_negtest_security_integrity_pcr_value_reporting_incorrect_range_sha256():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Negative test to check if CLI returns error if PCR values are out of range 
    (PCR index > 23).
    '''
    command = "show platform security integrity pcr 0-25 sha256"
    output_pattern = "Invalid PCR entry"

    basic_cli_output_string_check_helper(command, output_pattern, "PCR range is out-of-bounds")

def test_security_integrity_pcr_quote_reporting_sha256():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check CLI returns PCR quotes for the specified valid range of PCR. 
    '''
    command = cli_command.format("integrity pcr-quote 0,1,2-6,7,8-23 sha256 12345")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_negtest_security_integrity_pcr_quote_reporting_sha1():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Negative test to check if CLI throws error if invalid hash algorithm is 
    specified for fetch PCR quotes.
    '''
    command = cli_command.format("integrity pcr-quote 0,1,2-6,7,8-23 sha1 12345")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status,neg_test=True)

def test_negtest_security_integrity_pcr_quote_reporting_missing_nonce():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Negative test to check if CLI throws error if nonce is not specified for 
    fetching PCR quotes. 
    '''
    command = cli_command.format("integrity pcr-quote 0,1,2-6,7,8-23 sha256")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status, neg_test=True)

def test_security_integrity_attest_key_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if CLI returns text formatted attestation key.
    '''
    command = cli_command.format("integrity attest-key")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_security_integrity_attest_key_reporting_pem_format():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if CLI returns pem-formatted attestation key. 
    '''
    command = cli_command.format("integrity attest-key --pem")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_security_integrity_report_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if CLI returns the integrity report. 
    '''
    command = cli_command.format("integrity report")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

# Check presence of event log for TPM chip
def test_security_TPM_eventlog_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the TPM chip is successfully registered by the driver and 
    is exposing the TPM eventlog. 
    '''
    command = "test -f /sys/kernel/security/tpm0/binary_bios_measurements ; echo $?"
    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_tamcli_pcr_get_pcr_values():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if tamcli outputs the PCR values.
    '''
    command = "/opt/cisco/crypto/bin/tamcli -a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256 > /dev/null 2>&1 ; echo $?"
    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_tamcli_pcr_get_pcr_quote_values():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if tamcli outputs the PCR quotes and signatures.
    '''
    command = "/opt/cisco/crypto/bin/tamcli -a get-pcr-quote -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256 -m 12345 -q /tmp/spytest_pcr_quote.bin -o /tmp/spytest_pcr_quote.sig > /dev/null 2>&1 ; echo $? ; rm -f /tmp/spytest_pcr_quote.bin ; rm -f /tmp/spytest_pcr_quote.sig"

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)    

def test_tamcli_pcr_get_aik_certs_pem_format():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if tamcli outputs the attestation keys in PEM format.
    '''
    command = "/opt/cisco/crypto/bin/tamcli -a get-cert-chain-v2 -t CISCOAIK -f pem > /dev/null 2>&1 ; echo $?"

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_tamcli_pcr_get_aik_certs_brief_text_format():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if tamcli outputs the attestation keys in text format.
    '''
    command = "/opt/cisco/crypto/bin/tamcli -a get-cert-chain-v2 -t CISCOAIK -f text -b > /dev/null 2>&1 ; echo $?"

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_valid_pcr_eventlog():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to identify if the PCR eventlog has the signature "Spec ID Event03"
    present, which deems that the eventlog is valid and can be trusted.
    '''
    dut = st.get_dut_names()[0]
    eventlog_data = pcr_eventlog_output_helper(dut)
    signature_val = "Spec ID Event03"
    events = eventlog_data.get('events', [])
    if not events:
        st.report_fail("test_case_failed", dut)
        return
    first_event = events[0]
    spec_id = first_event.get('SpecID', [])
    if not spec_id:
        st.report_fail("test_case_failed", dut)
        return
    signature = spec_id[0].get('Signature', None)
    if signature == signature_val:
        st.report_pass("test_case_passed", dut)
    else:
        st.report_fail("test_case_failed", dut)
    return 

def test_validate_pcr_extension_count():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to verify PCR extension count from tamcli matches that from TPM2 util.
    TPM2 util log output is parsed and count is thus derived from the parsing.
    '''
    dut = st.get_dut_names()[0]
    eventlog_data = pcr_eventlog_output_helper(dut)
    pcr_index_list = [event['PCRIndex'] for event in eventlog_data['events']]
    pcr_extend_count = Counter(pcr_index_list)
    # For PCR index 0, remove one event from the event counter as first event is 
    # the spec id check and not included in the extension calculation. (?)
    pcr_extend_count[0] -= 1

    tamcli_data = pcr_tamcli_output_helper(dut, "-a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256")
    tamcli_data = str(tamcli_data).split('\n')
    pcr_info_dict = extract_pcr_info_helper(tamcli_data)

    incorrect_counter_flag = 0
    for pcr_ind,ext_count in pcr_extend_count.items():
        if pcr_info_dict[pcr_ind]['extension_counter'] != ext_count:
            st.log("Mismatching PCR extension counter for PCR index:{} ({} vs {})".format(pcr_ind, ext_count, pcr_info_dict[pcr_ind]['extension_counter']), dut)
            incorrect_counter_flag += 1
        else:
            st.log("PCR extension match for PCR: {}".format(pcr_ind))
    if incorrect_counter_flag > 0:
        st.report_fail("test_case_failed", dut)
    else:
        st.report_pass("test_case_passed", dut)
    return

def test_validate_pcr_values():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to validate the sha256 hashes output by tamcli against the outputs from
    the tpm2 util output.
    '''
    dut = st.get_dut_names()[0]
    eventlog_data = pcr_eventlog_output_helper(dut)
    tamcli_data = pcr_tamcli_output_helper(dut, "-a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256")
    tamcli_data = str(tamcli_data).split('\n')
    pcr_info_dict = extract_pcr_info_helper(tamcli_data)

    incorrect_counter_flag = 0
    for pcr_ind, pcr_sha256_hash in eventlog_data['pcrs']['sha256'].items():
        pcr_sha256_hash = hex(int(pcr_sha256_hash))[2:-1].zfill(64)
        if (pcr_info_dict[pcr_ind]['sha256_hash']) != pcr_sha256_hash:
            st.log("Mismatching sha256 PCR hash for PCR index:{}\nPCR hash: {} vs {}".format(pcr_ind, pcr_sha256_hash, pcr_info_dict[pcr_ind]['sha256_hash']), dut)
            incorrect_counter_flag += 1
        else:
            st.log("PCR hash match for PCR: {}".format(pcr_ind))
    if incorrect_counter_flag > 0:
        st.report_fail("test_case_failed", dut)
    else:
        st.report_pass("test_case_passed", dut)
    return

def test_pcr_value_0000_tamcli():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the PCR indices have 0000... as the correctly intended 
    sha256 hash value.
    '''
    dut = st.get_dut_names()[0]
    pcr_ind_to_be_0 = [10,11,12,13,14,16,23]
    tamcli_data = pcr_tamcli_output_helper(dut, "-a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256")
    tamcli_data = str(tamcli_data).split('\n')
    pcr_info_dict = extract_pcr_info_helper(tamcli_data)
    pcr_value_dict = {}
    for pcr_ind, pcr_detail_dict in pcr_info_dict.items():
        pcr_value_dict[int(pcr_ind)] = pcr_detail_dict['sha256_hash']
    st.log("PCR dict: {}".format(pcr_value_dict), dut)
    num_mismatches = pcr_sha256_hash_comparer('0', pcr_ind_to_be_0, pcr_value_dict)

    if num_mismatches > 0:
        st.log("Mismatch present. Num of mismatches: {}".format(num_mismatches), dut)
        st.report_fail("test_case_failed", dut)
    else:
        st.report_pass("test_case_passed", dut)
    return 

def test_negtest_pcr_value_not_0000_tamcli():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the PCR indices DO NOT have 0000... as the sha256 hash 
    value.
    '''
    dut = st.get_dut_names()[0]
    pcr_ind_to_be_not_0 = [0,1,2,3,4,5,6,7,8,9,15,17,18,19,20,21,22]
    tamcli_data = pcr_tamcli_output_helper(dut, "-a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256")
    tamcli_data = str(tamcli_data).split('\n')
    pcr_info_dict = extract_pcr_info_helper(tamcli_data)
    pcr_value_dict = {}
    for pcr_ind, pcr_detail_dict in pcr_info_dict.items():
        pcr_value_dict[int(pcr_ind)] = pcr_detail_dict['sha256_hash']
    st.log("PCR dict: {}".format(pcr_value_dict), dut)
    num_mismatches = pcr_sha256_hash_comparer('0', pcr_ind_to_be_not_0, pcr_value_dict, inverse_cond=True)

    if num_mismatches > 0:
        st.log("Mismatch present. Num of mismatches: {}".format(num_mismatches), dut)
        st.report_fail("test_case_failed", dut)
    else:
        st.report_pass("test_case_passed", dut)
    return 

def test_pcr_value_ffff_tamcli():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the PCR indices have ffff... as the correctly intended 
    sha256 hash value.
    '''
    dut = st.get_dut_names()[0]
    pcr_ind_to_be_f = [17,18,19,20,21,22]
    tamcli_data = pcr_tamcli_output_helper(dut, "-a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256")
    tamcli_data = str(tamcli_data).split('\n')
    pcr_info_dict = extract_pcr_info_helper(tamcli_data)
    pcr_value_dict = {}
    for pcr_ind, pcr_detail_dict in pcr_info_dict.items():
        pcr_value_dict[int(pcr_ind)] = pcr_detail_dict['sha256_hash']
    st.log("PCR dict: {}".format(pcr_value_dict), dut)
    num_mismatches = pcr_sha256_hash_comparer('f', pcr_ind_to_be_f, pcr_value_dict)

    if num_mismatches > 0:
        st.log("Mismatch present. Num of mismatches: {}".format(num_mismatches), dut)
        st.report_fail("test_case_failed", dut)
    else:
        st.report_pass("test_case_passed", dut)
    return

def test_negtest_pcr_value_not_ffff_tamcli():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the PCR indices DO NOT have ffff... as the sha256 hash 
    value.
    '''
    dut = st.get_dut_names()[0]
    pcr_ind_to_be_not_f = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23]
    tamcli_data = pcr_tamcli_output_helper(dut, "-a get-pcr -r 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -d sha256")
    tamcli_data = str(tamcli_data).split('\n')
    pcr_info_dict = extract_pcr_info_helper(tamcli_data)
    pcr_value_dict = {}
    for pcr_ind, pcr_detail_dict in pcr_info_dict.items():
        pcr_value_dict[int(pcr_ind)] = pcr_detail_dict['sha256_hash']
    st.log("PCR dict: {}".format(pcr_value_dict), dut)
    num_mismatches = pcr_sha256_hash_comparer('f', pcr_ind_to_be_not_f, pcr_value_dict, inverse_cond=True)

    if num_mismatches > 0:
        st.log("Mismatch present. Num of mismatches: {}".format(num_mismatches), dut)
        st.report_fail("test_case_failed", dut)
    else:
        st.report_pass("test_case_passed", dut)
    return 