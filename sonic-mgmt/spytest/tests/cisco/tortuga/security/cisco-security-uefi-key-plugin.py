""" Tests to check `show platform security` utility. 

    This test module checks if the system's security is up and running with
    no issues.
"""

from spytest import st

cli_command = "show platform security {} > /dev/null 2>&1; echo $?"

def basic_cli_output_string_check_helper(command, output_pattern, error_log, neg_test=False):
    ''' 
        Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

        Helper function to identify if the required text substring is contained
        within the cmdline output. 
        If not, the particular test is reported as fail and the error_log msg is
        logged.
    '''
    dut = st.get_dut_names()[0]
    output = st.config(dut, command)
    if (output_pattern in output) != neg_test:
        st.report_pass("test_case_passed", dut)
    else:
        st.log("{}: {}".format(error_log, output))
        st.report_fail("test_case_failed", dut)

def run_cmd_w_status_helper(cmd):
    '''
        Helper function to execute cmd on dut and return exec status and output.
    '''
    dut = st.get_dut_names()[0]
    st.log(cmd, dut)
    return st.config(dut, cmd, skip_error_check=True)

def cmd_exec_status_check_helper(cmd_exec_status, neg_test=False):
    '''
        Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

        Helper function to report pass or fail for successful or failed execution 
        status for the command on dut.
    '''
    dut = st.get_dut_names()[0]
    cmd_exec_status = int(cmd_exec_status.split()[0])
    # Handle specific exec statuses
    if cmd_exec_status in (127, 2, 1):
        if neg_test:
            st.report_pass("test_case_passed", dut)
        else:
            st.report_fail("test_case_failed", dut)
    else:
        # Determine pass/fail based on the neg_test flag with XOR logic
        if (cmd_exec_status == 0) != neg_test:
            st.report_pass("test_case_passed", dut)
        else:
            st.report_fail("test_case_failed", dut)
    return


def test_check_platform_security_cli_availability():
    '''
        Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

        Test to check if UEFI CLI utility is available.
    '''
    command = cli_command.format("")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_check_platform_security_cli_health_report_availability():
    '''
        Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

        Test to check if the overall system security health is being reported.
    '''
    command = cli_command.format("health")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)


def test_device_ownership_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if device ownership is being reported. 
    '''
    command = cli_command.format("ownership")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_device_ownership_is_Cisco():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the Device Ownership is Cisco ('Generic').
    '''
    command = "show platform security ownership"
    output_pattern = "Device Ownership: Cisco"

    basic_cli_output_string_check_helper(command, output_pattern, "Device ownership is NOT Cisco")

def test_device_secureboot_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if SecureBoot is enabled.
    '''
    command = cli_command.format("secureboot")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_check_udi_cert_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to check if the UDI certificate is present and being reported.
    '''
    command = cli_command.format("udi")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_platform_dbCisco_variable_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to cross-verify the output of DB certs from Cisco from UEFI CLI against
    the output from tamcli, and make sure it matches.
    '''
    command = cli_command.format("variable db")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_platform_dbxCisco_variable_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to cross-verify the output of DB certs from Cisco from UEFI CLI against
    the output from tamcli, and make sure it matches.
    '''
    command = cli_command.format("variable dbx")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_platform_kekCisco_variable_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to cross-verify the output of DB certs from Cisco from UEFI CLI against
    the output from tamcli, and make sure it matches.
    '''
    command = cli_command.format("variable kek")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

def test_platform_pkCisco_variable_reporting():
    '''
    Author: Shivasakthi Senthil Velan (shisenth@cisco.com)

    Test to cross-verify the output of DB certs from Cisco from UEFI CLI against
    the output from tamcli, and make sure it matches.
    '''
    command = cli_command.format("variable pk")

    status=run_cmd_w_status_helper(command)
    cmd_exec_status_check_helper(status)

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
