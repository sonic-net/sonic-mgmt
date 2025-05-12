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
