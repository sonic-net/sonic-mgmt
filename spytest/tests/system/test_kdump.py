import time
import pytest
from spytest import st

show_kdump_status = "sudo show kdump status"
no_kernel_crash_log_1 = "There is no kernel core file stored"
no_kernel_crash_log_2 = "Kernel crash log not found"

## Trigger a kernel crash
def trigger_kernel_crash(vars):
    st.config(vars.D1, 'echo 1 | sudo tee /proc/sys/kernel/sysrq')
    st.config(vars.D1, 'echo c | sudo tee /proc/sysrq-trigger', expect_reboot=True, skip_error_check=True)
    time.sleep(10)
    st.log("After kernel crash...")

def get_kdump_status(vars):
    output = st.show(vars.D1, show_kdump_status)
    st.log(output)
    return output[0]["admin_status"], output[0]["oper_status"]

## Verify if kudmp is Ready
def is_ready_to_kdump(vars):
    _, oper_status = get_kdump_status(vars)
    if oper_status not in ["Enabled", "Ready"]:
        st.log("Error: kdump should be ready")
        return False
    return True

def get_num_dump_files(vars):
    output = st.config(vars.D1, 'find /var/crash/ -name "kdump.*"')
    crash_dir = output.split('\n')
    num_crashes = 0
    for x in crash_dir:
        if x.find('/var/crash/20') != -1:
            num_crashes += 1
    return num_crashes

## Verify that file exist and is at least 10 bytes size
def is_file_exist(vars, fname):
    output = st.config(vars.D1, 'stat %s' % fname)
    return ("File: %s" % fname) in output

## Verify that the dump file is a valid kdump file
def is_file_a_kdump_file(vars, fname):
    output = st.config(vars.D1, 'file %s' % fname)
    return "Kdump compressed dump" in output

## Checking the dump files which are stored locally
def check_dump_files(vars):
    result = True
    output = st.config(vars.D1, 'show kdump files')
    output_files = output.split('\n')
    crash_files = output_files[2:-1]
    for x in range(len(crash_files)):
        if x % 2 == 0:
            l = crash_files[x]
            key = l[7:19]
            dmesg_file = "/var/crash/%s/dmesg.%s" % (key, key)
            dump_file = "/var/crash/%s/kdump.%s" % (key, key)
            if not is_file_exist(vars, dmesg_file):
                st.log("Error: file %s is missing" % dmesg_file)
                result = False
            if not is_file_exist(vars, dump_file):
                st.log("Error: file %s is missing" % dump_file)
                result = False
            if not is_file_a_kdump_file(vars, dump_file):
                st.log("Error: file %s is not a valid kdump file" % dump_file)
                result = False
    return result

def clean_up(vars):
    st.config(vars.D1, 'config kdump disable')
    st.config(vars.D1, 'config kdump num_dumps 3')
    st.config(vars.D1, 'config kdump memory 0M-2G:448M,2G-4G:512M,4G-8G:576M,8G-:640M')
    st.config(vars.D1, 'config save -y')

def abort_test(reason):
    st.error("Test is failing: {}".format(reason))
    return reason

def perform_test(vars):

    # If kdump is enabled, we will disable it
    admin_status, oper_status = get_kdump_status(vars)
    if admin_status == "Enabled" or oper_status in ["Enabled", "Ready"]:
        clean_up(vars)

    # Just in case we have kernel core files stored
    st.config(vars.D1, 'rm -rf /var/crash/20*')

    # Verify that kdump is disabled
    st.log("1) Verify that kdump is disabled")
    admin_status, oper_status = get_kdump_status(vars)
    if admin_status != "Disabled" and oper_status != "Disabled":
        clean_up(vars)
        st.reboot(vars.D1, 'normal', True)
        admin_status, oper_status = get_kdump_status(vars)
        if admin_status != "Disabled" and oper_status != "Disabled":
            return abort_test("kdump should be disabled when this test start")

    # Verify command "show kdump log" when there is no kernel core file stored
    st.log('2) Verify command "sudo show kdump log" when there is no kernel core file stored')
    output = st.show(vars.D1, 'sudo show kdump log 1', skip_tmpl=True)
    if no_kernel_crash_log_1 not in output and no_kernel_crash_log_2 not in output:
        return abort_test("command should have displayed '{}' or '{}'".format(
                    no_kernel_crash_log_1, no_kernel_crash_log_2))

    # Enable kdump
    st.log("3) Enable kdump")
    output = st.config(vars.D1, 'config kdump enable')
    search1 = "kdump will be only operational after the system reboots"
    search2 = "Kdump configuration changes will be applied after the system reboots"
    if search1 not in output and search2 not in output:
        msg = "should have warned that kdump will be only operational after the system reboots"
        return abort_test("command 'config kdump enable' {}".format(msg))

    # Reboot the switch and verify that kdump is ready to go
    st.log("4) Reboot the switch and verify that kdump is ready to go")
    st.config(vars.D1, 'config save -y')
    st.reboot(vars.D1, 'normal', True)
    if not is_ready_to_kdump(vars):
        return abort_test("After system reboots, kdump should be ready")

    # Extract memory used for kdump
    st.log("5) Extract memory used for kdump")
    memory = None
    output = st.config(vars.D1, 'show kdump memory')
    p = output.find(': ')
    if p != -1:
        memory = output[p+2:]

    # Verify that /proc/cmdline has the kdump memory parameter
    st.log("6) Verify that /proc/cmdline has the kdump memory parameter")
    output = st.config(vars.D1, 'cat /proc/cmdline')
    if "crashkernel=" not in output:
        return abort_test("crashkernel= kernel parameter is missing in kernel parameters")

    # Trigger a first kernel crash
    st.log("7) Trigger a kernel crash")
    trigger_kernel_crash(vars)
    if not is_ready_to_kdump(vars):
        return abort_test("After kernel crash and system restart, kdump should be ready")

    # Verify that we have one crash dump file in the crash directory
    st.log("8) Verify that we have one crash dump file in the crash directory")
    num_crashes = get_num_dump_files(vars)
    if num_crashes != 1:
        return abort_test("There should be one kernel dump file in /var/crash")

    # Check the dump and dmesg files which are stored
    st.log("9) verify the dump and dmesg files which are stored")
    if not check_dump_files(vars):
        return abort_test("Kernel core dump and Kernel log files are not right")

    # Change the number of maximum dump file stored
    st.log("10) Change the number of maximum dump file stored")
    output = st.config(vars.D1, 'config kdump num_dumps 2')

    # Verify the number of dump file stored
    st.log("11) Verify the number of dump file stored")
    output = st.config(vars.D1, 'show kdump num_dumps')
    if "Maximum number of Kernel Core files Stored: 2" not in output:
        return abort_test("The maximum number of dump files stored should be 2")

    # Change the memory used for kdump capture kernel
    st.log("12) Change the memory used for kdump capture kernel")
    output = st.config(vars.D1, 'config kdump memory 512M')
    if "kdump updated memory will be only operational after the system reboots" not in output:
        return abort_test('Should have displayed "kdump updated memory will be only operational after the system reboots"')
    st.config(vars.D1, 'config save -y')

    # Verify the memory settings for kdump
    st.log("13) Verify the memory settings for kdump")
    output = st.config(vars.D1, 'show kdump memory')
    if "Memory Reserved: 512M" not in output:
        return abort_test("The memory allocated for kdump should be 512M")

    # Trigger a second kernel crash
    st.log("14) Trigger a kernel crash")
    trigger_kernel_crash(vars)
    if not is_ready_to_kdump(vars):
        return abort_test("After kernel crash and system restart, kdump should be ready")

    # Verify that memory for kdump is specified to the kernel
    st.log("15) Verify that memory for kdump is specified to the kernel")
    output = st.config(vars.D1, 'cat /proc/cmdline')
    if "crashkernel=512M" not in output:
        return abort_test("The kernel memory allocated for kdump should be 512M")

    # Verify that we have two crash dump files in the crash directory
    st.log("16) Verify the number of crash dump files in the crash directory")
    num_crashes = get_num_dump_files(vars)
    if num_crashes != 2:
        return abort_test("There should be two kernel dump files in /var/crash")

    # Verify the dump and dmesg files which are stored
    st.log("17) Verify the dump and dmesg files which are stored")
    if not check_dump_files(vars):
        return abort_test("Kernel core dump and Kernel log files are not right")

    # Trigger a third kernel crash
    st.log("18) Trigger a kernel crash")
    trigger_kernel_crash(vars)
    if not is_ready_to_kdump(vars):
        return abort_test("After kernel crash and system restart, kdump should be ready")

    # Verify that we still have two crash dump files in the crash directory
    st.log("19) Verify that we still have two crash dump files in the crash directory")
    num_crashes = get_num_dump_files(vars)
    if num_crashes != 2:
        return abort_test("Error: there should be two kernel dump files in /var/crash")

    # Check the dump and dmesg files which are stored
    st.log("20) Check the dump and dmesg files which are stored")
    if not check_dump_files(vars):
        return abort_test("Kernel core dump and Kernel log files are not right")

    # Retrieve the SONiC current image name")
    st.log("21) Retrieve the SONiC current image name")
    output = st.config(vars.D1, "sonic_installer list | grep 'Current: ' | cut -d ':' -f 2- | sed -e 's,^ *,,'")
    st.log(output)
    outputln = output.split('\n')
    current_image = outputln[0]

    # Install a new SONiC image
    st.log("22) Install a new SONiC image")
    output = st.config(vars.D1, "sonic_installer install http://10.59.132.240:9009/projects/csg_sonic/sonic_builds/daily/3.0/broadcom/LAST_BUILD/sonic-broadcom.bin --yes")

    # Verify that two images in grub.cfg have the parameter "crashkernel=X"
    st.log('23) Verify that two images in grub.cfg have the parameter "crashkernel=X"')
    output = st.config(vars.D1, 'show kdump memory')
    p = output.find(': ')
    if p == -1:
        return abort_test("")
    memory = output[p+2:].split('\n')
    memory = memory[0]
    output = st.config(vars.D1, 'grep -c "%s" /host/grub/grub.cfg' % memory)
    memory_nb = output.split('\n')
    if memory_nb[0] != '2':
        return abort_test("The two SONiC images should have %s memory allocated for kdump" % memory)

    # Remove this new SONiC image
    st.log("24) Remove this new SONiC image")
    output = st.config(vars.D1, "sonic_installer set_next_boot %s" % current_image)
    output = st.config(vars.D1, "sonic_installer cleanup --yes")
    output = st.config(vars.D1, "sonic_installer list")

    return None

@pytest.mark.kdump
def test_ft_enable_kdump():

    vars = st.get_testbed_vars()

    if not st.is_feature_supported("show-kdump-status-command", vars.D1):
        st.report_unsupported('test_case_unsupported')

    result = perform_test(vars)
    clean_up(vars)
    st.config(vars.D1, 'rm -rf /var/crash/20*')
    if result: st.report_fail("msg", result)
    st.report_pass("operation_successful")

