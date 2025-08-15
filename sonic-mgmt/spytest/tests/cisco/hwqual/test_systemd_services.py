import pytest
from spytest import st, SpyTestDict
import re
from apis.system.basic import verify_docker_status
from utilities.common import poll_wait

@pytest.fixture(scope="module", autouse=True)
def systemd_module_hooks(request):
    global globalVars
    globalVars = st.get_testbed_vars()
    global data
    data = SpyTestDict()
    data.dut_list = [globalVars.D1, globalVars.D2]
    data.expected_down_dockers = ['sflow','nat']


def check_systemd_service_status(service, dut):
    '''
    return 0 if service is inactive or service is active(exited) and status != 0/SUCCESS
    return 1 if service is active(running) or service is active(exited) and status == 0/SUCCESS
    '''
    res = -1
    cmd1 = "systemctl is-active {}".format(service)
    output = st.config(dut, cmd1)
    status = output.split("\n")[0]
    if status != 'active':
        res = 0
    else:
        cmd2 = "systemctl status {}".format(service)
        output = st.config(dut, cmd2)
        active_status = re.search(r"(Active:.*)\)",output)
        active_status = active_status.group(0)
        if('running' in active_status):
            res = 1
        elif('exited' in active_status):
            if('status=0/SUCCESS' in output):
                res = 1
            else:
                res = 0
        else:
            res = 0
    return res


def validate_docker_status(dut, time_out=240):
    result = True
    if not poll_wait(verify_docker_status, time_out, dut, 'Exited'):
        st.log("Some of the dockers are in 'Exited' state")
        output = st.show(dut,'docker ps -a')
        for line in output:
            if ('Exited' in line['status']) and (line['names'] not in data.expected_down_dockers):
                st.log("docker {} should be UP, but it is Exited".format(line['names']))
                result = False
    return result


def validate_system_health_summary(dut):
    output = st.config(dut, "sudo show system-health summary")
    led_status = re.search("(System status LED\s+)(.*)", output).group(2)
    if(led_status != "green"):
        st.log("System status LED is not as expected on DUT {}. Expected green, observed {}".format(dut, led_status))
        return False
    services_status = re.search("(Services:\n)(\s+Status:\s+)(.*)", a).group(3)
    if(services_status != 'OK'):
        st.log("Services status is not as expected on DUT {}. Expected OK, observed {}".format(dut, services_status))
        return False
    hardware_status = re.search("(Hardware:\n)(\s+Status:\s+)(.*)", a).group(3)
    if(hardware_status != 'OK'):
        st.log("Hardware status is not as expected on DUT {}. Expected OK, observed {}".format(dut, hardware_status))
        return False
    return True


class TestSystemdServices():

    def test_systemd_services(self):
        systemd_services_to_be_checked = ["cisco-platform-setup.service", "platform-topology.service", "platform-dev-cfg.service", "platform-obfl.service", "config-setup.service"]
        for dut in data.dut_list:
            for service in systemd_services_to_be_checked:
                service_status = check_systemd_service_status(service, dut)
                if(service_status == 0):
                    st.log("Service {} is not Active on DUT {}".format(service, dut))
                    st.log("*************************************************************")
                    st.report_fail("Service {} is not Active on DUT {}".format(service, dut))
        st.report_pass("test_case_passed")


    def test_validate_docker_status(self):
        for dut in data.dut_list:
            if not validate_docker_status(dut):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")


    def test_system_health_summary(self):
        for dut in data.dut_list:
            if not validate_system_health_summary(dut):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")
