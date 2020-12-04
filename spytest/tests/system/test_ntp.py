import pytest
import time
from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.reboot as reboot_obj
import apis.system.ntp as ntp_obj
import apis.system.logging as syslog_obj
import apis.system.basic as basic_obj
import utilities.utils as utils_obj
import apis.routing.ip as ping_obj

@pytest.fixture(scope="module", autouse=True)
def ntp_module_hooks(request):
    global vars
    vars = dict()
    vars = st.get_testbed_vars()
    global_vars()
    yield
    ntp_obj.delete_ntp_servers(vars.D1)

@pytest.fixture(scope="function", autouse=True)
def ntp_func_hooks(request):
    global_vars()
    yield

def global_vars():
    global data
    data = SpyTestDict()
    data.servers = utils_obj.ensure_service_params(vars.D1, "ntp", "host")
    data.verify_no_server = 'None'
    data.ntp_service = 'ntp'


def config_ntp_server_on_config_db_file(dut, iplist):
    """
    Author: Anil Kumar Kacharla <anilkumar.kacharla@broadcom.com>
    """
    st.log("Configuring NTP servers in Config_db file")
    ntp_obj.add_ntp_servers(dut, iplist=iplist)
    data.time_date = time.strftime('%a %B %d %H:%M:%S %Z %Y')
    ntp_obj.config_date(vars.D1, data.time_date)
    reboot_obj.config_save(vars.D1)
    st.log("verifying ntp service status")
    if ntp_obj.verify_ntp_service_status(vars.D1, 'active (running)'):
        st.log("ntpd is running")
    else:
        st.log("ntpd is exited and restarting ntp service")
        basic_obj.service_operations(vars.D1, data.ntp_service, action="restart")
    if not st.poll_wait(ntp_obj.verify_ntp_server_details, 10, dut, iplist, remote=iplist):
        st.log("ip not matching")
        st.report_fail("operation_failed")
    if not ntp_obj.verify_ntp_service_status(dut, 'active (running)', iteration=65, delay=2):
        st.log("ntp is exited")
        st.report_fail("operation_failed")
    st.log("Verify that NTP server connectivity from DUT")
    result = 0
    for server_ip in data.servers:
        if not ping_obj.ping(vars.D1, server_ip):
            st.log("ping to ntp server is not successfull:{}".format(server_ip))
            result += 1
    if len(data.servers) == result:
        st.report_fail("None_of_the_configured_ntp_server_reachable")
    if not ntp_obj.verify_ntp_status(vars.D1, iteration=65, delay=2, server=data.servers):
        st.log("ntp syncronization failed")
        st.report_fail("operation_failed")


@pytest.mark.ntp_disable_enable_message_log
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_ntp_disable_enable_with_message_log():
    """
    Author: Anil Kumar Kacharla <anilkumar.kacharla@broadcom.com>
    Referrence Topology : 	Test bed ID:4 D1--Mgmt network
    Verify that Ntp synchronization is successful after doing NTP server on and off  and the message log display the correct time based upon the system up time.
    """
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1")
    data.string_generate = 'Iam Testing NTP'
    data.lines = 1
    data.time_date = time.strftime('%a %B %d %H:%M:%S %Z %Y')
    ntp_obj.config_date(vars.D1, data.time_date)
    st.log("checking time in message log without ntp ")
    log_message_1=syslog_obj.show_logging(vars.D1, severity=None, filter_list=[], lines=data.lines)
    if not log_message_1:
        st.log("log message_1 not created")
        st.report_fail("operation_failed")
    clock= utils_obj.log_parser(log_message_1[0])
    config_ntp_server_on_config_db_file(vars.D1, data.servers)
    st.log("Generating log messages")
    syslog_obj.clear_logging(vars.D1)
    syslog_obj.write_logging(vars.D1, data.string_generate)
    log_message = syslog_obj.show_logging(vars.D1, severity=None, filter_list=[data.string_generate])
    if not log_message:
        st.log("log message not created")
        st.report_fail("operation_failed")
    st.log("printing system clock")
    ntp_obj.show_clock(vars.D1)
    out = utils_obj.log_parser(log_message[0])
    if not (clock[0]['month'] == out[0]['month'] and clock[0]['hours'] == out[0]['hours'] and
            clock[0]['date'] == out[0]['date'] and clock[0]['minutes'] <= out[0]['minutes'] or clock[0]['seconds'] >= out[0]['seconds']):
        st.log("time not updated")
        st.report_fail("operation_failed")
    st.log("message log displaying correct timed based on system up time")
    st.log("disabling ntp")
    basic_obj.service_operations(vars.D1, data.ntp_service, action="stop")
    if not ntp_obj.verify_ntp_service_status(vars.D1, 'inactive (dead)'):
        st.log("ntp disabled failed")
        st.report_fail("operation_failed")
    st.log("Enabling NTP")
    basic_obj.service_operations(vars.D1, data.ntp_service, action="restart")
    if not ntp_obj.verify_ntp_service_status(vars.D1, 'active (running)', iteration=65, delay=2):
        st.log("ntp is exited after enable and disable ntp")
        st.report_fail("operation_failed")
    if not ntp_obj.verify_ntp_status(vars.D1, iteration=65, delay=2, server=data.servers):
        st.log("ntp syncronization failed after enable and disable ntp")
        st.report_fail("operation_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ntpdef
def test_ntp_exists_config():
    if ntp_obj.ensure_ntp_config(vars.D1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

