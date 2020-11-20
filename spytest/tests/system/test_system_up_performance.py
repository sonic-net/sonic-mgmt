import pytest
import pprint
from datetime import datetime
from spytest import st
import utilities.utils as utils
import utilities.common as cutils
import apis.system.interface as intapi
import apis.system.logging as logapi
import apis.system.basic as bcapi
from apis.system.reboot import config_reload


@pytest.fixture(scope="module", autouse=True)
def system_up_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:1")
    yield


@pytest.fixture(scope="function", autouse=True)
def system_up_func_hooks(request):
    yield


def test_system_up_performance():
    timer_dict = {}
    test_port = vars.D1D2P1
    max_port_up_time = 20
    if not intapi.verify_interface_status(vars.D1, test_port, 'oper', 'up'):
        st.error('{} interface is down on dut'.format(test_port))
        st.report_fail('test_case_failed')

    st.banner("START - REBOOT TEST ")
    tstart = datetime.now()
    st.reboot(vars.D1)
    bcapi.get_system_status(vars.D1)
    tdiff = datetime.now() - tstart
    timer_dict['REBOOT_TEST'] = "{} {}".format(tdiff, 'H:M:S:msec')
    st.banner("END - REBOOT TEST -- {}".format(timer_dict['REBOOT_TEST']))

    st.banner("START - CONFIG REBOOT TEST ")
    tstart = datetime.now()
    config_reload(vars.D1)
    bcapi.get_system_status(vars.D1)
    tdiff = datetime.now() - tstart
    timer_dict['CONFIG_REBOOT_TEST'] = "{} {}".format(tdiff, 'H:M:S:msec')
    st.banner("END - CONFIG REBOOT TEST -- {}".format(timer_dict['CONFIG_REBOOT_TEST']))

    st.banner("START - PORT UP TEST ")
    logapi.clear_logging(vars.D1)
    intapi.interface_shutdown(vars.D1, test_port)
    intapi.verify_interface_status(vars.D1, test_port, 'oper', 'down')
    st.wait(5)
    intapi.interface_noshutdown(vars.D1, test_port)
    if not intapi.poll_for_interface_status(vars.D1, test_port, 'oper', 'up', iteration=max_port_up_time, delay=1):
        st.error('{} interface is down on dut for MAX time = {}'.format(test_port, max_port_up_time))
    log_down = logapi.show_logging(vars.D1, filter_list=['sudo config interface startup {}'.format(test_port)])
    log_up = logapi.show_logging(vars.D1, filter_list=['Set operation status UP to host interface {}'.
                                 format(test_port)])
    logapi.show_logging(vars.D1)
    log_down_time = utils.log_parser(log_down[0])[0]
    log_up_time = utils.log_parser(log_up[0])[0]
    f_down_time = utils.convert_time_to_milli_seconds(days=0, hours=log_down_time['hours'],
                                                      minutes=log_down_time['minutes'],
                                                      seconds=log_down_time['seconds'],
                                                      milli_second=log_down_time['micro_second'])

    f_up_time = utils.convert_time_to_milli_seconds(days=0, hours=log_up_time['hours'],
                                                    minutes=log_up_time['minutes'],
                                                    seconds=log_up_time['seconds'],
                                                    milli_second=log_up_time['micro_second'])

    st.log("f_down_time : {} , f_up_time : {}".format(f_down_time, f_up_time))
    timer_dict['PORT_UP_TEST'] = "{} {}".format((f_up_time - f_down_time) / 1000, 'mili sec')
    st.banner("END - PORT UP TEST -- {}".format(timer_dict['PORT_UP_TEST']))

    st.log("\n" + pprint.pformat(timer_dict, width=2) + '\n')
    st.log('\n' + cutils.sprint_vtable(['Test Name', 'Time'], timer_dict.items()) + '\n')
    csv_str = '\nTest, Result\n'
    for i, j in timer_dict.items():
        csv_str += "{}, {}\n".format(i, j)
    st.log(csv_str)
    st.report_pass('test_case_passed')
