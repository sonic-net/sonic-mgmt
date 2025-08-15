import pytest
from spytest import st, SpyTestDict
import re

@pytest.fixture(scope="module", autouse=True)
def fan_module_hooks(request):
    global globalVars
    globalVars = st.get_testbed_vars()
    global data
    data = SpyTestDict()
    data.dut_list = [globalVars.D1, globalVars.D2]


@pytest.fixture(scope='class')
def get_fan_keys():
    fan_keys = {}
    for dut in data.dut_list:
        keys_output = st.config(dut, "redis-cli -n 6 keys FAN_INFO*")
        keys = re.findall(r'"FAN_INFO\|[a-zA-Z0-9.]+"', keys_output)
        fan_keys[dut] = keys
    yield fan_keys


def check_fan_presence(dut, fan_keys):
    for key in fan_keys[dut]:
        fan_presence = st.config(dut,"redis-cli -n 6 hget {} presence".format(key))
        if('False' in fan_presence):
            st.log("Some fans are missing on dut {}".format(dut))
            return False
    return True


def check_fan_speeds(dut, fan_keys):
    for key in fan_keys[dut]:
        is_under_speed = st.config(dut,"redis-cli -n 6 hget {} is_under_speed".format(key))
        if('True' in is_under_speed):
            st.log("DUT {}, Fan {} is running under_speed".format(dut, key))
            return False
        is_over_speed = st.config(dut,"redis-cli -n 6 hget {} is_over_speed".format(key))
        if('True' in is_over_speed):
            st.log("DUT {}, Fan {} is running over_speed".format(dut, key))
            return False
    return True


def check_fan_direction(dut, fan_keys):
    direction = ""
    for key in fan_keys[dut]:
        if("PSU" in key):
            continue
        else:
            fan_direction = st.config(dut,"redis-cli -n 6 hget {} direction".format(key))
            if(direction == ""):
                direction = fan_direction
            else:
                if(fan_direction != direction):
                    st.log("All fans on DUT {} don't have same direction".format(dut))
                    return False
    return True


def check_fan_led_status(dut, fan_keys):
    for key in fan_keys[dut]:
        if("PSU" in key):
            continue
        fan_led_status = st.config(dut,"redis-cli -n 6 hget {} led_status".format(key))
        if('green' not in fan_led_status):
            st.log("led_status is incorrect on some of the fans on dut {}".format(dut))
            return False
    return True


@pytest.mark.usefixtures('get_fan_keys')
class TestFanModule():

    def test_fan_presence(self, get_fan_keys):
        for dut in data.dut_list:
            if not check_fan_presence(dut, get_fan_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")


    def test_fan_speed(self, get_fan_keys):
        for dut in data.dut_list:
            if not check_fan_speeds(dut, get_fan_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")


    def test_fan_direction(self, get_fan_keys):
        for dut in data.dut_list:
            if not check_fan_direction(dut, get_fan_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")


    def test_fan_led_status(self, get_fan_keys):
        for dut in data.dut_list:
             if not check_fan_led_status(dut, get_fan_keys):
                 st.log("*************************************************************")
                 st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")
