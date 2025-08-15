import pytest
from spytest import st, SpyTestDict
import re

@pytest.fixture(scope="module", autouse=True)
def psu_module_hooks(request):
    global globalVars
    globalVars = st.get_testbed_vars()
    global data
    data = SpyTestDict()
    data.dut_list = [globalVars.D1, globalVars.D2]


@pytest.fixture(scope='class')
def get_psu_keys():
    psu_keys = {}
    for dut in data.dut_list:
        keys_output = st.config(dut, "redis-cli -n 6 keys PSU_INFO*")
        keys = re.findall(r'"PSU_INFO\|PSU [a-zA-Z0-9.]+"', keys_output)
        psu_keys[dut] = keys
    yield psu_keys


def check_psu_presence(dut, psu_keys):
    for key in psu_keys[dut]:
        psu_presence = st.config(dut,"redis-cli -n 6 hget {} presence".format(key))
        if('False' in psu_presence):
            st.log("Some PSU is missing on dut {}".format(dut))
            return False
    return True


def check_psu_status(dut, psu_keys):
    for key in psu_keys[dut]:
        psu_status = st.config(dut,"redis-cli -n 6 hget {} status".format(key))
        if('False' in psu_status):
            st.log("status is NOT OK for some of the PSUs on dut {}".format(dut))
            return False
    return True


def check_psu_led_status(dut, psu_keys):
    for key in psu_keys[dut]:
        psu_led_status = st.config(dut,"redis-cli -n 6 hget {} led_status".format(key))
        if('green' not in psu_led_status):
            st.log("led_status is incorrect on some of the PSUs on dut {}".format(dut))
            return False
    return True


def check_power_overload(dut, psu_keys):
    for key in psu_keys[dut]:
        psu_power_overload = st.config(dut,"redis-cli -n 6 hget {} power_overload".format(key))
        if('True' in psu_power_overload):
            st.log("power overload on one of the PSUs on dut {}".format(dut))
            return False
    return True


def check_psu_temperature_below_threshold(dut, psu_keys):
    for key in psu_keys[dut]:
        temp = st.config(dut,"redis-cli -n 6 hget {} temp".format(key))
        if('N/A' in temp):
            st.log("Temperature is N/A for one of the PSUs on dut {}".format(dut))
            return False
        temp_threshold = st.config(dut,"redis-cli -n 6 hget {} temp_threshold".format(key))
        if('N/A' in temp_threshold):
            st.log("Temperature threshold is N/A for one of the PSUs on dut {}".format(dut))
            return False
        if(temp > temp_threshold):
            st.log("Temperature is above threshold on one of the PSUs on dut {}".format(dut))
            return False
    return True

def check_psu_voltage_within_threshold(dut, psu_keys): 
    for key in psu_keys[dut]:
        voltage = st.config(dut,"redis-cli -n 6 hget {} voltage".format(key))
        if('N/A' in voltage):
            st.log("voltage is N/A for one of the PSUs on dut {}".format(dut))
            return False
        voltage_max = st.config(dut,"redis-cli -n 6 hget {} voltage_max_threshold".format(key))
        if('N/A' in voltage_max):
            st.log("voltage_max_threshold is N/A for one of the PSUs on dut {}".format(key))
            return False
        voltage_min = st.config(dut,"redis-cli -n 6 hget {} voltage_min_threshold".format(key))
        if('N/A' in voltage_min):
            st.log("voltage_min_threshold is N/A for one of the PSUs on dut {}".format(dut))
            return False
        if(voltage < voltage_min or voltage > voltage_max):
            st.log("voltage is not between minimum threshold and maximum threshold for one of the PSUs on dut {}".format(dut))
            return False
    return True


@pytest.mark.usefixtures('get_psu_keys')
class TestPSUModule():

    def test_psu_presence(self, get_psu_keys):
        for dut in data.dut_list:
            if not check_psu_presence(dut, get_psu_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")

    
    def test_psu_status(self, get_psu_keys):
        for dut in data.dut_list:
            if not check_psu_status(dut, get_psu_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")

    
    def test_psu_led_status(self, get_psu_keys):
        for dut in data.dut_list:
            if not check_psu_led_status(dut, get_psu_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")


    def test_power_overload(self, get_psu_keys):
        for dut in data.dut_list:
            if not check_power_overload(dut, get_psu_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")

    
    def test_psu_temperature(self, get_psu_keys):
        for dut in data.dut_list:
            if not check_psu_temperature_below_threshold(dut, get_psu_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")


    def test_psu_voltage(self, get_psu_keys):
        for dut in data.dut_list:
            if not check_psu_voltage_within_threshold(dut, get_psu_keys):
                st.log("*************************************************************")
                st.report_fail("test_case_failed")
        st.report_pass("test_case_passed")
