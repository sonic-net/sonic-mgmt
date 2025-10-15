import os
import yaml
import pytest
from spytest import st, tgapi
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
from spytest.tgen.tg import tgen_obj_dict
import vxlan_helper as vxlan_obj
from spytest.utils import poll_wait
from spytest.tgen import tg

@pytest.fixture(scope="module", autouse=True)
def initialize_variables(request):
    global vars, nodes, tgen_handles, test_cfg, CONFIGS_FILE

    vars = st.ensure_min_topology("D2T1:1")
    test_cfg = {'testcases': {'TC1': {'key1': 'val1'}}}
    st.log('In initialize_variables')

@pytest.fixture(scope="class")
def configure_test(request):

    st.log('In configure_test')
    "2025-04-16 15:24:30,767 T0000: ERROR TG API Fatal Error: ERROR in ::ixia::test_control: Failed to start Protocols !!!"
    dbg_msg = "ERROR in ::ixia::test_control: Failed to start Protocols !!!"
    msgid = "tgen_failed_start_protocols"
    msgid = "tgen_failed_abort"
    tg.tgen_abort(dbg_msg, msgid)

@pytest.fixture(scope="class")
def tgen_recovery(request):

    st.log('In tgen_recovery')
    yield
    st.log('Back In tgen_recovery')
    from spytest import framework
    res, desc = framework.get_current_result('module')
    st.log('Current Module Result: {} Desc: {}'.format(res, desc))
    framework.set_current_result(res=None, scope='module')
    res, desc = framework.get_current_result('module')
    st.log('New Module Result set: {} Desc: {}'.format(res, desc))
    st.log(st.getwa().abort_module_msg)
    st.log(st.getwa().abort_module_res)
    st.getwa().abort_module_msg = None
    st.getwa().abort_module_res = None

@pytest.fixture(scope="class")
def configure_test2(request):

    st.log('In configure_test2')
    yield
    st.log('Back In configure_test2')
    
@pytest.fixture(scope = "function", autouse=True)
def pretest():
    st.log('In pretest')
    yield
    st.log('Back In pretest')

@pytest.mark.usefixtures("tgen_recovery", "configure_test")
class TestPytest():
    
    def test_tc1(self, cleanup_tc1):
        st.banner('In TC1')
        test_cfg['testcases']['TC1']['cfg'] = "test"

        report_result(True, 'TC1')
    
    @pytest.fixture
    def cleanup_tc1(self):
        st.log('In cleanup_tc1')
        yield
        st.log('Back In cleanup_tc1')

    def test_tc2(request):
        st.banner('In TC2')
        report_result(True, 'TC2')

@pytest.mark.usefixtures("tgen_recovery", "configure_test2")
class TestPytest2():
    
    def test_tc21(self, cleanup_tc21):
        st.banner('In TC21')

        report_result(True, 'TC21')
    
    @pytest.fixture
    def cleanup_tc21(self):
        st.log('In cleanup_tc21')
        yield
        st.log('Back In cleanup_tc21')

    def test_tc22(request):
        st.banner('In TC22')
        report_result(True, 'TC22')

def report_result(result, tc_id='', rc_msg=''):
    if result:
        st.banner('Testcase: {} :: Result: Pass'.format(tc_id))
        st.report_pass('test_case_passed')
    else:
        st.banner('Testcase: {} :: Result: Fail'.format(tc_id))
        st.banner('Testcase: {} :: Diags: {}'.format(tc_id, rc_msg))
        st.report_fail("test_case_failed")
        #st.report_tgen_fail('start protocols failed!')


