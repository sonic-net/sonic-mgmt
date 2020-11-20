import pytest
from spytest import st
import apis.switching.pvst as stp
import apis.switching.pvst_elasticity_wrapper as stp_wrap
import apis.switching.portchannel as portchannel
import apis.switching.vlan as vlan
import lib_stp as lib_stp

vars = dict()
stp_protocol = "rpvst"
max_stp_instances = 64

@pytest.fixture(scope="module", autouse=True)
def rpvst_elastic_module_hooks(request):
    global vars
    global stp_ela
    try:
        vars = st.ensure_min_topology("D1D2:3", "D2D3:3", "D1D3:3")
        lib_stp.init_cli_type()
        stp_ela = stp_wrap.apply_and_verify_module_config(vars, stp_protocol)
        st.log(stp_ela)
    except Exception as e:
        st.log(e)
        st.report_fail("exception", e)
    lib_stp.config_max_age_and_edge_port(vars, stp_ela, stp_protocol)

    yield
    dut_list = stp_wrap.get_dut_list(vars)
    stp.config_stp_in_parallel(dut_list, feature=stp_protocol, mode="disable")
    vlan.clear_vlan_configuration(dut_list)
    portchannel.clear_portchannel_configuration(dut_list)
    stp_wrap.complete_data.clear()

@pytest.fixture(scope="function", autouse=True)
def rpvst_elastic_function_hooks(request):
    if not stp_ela:
        st.log("{} MODULE DATA CHECK FAILED".format(stp_protocol))
        st.report_fail("feature_module_data_check_failed",stp_protocol)
    if not stp_wrap.complete_data:
        st.log("{} MODULE CONFIG DATA NOT FOUND".format(stp_protocol))
        st.report_fail("feature_module_config_data_not_found",stp_protocol)
    if not stp_wrap.tg_info:
        st.log("TG INFO OBJECT NOT FOUND")
        st.report_fail("tg_object_not_found")
    yield

def test_ft_rpvst_stress_stp_disable_enable():
    if lib_stp.lib_stp_stress_stp_disable_enable(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_stress_bridge_priority():
    if lib_stp.lib_stp_stress_bridge_priority(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_stress_lag_shut_noshut():
    if lib_stp.lib_stp_stress_lag_shut_noshut(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_stress_shut_noshut():
    if lib_stp.lib_stp_stress_shut_noshut(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_general_verification():
    if lib_stp.lib_stp_general_verification(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_port_actions():
    if lib_stp.lib_stp_port_actions(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_portchannel():
    if lib_stp.lib_stp_portchannel(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_traffic():
    if lib_stp.lib_stp_traffic(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_cost_priority():
    if lib_stp.lib_stp_cost_priority(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_minlink_lldp():
    if lib_stp.lib_stp_minlink_lldp(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_rootswitch_trigger():
    if lib_stp.lib_stp_rootswitch_trigger(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_save_reload():
    if lib_stp.lib_stp_save_reload(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_config_reload():
    if lib_stp.lib_stp_config_reload(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_fast_reboot():
    if lib_stp.lib_stp_fast_reboot(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_timers():
    if lib_stp.lib_stp_timers(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')
      
def test_ft_rpvst_bpdu_filter():
    if lib_stp.lib_stp_bpdu_filter(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_default_convergence():
    if lib_stp.lib_stp_default_convergence(vars, stp_ela, stp_protocol):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rpvst_max_vlan_instances():
    if lib_stp.lib_stp_max_vlan_instances(vars, stp_ela, stp_protocol, max_stp_instances):
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')

def test_ft_rest_rpvst():
    if lib_stp.lib_stp_rest(vars, stp_protocol):
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def test_ft_gnmi_rpvst():
    if lib_stp.lib_stp_gnmi(vars, stp_protocol, stp_ela):
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')