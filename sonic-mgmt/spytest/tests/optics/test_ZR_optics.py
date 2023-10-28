import pytest
import random
from spytest import st, tgapi, SpyTestDict
import re, time,json
import apis.system.logging as logapi
import apis.routing.ip as ipapi
from tests.macsec.ZR_helper import get_asic_from_port,run_traffic,variables,frequency_dom,verify_int_stat


@pytest.fixture(scope="module", autouse=True)
def optics_module_hooks(request):
    global vars, ports, duts, local_links_D1, local_links_D2, tg1, tg2, tg_handle_1, tg_handle_2, asic_dut1, asic_dut2, dut1_port, dut2_port
    (tg1, tg2, tg_handle_1, tg_handle_2) = get_handles()
    vars = st.ensure_min_topology("D1T1:1","D1D2:1","D2T1:1")
    ports = {vars.D1:[vars.D1D2P1], vars.D2: [vars.D2D1P1]}
    duts = [vars.D1, vars.D2]
    dut1_port = vars.D1D2P1
    dut2_port = vars.D2D1P1
    local_links_D1=st.get_dut_links_local(vars.D1)
    local_links_D2=st.get_dut_links_local(vars.D2)
    asic_dut1=get_asic_from_port(dut1_port)
    asic_dut2=get_asic_from_port(dut2_port)
    st.config(vars.D1, "sudo config interface -n asic0 ip add {} 100.100.100.1/24".format(vars.D1T1P1))
    st.config(vars.D2, "sudo config interface -n asic0 ip add {} 200.200.200.1/24".format(vars.D2T1P1))
    yield
    st.config(vars.D1, "sudo config interface -n asic0 ip remove {} 100.100.100.1/24".format(vars.D1T1P1))
    st.config(vars.D2, "sudo config interface -n asic0 ip remove {} 200.200.200.1/24".format(vars.D2T1P1)) 



var = variables()
ZR_frequency = var.ZR_frequency
tx_power  = var.tx_power
ZR_negative_frequency = var.ZR_negative_frequency


def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

class Test_zr():
   def test_frequency_one_router(self):
            st.log("Configure frequency on one router and make sure interface is down")
            st.config(vars.D1, "sudo config interface -n asic"+str(asic_dut1)+" transceiver frequency " + dut1_port + " " + ZR_negative_frequency )
            time.sleep(15)
            if not verify_int_stat(vars.D1,dut1_port):
                st.log("Interface is not up")
                st.report_pass("test_case_passed")
                st.config(vars.D2, "sudo config interface -n asic"+str(asic_dut2)+" transceiver frequency " + dut2_port + " " + ZR_negative_frequency )
                time.sleep(60)
            else:
                st.report_fail("test_case_failed")
                st.config(vars.D2, "sudo config interface -n asic"+str(asic_dut2)+" transceiver frequency " + dut2_port + " " + ZR_negative_frequency )
                time.sleep(60)
 
   def test_frequency(self):
            test_fail=0
            st.log("configure frequency")
            for dut in duts:
                if dut==vars.D1:
                   namespace = str(get_asic_from_port(dut1_port))
                   dut_port = vars.D1D2P1
                else:
                   namespace = str(get_asic_from_port(dut2_port))
                   dut_port = vars.D2D1P1
                st.config(dut, "sudo config interface -n asic"+namespace+" transceiver frequency " + dut_port + " " + ZR_frequency )
                st.log("waiting for the interface to come up")
                time.sleep(60)
            if not verify_int_stat(dut,dut1_port):
                st.log("Interface is not up")
                test_fail+=1
            for dut in duts:
                if dut==vars.D1:
                   op = frequency_dom(vars.D1,asic_dut1,dut1_port,'laser_config_freq')
                   if op != ZR_frequency:
                       test_fail+=1
                else:
                   op = frequency_dom(vars.D2,asic_dut2,dut2_port,'laser_config_freq')
                   if op != ZR_frequency:
                       test_fail+=1
            if test_fail == 0:    
                st.report_pass("test_case_passed")
            else:
                st.report_fail("test_case_failed")

   def test_tx_power(self):
            st.log("Configure laser tx power")
            for dut in duts:
                if dut==vars.D1:
                    namespace = str(get_asic_from_port(dut1_port))
                    dut_port = vars.D1D2P1
                else:
                    namespace = str(get_asic_from_port(dut2_port))
                    dut_port = vars.D2D1P1

                st.config(dut, "sudo config interface -n asic"+namespace+" transceiver tx_power " + dut_port + " " + tx_power )
                time.sleep(5)
                op = frequency_dom(vars.D1,asic_dut1,dut1_port,'tx_config_power')
                if op == tx_power:
                    st.report_pass("test_case_passed")
            else:
                    st.report_pass("test_case_failed")

   def test_tx_power_one_router(self):
            st.log("Configure tx power and make sure interface is up")
            st.config(vars.D1, "sudo config interface -n asic"+str(asic_dut1)+" transceiver tx_power " + dut1_port + " " + tx_power )
            time.sleep(5)
            if verify_int_stat(vars.D1,dut1_port):
                st.log("Interface is up")
                st.report_pass("test_case_passed")
            else:
                st.report_fail("test_case_failed")
  
