import pytest
from spytest import st
import apis.system.box_services as boxserv_obj

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
#    vars = st.ensure_min_topology("D1","D2","D3","D4")
#    dut_list = [vars.D1, vars.D2, vars.D3, varsD4]
    vars = st.ensure_min_topology("D1D2:1", "D1D3:1", "D1D4:1")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

def ping_neighbor (_hostname):

 #   sonic.sendline('show lldp nei | grep -i mgmtip')
 #   sonic.expect('\$')
    
    global ipv6_nei , ipv4_nei
    ipv6_nei = []
    ipv4_nei = []
    st.log("-------------------", _hostname, "LLDP Neighbor IP ------------------")
    for line in sonic.before.decode('utf8').split("\n"):
        line.rstrip()
        if "MgmtIP" in line:
            #print (line.split('IP:'))
            k= (line.split('IP:'))[1]  
            if "::" in k:
                ipv6_nei.append(k)
            else:
                ipv4_nei.append(k)
    st.log("-------------------", _hostname, "LLDP Neighbor IP ------------------")
    
    ipv4_nei = list(set(ipv4_nei))
    # Ping IPV4 Neighbor
    for ipv4 in ipv4_nei:
        sonic.sendline('ping -c 4 ' + ipv4)
       
        if not sonic.expect_exact('0% packet loss'):
            st.log('Ping4', ipv4.strip(), ' Sucessful')
            _result = "Passed"
        else:
            st.log("Ping4 Failed, please check the connectivity")
            st.report_fail("Ping4 failed",vars.D1)
            
            _result="Failed"
        st.report_pass("IPV4 Ping test_case_passed")

    # Ping IPV6 Neighbor  
    for ipv6 in ipv6_nei:
        sonic.sendline('ping -v6 -c 4 ' + ipv6)
        
        if not sonic.expect_exact('0% packet loss'):
            st.log('Ping6', ipv4.strip(), ' Sucessful')
            _result = "Passed"
        else:
            st.log("Ping6 Failed,please check the connectivity")
            st.report_fail("Ping6 failed",vars.D1)
            _result = "Failed"
        st.report_pass("IPV6 Ping test_case_passed")

def check_ping (_output):
    #_output.rstrip()
    if "0% packet loss" in _output:
        st.log("Ping Sucessful")
    else:
        st.log("Ping Failed,please check the connectivity")

def test_box_ping():
    vars = st.get_testbed_vars()    
    #output=st.config(vars.D1, "whoami") 
    #dut_list = [vars.D1, vars.D2, vars.D3]
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    for dut in dut_list:
        output=st.config(dut, "ifconfig eth0") 
        output=output.encode('ascii','ignore') 
    #st.log("whoami output is {}".format(output))
    #st.log("Ping Test")
    #if uptime_after_1min<=sys_uptime<=uptime_after_1min+60:
    #    st.log("System Uptime is getting updated with correct value")
    #else:
    #    st.report_fail("sytem_uptime_fail",vars.D1)
        if "192" in str(output): 
        #st.log("whoami is root")
            st.log("ifconfig contain 192",dut)
        else:
            st.error("Failed ifconfig eth0",dut)
        #st.report_fail("whoami NOT root",vars.D1)
            st.report_fail("eth0 doesn't has 192",dut)
        st.report_pass("test_case_passed",dut)

