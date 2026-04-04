import pytest
from spytest import st
import apis.system.box_services as boxserv_obj

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:4",  "D1D4:4", "D2D3:4",  "D2D4:4")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

def test_ping_neighbor ():

    vars = st.get_testbed_vars()
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    for dut in dut_list:
        ipv6_nei = []
        ipv4_nei = []
        output = st.config(dut, "show lldp nei | grep -i mgmtip")
        output = output.encode('ascii','ignore')
        st.log("-------------------LLDP Neighbor IP ------------------", dut)
        for line in output.decode('utf8').split("\n"):
            line.rstrip()
            if "MgmtIP" in line:
                #print (line.split('IP:'))
                k= (line.split('IP:'))[1]  
                if "::" in k:
                    ipv6_nei.append(k)
                else:
                    ipv4_nei.append(k)
        st.log("-------------------LLDP Neighbor IP ------------------", dut)
           
        ipv4_nei = list(set(ipv4_nei))
        # Ping IPV4 Neighbor
        for ipv4 in ipv4_nei:
            v4_ping = 'ping -c 4 ' + ipv4
            v4_ping_output = st.config(dut, v4_ping)
            
            if " 0% packet loss" in str(v4_ping_output.encode('ascii','ignore')):
                st.log("Ping4 Sucessful", dut)
            else:
                st.log("Ping4 LLDP Failed, please check the connectivity",dut)
                st.error("Ipv4 Ping LLDP Failed",dut)
                st.report_fail("test_case_failed",dut)
            st.report_pass("test_case_passed",dut)

            # Ping IPV6 Neighbor  
        for ipv6 in ipv6_nei:
            v6_ping = 'ping -v6 -c 4 ' + ipv6
            v6_ping_output = st.config(dut, v6_ping)

            if " 0% packet loss" in str(v6_ping_output.encode('ascii','ignore')):
                st.log("Ping6 Sucessful", dut)
            else:
                st.log("Ping6 LLDP Failed, please check the connectivity",dut)
                st.error("Ipv6 Ping LLDP Failed",dut)
                st.report_fail("test_case_failed",dut)
            st.report_pass("test_case_passed",dut)       


def test_box_eth_setting():
    vars = st.get_testbed_vars()    
    
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    for dut in dut_list:
        cmd = "ifconfig eth0"
        cmd_output = st.config(dut, cmd)

        parsed_output = st.parse_show(dut, cmd, cmd_output, 'linux/ifconfig_eth.tmpl')
        for intf in parsed_output:
            if not intf['inet'] or not intf['inet6']:
                st.error("ifconfig eth0 does not contain inet or inet6", dut)
                st.report_fail("test_case_failed", dut)
            st.log("ifconfig eth0 contains inet {} and inet6 {}".format(intf['inet'], intf['inet6']), dut)
        st.report_pass("test_case_passed",dut)
