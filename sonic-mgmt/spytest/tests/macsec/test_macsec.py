import pytest
import random
from spytest import st, tgapi, SpyTestDict
import re, time
import apis.system.logging as logapi
import apis.routing.ip as ipapi
from tests.macsec.macsec_helper import get_asic_from_port, enable_macsec_feature, apply_profile, check_syslog, \
                                          run_traffic, config_portchannel, deconfig_portchannel, \
                                          is_container_running, restart_container, variables



@pytest.fixture(scope="module", autouse=True)
def macsec_module_hooks(request):
    global vars, ports, duts, local_links_D1, local_links_D2, tg1, tg2, tg_handle_1, tg_handle_2
    (tg1, tg2, tg_handle_1, tg_handle_2) = get_handles()
    vars = st.ensure_min_topology("D1T1:1","D1D2:2","D2T1:1")
    ports = {vars.D1:[vars.D1D2P1], vars.D2: [vars.D2D1P1]}
    duts = [vars.D1, vars.D2]
    local_links_D1=st.get_dut_links_local(vars.D1)
    local_links_D2=st.get_dut_links_local(vars.D2)
    global SESSION_KEYS, INTERFACE_KEYS
    SESSION_KEYS = SpyTestDict()
    INTERFACE_KEYS = SpyTestDict()
    st.config(vars.D1, "sudo config interface -n asic0 ip add {} 100.100.100.1/24".format(vars.D1T1P1))
    st.config(vars.D2, "sudo config interface -n asic0 ip add {} 200.200.200.1/24".format(vars.D2T1P1))
    yield
    st.config(vars.D1, "sudo config interface -n asic0 ip remove {} 100.100.100.1/24".format(vars.D1T1P1))
    st.config(vars.D2, "sudo config interface -n asic0 ip remove {} 200.200.200.1/24".format(vars.D2T1P1)) 


@pytest.fixture(scope='class')
def macsec_class_hook(request):
    subnet = re.search("\d+", str(ports[vars.D1])).group(0)
    request.config.subnet = subnet
    config_routes(vars.D1, vars.D2, vars.D1D2P1, vars.D2D1P1, request.config.subnet)
    yield
    # st.config(vars.D1, "sudo sonic-db-cli -n asic0 CONFIG_DB HSET 'PORT|Ethernet16' 'macsec' ' '")
    # st.config(vars.D2, "sudo sonic-db-cli -n asic0 CONFIG_DB HSET 'PORT|Ethernet16' 'macsec' ' '")
    # delete_macsec_config(ports)
    # delete_macsec_profile(request.config.encrypt)
    deconfig_routes(vars.D1, vars.D2, vars.D1D2P1, vars.D2D1P1, request.config.subnet)

def cleanup(request):
    delete_macsec_config(ports)
    delete_macsec_profile(request.config.encrypt)

var = variables()
MACSEC_PROFILE = var.MACSEC_PROFILE
MACSEC_REGEX = var.MACSEC_REGEX
# MACSEC_PROFILE= {"aes_128": "GCM-AES-128", "aes_256": "GCM-AES-256", "aes_xpn_128":"GCM-AES-XPN-128", "aes_xpn_256":"GCM-AES-XPN-256"}
# MACSEC_REGEX = "install_tx_sa:.*TxSA added and activated for port {}\|phy_install_tx_sa_on_hw:.*TX SA install on port: {}\|macsec_install_tx_sa: PhyID .*:Install Tx SA: idx: {}\|\
# install_rx_sa:.*RxSA added and activated for port {}\|phy_install_rx_sa_on_hw:.*RX SA install on port: {}\|macsec_install_rx_sa: PhyID .*:Install Rx SA: idx: {}"

def delete_macsec_profile(profile):
    for dut in duts:
        st.config(dut, "sudo config macsec -n asic0 profile del {}".format(profile))

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

def delete_macsec_config(ports, is_lag = False):
    for dut in duts:
        for port in ports[dut]:
            asic = get_asic_from_port(port) if is_lag is False else 0
            st.config(dut, "sudo sonic-db-cli -n asic{} CONFIG_DB HSET 'PORT|{}' 'macsec' ''".format(asic, port), skip_tmpl=True, skip_error_check=False)  

def macsec_session_test(encryption, request, toggle = False, check_syslogs = True, mismatch= False):
    '''Enable macsec feature, create macsec profile, apply macsec profile on interface, 
    validate macsec application and ping test between the b2b connected interfaces. Delete macsec config on D2 and verify ping failure'''
    #Enable macsec on the duts
    for dut in duts:  
        logapi.clear_logging(dut) 
        result = enable_macsec_feature(dut)
        if result is False:
            cleanup(request)
            st.report_fail("test_case_failed")

    ports = {vars.D1:[vars.D1D2P1], vars.D2: [vars.D2D1P1]}
    
    #Apply macsec profile on the interface
    try:
        apply_profile(duts, ports, encryption, "security")  
    except:
        cleanup(request)
        st.report_fail("test_case_failed")
    
    for port in ports[vars.D1]:
        if toggle is True: 
            asic =str(get_asic_from_port(port))
            command="sudo config interface -n asic{} {} {}"
            st.config(vars.D1, command.format(asic, "shutdown", port))
            st.wait(5)
            st.config(vars.D1, command.format(asic, "startup", port))
            st.wait(5)

    
    #Wait for logs to be generated
    st.wait(10)

    # #Check for syslogs
    # if check_syslogs:
    #     for dut in duts:
    #         for port in ports[dut]:
    #             result = check_syslog(dut, port, MACSEC_REGEX)
    #             if mismatch is False:
    #                 if result is False: 
    #                     cleanup(request)
    #                     st.report_fail("test_case_failed")
    for dut in duts:
        for port in ports[dut]:
            #Validate macsec session
            session_validation(dut, port, MACSEC_PROFILE[encryption], request)   
            SESSION_KEYS["{}".format(dut)] = INTERFACE_KEYS

    for port1, port2 in zip(ports[vars.D1], ports[vars.D2]):
        #Compare ingress and egress keys on back to back interfaces     
        if SESSION_KEYS['D1'][port1]["i_auth_key"] != SESSION_KEYS['D2'][port2]["i_auth_key"] or SESSION_KEYS['D1'][port1]["e_auth_key"] != SESSION_KEYS['D2'][port2]["e_auth_key"]:
            st.error("Auth key on both devices does not match")
            cleanup(request)
            st.report_fail("test_case_failed")
        if SESSION_KEYS['D1'][port1]["e_sak"] != SESSION_KEYS['D2'][port2]["e_sak"] or SESSION_KEYS['D1'][port1]["i_sak"] != SESSION_KEYS['D2'][port2]["i_sak"]:
            st.error("SAK on both devices does not match")
            cleanup(request)
            st.report_fail("test_case_failed")
        if SESSION_KEYS['D1'][port1]["e_salt"] != SESSION_KEYS['D2'][port2]["e_salt"] or SESSION_KEYS['D1'][port1]["i_salt"] != SESSION_KEYS['D2'][port2]["i_salt"]:
            st.error("SALT on both devices does not match")
            cleanup(request)
            st.report_fail("test_case_failed")

    if not run_traffic(request):  
        st.error("Failed to send traffic across the LCs")
        cleanup(request)
        st.report_fail("test_case_failed")
    
    else:
        cleanup(request)
        st.report_pass("test_case_passed")

def session_validation(dut, port, cipher, request, is_lag = False):
    asic = get_asic_from_port(port) if is_lag is False else 0
    cmd_output = st.config(dut, "show macsec -n asic{} {}".format(asic, port), skip_tmpl=True, skip_error_check=False)
    
    output = cmd_output.split("\n")
    if len(output) == 0:
        st.error("Show macsec output returning nothing")
        cleanup(request)
        st.report_fail("test_case_failed")
    if output[0].find(port) == -1:
        st.error("Interface {} not showing up in show macsec on asic{} {}".format(port, asic, output[1]))
        cleanup(request)
        st.report_fail("test_case_failed")
    if output[2].find(cipher) == -1:
        st.error("Cipher for interface {} in show macsec on asic{} does not match with the configuration {}".format(port, asic, output[3]))
        cleanup(request)
        st.report_fail("test_case_failed")
    if output[4].find("true") == -1:
        st.error("enable_encrypt for interface {} in show macsec on asic{} should be true {}".format(port, asic, output[5]))
        cleanup(request)
        st.report_fail("test_case_failed")
    if output[5].find("true") == -1:
        st.error("enable_protect for interface {} in show macsec on asic{} should be true {}".format(port, asic, output[6]))
        cleanup(request)
        st.report_fail("test_case_failed")
    cmd_output = cmd_output.encode('ascii','ignore')
    
    authkey = re.search(r"MACsec Egress SA \(\d\).*?auth_key\s+([A-F0-9]+)", cmd_output, re.DOTALL)
    sak = re.search(r"MACsec Egress SA \(\d\).*?sak\s+([A-F0-9]+)", cmd_output, re.DOTALL)
    salt = re.search(r"MACsec Egress SA \(\d\).*?salt\s+([A-F0-9]+)", cmd_output, re.DOTALL)
    
    if authkey and sak and salt:
        egress_auth = authkey.group(1)
        egress_sak = sak.group(1)
        egress_salt = salt.group(1)
    
    i_auth = re.search(r"MACsec Ingress SA \(\d\).*?auth_key\s+([A-F0-9]+)", cmd_output, re.DOTALL)
    i_sak = re.search(r"MACsec Ingress SA \(\d\).*?sak\s+([A-F0-9]+)", cmd_output, re.DOTALL)
    i_salt = re.search(r"MACsec Ingress SA \(\d\).*?salt\s+([A-F0-9]+)", cmd_output, re.DOTALL)
    
    if i_auth and i_sak and i_salt:
        ingress_auth= i_auth.group(1)
        ingress_sak = i_sak.group(1)
        ingress_salt = i_salt.group(1)
    
    time.sleep(2)
    INTERFACE_KEYS["{}".format(port)] = {"e_auth_key": egress_auth, "e_sak": egress_sak, "e_salt": egress_salt, "i_auth_key": ingress_auth, "i_sak": ingress_sak, "i_salt": ingress_salt}
    st.log("Interface keys updated to {}".format(INTERFACE_KEYS))

def config_routes(dut1, dut2, d1_link, d2_link, subnet, is_lag = False):
    ''' Applies IP on the b2b links and checks bidirectional ping'''
    d1_asic = get_asic_from_port(d1_link) if is_lag is False else 0
    d2_asic = get_asic_from_port(d2_link) if is_lag is False else 0
    
    st.config(dut1, "sudo config interface -n asic{} ip add {} 10.10.{}.1/24".format(d1_asic, d1_link, subnet))
    
    st.config(dut2, "sudo config interface -n asic{} ip add {} 10.10.{}.2/24".format(d2_asic, d2_link, subnet))                                                      
    
    st.config(vars.D1, "sudo ip netns exec asic0 config route add prefix 200.200.200.0/24 nexthop 10.10.{}.2".format(subnet))


def deconfig_routes(dut1, dut2, d1_link, d2_link, subnet, is_lag = False):
    d1_asic = get_asic_from_port(d1_link) if is_lag is False else 0
    d2_asic = get_asic_from_port(d2_link) if is_lag is False else 0
    if is_lag is False:
        # This is a temporary workaround to address MIGSOFTWAR-9488
        st.config(vars.D1, "sudo ip netns exec asic0 config route del prefix 200.200.200.0/24")
        #st.config(vars.D1, "sudo ip netns exec asic0 config route del prefix 200.200.200.0/24 nexthop 10.10.{}.2".format(subnet))
    else:
        st.config(vars.D1, "sudo ip netns exec asic0 config route del prefix 200.200.200.0/24")
    st.wait(5)
    st.config(dut1, "sudo config interface -n asic{} ip remove {} 10.10.{}.1/24".format(d1_asic, d1_link, subnet))
    st.config(dut2, "sudo config interface -n asic{} ip remove {} 10.10.{}.2/24".format(d2_asic, d2_link, subnet)) 

def process_status(dut, container_name, asic,prs_name):
    cmd = "docker exec {}{} supervisorctl status {}".format(container_name, asic,prs_name)
    output = st.config(dut, cmd)
    if re.search("\S+\s+RUNNING", output):
        st.log("the process {} is running in the container {}".format(prs_name, container_name))
        return True
    else:
        st.log("the process {} is not running in the container {}".format(prs_name, container_name))
        return False

def restart_process(dut, container_name, asic, prs_name):
    cmd = "docker exec {}{} supervisorctl restart {}".format(container_name, asic, prs_name)
    result = st.config(dut, cmd)
    st.log("result for process restart {} is {}".format(cmd, result))
    st.wait(100)

def generic_process_restart(container_name, prs_name, request, encryption="aes_128"):
    # Enable macsec on the duts
    for dut in duts:
        logapi.clear_logging(dut)
        result = enable_macsec_feature(dut)
        if result is False:
            cleanup(request)
            st.report_fail("test_case_failed")

    dut1_port = vars.D1D2P1
    dut2_port = vars.D2D1P1
    asic1 = get_asic_from_port(dut1_port)
    ports = {vars.D1: [dut1_port], vars.D2: [dut2_port]}

    # Apply macsec profile on the interface
    apply_profile(duts, ports, encryption, "security")
    #st.config(dut, "config save -y")

    # Wait for session to start
    st.wait(20)
    # Validate macsec session
    for dut in duts:
        for port in ports[dut]:
            session_validation(dut, port, MACSEC_PROFILE[encryption], request)

    if process_status(vars.D1, container_name, 0, prs_name):
        restart_process(vars.D1, container_name, 0, prs_name)
        if process_status(vars.D1, container_name, 0, prs_name):
            # Validate macsec session
            for dut in duts:
                for port in ports[dut]:
                    session_validation(dut, port, MACSEC_PROFILE[encryption],  request)
            subnet = re.search("\d+", str(ports[vars.D1])).group(0)
            config_routes(vars.D1, vars.D2, ports[vars.D1][0], ports[vars.D2][0], subnet)
            if run_traffic(request):
                delete_macsec_config(ports)
                delete_macsec_profile(encryption)
                deconfig_routes(vars.D1, vars.D2, ports[vars.D1][0], ports[vars.D2][0], subnet)
                st.report_pass("test_case_passed")
            else:
                delete_macsec_config(ports)
                delete_macsec_profile(encryption)
                deconfig_routes(vars.D1, vars.D2, ports[vars.D1][0], ports[vars.D2][0], subnet)
                st.error("Failed to send traffic across the LCs")
                st.report_fail("test_case_failed")
        else:
            st.error("Test case failed because container {} is not running".format(container_name))
            
            st.report_fail("test_case_failed")

def generic_container_restart(container_name, request, encryption = "aes_128"):
    #Enable macsec on the duts
    for dut in duts:  
        logapi.clear_logging(dut) 
        result = enable_macsec_feature(dut)
        if result is False:
            cleanup(request)
            st.report_fail("test_case_failed")

    dut1_port = vars.D1D2P1
    dut2_port = vars.D2D1P1
    asic1 = get_asic_from_port(dut1_port)
    ports = {vars.D1:[dut1_port], vars.D2:[dut2_port]}

    #Apply macsec profile on the interface
    apply_profile(duts, ports, encryption, "security")  
    #st.config(dut, "config save -y")

    #Wait for session to start
    st.wait(20)

    #Validate macsec session
    for dut in duts: 
        for port in ports[dut]:
            session_validation(dut, port, MACSEC_PROFILE[encryption], request)   
    
    if is_container_running(vars.D1, container_name, asic1):
        restart_container(vars.D1, container_name, asic1)
        if is_container_running(vars.D1, container_name, asic1):
            #Validate macsec session
            for dut in duts: 
                for port in ports[dut]:
                    session_validation(dut, port, MACSEC_PROFILE[encryption], request) 
            subnet = re.search("\d+", str(ports[vars.D1])).group(0)
            config_routes(vars.D1, vars.D2, ports[vars.D1][0], ports[vars.D2][0], subnet)
            if run_traffic(request):  
                cleanup(request)
                st.report_pass("test_case_passed")
            else:
                cleanup(request)
                st.error("Failed to send traffic across the LCs")
                st.report_fail("test_case_failed")
        else:
            st.error("Test case failed because container {} is not running".format(container_name))
            st.report_fail("test_case_failed")

@pytest.mark.usefixtures('macsec_class_hook')
class TestMacSec():
    def test_macsec_session_aes_128(self, request):
        encryption = "aes_128"
        request.config.encrypt = encryption
        macsec_session_test(encryption, request)

    def test_macsec_session_toggle(self, request):
        encryption = "aes_128"
        request.config.encrypt = encryption
        macsec_session_test(encryption, request, toggle = True)

    def test_macsec_session_aes_256(self, request):
        encryption = "aes_256"
        request.config.encrypt = encryption
        macsec_session_test(encryption, request)

    def test_macsec_session_aes_xpn_128(self, request):
        encryption = "aes_xpn_128"
        request.config.encrypt = encryption
        macsec_session_test(encryption, request)

    def test_macsec_session_aes_xpn_256(self, request):
        encryption = "aes_xpn_256"
        request.config.encrypt = encryption
        macsec_session_test(encryption, request)

    def test_macsec_key_mismatch(self, request):
        encryption = "aes_xpn_256"
        request.config.encrypt = encryption
        macsec_session_test(encryption, request, mismatch = True)
    
    def test_swss_container_restart(self, request):
        encryption = "aes_128"
        request.config.encrypt = encryption
        generic_container_restart("swss", request, encryption)

    def test_syncd_container_restart(self, request):
        encryption = "aes_128"
        request.config.encrypt = encryption
        generic_container_restart("syncd", request, encryption)

    def test_gbsyncd_container_restart(self, request):
        encryption = "aes_128"
        request.config.encrypt = encryption
        generic_container_restart("gbsyncd", request, encryption)

    def test_macsec_container_restart(self, request):
        encryption = "aes_128"
        request.config.encrypt = encryption
        generic_container_restart("macsec", request, encryption)
                                                            
# def test_portchannel_macsec(request):
#     for dut in duts:  
#         result = enable_macsec_feature(dut)
#         if result is False:
            
#             st.report_fail("test_case_failed")
#     #Apply macsec profile on the interface
#     ports = {vars.D1: [vars.D1D2P1, vars.D1D2P2], vars.D2: [vars.D2D1P1, vars.D2D1P2]}
#     apply_profile(duts, ports, "aes_128", "security", is_lag = True)  
    
#     st.wait(7)
#     for dut in duts: 
#         for port in ports[dut]:
#             session_validation(dut, port, MACSEC_PROFILE["aes_128"], request, is_lag = True)   

#     config_portchannel()
#     config_routes(vars.D1, vars.D2, "PortChannel24", "PortChannel24", 2, is_lag = True)
#     if not run_traffic(request):
#         delete_macsec_config(ports, is_lag = True)
#         deconfig_routes(vars.D1, vars.D2, "PortChannel24", "PortChannel24", 2, is_lag = True)
#         deconfig_portchannel()
#         delete_macsec_config(ports)
#         delete_macsec_profile("aes_128")
#         st.error("Failed to send traffic across the LCs")
        
#         st.report_fail("test_case_failed")
#     else:
#         delete_macsec_config(ports, is_lag = True)
#         deconfig_routes(vars.D1, vars.D2, "PortChannel24", "PortChannel24", 2, is_lag = True)
#         deconfig_portchannel()
#         delete_macsec_config(ports)
#         delete_macsec_profile("aes_128")
#         st.report_pass("test_case_passed")


# def test_scale_macsec(request):
#     for dut in duts:  
#         logapi.clear_logging(dut) 
#         result = enable_macsec_feature(dut)
#         if result is False:
            
#             st.report_fail("test_case_failed")
#     ports = {vars.D1: local_links_D1, vars.D2: local_links_D2}
#     apply_profile(duts, ports, "aes_128", "security")  
#     st.log("Wait for the macsec sessions to come up")
#     st.wait(7)
#     for dut in duts:
#         for port in ports[dut]:
#             result = check_syslog(dut, port, MACSEC_REGEX)
#             if result is False: 
                
#                 st.report_fail("test_case_failed")
#             session_validation(dut, port, MACSEC_PROFILE["aes_128"], request)  
#             SESSION_KEYS["{}".format(dut)] = INTERFACE_KEYS
#     for port1, port2 in zip(ports[vars.D1], ports[vars.D2]):
#         #Compare ingress and egress keys on back to back interfaces     
#         if SESSION_KEYS['D1'][port1]["i_auth_key"] != SESSION_KEYS['D2'][port2]["i_auth_key"] or SESSION_KEYS['D1'][port1]["e_auth_key"] != SESSION_KEYS['D2'][port2]["e_auth_key"]:
#             st.error("Auth key on both devices does not match")
            
#             st.report_fail("test_case_failed")
#         if SESSION_KEYS['D1'][port1]["e_sak"] != SESSION_KEYS['D2'][port2]["e_sak"] or SESSION_KEYS['D1'][port1]["i_sak"] != SESSION_KEYS['D2'][port2]["i_sak"]:
#             st.error("SAK on both devices does not match")
            
#             st.report_fail("test_case_failed")
#         if SESSION_KEYS['D1'][port1]["e_salt"] != SESSION_KEYS['D2'][port2]["e_salt"] or SESSION_KEYS['D1'][port1]["i_salt"] != SESSION_KEYS['D2'][port2]["i_salt"]:
#             st.error("SALT on both devices does not match")
            
#             st.report_fail("test_case_failed")
#         subnet = re.search("\d+", str(port1)).group(0)
#         config_routes(vars.D1, vars.D2, port1, port2, subnet)
#         if not run_traffic(request):  
#             delete_macsec_config(ports)
#             delete_macsec_profile("aes_128")
#             deconfig_routes(vars.D1, vars.D2, port1, port2, subnet)
#             st.error("Failed to send traffic across the LCs")
#             st.report_fail("test_case_failed")
#         else:
#             #Delete_config_on_duts
#             delete_macsec_config(ports)
#             delete_macsec_profile("aes_128")
#             deconfig_routes(vars.D1, vars.D2, port1, port2, subnet)
#             st.report_pass("test_case_passed")
