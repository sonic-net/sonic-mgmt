''' This script is for testing DPB CLI testing on Tortuga platforms. 
    Test Topology:

          --------    ---------
          |      |----|       |
          | DUT1 |----| DUT2  |
          --------    ---------

    Test Cases: 
        Group 1: DPB SpeedChange/Breakout : Check Links, Disable DPB, Enable DPB
        Group 2: Test_reload: Reload testing (3 test cases)                 
''' 
import pytest
import json
import re, time, os
from os.path import join, split,normpath
from spytest import st,tgapi
from spytest.dicts import SpyTestDict
from apis.system.basic import get_docker_ps, get_and_match_docker_count, get_hwsku,verify_docker_status
from utilities.common import poll_wait
import apis.system.interface as intapi
import apis.system.port as papi  

@pytest.fixture(scope="module", autouse=True)
def optics_module_hooks(request):
    global globalVars
    globalVars = st.get_testbed_vars()
    global data
    data = SpyTestDict()

    initialize_data() 

    data.dut_list = [globalVars.D1, globalVars.D2]  
    data.username = st.get_username(globalVars.D1)
    data.password = st.get_password(globalVars.D1)
    data.ssh_port = "22"
    data.destination_path = "/home/cisco"
    data.dut_mgmt_list=[data.lc0_mgmt_ip,data.lc1_mgmt_ip] 
    data.key_devices = [globalVars.D1,globalVars.D2]
    data.allDUTs = [globalVars.D1,globalVars.D2]
    data.DUTs = [globalVars.D1,globalVars.D2]
    data.lc_name_list = [globalVars.D1,globalVars.D2]
    data.corresponding_mgmt_ip_to_dut_name = {}
    data.corresponding_dut_name_to_mgmt_ip = {}
    for dut in data.dut_list:
        mgmt_ip = st.get_mgmt_ip(dut)
        data.corresponding_mgmt_ip_to_dut_name[dut]=mgmt_ip
        data.corresponding_dut_name_to_mgmt_ip[mgmt_ip] = dut
    data.slot_name = {}
    data.slot_name[globalVars.D1] = 0
    data.slot_name[globalVars.D2] = 3  
    data.expected_down_dockers = ['sflow','nat']
    #To ensure all connections are up in our topology
    st.ensure_min_topology("D1T1:1","D1D2:1","D2T1:1")
    #Interface between D1(LC0) & T1
    data.d1t1_ip_addr="200.200.1.1"
    #Interface between TGEN & D1(LC0)
    data.t1d1_ip_addr="200.200.1.2"
    #Interface between TGEN & D2(LC3) 
    data.t1d2_ip_addr="200.100.1.2"
    #Interface between D2(LC3) & TGEN
    data.d2t1_ip_addr="200.100.1.1"
    #Setting subnetmask to /24
    data.mask="24"
    data.dut_asn_list={dut1:"65100",dut2:"65103"} 
    #TGEN Port1 AS number
    data.tgen1_asn = "65200"
    #TGEN Port2 AS Number
    data.tgen2_asn = "65203"
    data.pc1 =  "PortChannel152" 
    global tg1,tg2, tg_handle_1, tg_handle_2 
    (tg1,tg2, tg_handle_1, tg_handle_2) = get_handles()
    st.log("Clear interface counters") 
    papi.clear_interface_counters(globalVars.D1)
    papi.clear_interface_counters(globalVars.D2)
    yield 
    tg1.clean_all()
    tg2.clean_all() 
    st.report_pass("test_case_passed")

def initialize_data():
    global dut1, dut2, local_links_dut1, local_links_dut2, no_local_links
    platform_type=get_platform()
    print("Platform type: "+platform_type)
    dut1 = data.dut_list[0]
    dut2 = data.dut_list[1]
    local_links_dut1=st.get_dut_links_local(dut1)
    local_links_dut2=st.get_dut_links_local(dut2)
    global cli_type 
    cli_type='click' 
    no_local_links=len(local_links_dut1)
    data.local_links_info={}
    tgen_ports=[]
    for k,v in globalVars.items():
        if v in local_links_dut1 or v in local_links_dut2:
            data.local_links_info[k]={'name':v}
        elif re.search('T[1|2]D[1|2]P1',k) or re.search('D[1|2]T[1|2]P1',k):
            tgen_ports.append(k)
    for port in tgen_ports:
        for i in range(len(local_links_dut1)):
            key=port.split('P')[0]+'P'+str(i+1)
            data.local_links_info[key]={'name': port}
    data.local = None
    data.remote = None
    data.mask = "24"
    data.mask_v6 = "64"
    data.counters_threshold = 10
    data.tgen_stats_threshold = 20
    data.tgen_rate_pps = '1000'
    data.tgen_l3_len = '500'
    data.traffic_run_time = 20
    data.clear_parallel = True

def get_platform():
    global globalVars, data, cli_type, is_sfd_system
    global rp_list, lc_list
    globalVars =st.get_testbed_vars()
    data = SpyTestDict()
    data.dut_list = st.get_dut_names()
    rp_list = []
    lc_list = []
    for plat in globalVars.hwsku:
        print(plat)
        if 'rp' in globalVars.hwsku[plat].lower():
            rp_list.append(plat)
        elif 'lc' in globalVars.hwsku[plat].lower():
            lc_list.append(plat)
    if rp_list == [] and lc_list == []:
        is_sfd_system=False
        lc_list=data.dut_list
        rp_list=data.dut_list
        return "Non-SF-D"
    else:
        is_sfd_system=True
        return "SF-D"

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

def dpb_device_prechecks(dut, links):
    linkup_count = 0
    lldp_count = 0
    num_breakout_ports = 0
    num_breakout_sub_ports = 0
    total_ports = 0
    speed_change_port = 0
    command = "sudo show interfaces status"
    show_int_result=st.show(dut, command)
    for output_line in show_int_result:
        output_port = output_line['interface']
        # Only care about port that connect to current DUT
        if output_port in links:
            # Either oper or admin status 'down' means link down
            # for SONiC OS, oper/admin status could only be up/down, so only 2 conditions here
            if 'up' in output_line['oper']:
                linkup_count += 1 
    s1 = st.config(dut,"sudo show interfaces breakout")
    lines = s1.strip().split("\n")
    lines = lines[:-1]
    s2 = '\n'.join(lines)
    def_mode = json.loads(s2)
    show_breakout = st.config(dut,'sudo show lldp table')
    lines = show_breakout.strip().split("\n")
    for line in lines:
        if not line.startswith("Total entries"):
            continue
        columns = line.split(':')
        lldp_count = columns[1].strip(' ')
        lldp_count.lstrip(' ')
        print(lldp_count)
    command = "sudo show interface breakout current-mode"
    show_breakout = st.config(dut, "sudo show interface breakout current-mode")
    lines = show_breakout.strip().split("\n")
    dpb = {}
    for line in lines:
        # Skip lines that are not part of the data rows
        if not line.startswith("| Ethernet"):
            continue
        # Split the line into columns
        columns = line.split("|")
        interface = columns[1].strip()
        breakout_mode = columns[2].strip()
        total_ports += 1
        ports = breakout_mode.split("x")
        # Check if the breakout mode is "1x400G"
        if breakout_mode != def_mode[interface]['default_brkout_mode']:
            dpb[interface] = breakout_mode
            sub_port = ports[0].strip()
            if int(sub_port) > 1: 
                num_breakout_ports += 1
                num_breakout_sub_ports += int(sub_port)
            else:
                speed_change_port += 1
    if ((linkup_count+1) == (total_ports - num_breakout_ports + num_breakout_sub_ports) and lldp_count == linkup_count+1):
        print("DPB Precheck complete Total Ports {} Breakout Ports {} Speed_change ports {} LLDP {}\n".format(total_ports, num_breakout_ports, speed_change_port, lldp_count))
        return linkup_count,dpb,def_mode
    else:
        return 0,dpb,def_mode

def enable_links(dut, links):
    command = "sudo show interfaces status"
    show_int_result=st.show(dut, command)
    for output_line in show_int_result:
        output_port = output_line['interface']
        command1 = 'sudo config interface startup {}'.format(output_port)
        if output_port in links:
            if 'down' in output_line['admin']:
                st.config(dut, command1)

def dpb_link_enable(dut_end):
    if dut_end=="local":
        st.log("TEST CASE: Local DUT Link Enable")
        dut=dut1
        local_links=local_links_dut1
    else:
        st.log("TEST CASE: Remote DUT Link Enable")
        dut=dut2
        local_links=local_links_dut2
    return enable_links(dut, local_links)    

def dpb_link_precheck(dut_end):
    if dut_end=="local":
        st.log("TEST CASE: Local DUT Precheck")
        dut=dut1
        local_links=local_links_dut1
    else:
        st.log("TEST CASE: Remote DUT Precheck")
        dut=dut2
        local_links=local_links_dut2
    return dpb_device_prechecks(dut, local_links)    

def disable_dpb_port(dut, dpb, def_mode):
    dpb_disable = 1
    for key in dpb:
        cmd_status = 0
        command = 'sudo config interface breakout {} "{}" -yf'.format(key,def_mode[key]['default_brkout_mode'])
        substrings = ["1x400G", "1x50G(1)"]
        for substring in substrings:
            if substring in str(def_mode[key]['default_brkout_mode']):
                command = 'sudo config interface breakout {} "{}" -yfl'.format(key, def_mode[key]['default_brkout_mode'])
        show_breakout = st.config(dut,command)
        exp_output = " Breakout process got successfully completed."
        exp_output1 = "[WARNING] No action will be taken as current and desired Breakout Mode are same."
        lines = show_breakout.strip().split("\n")
        for line in lines:
            if line == exp_output or line == exp_output1:
                print("Breakout Removed",str(key))
                cmd_status = 1
        dpb_disable &= cmd_status
        if dpb_disable == 0:
            print("Test Case failed", str(key))
            return dpb_disable
    print("Test Case passed DPB disable")
    return dpb_disable

def enable_dpb_port(dut, dpb):
    dpb_enable = 1
    for key in dpb:
        command = 'sudo config interface breakout {} "{}" -yf'.format(key, dpb[key])
        cmd_status = 0
        substrings = ["400G", "100G", "200G", "50G", "25G"]
        for substring in substrings:
            if substring in str(dpb[key]):
                command = 'sudo config interface breakout {} "{}" -yfl'.format(key, dpb[key])
        show_breakout = st.config(dut,command)
        exp_output = " Breakout process got successfully completed."
        exp_output1 = "[WARNING] No action will be taken as current and desired Breakout Mode are same."
        lines = show_breakout.strip().split("\n")
        for line in lines:
            if line == exp_output or line == exp_output1:
                print("Breakout configured: ",str(key))
                cmd_status = 1
        dpb_enable &= cmd_status
        if dpb_enable == 0:
            print("Test Case failed", str(key))
            return dpb_enable
    print("Test Case passed DPB enabled")
    return dpb_enable

def disable_dpb(dut_end, dpb, def_mode):
    if dut_end=="local":
        st.log("TEST CASE: Local DUT Disable DPB")
        dut=dut1
    else:
        st.log("TEST CASE: Remote DUT Disable DPB")
        dut=dut2
    return disable_dpb_port(dut, dpb, def_mode)

def enable_dpb(dut_end, dpb):
    if dut_end=="local":
        st.log("TEST CASE: Local DUT Enable DPB")
        dut=dut1
    else:
        st.log("TEST CASE: Remote DUT Enable DPB")
        dut=dut2
    return enable_dpb_port(dut, dpb)

class TestDPB():
    local_dpb = {}
    remote_dpb = {}
    def test_dpb(self):
        global local_dpb,remote_dpb
        tb1_links,local_dpb,l_def_mode = dpb_link_precheck("local")
        tb2_links,remote_dpb, r_def_mode = dpb_link_precheck("remote")
        if tb1_links != tb2_links:
            st.report_fail('test_case_failed')
        if not disable_dpb("local", local_dpb, l_def_mode):
            st.report_fail('test_case_failed')
        if not disable_dpb("remote", remote_dpb, r_def_mode):
            st.report_fail('test_case_failed')
        if not enable_dpb("local", local_dpb):
            st.report_fail('test_case_failed')
        dpb_link_enable("local")
        if not enable_dpb("remote", remote_dpb):
            st.report_fail('test_case_failed')
        dpb_link_enable("remote")
        time.sleep(30)
        tb11_links,local_dpb1,l1_def_mode = dpb_link_precheck("local")
        tb21_links,remote_dpb1, r1_def_mode = dpb_link_precheck("remote")
        if tb11_links == tb21_links:
            if ((tb1_links == tb11_links) and (tb2_links == tb21_links) and
                    (local_dpb == local_dpb1) and (remote_dpb == remote_dpb1)):
                st.report_pass('test_case_passed')
            else:
                st.report_fail('test_case_failed')

    def test_clean(self):
        global local_dpb, remote_dpb
        if not enable_dpb("local", local_dpb):
            st.report_fail('test_case_failed')
        dpb_link_enable("local")
        if not enable_dpb("remote", remote_dpb):
            st.report_fail('test_case_failed')
        dpb_link_enable("remote")
        st.report_pass('test_case_passed')

def check_optics_type(dut, interface):
    try:
        output=st.config(dut, "sudo sfputil show eeprom -d -p "+interface)
    except Exception as e:
        st.log("## Capture the show command error #")
        if re.search(r'ValueError|TypeError|Command.*returned error|Error', str(e)):
            if re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',str(e)):
                match=re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',str(e))
                optics_type=match.group(1)
                return optics_type
            else:
                return "unknown Optics Type"
        else:
            return "unknown Optics Type"

    if re.search(r'Extended Specification Compliance: +([100G|400G|40G].*)',output) or re.search(r"'module_media_interface_id': +'([100G|400G|40G][\w\-]+)",output) or re.search(r"Media Interface Code: +([100G|400G|40G][\w\-]+)",output) or re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',output):
        match1=re.search('Extended Specification Compliance.*([400G|100G|40G].*)',output)
        match2=re.search("'module_media_interface_id': +'([100G|400G|40G][\w\-]+)",output)
        match3=re.search(r"Media Interface Code: +([100G|400G|40G][\w\-]+)",output)
        match4=re.search(r'Application Advertisement: +([100G|400G|200G].*) \(',output)
        if match1:
            return match1.group(1)
        elif match2:
            return match2.group(1)
        elif match3:
            return match3.group(1)
        elif match4:
            return match4.group(1)
        else:
            raise AssertionError("Optics Type not found in the CLI sfputil shows eeprom")
    elif re.search(r'Extended Specification Compliance:.*',output) or re.search(r"module_media_interface_id",output) or re.search(r"Media Interface Code",output) or re.search(r'Application Advertisement',output):
        match1=re.search('Extended Specification Compliance',output)
        match2=re.search('module_media_interface_id',output)
        match3=re.search(r"Media Interface Code",output)
        match4=re.search(r'Application Advertisement',output)
        if match1:
            return match1.group(0)
        elif match2:
            return match2.group(0)
        elif match3:
            return match3.group(0)
        elif match4:
            return match4.group(0)
        else:
            raise AssertionError("Optics Type not found in the CLI sfputil shows eeprom")
    else:
        #raise AssertionError("Optics Type not parsed in the CLI sfputil shows eeprom")
        output1=st.config(dut, "sudo sfputil show eeprom-hexdump -n 3 -p "+interface)
        output2=st.config(dut, "sudo sfputil show eeprom -d -p "+interface) 
        match=re.search(r'CISCO-.*|QDD-.*',output1)
        if match:
            return match.group(0) 
        else:     
            match2=re.search(r'Vendor Name:(.*)',output2) 
            match3=re.search(r'Vendor PN:(.*)',output2) 
            if not match2 or not match3: 
                return "Unknown Optics type" 
            else: 
                return "Optics with "+match2.group(0)+match.group(0) 

@pytest.fixture(scope="function")
def reload_hook():
    data.dockers_count = {}
    for dut in data.DUTs:
        #copy_configdb_before_reload()
        st.log("# Save the runningconfig #")
        st.config(dut, "sudo config save -y")
        time.sleep(60)
        data.dockers_count[dut] = get_and_match_docker_count(dut)
        st.log('dockers count of {}: is {}'.format(dut,data.dockers_count[dut]))
        if not poll_wait(verify_docker_status, 120, dut, 'Exited'):
            data.docker_check = False
        else:
            data.docker_check = True
    st.log("Check optics types before reload")
    fail=0
    optics_dut1={}
    optics_dut2={}
    for i, link in enumerate(local_links_dut1):
        optics_dut1[link]=check_optics_type(dut1, link)
        link2=local_links_dut2[i]
        optics_dut2[link2]=check_optics_type(dut2,link2)
        st.log('### On dut1: Link %s with optics Type %s###'%(link,optics_dut1[link]))
        st.log('### On dut2: Link %s with optics Type %s###'%(link2,optics_dut2[link2]))
    start_time=time.time()
    yield
    time.sleep(120)
    fail=0
    st.log("Checking if the interface is operationally up")
    for i, link in enumerate(local_links_dut1):
        link2=local_links_dut2[i]
        if not st.poll_wait(intapi.verify_interface_status, 120, dut1, link, 'oper', 'up'):
            fail+=1 
        if not st.poll_wait(intapi.verify_interface_status, 120, dut2, link2, 'oper', 'up'):
            fail+=1
    st.log("After reload, it took %s seconds for the interfaces to come up"%str(time.time()-start_time))
    st.log('## Check Optics Again After System Reload##')
    optics_dut1_after, optics_dut2_after={}, {}
    for i, link in enumerate(local_links_dut1):
        optics_dut1_after[link]=check_optics_type(dut1, link)
        link2=local_links_dut2[i]
        optics_dut2_after[link2]=check_optics_type(dut2,link2)
        if optics_dut1_after[link]!=optics_dut1[link]:
            st.error('On DUT1, Optics Type on %s changed after process restart'%link)
            st.error('It was %s before restart, but now it is %s'%(optics_dut1[link], optics_dut1_after[link]))
            fail+=1
        if optics_dut2_after[link2]!=optics_dut2[link2]:
            st.error('On DUT2, Optics Type on %s changed after process restart'%link2)
            st.error('It was %s before restart, but now it is %s'%(optics_dut2[link2], optics_dut2_after[link2]))
            fail+=1
    if fail:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.usefixtures('reload_hook')
class Test_reload():
    def test_config_reload(self):
        try:
            fail=0
            st.log("Do config Reload")
            command="config reload -yf"
            start_time=time.time()
            st.config(dut1, command)
        except Exception as e:
            st.log("Config reload failed")
            fail=1
        finally:
            time.sleep(240)
        if not fail:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")
