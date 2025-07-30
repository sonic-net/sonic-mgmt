import os
import yaml
import pytest
import re

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ipapi
import apis.system.interface as intfapi
#  Inject packet using inbuilt tgen
#  Check packet counter and data is fine to declare pass

# test case for fixed chassis platforms
# test case for line card (multi-asic)
# test case for fabric card on RP (L2 switching)

CONFIG_WAIT_TIME = 60
@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    vars = st.get_testbed_vars()

# Stop
def stop_traffic_gen(tgen_data):
    tgen_stop_cmd = "config platform cisco tgen stop -id {} ".format(tgen_data.oid)
    st.config(vars.D1, tgen_stop_cmd)

# Verify
def verify_traffic(tgen_data):

    # Check interface counters and see it matches
    count = 0
    for each_port in tgen_data.port_list:
        for each_property in tgen_data.properties:
            value_1 = tgen_data.counters_1[each_port][each_property]
            value_2 = tgen_data.counters_2[each_port][each_property]
            print("tx_ok_1:{0}, tx_ok_2:{1}, change:{2} on ports:{3}".format(value_1, value_2, value_2-value_1, each_port))
            if (value_2 - value_1) >= 10:
                count += 1
    if (count < 1):
        st.report_fail('test_case_failed as packets are not sent out')
    else:
         st.report_pass("test_case_passed")


# Create
def create_traffic_gen(tgen_data):
    # Create
    if (tgen_data.type ==  "packet_data_complete"):
       tgen_cmd = 'config platform cisco tgen create -i {} \
                   -p \'Ether(src="{}",dst="{}")/IP(src="{}",dst="{}",ttl={})/Raw(load="f"*{})\'' \
                   ' -m {} -d {}'.format(tgen_data.interface, \
                                         tgen_data.smac,  \
                                         tgen_data.dmac,  \
                                         tgen_data.src_ip, \
                                         tgen_data.dst_ip, \
                                         tgen_data.ttl, \
                                         tgen_data.size, tgen_data.mode, tgen_data.duration)
    elif (tgen_data.type ==  "packet_data_no_dmac"):
        tgen_cmd = 'config platform cisco tgen create -i {} \
                   -p \'Ether(src="{}")/IP(src="{}",dst="{}",ttl={})/Raw(load="f"*{})\'' \
                   ' -m {} -d {}'.format(tgen_data.interface, \
                                         tgen_data.smac, \
                                         tgen_data.src_ip, \
                                         tgen_data.dst_ip, \
                                         tgen_data.ttl, \
                                         tgen_data.size, tgen_data.mode, tgen_data.duration)
    elif (tgen_data.type ==  "packet_data_no_ether"):
        tgen_cmd = 'config platform cisco tgen create -i {} \
                   -p \'IP(src="{}",dst="{}",ttl={})/Raw(load="f"*{})\'' \
                   ' -m {} -d {}'.format(tgen_data.interface, \
                                         tgen_data.src_ip, \
                                         tgen_data.dst_ip, \
                                         tgen_data.ttl, \
                                         tgen_data.size,\
                                         tgen_data.mode, \
                                         tgen_data.duration)
    elif (tgen_data.type ==  "file_data"):
       tgen_cmd = 'config platform cisco tgen create -i {}  -f "{}" -m {} -d {}'.format(tgen_data.interface, \
                                                                                        tgen_data.file, \
                                                                                        tgen_data.mode, \
                                                                                        tgen_data.duration)
    else:
       st.report_fail('test_case_failed due to unsupported tgen data type')
       return(None)

    result = st.config(vars.D1, tgen_cmd)
    print(result)
    match = re.search(r'OID:(\d+)', result)
    if match:
        oid = match.group(1)
        return(oid)
    else:
        print("No match for OID")
        return(None)

def start_traffic_gen(tgen_data):
    # Start
   tgen_start_cmd = "config platform cisco tgen start -id {} -tc {} -r {}".format(tgen_data.oid, tgen_data.tc, tgen_data.rate)
   st.config(vars.D1, tgen_start_cmd)


def configure_and_verify(vars, tgen_data):

    # create
    tgen_data.oid = create_traffic_gen(tgen_data)
    if (tgen_data.oid == None):
       st.report_fail('test_case_failed as tgen creation is not successful')
       return
    tgen_data.counters_1 = intfapi.get_interface_counter_value(vars.D1, tgen_data.port_list, tgen_data.properties)

    # Start
    start_traffic_gen(tgen_data)

    st.wait(int(tgen_data.duration) + 10)

    tgen_data.counters_2 = intfapi.get_interface_counter_value(vars.D1, tgen_data.port_list, tgen_data.properties)
    output = st.show(vars.D1, 'sudo show platform npu voq queue_counters -i {} -t {}'.format(tgen_data.interface, tgen_data.tc), \
                                skip_tmpl=True, skip_error_check=True)

    # verify
    verify_traffic(tgen_data)


    #verify
    output = st.show(vars.D1, 'sudo show platform npu tgen list',skip_tmpl=True, skip_error_check=True)
    print(output)

# Test injectdown with packet in scapy format as input
def test_injectdown_with_scapy_packet():
    tgen_data = SpyTestDict()
    tgen_data.smac = "0:0:C:D:E:F"
    tgen_data.dmac = "78:7e:63:4c:00:00"
    tgen_data.src_ip = "1.1.1.1"
    tgen_data.dst_ip = "1.1.1.2"
    tgen_data.ttl = "64"
    tgen_data.size = "512"
    tgen_data.mode =  "injectdown"
    tgen_data.duration = "10"
    tgen_data.type =  "packet_data_complete"
    tgen_data.interface = vars.D1D2P1
    tgen_data.port_list = [vars.D1D2P1]
    tgen_data.tc = "3"
    tgen_data.rate = "2"
    tgen_data.properties = ['tx_ok']
    st.wait(60)
    configure_and_verify(vars, tgen_data)

# Test injectup with packet in scapy format as input
def test_injectup_with_nodmac_v4_scapy_packet():
    tgen_data = SpyTestDict()
    tgen_data.smac = "0:0:C:D:E:F"
    tgen_data.src_ip = "1.1.1.1"
    tgen_data.dst_ip = "1.1.1.2"
    tgen_data.ttl = "64"
    tgen_data.size = "512"
    tgen_data.mode =  "injectup"
    tgen_data.duration = "10"
    tgen_data.type =  "packet_data_no_dmac"
    tgen_data.interface = vars.D1D2P1
    tgen_data.port_list = [vars.D1D2P1]
    tgen_data.tc = "3"
    tgen_data.rate = "2"
    tgen_data.properties = ['tx_ok']
    st.config(vars.D1, 'config interface ip add {} {}/24'.format(tgen_data.interface, tgen_data.src_ip))
    st.config(vars.D1, 'ip neigh add {} lladdr 0:0:0:0:0:1 dev {}'.format(tgen_data.dst_ip,tgen_data.interface))
    st.wait(CONFIG_WAIT_TIME)
    configure_and_verify(vars, tgen_data)

#Test injectup with packet in scapy format as input
# we have limitation here where DMAC should be same as mymac
def test_injectup_with_nodmac_v6_scapy_packet():
    tgen_data = SpyTestDict()
    tgen_data.smac = "0:0:C:D:E:F"
    tgen_data.dmac = "78:7e:63:4c:00:00"
    tgen_data.src_ip = "1111::1"
    tgen_data.dst_ip = "1111::2"
    tgen_data.ttl = "64"
    tgen_data.size = "512"
    tgen_data.mode =  "injectup"
    tgen_data.duration = "10"
    tgen_data.type =  "packet_data_no_dmac"
    tgen_data.interface = vars.D1D2P1
    tgen_data.port_list = [vars.D1D2P1]
    tgen_data.tc = "3"
    tgen_data.rate = "2"
    tgen_data.properties = ['tx_ok']
    st.config(vars.D1, 'config interface ip add {} {}/64'.format(tgen_data.interface, tgen_data.src_ip))
    st.config(vars.D1, 'ip -6 neigh add {} lladdr 0:0:0:0:0:1 dev {}'.format(tgen_data.dst_ip,tgen_data.interface))
    st.wait(CONFIG_WAIT_TIME)
    configure_and_verify(vars, tgen_data)

def test_injectup_with_noether_scapy_packet():
    tgen_data = SpyTestDict()
    tgen_data.smac = "0:0:C:D:E:F"
    tgen_data.dmac = "78:7e:63:4c:00:00"
    tgen_data.src_ip = "1.1.1.1"
    tgen_data.dst_ip = "1.1.1.2"
    tgen_data.ttl = "64"
    tgen_data.size = "512"
    tgen_data.mode =  "injectup"
    tgen_data.duration = "10"
    tgen_data.type =  "packet_data_no_ether"
    tgen_data.interface = vars.D1D2P1
    tgen_data.port_list = [vars.D1D2P1]
    tgen_data.tc = "3"
    tgen_data.rate = "2"
    tgen_data.properties = ['tx_ok']
    st.config(vars.D1, 'config interface ip add {} {}/24'.format(tgen_data.interface, tgen_data.src_ip))
    st.config(vars.D1, 'ip neigh add {} lladdr 0:0:0:0:0:1 dev {}'.format(tgen_data.dst_ip,tgen_data.interface))

    st.wait(CONFIG_WAIT_TIME)
    configure_and_verify(vars, tgen_data)
