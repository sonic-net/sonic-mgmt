import pprint
import pytest
import time, random, os, sys, yaml, re, json

from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.qos.acl as acl_obj
#import tests.scaling.acl_json_config as acl_data
import tests.scaling.acl_utils as acl_utils
import apis.switching.portchannel as pc_obj
import apis.system.interface as intf_obj
import apis.system.lldp as lldp_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.system.port as port_obj
import apis.system.rest as rest_obj
import apis.system.gnmi as gnmiapi
from apis.system.interface import clear_interface_counters,get_interface_counters
from apis.system.rest import rest_status

from utilities.parallel import ensure_no_exception
import utilities.common as utils
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
from utilities.parallel import exec_all, exec_parallel, ensure_no_exception
from utilities.common import ExecAllFunc
from utilities.common import random_vlan_list, poll_wait

def clean_testbed(testbedInfo,dut_username,dut_passwd):
    '''Clean up the DUTs
       Parameters:
                  testbedInfo: output of st.ensure_min_topology("D1D2:x", "D1T1:y", "D2T1:z") 
                               type: {} 
                  dut_username: default username to access the DUTs 
                               type: [] 
                  dut_passwd: default passwd to access the DUTs 
                               type: [] 
    '''

    st.log('Clean Up Configuration')
    dut_list=testbedInfo.get('dut_list') 
    ip_addr=[None]*len(dut_list) 
    ssh_conn_obj=[None]*len(dut_list) 


    for x in range(len(dut_list)):
        ip_addr[x]=testbedInfo['mgmt_ipv4'][dut_list[x]]


        # Connect to the linux machine and check
        ssh_conn_obj[x]=connect_to_device(ip_addr[x], dut_username[x], dut_passwd[x])
        if not ssh_conn_obj[x]:
            raise AssertionError('Not able to connect to the DUT')

        st.log('Connected to device '+str(ip_addr[x]))
        execute_command(ssh_conn_obj[x],'rm /etc/sonic/config_db.json')
        ssh_disconnect(ssh_conn_obj[x])

    time.sleep(15)

    st.log("Reboot DUT")
    dict1={"method": "normal"}
    exec_parallel(True, dut_list, st.reboot, [dict1 for x in range(len(dut_list))])
    time.sleep(120)

    dict2={"iteration_count":180, "delay":1}
    exec_parallel(True, dut_list, intf_obj.poll_for_interfaces, [dict2 for x in range(len(dut_list))])

    for x in range(len(dut_list)):

        # Connect to the linux machine and check
        ssh_conn_obj[x]=connect_to_device(ip_addr[x], dut_username[x], dut_passwd[x])
        if not ssh_conn_obj[x]:
            raise AssertionError('Not able to connect to the DUT after reboot')

        st.log('Disable FEC for Ethernet0 connected to Spirent TC 100G port')
        execute_command(ssh_conn_obj[x],'config interface fec Ethernet0 none')
        ssh_disconnect(ssh_conn_obj[x])


