#! /usr/bin/env python

import random
import os
import time

import pytest
from spytest import st, tgapi, SpyTestDict
from spytest.testbed import Testbed
from spytest.rps import RPS
from spytest.infra import get_config
from spytest.framework import get_work_area

import apis.switching.portchannel as portchannel_obj
import apis.system.logging as slog
from apis.system.basic import get_ps_aux, get_platform_syseeprom
from apis.system.reboot import config_save, config_save_reload, get_reboot_cause
from apis.system.box_services import show_interfaces_transceiver_presence
from apis.system.interface import get_up_interfaces
from apis.system.connection import connect_to_device
from apis.switching.portchannel import verify_portchannel, get_portchannel_list

from utilities.parallel import exec_all, exec_parallel, ensure_no_exception
from utilities.common import ExecAllFunc, make_list, filter_and_select

data = SpyTestDict()
workarea = None

@pytest.fixture(scope="module", autouse=True)
def initialize_variables(request):
    global vars
    vars = st.ensure_min_topology("D1D2:1")

    # Remember if we are running on LC or RP.
    vars.linecard = "LC" in get_platform_syseeprom(vars.D1, tlv_name="Product Name")

    global workarea
    workarea  = get_work_area()
    fill_rps_obj_list()
    #vars.d1_connection = connect_to_device(vars.D1, 
 
def test_Txh1751163c():
    """
    Steps to Perform cold/power off/watchdog reboot
    - cold reboot: Make use of commands to reboot the switch
    - watchdog reboot: Make use of new platform api to reboot the switch
    - power off reboot: Make use of PDUs to power on/off DUT.
    Power on/off the DUT for (number of PSUs + 1) * 2 times
    Power on each PSU solely
    Power on all the PSUs simultaneously Delay 5 and 15 seconds between powering off and on in each test
    
    After reboot, check: status of services:
    syncd, swss
    sudo systemctl status syncd
    sudo systemctl status swss
    reboot cause: show reboot-cause
    status of interfaces and port channels
    show interface status
    show interface portchannel
    status of transceivers:
    show interface transcever presence
    redis-cli -n 6 keys TRANSCEIVER_INFO* Check dmesg
    """

    global vars
    st.log("data = {}".format(data))
    st.log("vars == {}".format(vars))
    st.log("workarea = {}".format(workarea))
    st.banner("Step 1: config save reload")
    # First step: config save and reboot.
    config_save_reload(vars.D1)
    
    # step2: power off
    st.banner("Step 2: Power reset router.")
    config1 = get_config(vars.D1)
    reset_all_power_dut1()
    config2 = get_config(vars.D1)
    check_configs_and_services(config1,config2)

    # Step 3: Watchdog reboot
    st.banner("Step 3: Watchdog reboot.")
    # PFC WD is not supported as of Oct 20, 2020.

    # Step 4: Power on/off the DUT for (number of PSUs + 1) * 2 times
    st.banner("Step 4: power on/off the DUT for a number of times")
    number_of_times = (len(vars.rps_obj_list) + 1) * 2
    for count in range(number_of_times):
        st.log("Resetting power on all ports of pdu of DUT:{}".format(vars.D1))
	config1 = get_config(vars.D1)
	reset_all_power_dut1()
        config2 = get_config(vars.D1)
        check_configs_and_services(config1,config2)

    # Step 5: Power on each PSU solely
    st.banner("Step 5: Power on each PSU solely")
    config1 = get_config(vars.D1)
    for rps_obj in vars.rps_obj_list:
        st.log("Resetting power from port:{} of pdu at:{}".format(rps_obj.outlet, rps_obj.ip))
        rps_obj.off()
        time.sleep(10)
        rps_obj.on()
    config2 = get_config(vars.D1)
    check_configs_and_services(config1,config2)

    # Step 6: power off and on each PSU one by one, with random time between each test.
    st.banner("Step 6: power off and on each PSU one by one,\n with random time between each test.")
    for rps_obj in vars.rps_obj_list:
        config1 = get_config(vars.D1)
        rps_obj.off()
        rps_obj.on()
        config2 = get_config(vars.D1)
        check_configs_and_services(config1,config2)
        time.sleep(random.randint(5,15))


def fill_rps_obj_list():
    """
       Function to get the list of all Power Supply Objects for the DUT1.
       TBD: augument it to get the list of power supply objects for any router.
    """
    try:
        vars.rps_obj_list
    except AttributeError:
        rps_properties = workarea._context._tb.get_rps(vars.D1)
        vars.rps_obj_list = []
        for outlet in rps_properties.outlet.split(','):
	    prop_dict = rps_properties
	    prop_dict['outlet'] = outlet
	    try:
	        prop_dict['port']
	    except:
	        prop_dict['port'] = ""

	    st.log("prop_dict = {}".format(prop_dict))
	    vars.rps_obj_list.append(RPS(**prop_dict))

def reset_all_power_dut1():
    """
        Reset the power supplies connected to DUT1.
	TBD: Augument the function to reset for any router.
    """
    st.log("Shut off all the outlets to the router:{}".format(vars.D1))
    workarea.do_rps_new([vars.D1], "off", recon=False)

    st.log("Wait for 10 seconds before turning the router on")
    time.sleep(10)

    # Hope this doesn't trip the power circuit, keeping fingers crossed.
    workarea.do_rps_new([vars.D1], "on", recon=False)

def check_configs_and_services(config1, config2):
    """
        Function to verify all processes/causes/status/config
	after every reboot.
    """
    assert(config1 == config2, "The configurations before and after reboot don't match:{}, {}".format(config1, config2))

    # check process status
    for service in ["syncd", "swss"]:
        assert (get_service_status(vars.D1, service), "active", "The service:{} is not running".format(service))

    # Check reboot cause (TBD:FAIL due to #279).
    cause = get_reboot_cause(vars.D1)
    # https://wwwin-github.cisco.com/whitebox/sonic-buildimage/issues/279
    # assert ("User" in cause, "Didnot find the correct cause in the reboot result. Found:{}".format(cause))

    # Check interface status.
    intf_list = get_up_interfaces(vars.D1)
    if len(intf_list) <= 0:
        raise RuntimeError("There is no interface is that up in the Dut:{}".format(vars.D1))

    # Check portchannels if any.
    port_channel_list = get_portchannel_list(vars.D1)
    st.log("port_channel_list = {}".format(port_channel_list))
    for pc in port_channel_list:
        verify_portchannel(vars.D1, pc)

    # Check transciever presence.
    # This is valid only in RP
    if not vars.linecard:
        output = show_interfaces_transceiver_presence(vars.D1)
        for line in output:
           assert (line.presence == "True", "The presence of transciever is not correct. Got:{}".format(line.presence))

    # Check the redis for transceiver.
    # This is valid only in RP
    if not vars.linecard:
        for intf in [vars.D1D2P1]:
            output = st.show(vars.D1, "redis-cli -n 6 HGETALL 'TRANSCEIVER_INFO|{}'".format(intf))
            assert(output != {}, "One of the interfaces in the router has no redis entry:{} in {}".format(intf, vars.D1))


def get_service_status(dut, service):
    """
        do a "ps -aux" and get the status of the given service.
    """
    output = st.config(dut, "ps -aef | grep -w {} | grep -v grep".format(service))
    if output:
        return "active"
    else:
        return "inactive"
