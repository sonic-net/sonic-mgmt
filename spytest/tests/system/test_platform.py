import pytest
import json
import yaml
import os
import sys
from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.box_services as boxserv_obj
import apis.system.basic as basic_obj
import apis.system.port as port_obj
import apis.system.reboot as reboot_obj
import apis.switching.mac as mac_obj
import apis.routing.ip as ip_obj
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
import re
import datetime
import apis.routing.ip as ipfeature
from utilities import parallel
 


platform_summary_data = {
    "sherman" : {"platform": "x86_64-8201_sys-r0","hwsku": "36x100Gb","asic": "cisco-8000","product_name": "8201-SYS","udi_desc": "Cisco 8201 Open Network"},
    "SF_D_RP": {"platform": "x86_64-8800_rp_o-r0", "hwsku": "8800-RP-O", "asic": "cisco-8000","product_name": "8800-RP-O","udi_desc": "Cisco 8800 Route Processor"},
    "SF_D_LC": {"platform": "x86_64-8800_lc_48h_o-r0", "hwsku": "8800-LC-48H-O", "asic": "cisco-8000", "product_name": "8800-LC-48H-O","udi_desc": "Cisco 8800 48x100GE QSFP28 Line Card"},
    "mathilda32": {"platform": "x86_64-8101_32h_o-r0", "hwsku": "32x100Gb", "asic": "cisco-8000", "product_name": "8101-32H-O","udi_desc": ""},
    "mathilda64": {"platform": "x86_64-8102_64h_o-r0", "hwsku": "64x100Gb", "asic": "cisco-8000", "product_name": "8102-64H-O","udi_desc": "Cisco 8100 64x100G QSFP28 2RU",
    "voltage_sensors" : ["MB_GB_VDDS_L1_VIN", "MB_GB_VDDA_L2_VOUT", "MB_GB_VDDS_L1_VOUT", "CPU_U17_PVCCIN_VIN", "CPU_U17_PVCCIN_VOUT", "CPU_U17_P1P05V_VOUT", "MB_3_3V_R_L1_VIN", "MB_3_3V_R_L1_VOUT", "MB_GB_VDDCK_L2_VOUT", "MB_3_3V_L_L1_VIN", "MB_3_3V_L_L1_VOUT", "GB_PCIE_VDDH", "GB_PCIE_VDDACK", "GB_P1V8_VDDIO", "GB_P1V8_PLLVDD", "CPU_U117_P1P2V_VIN", "CPU_U117_P1P2V_VOUT", "CPU_U117_P1P05V_VOUT", "MB_A1V8", "MB_A1V", "MB_A3V3", "MB_A1V2", "MB_P3V3", "MB_GB_CORE_VIN_L1", "MB_GB_CORE_VOUT_L1", "MB_GB_CORE_IOUT_L1"],
    "current_sensors" : ["MB_GB_VDDS_L1_IIN","MB_GB_VDDS_L1_IOUT","MB_GB_VDDA_L2_IOUT","CPU_U17_PVCCIN_IIN","CPU_U17_PVCCIN_IOUT","CPU_U17_P1P05V_IOUT", "MB_3_3V_R_L1_IIN", "MB_GB_CORE_IIN_L1", "MB_3_3V_R_L1_IOUT", "MB_GB_VDDCK_L2_IOUT", "MB_3_3V_L_L1_IIN", "MB_3_3V_L_L1_IOUT", "CPU_U117_P1P2V_IIN", "CPU_U117_P1P2V_IOUT", "CPU_U117_P1P05V_IOUT"]
    },
    "churchill": {"platform": "x86_64-8201_32fh_o-r0", "hwsku": "32x400Gb", "asic": "cisco-8000", "product_name": "8201-32FH-O","udi_desc":"Cisco 8200 32x400G QSFPDD 1RU"}
}

docker_data = {
    "syncd" : ['supervisord', 'rsyslogd -n', 'sai.profile'],
    "swss" : ['supervisord', 'supervisor-proc-exit-listener --container-name swss', 'rsyslogd -n -iNONE', 'portsyncd', 'neighsyncd', 'vlanmgrd', 'intfmgrd', 'portmgrd', 'pg_profile_lookup.ini', 'vrfmgrd', 'nbrmgrd', 'vxlanmgrd'],
    "pmon" : ['supervisord', 'supervisor-proc-exit-listener --container-name pmon', 'rsyslogd -n -iNONE', 'xcvrd', 'psud', 'thermalctld'],
    "database" : ['supervisord', 'supervisor-proc-exit-listener --container-name database', 'rsyslogd -n -iNONE']
}
platform_details = {
    "manufacturer" : "Cisco",
    "vendor" : "Cisco",
    "devicemodel" : "INTEL",
    "health" : "100.0%",
    "image_name" : "sonic-cisco-8000.bin",
    "fault_thermal_induction" : {"high_th": 200, "low_th": -10, "list_of_sensors": ['CPU_U17_P1P05V_TEMP', 'ACPI', 'X86_CORE_3_T']}
}
cli_type = 'vtysh'


@pytest.fixture(scope="module", autouse=True)
def platform_module_hooks(request):
    """
    Objective: Collecting/initialising global variables and module parameters
    Minimum number of routers needed : 1 
    
    """
    global vars
    global data
    global cli_type
    vars = st.get_testbed_vars()
    data = SpyTestDict()
    data.dut_list = st.get_dut_names()
    data.username = st.get_username(vars.D1)
    data.password = st.get_password(vars.D1)
    rp_list = []
    lc_list = []
    for plat in vars.hwsku:
        if 'rp' in vars.hwsku[plat].lower():
            rp_list.append(plat)
        if 'lc' in vars.hwsku[plat].lower():
            lc_list.append(plat)
            cli_type = 'vtysh-multi-asic'
    data.rp_list  = rp_list
    data.lc_list = lc_list
    data.both = data.dut_list
    if rp_list == [] and lc_list == []:
        data.lc_list.append(vars.D1)
        data.rp_list.append(vars.D1)
    platform_out = st.show(vars.D1, 'show platform summary')
    data.Supported_HW = False
    if 'cisco' in platform_out[0]['asic'].lower():
        data.Supported_HW = True
    yield

@pytest.fixture(scope="function", autouse=True)
def platform_func_hooks(request):
    yield

def get_platform_data(platform_name):
    for key, value in platform_summary_data.items():
        if key == platform_name:
            return value
    return None

def verify_platform_idprom_valid(dut):
    """
    Verify 'show platform idprom' command
    """
    try:
        st.log("IN VERIFER PLATFORM IDPROM VALID")
        #Get the idprom data 
        idprom_data = basic_obj.get_platform_idprom(dut)
        #Get platform name 
        platform_name = st.get_platform_type(dut)
        if platform_name is None:
            st.log("Platform name")
            st.log(platform_name)
            st.log("Platform name from the input test bed file retuned None {}")
            raise Exception("Platform name from the input test bed file retuned None")
        #Get object from the platform_name from my current file
        pdata_obj = get_platform_data(platform_name) 
        if pdata_obj is None:
            st.log("Platform object")
            st.log(pdata_obj)
            st.log("Platform object from the current object retuned None {}")
            raise Exception("Platform data object from teh current file returned none to get data")
        print("parsed result")
        print(idprom_data)
        
        if idprom_data is None:
            raise Exception("Parsed idprom data returned None")

        if isinstance(idprom_data, dict):
            if(pdata_obj.get('udi_desc') in idprom_data.get('udi_desc')):
                st.log("Udi description parsed {} matched to be present in idprom data {}".format(idprom_data.get('udi_desc'), pdata_obj.get('udi_desc')))
            else:
                st.log("Udi description parsed {} does not match to be present in idprom data {}".format(idprom_data.get('udi_desc'), pdata_obj.get('udi_desc')))
                raise Exception("Udi description parsed {} does not match to be present in idprom data {}".format(idprom_data.get('udi_desc'), pdata_obj.get('udi_desc')))
        else:
            raise Exception("Version data expected to be dict but resulted {}".format(type(idprom_data)))
        return True                
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False


def ft_platform_idprom_with_reboot(dut):
    """
    Validate 'show platform idprom' command
    """

    try:
        st.log("IN TEST PLATFORM IDPROM")
        if verify_platform_idprom_valid(dut):
            st.log("RETURNED TRUE FROM THE VERIFIER OF IDPROM DATA")
            st.log("FETCH IDPROM DATA BEFORE REBOOT")
            result1 = basic_obj.get_platform_idprom(dut)
            st.log("PRINT IDPROM DATA BEFORE REBOOT")
            st.log(result1)
            st.log("Reboot the DUT {}".format(dut))
            st.reboot(dut)
            st.log("FETCH IDPROM DATA AFTER REBOOT")
            result2 = basic_obj.get_platform_idprom(dut)
            st.log("COMPARE DATA BEFORE AND AFTER REBOOT")
            if result1 == result2:
                st.log("The Idprom data before and after reboot for show platform idprom is same")
                 
                return True
            else:
                st.log("The result before and after reboot is not same")
                raise Exception("The result before and after reboot is not same")
            st.log("Idprom status Compared Before and After reboot Successful")
        else:
            st.log("The idprom data verifier returned False")
            raise Exception("idprom data verifer returned False")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False


def ft_platform_idprom_valid(dut):
    """
    Validate 'show platform idprom' command
    """

    try:
        st.log("IN TEST PLATFORM IDPROM VALID")
        if verify_platform_idprom_valid(dut):
            st.log("IN TEST PLATFORM IDPROM VALID")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
             
            return True
        else:
            st.log("IN TEST PLATFORM IDPROM VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier idprom returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False


def verify_platform_syseeprom_valid(dut):
    """
    Verify 'show platform idprom' command
    """
    try:
        st.log("syseeprom started")
        #Get the syseeprom data 
        syseeprom_data = basic_obj.get_platform_syseeprom(dut)
        if syseeprom_data is None:
            st.log("SYSEEPROM DATA RETURNED NONE")
        #Run the summary test case before the comparision of summary data with syseeprom data 
        if not verify_platform_summary(dut):
            st.log("Verifier for platform summary returned False")
            raise Exception("Verifier for platform summary returned False")
        #Get the summary_data
        summary_data = basic_obj.get_platform_summary(dut)
        #Get platform Name
        platform_name = st.get_platform_type(dut)
        #Get platform_data from platform name 
        pdata_obj = get_platform_data(platform_name)  
        print("parsed result")
        print(syseeprom_data)
        print(summary_data)

        for val in syseeprom_data:
            if(val.get('tlv_name') == 'Product Name' and val.get('value') is not None):
                if(val.get('value') == pdata_obj.get('product_name')):
                    st.log("Parsed Product name {} check matched with Input Product name {}".format(val.get('value'),pdata_obj.get('product_name')))
                    st.log("Product Name validation successful")
                else:
                    st.log("Parsed Product name {} check does not matched with Input Product name {} failed".format(val.get('value'),pdata_obj.get('product_name')))
                    raise Exception("Parsed Product name {} check does not matched with Input Product name {} failed".format(val.get('value'),pdata_obj.get('product_name')))
            if(val.get('tlv_name') == 'Platform Name' and val.get('value') is not None):
                if(val.get('value') == summary_data.get('platform')):
                    st.log("Parsed Platform name {} check matched with Input Platform name {}".format(val.get('value'),pdata_obj.get('platform')))
                    st.log("Platform Name validation successful")
                else:
                    st.log("Parsed Platform name {} check matched with Input Platform name {} failed".format(val.get('value'),pdata_obj.get('platform')))
                    st.log("Platform name check with summary output failed")
                    raise Exception("Parsed Platform name {} check matched with Input Platform name {} failed".format(val.get('value'),pdata_obj.get('platform')))
            if(val.get('tlv_name') == 'Manufacturer'):
                if(val.get('value') == platform_details.get('manufacturer')):
                    st.log("Parsed manufacture name {} check matched with Input name {}".format(val.get('value'),platform_details.get('manufacturer')))
                    st.log("Manufacturer value check successful")
                else:
                    st.log("Manufacturer value check failed")
                    st.log("Parsed manufacture name {} check matched with Input name {} failed".format(val.get('value'),platform_details.get('manufacturer')))                   
                    raise Exception("Parsed Manufacturer name {} check matched with Input name {} failed".format(val.get('value'),platform_details.get('manufacturer')))
            if(val.get('tlv_name') == 'Vendor'):
                if(val.get('value') == platform_details.get('vendor')):
                    st.log("Parsed Vendor name {} check matched with Input name {}".format(val.get('value'),platform_details.get('vendor')))
                    st.log("Vendor value check successful")
                else:
                    st.log("Parsed Vendor name {} check matched with Input name {} failed".format(val.get('value'),platform_details.get('vendor')))
                    st.log("Vendor value check failed")
                    raise Exception("Parsed Vendor name {} check matched with Input name {} failed".format(val.get('value'),platform_details.get('vendor')))
        st.log("Verifier successfully verified returning true")
        st.log("Exiting Verifier")
        return True
    except Exception as err:
        print("Exception occured in show platform syseeprom", sys.exc_info()[0])
        print(err)
        st.log("Exception occured")
        return False
        
def ft_platform_syseeprom_with_reboot(dut):
    """
    Validate 'show platform syseeprom' command
    """


    try:
        st.log("IN TEST PLATFORM SYSEEPROM")
        if verify_platform_syseeprom_valid(dut):
            st.log("RETURNED TRUE FROM THE VERIFIER OF SYSEEPROM DATA")
            st.log("FETCH SYSEEPROM DATA BEFORE REBOOT")
            result1 = basic_obj.get_platform_syseeprom(dut)
            st.log("PRINT SYSEEPROM DATA BEFORE REBOOT")
            st.log(result1)
            st.log("Reboot the DUT {}".format(dut))
            st.reboot(dut)
            st.log("FETCH SYSEEPROM DATA AFTER REBOOT")
            result2 = basic_obj.get_platform_syseeprom(dut)
            st.log("COMPARE DATA BEFORE AND AFTER REBOOT")
            if result1 == result2:
                st.log("The Syseeprom data before and after reboot for show platform syseeprom is same")
                 
                return True
            else:
                st.log("The result before and after reboot is not same")
                raise Exception("The result before and after reboot is not same")
            st.log("Syseeprom status Compared Before and After reboot Successful")
        else:
            st.log("The syseeprom data verifier returned False")
            raise Exception("syseeprom data verifer returned False")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_platform_syseeprom_valid(dut):
    """
    Validate 'show platform syseeprom' command
    """

    try:
        st.log("IN TEST PLATFORM SYSEEPROM VALID")
        if verify_platform_syseeprom_valid(dut):
            st.log("IN TEST PLATFORM SYSEEPROM VALID")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
             
            return True
        else:
            st.log("IN TEST PLATFORM SYSEEPROM VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier syseeprom returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
        
def ft_platform_inventory(dut):
    """
    Validate 'show platform inventory' command
    """

    try:
        result1 = basic_obj.get_platform_inventory(dut)
        st.log(result1)
        st.reboot(dut)
        result2 = basic_obj.get_platform_inventory(dut)
        if result1 == result2:
            st.log("The Inventory data before and after reboot for show platform fan is same")
             
            return True
        else:
            st.log("The result before and after reboot is not same")
            raise Exception("The result before and after reboot is not same")
        st.log("Inventory status Compared Before and After reboot Successful")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def verify_platform_psustatus_valid(dut):
    """
    Verify show platform psustatus
    """
    vars = st.get_testbed_vars()
    try:
        #Get psustatus data validation
        result = basic_obj.get_platform_psustatus(dut)
        if result is None:
            st.log("Result returned None")
        print(result)
        is_psu_status = False
        #Check if the status is "OK" for any one PSU as of now 
        for data in result:
            if data.get('voltage') == 'N/A' and data.get('current') == 'N/A' and data.get('led') == 'N/A' and data.get('power') == 'N/A' and data.get('status') == 'OK':
                st.log("PSU Status is listed {} which is expected".format(data.get('status')))
                st.log("PSU Status is OK for PSU {}".format(data.get('psu')))
                st.log("Updating the psu_status boolean value to true if found one PSU")
                is_psu_status = True
            else:
                st.log("PSU Status is {} for PSU name {}".format(data.get('status'),data.get('psu')))
                st.log("Psu reported not present or not ok")
        if is_psu_status:
            st.log("Atleast one PSU status found Ok ")
            st.log("Verifier of PSU STatus successfully verified")
            st.log("Verifier returning true")
            st.log("EXITING VERIFIER")
            return True
        else:
            st.log("Atleast one PSU have not reported status to be OK or PRESENT , so reporting the test case to be failed")
            raise Exception("PSU Status is listed NOT PRESENT which is not expected")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_platform_psustatus_with_reboot(dut):
    """
    Validate 'show platform psustatus' command
    """


    try:
        st.log("IN TEST PLATFORM PSUSTATUS")
        if verify_platform_psustatus_valid(dut):
            st.log("RETURNED TRUE FROM THE VERIFIER OF PSUSTATUS DATA")
            st.log("FETCH PSUSTATUS DATA BEFORE REBOOT")
            result1 = basic_obj.get_platform_psustatus(dut)
            st.log("PRINT PSUSTATUS DATA BEFORE REBOOT")
            st.log(result1)
            st.log("Reboot the DUT {}".format(dut))
            st.reboot(dut)
            st.log("FETCH PSUSTATUS DATA AFTER REBOOT")
            result2 = basic_obj.get_platform_psustatus(dut)
            st.log("COMPARE DATA BEFORE AND AFTER REBOOT")
            if result1 == result2:
                st.log("The Psudata  before and after reboot for show platform psustatus is same")
                 
                return True
            else:
                st.log("The result before and after reboot is not same")
                raise Exception("The result before and after reboot is not same")
            st.log("PSUstatus status Compared Before and After reboot Successful")
        else:
            st.log("The psustatus data verifier returned False")
            raise Exception("psustatus data verifer returned False")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_platform_psustatus_valid(dut):
    """
    Validate 'show platform psustatus' command
    """
    try:
        st.log("IN TEST PLATFORM PSUSTATUS VALID")
        if verify_platform_psustatus_valid(dut):
            st.log("IN TEST PLATFORM PSUSTATUS VALID")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
             
            return True
        else:
            st.log("IN TEST PLATFORM PSUSTATUS VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier psustatus returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def verify_platform_fanstatus_valid(dut):
    """
    Verify "show platform fan" command 
    """ 
    try:
        st.log("fan started")
        #Get platform fan as obj
        st.log("Get the show platform fan output")
        fan_data = basic_obj.get_platform_fan(dut)
        print("parsed result")
        print(fan_data)
        st.log("Starting validation on fan data output")        
        if fan_data is None:
            raise Exception("Parsed Fan data output returned None")
        #Verify fan status to be Ok, if not report failure
        if isinstance(fan_data, list):
            for val in fan_data:
                if(val.get('status') == 'OK'):
                    st.log("Fan data status of each fan is {}".format(val.get('status')))
                else:
                    st.log("Fan data status of each fan is {}".format(val.get('status')))
                    raise Exception("Fan data status of each fan is {}".format(val.get('status')))
        else:
            st.log("Returned object expected to be dict but returned type is {}".format(type(fan_data)))
            raise Exception("Fan data expected to be dict but resulted {}".format(type(fan_data)))        
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_platform_fanstatus_with_reboot(dut):
    """
    Validate 'show platform fan' command
    """

    try:
        st.log("IN TEST PLATFORM FAN")
        if verify_platform_fanstatus_valid(dut):
            st.log("RETURNED TRUE FROM THE VERIFIER OF FAN DATA")
            st.log("FETCH FAN DATA BEFORE REBOOT")
            result1 = basic_obj.get_platform_fan(dut)
            st.log("PRINT FAN DATA BEFORE REBOOT")
            st.log(result1)
            st.log("Reboot the DUT {}".format(dut))
            st.wait(120)
            st.reboot(dut)
            st.log("FETCH FAN DATA AFTER REBOOT")
            result2 = basic_obj.get_platform_fan(dut)
            st.log("COMPARE DATA BEFORE AND AFTER REBOOT")
            for row, column in zip(result1, result2):
                if((row.get('drawer') == column.get('drawer')) and (row.get('led') == column.get('led')) and (row.get('status') == column.get('status')) and (row.get('direction') == column.get('direction')) and (row.get('fan') == column.get('fan')) and (row.get('presence') == column.get('presence'))):
                        st.log("The fan before and after reboot for show platform fan is same")
                         
                        return True
                else:
                        st.log("The fan conditions for {} fantray didnot met expected result to be equal for {} before reboot and After reboot {}".format(row.get('drawer'),row,column))
                        st.log("The result before and after reboot is not same")
                        raise Exception("The result before and after reboot is not same")
            st.log("fan status Compared Before and After reboot Successful")
        else:
            st.log("The fan data verifier returned False")
            raise Exception("fan data verifer returned False")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_platform_fanstatus_valid(dut):
    """
    Validate 'show platform fan' command
    """
    try:
        st.log("IN TEST PLATFORM FAN VALID")
        if verify_platform_fanstatus_valid(dut):
            st.log("IN TEST PLATFORM FAN VALID")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
             
            return True
        else:
            st.log("IN TEST PLATFORM FAN VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier fan returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
        
def verify_platform_temperature_valid(dut):
    """
    Verify 'show paltform temperature' command
    """
    try:
        st.log("Getting the output from show platform temperature")
        temp_data = basic_obj.get_platform_temperature(dut)
        print("parsed result")
        print(temp_data)
        
        if temp_data is None:
            raise Exception("Parsed Temperature output returned null")

        if isinstance(temp_data, list):
            for data in temp_data:
                if(float(data.get('temperature')) > float(data.get('low_th')) and float(data.get('temperature')) < float(data.get('high_th'))):
                    st.log("Temperature {} matched to the expectation in the range between {} and {}".format(data.get('temperature'), data.get('low_th'), data.get('high_th')))
                else:
                    st.log("Temperature {} does not matched to the expectation in the range between {} and {}".format(data.get('temperature'), data.get('low_th'), data.get('high_th')))
                    raise Exception("Temperature {} does not matched to the expectation in the range between {} and {}".format(data.get('temperature'), data.get('low_th'), data.get('high_th')))
        else:
            st.log("Returned object expected to be list but returned type is {}".format(type(temp_data)))
            raise Exception("Temperature data expected to be list but resulted {}".format(type(temp_data)))
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_platform_temperature_valid(dut):
    """
    Validate 'show platform temperature' command
    """
    
    try:
        st.log("IN TEST PLATFORM TEMPERATURE VALID")
        if verify_platform_temperature_valid(dut):
            st.log("IN TEST PLATFORM TEMPERATURE VALID")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
             
            return True
        else:
            st.log("IN TEST PLATFORM TEMPERATURE VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier fan returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_platform_temperature_with_reboot(dut):
    """
    Validate 'show platform temperature' command
    """

    try:
        st.log("IN TEST PLATFORM TEMPERATURE")
        if verify_platform_temperature_valid(dut):
            st.log("RETURNED TRUE FROM THE VERIFIER OF TEMPERATURE DATA")
            st.log("FETCH TEMPERATURE DATA BEFORE REBOOT")
            result1 = basic_obj.get_platform_temperature(dut)
            st.log("PRINT TEMPERATURE DATA BEFORE REBOOT")
            st.log(result1)
            st.log("Reboot the DUT {}".format(dut))
            st.reboot(dut)
            st.log("FETCH TEMPERATURE DATA AFTER REBOOT")
            result2 = basic_obj.get_platform_temperature(dut)
            st.log(result2)
            st.log("COMPARE DATA BEFORE AND AFTER REBOOT")
            for row, column in zip(result1, result2):
                if (float(column.get('temperature')) <= float(row.get('temperature'))+10.0) or (float(column.get('temperature')) >= float(row.get('temperature'))-10.0):
                        st.log("The TEMPERATURE  before and after reboot for show platform temperature is same")
                         
                        return True
                else:
                        st.log("The temperature conditions for {} sensor didnot met expected result to be equal for {} before reboot and After reboot {}".format(row.get('sensor'),row,column))
                        st.log("The result before and after reboot is not same")
                        raise Exception("The result before and after reboot is not same")
            st.log("temperature status Compared Before and After reboot Successful")
        else:
            st.log("The temperature data verifier returned False")
            raise Exception("temperature data verifer returned False")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_show_system_memory(dut):
    """
    Validate 'show system-memory' command 
    """

    try:
        #Get get system memory as object 
        memory_data = basic_obj.get_show_system_memory(dut)
        threshold_free_memory = 1500 
        if memory_data is None:
             
            return False
        if isinstance(memory_data, dict):
            if(int(memory_data.get('free')) < threshold_free_memory):
                st.log("free memory is less than the threshold")
                raise Exception("Free memory is {} which is less than the threshold {} ".format(memory_data.get('free'), threshold_free_memory))
        else:
            raise Exception("System memory data expected to be dict but resulted {}".format(type(memory_data)))
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
    
def check_uptime_docker(dut, container_name):
    """
    Checking if container is up about a minute"
    """
    try:
        container_data = basic_obj.get_docker_ps_container(dut, container_name)
        if not container_data:
            st.log("No container data found after issuing docker ps -f name={}".format(container_name))
            raise Exception("Container data parsed after docker restart {} is none ".format(container_name))
        time = 1
        pattern = r'[\S]+ (?P<time>[\d]+|About a|Less than a) (?P<unit>[\S]+)'
        match = re.search(pattern, container_data.get('status'))
        if match is None:
            st.log("match is None")
            raise Exception("Expected Uptime of the container not found")
        output = match.group('time', 'unit')
        st.log("output")
        st.log(output)
        if output:
            if output[0].isnumeric():
                uptime = int(output[0])
                st.log("uptime")
                st.log(output[0])
            else:
                st.log("uptime not integer")
                uptime = output[0]
                st.log(uptime)
            units = output[1]
            st.log("units")
            st.log(units)
        else:
            st.log("No output found by match {}".format(output))
            uptime = 0
        if((units.startswith("second") and time <= uptime < time+60) or (units.startswith("minute") and time < uptime < time+2) or ((uptime == "About a" or uptime == "Less than a") and (units.startswith("minute") or units.startswith("second")))):
            return True
        return False
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_docker_ps(dut):
    """
    Validate 'docker ps' command 
    """

    try:
        docker_data = basic_obj.get_docker_ps(dut)
        if docker_data is None:
            raise Exception("Parsed docker data returned null")
        for data in docker_data:
            restart_ouput = basic_obj.docker_operation(dut, data.get('names'), "restart")
            parsed_restart_docker_name = restart_ouput.split('\n')[0]
            if parsed_restart_docker_name == data.get('names'):
                st.log("Parsed Docker {} name after restart matched with input docker name before restart {}".format(parsed_restart_docker_name, data.get('names')))
                st.log("Restart of the docker is successful")
            else:
                st.log("Parsed Docker {} name after restart not matched with input docker name before restart {}".format(parsed_restart_docker_name, data.get('names')))
                st.log("Restart of the docker is not successful")
                raise Exception("Parsed Docker {} name after restart matched with input docker name before restart {}".format(parsed_restart_docker_name, data.get('names')))           
            st.wait(60)
            if not check_uptime_docker(dut, data.get('names')):
                st.log("docker {} container verification failed".format(data.get('names')))
                raise Exception("docker {} container verification failed".format(data.get('names')))
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
 
def verify_service_restart(dut, service_name):
    """
    Verify 'service restart telemety ' command 
    """

    try:
        st.log("IN VERIFY SERVICE RESTART")
        basic_obj.service_operations(dut, service_name, action="restart")
        st.wait(60)
        if not check_uptime_docker(dut, service_name):
            st.log("The docker ps check after restart returned false")
            st.log("docker container {} verification failed".format(service_name))
            raise Exception("docker restart {} container verification failed".format(service_name))
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False
   
def ft_service_restart(dut):
    """
    Validate 'service restart telemety ' command 
    """
    ret_val = False
    try: 
        ret_val = verify_service_restart(dut, "telemetry")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
    return ret_val    
    

def ft_show_version(dut):
    """
    Validate 'show version' command
    """

    try:
        #Get Show version 
        version_data = basic_obj.show_version(dut)
        #Test idprom data before using idprom_output
        commit_data = st.get_build_commit_hash(dut)
        if commit_data is None:
            raise Exception("Commit_data retuned null from the input file ")

        if version_data is None:
            raise Exception("Parsed version date retuned null") 
        #Validate as below 
        if isinstance(version_data, dict):
            if version_data.get('build_commit') is None and version_data.get('build_commit') != commit_data :
                raise Exception("Parsed built commit val {} not matched to the commit_data {}".format(version_data.get('built_commit'), commit_data))
            if version_data.get('kernel') is None:
                raise Exception("Kernel val {} not expected".format(version_data.get('kernel')))
            if version_data.get('build_date') is None:
                raise Exception("Parsed built date val {} not expected".format(version_data.get('built_date')))
            if version_data.get('built_by') is None:
                raise Exception("Parsed built by val {} not expected".format(version_data.get('built_by')))
            if version_data.get('hwsku') is None and version_data.get('hwsku') != summary_data.get('hwsku'):
                raise Exception("Parsed hwsku val {} not matched with summary input platform val".format(version_data.get('hwsku'),summary_data.get('hwsku')))
            if version_data.get('platform') is None and version_data.get('platform') != summary_data.get('platform'):
                raise Exception("Parsed platform val {} not matched with summary input platform val".format(version_data.get('platform'),summary_data.get('platform'))) 
            if version_data.get('asic') is None and version_data.get('asic') != summary_data.get('asic'):
                raise Exception("Parsed asic val {} not matched with summary input asic val".format(version_data.get('asic'),summary_data.get('asic'))) 
        else:
            raise Exception("Version data expected to be dict but resulted {}".format(type(version_data)))
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def verify_platform_summary(dut):
    """
    Verify platform summary
    """
    try:
        #Get platform summary as obj 
        result = basic_obj.get_platform_summary(dut)
        platform_name = st.get_platform_type(dut)
        if platform_name is None:
            st.log("Failed to get platform_type from DUT1")
            raise Exception("Failed to get platform_type from DUT1")
        pdata_obj = get_platform_data(platform_name)  
        if pdata_obj is None:
            st.log("Failed to get the platform data object from the current script")
            raise Exception("Failed to get the platform data object from the current script")
        print("parsed result")
        if result is None:
            st.log("Parsed summary result is not None")
            raise Exception("Parsed summary result is not None")
        #Check the validation with input and compare the values
        if result.get('platform') is None or  pdata_obj.get('platform') not in result.get('platform'):
            raise Exception("Parsed summary result is not None")
        if result.get('hwsku') is None or result.get('hwsku') != pdata_obj.get('hwsku'):
            raise Exception("Parsed hwsku val {} not matched with input hwsku val".format(result.get('hwsku'),pdata_obj.get('hwsku')))
        if result.get('asic') is None or result.get('asic') != pdata_obj.get('asic'):
            raise Exception("Parsed asic val {} not matched with input asic val".format(result.get('asic'),pdata_obj.get('asic'))) 
        st.log("show platform summary completed")
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_platform_summary(dut):
    """
    Validate 'show platform summary' command
    """

    try:
        st.log("IN TEST PLATFORM SUMMARY")
        if verify_platform_summary(dut):
            st.log("IN TEST PLATFORM SUMMARY")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
             
            return True
        else:
            st.log("IN TEST PLATFORM SUMMARY")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier summary returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
    
def ft_platform_rebootcause(dut):
    """
    Validate 'show platform reboot-cause' command 
    """

    #Get the username of the yaml file
    reboot_cause_valid = False
    try:
        user_name = st.get_username(dut)
        result = reboot_obj.get_reboot_cause(dut)
        #if result is None, then report fail
        if result is None:
             
            return False
        if isinstance(result, list):
            for data in result:
                message = data.get('message')
                pattern = r'User issued \'reboot\' command \[User: (?P<user>\S+), Time: (?P<time>.*)\]'
                match = re.match(pattern, message)
                if match is None:
                    continue
                output = match.group('user', 'time')
                if(output[0] == user_name):
                    st.log("user name matched and verified successfully with current user {}".format(user_name))
                    reboot_cause_valid = True
                else:
                    st.log("username does not match  with current user {}".format(user_name))
                    raise Exception("username does not match  with current user {}".format(user_name))
        return reboot_cause_valid
         
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_platform_rebootcause_valid(dut):
    """
    Validate 'show platform reboot-cause' command 
    """

    #Get the username of the yaml file
    user_name = st.get_username(dut)
    try:
        date_before_reboot = basic_obj.get_dut_date_time(dut)
        if date_before_reboot is None:
            raise Exception("The Parsed Date object retuned None")
        date1 = datetime.datetime.strptime(date_before_reboot, '%a %d %b %Y %I:%M:%S %p %Z')
        st.reboot(dut)
        result = reboot_obj.get_reboot_cause(dut)
        #if result is None, then report fail
        if result is None:
            raise Exception("The Parsed reboot-cause output returned None")
        if isinstance(result, list):
            for data in result:
                message = data.get('message')
                if message is None:
                    raise Exception("The parsed message attribute returned None")
                pattern = r'User issued \'reboot\' command \[User: (?P<user>\S+), Time: (?P<time>.*)\]'
                match = re.match(pattern, message)
                if match is None:
                    st.log('message not found as expected')
                    continue
                output = match.group('user', 'time')
                reboot_date = output[1]
                date2 = datetime.datetime.strptime(reboot_date, '%a %d %b %Y %I:%M:%S %p %Z')
                diff = date2 - date1
                if(diff.total_seconds() > 360):
                    st.log("Time stamp expected to be less than 360 seconds after reboot cause is issued , failed")
                    raise Exception("Time in seconds expected to be less than 360 but the time seen is {}".format(diff.total_seconds()))
                else:
                    st.log("Time stamp expected to be less than 360 seconds after reboot cause is issued ")
                if(output[0] == user_name):
                    st.log("user name matched and verified successfully with current user {}".format(user_name))
                else:
                    st.log("username does not match  with current user {}".format(user_name))
                    raise Exception("username does not match  with current user {}".format(user_name))
                 
                return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
    return False
 
def ft_users(dut):
    """
    Validate 'show users' command 
    """

    try:
        user_data = basic_obj.get_users(dut)
        #Get the username from the yaml file
        user_name = st.get_username(dut)

        if user_data is None:
            raise Exception("Parsed User output returned None")
        #If user_data is dict, if user is matched then test case passed
        if isinstance(user_data, dict):
            if(user_data.get('user') == user_name):
                st.log("User {} matched with current user logged in".format(user_name))
            else:
                st.log("User {} didnot matched the current user who is {}".format(user_data.get('user'), user_name))
                raise Exception("User {} didnot matched the current user who is {}".format(user_data.get('user'), user_name))
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False


def ft_show_boot(dut):
    """
    Validate 'show boot' command 
    """

    try:
        boot_data = basic_obj.get_show_boot(dut)
        if boot_data is None:
            raise Exception("Parsed Boot data is returned null")
        #getting the build commit hash from the input yaml file 
        commit_data = st.get_build_commit_hash(dut)
        if commit_data is None:
            raise Exception("Commit hash Not defined in the input yaml")
        st.log(boot_data)
        if boot_data['current'] is None:
            raise Exception("Parsed current image value is reported None for show boot output")
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error :", sys.exc_info()[0])
         
        return False

def ft_show_mgmt_vrf(dut):
    """
    Validate 'show mgmt-vrf' command 
    """
 
    try:
        #Get the username from the input yaml
        user_name = st.get_username(dut)
        #Get the password from the input yaml
        password = st.get_password(dut)
        #Connecting to ssh session and enabling mgmt-vrf 
        ssh_d1 = connect_to_device(st.get_mgmt_ip(dut), user_name, password)
        if ssh_d1:
            st.log("Executing command - 'sudo config vrf add mgmt' in to the SSH session.")
            st.log(execute_command(ssh_d1, 'sudo config vrf add mgmt'))
            st.wait(5, 'After executing "confif vrf mgmt" cmd on SSH session.')
            st.log("Forcefully disconnecting the SSH session..")
            ssh_disconnect(ssh_d1)
        else:
            raise Exception('SSH connection unsuccessful')
        #getting the show mgmt-vrf output
        vrf_data = basic_obj.get_show_mgmt_vrf(dut)
        if vrf_data is None:
            raise Exception("Mgmt vrf data after mgmt vrf enable returned None which is not expected")

        ssh_d1 = connect_to_device(st.get_mgmt_ip(dut), user_name, password)
        if ssh_d1:
            st.log("Executing command - 'sudo config vrf del mgmt' in to the SSH session.")
            st.log(execute_command(ssh_d1, 'sudo config vrf del mgmt'))
            st.wait(5, 'After executing "confif vrf mgmt" cmd on SSH session.')
            st.log("Forcefully disconnecting the SSH session..")
            ssh_disconnect(ssh_d1)
        else:
           raise Exception('SSH connection unsuccessful')
        st.log(vrf_data)
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
     
def ft_show_mgmt_int_address(dut):
    """
    Validate 'show management_interface address' command 
    """
    
    try:
        #Get show ip route output
        ip_data = ip_obj.show_ip_route(dut)
        #Get gateway address from the ip route data
        ipv4_gw = [x for x in ip_data if x['ip_address'] == '0.0.0.0/0'][0]['nexthop']
        #Get show ipv6 route output
        ipv6_data = ip_obj.show_ip_route(dut, family="ipv6")
        #Get ipv6 gateway address from the ipv6 route data 
        ipv6_gw = [x for x in ipv6_data if x['ip_address'] == '::/0'][0]['nexthop']
        #Get show ip int data output
        ip_int_data = ip_obj.get_interface_ip_address(dut)
        #Get show ipv6 int data output
        ipv6_int_data = ip_obj.get_interface_ip_address(dut,family="ipv6")
        #Extract ipv4 mgmt address from show ip int data 
        ipv4_mgmt = [x for x in ip_int_data if x['interface'] == 'eth0'][0]['ipaddr']
        #Extract ipv6 mgmt address from show ipv6 int data 
        ipv6_mgmt = [x for x in ipv6_int_data if x['interface'] == 'eth0'][0]['ipaddr']
        #Create a json object for mgmt config 
        mgmt_json = {"MGMT_INTERFACE": { "eth0|"+ ipv4_mgmt : {"gwaddr": ipv4_gw },"eth0|"+ ipv6_mgmt : {"gwaddr": ipv6_gw } },"MGMT_PORT": {"eth0": {"admin_status": "up","alias": "eth0"}}}
        #Create a file from json 
        mgmt_file_data = json.dumps(mgmt_json)
        #Apply config load mgmt.json 
        st.apply_json(dut, mgmt_file_data)
        #Get the Management_interface_address from the DUT
        mgmt_data = basic_obj.get_show_management_int_address(dut)
        if mgmt_data is None:
            raise Exception("Parsed mgmt interface address returned null which is not expected")
        #Verify if the Ip and gateway matches
        if isinstance(mgmt_data, dict):
            if mgmt_data.get('management_ipv4_gateway') == ipv4_gw:
                st.log("Verified ipv4 gateway OK")
            else:
                st.log("Verification of ipv4 gateway failed")
                st.report_fail("test_case_failed")
            if mgmt_data.get('management_ipv6_gateway') == ipv6_gw:
                st.log("Verified ipv6 gateway OK")
            else:
                st.log("Verification of ipv6 gateway failed")
                st.report_fail("test_case_failed")
            mgmt_ipv4 = mgmt_data.get('management_ipv4_ip')+mgmt_data.get('ipv4_mask')
            mgmt_ipv6 = mgmt_data.get('management_ipv6_ip')+mgmt_data.get('ipv6_mask')
            if mgmt_data.get('management_ipv4_gateway') == ipv4_gw:
                st.log("Verified ipv4 gateway OK")
            else:
                st.log("Verification of ipv4 gateway failed")
                st.report_fail("test_case_failed")
            if mgmt_data.get('management_ipv6_gateway') == ipv6_gw:
                st.log("Verified ipv6 gateway OK")
            else:
                st.log("Verification of ipv6 gateway failed")
                st.report_fail("test_case_failed")
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_show_services(dut):
    """
    Validate 'show services' command 
    """


    #Get the show_services from the show_services
    try:
        services_data = basic_obj.get_show_services(dut)
        s_data = {}
        if services_data is None:
            raise Exception("Parsed Services output returned Null which is not expected")
        if isinstance(services_data, list):
            for data in services_data:
                if data.get('docker_name') not in s_data:
                    s_data[data.get('docker_name')] = []
                s_data[data.get('docker_name')].append(data.get('cmd').split('/')[-1])
        for d_name, d_list in docker_data.items():
            for d_list_val in d_list:
                if d_list_val in s_data.get(d_name):
                    #expected to be existed in the predefined docker data 
                    st.log("service {} exists in the container {}".format(d_list_val, d_name))
                else:
                    #if service doesnot exists in the container then report fail 
                    st.log("service {} does not exists in the container {}".format(d_list_val, d_name))
                    raise Exception("service {} does not exists in the container {}".format(d_list_val, d_name))
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of Error Occurred:", sys.exc_info()[0])
         
        return False

def ft_cpu_usage(dut):
    """
    Validate CPU usage for processes by
    1. system showing proper cpu utiliation data for each process
    2. Individual process not occupying more than 80% of cpu
    """

    try:
        output = basic_obj.get_processes_cpu(dut)
        print("Output of Show processes cpu")
        print(output)
        for row in output:
            if float(row['cpu']) < 80.0 and float(row['cpu']) >= 0.0:
                st.log("CPU usage for {} is {}".format(row['command'],row['cpu']))
            else:
                st.log("CPU usage for {} is {}".format(row['command'], row['cpu']))
                st.log("test case failed as {} reached more than allowed CPU usage".format(row['command']))
                raise Exception("test case failed as {} reached more than allowed CPU usage".format(row['command']))
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False
    
def ft_memory_usage(dut):
    """
    Validate Memory usage for processes by
    1. system showing proper memory utiliation data for each process
    2. Individual process not occupying more than 80% of memory
    """

    try:
        output = basic_obj.get_processes_memory(dut)
        print("Output of Show processes memory")
        print(output)
        for row in output:
            if float(row['mem']) < 80.0 and float(row['mem']) >= 0.0:
                st.log("Memory usage for {} is {}".format(row['command'],row['mem']))
            else:
                st.log("Memory usage for {} is {}".format(row['command'], row['mem']))
                st.log("Memory usage for {} is {}".format(row['command'],row['mem']))
                raise Exception("test case failed as {} reached more than allowed Memory usage".format(row['command']))
        st.log("Test Case Passed")
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_transceiver_status(dut,interface_list=[]):
    """
    Validate transceiver status
    """
    global vars
    if interface_list == []:
        required_int = ['D{0}D{0}P1','D{0}D{0}P2']
        required_int = [i.format(dut[-1]) for i in required_int]
        interface_list = [vars[i]for i in required_int]
    
    try:
        transceiverOutput = basic_obj.get_int_transceiver_eeprom(dut)
        presenceOutput = basic_obj.get_show_int_transceiver_presence(dut)
        interfacesTestBedFile = set(interface_list)
        interfacesEEProm = set([element['interface'] for element in transceiverOutput])
        if not (interfacesTestBedFile.issubset(interfacesEEProm)):
            raise Exception("Interfaces from testbed file didnt match with Interfaces from EEPROM Output")
        for row,column in zip(transceiverOutput,presenceOutput):
            if row['interface'] == column['port']:
                if (row['status'] == "detected" and column['presence']=="Present"):
                    st.log("Interfaces with  DETECTED status matched")
                elif (row['status'] == "Not detected" and column['presence']=="Not present"):
                    st.log("Interfaces with NOT DETECTED status matched")
                else:
                    raise Exception("Interfaces with DETECTED status did not match with interfaces of PRESENT status")
            else:
                raise Exception("Interfaces with DETECTED status did not match with interfaces of PRESENT status")
         
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False


def ft_transceiver_vendor_presence(dut,interface_list=[]):
    """
    Validate transceiver vendor presence
    """
    global vars
    if interface_list == []:
        required_int = ['D{0}D{0}P1','D{0}D{0}P2']
        required_int = [i.format(dut[-1]) for i in required_int]
        interface_list = [vars[i]for i in required_int]
    ret_val = True

    try:
        transceiverOutput = basic_obj.get_int_transceiver_eeprom(dut)
        interfacesTestBedFile = set(interface_list)
        interfacesEEProm = set ([element['interface'] for element in transceiverOutput])
        if not (interfacesTestBedFile.issubset(interfacesEEProm)):
            raise Exception("Interfaces from testbed file didnt match with Interfaces from EEPROM Output")
            ret_val = False
        for row in transceiverOutput:
            if row['status'] == "detected":
                if row['vendordate'] and row['vendorsn'] and row['vendorrev'] and row['vendoroui']:
                    st.log(row)
                    st.log("All vendor fields exist")
                else:
                    st.log(row)
                    raise Exception("Vendors fields doesnot exist")
                    ret_val = False
         
        return ret_val
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def verify_optics_presence(dut,intf_list=[]):
    """
    Verify the optics presence 
    """
    global vars
    if intf_list == []:
        return False
    try:
        trans_presence_data = basic_obj.get_show_int_transceiver_presence(dut)
        if trans_presence_data is None:
            raise Exception("Parsed transciever presence output returned Null")
        optics = intf_list
        for data in trans_presence_data:
            if data.get('port') in optics and data.get('presence') != "Present" :
                st.log("Optics for port {} show status to be  {} which is not expected".format(data.get('port'),data.get('presence')))
                raise Exception("Optics for port {} show status to be  {} which is not expected".format(data.get('port'),data.get('presence')))
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_show_int_transceiver_presence(dut,intf_list=[]):
    """
    Validate 'show int transceiver presence' command 
    """
    global vars
    if intf_list == []:
        required_int = ['D{0}D{0}P1','D{0}D{0}P2']
        required_int = [i.format(dut[-1]) for i in required_int]
        intf_list = [vars[i]for i in required_int]
    #Verify Optic presence
    try:
        if verify_optics_presence(dut,intf_list):
            st.log("Optics presence successful for the ports")
            st.log("Verified with show int transceiver presence")
             
            return True
        else:
            st.log("Verification of the optics is unsuccessful")
            st.log("Exception for verification ocuured")
            raise Exception("Verification of the optics was not successful")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False


def ft_optics_with_boot(dut,intf_list=[]):
    """
    Validate 'show int transceiver presence' after reboot command 
    """
    global vars
    if intf_list == []:
        required_int = ['D{0}D{0}P1','D{0}D{0}P2']
        required_int = [i.format(dut[-1]) for i in required_int]
        intf_list = [vars[i]for i in required_int]


    try:
        st.log("Verifying optics before reboot")
        if verify_optics_presence(dut,intf_list):
            st.log("Verificaton of the optics before reboot is successful")
            st.log("Rebooting the DUT")
            st.reboot(vars.D1)
            if verify_optics_presence(dut,intf_list):
                st.log("Verification of the optics after reboot is successful")
                st.log("Reporting the pass of testcase since verification is successful")
                 
                return True
            else:
                st.log("Verification of the optics after reboot is not successful")
                st.log("Reporting the failure of the test case since verification is not successful")
                st.log("Raising the Exception")
                raise Exception("After reboot Optics Verification is not successful")
        else:
            st.log("Verification of the optics after reboot is not successful")
            st.log("Reporting the failure since the verification is not successful")
            st.log("Raising the Exception")
            raise Exception("Before reboot Optics Verification is not successful")
         
        return False
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False

def ft_sfputil_reset(dut,intf=''):
    """
    Validate 'sudo sfputil reset Ethernet[/d+]' after reboot command 
    """
    if intf == '':
        required_int = 'D{0}D{0}P1'.format(dut[-1])
 
    try:
        st.log("Run sfputil reset port")
        reset_port = vars[required_int]
        is_port = False
        is_status = False
        current_date = basic_obj.get_dut_date_time(dut)
        if current_date is None:
            raise Exception("The Parsed Date object retuned None")
        current_date1 = datetime.datetime.strptime(current_date, '%a %d %b %Y %I:%M:%S %p %Z')
        util_data = basic_obj.get_sfputil_reset_ethernet(dut, reset_port)
        if util_data is None:
            st.log("Util data returned None which is not expected")
        st.log("Validating the interface status output")
        asic = required_int+'Npu'
        if cli_type == 'vtysh-multi-asic':
            interface_data = basic_obj.get_interface(dut, reset_port,'vtysh-multi-asic',vars[asic])
        else:
            interface_data = basic_obj.get_interface(dut, reset_port)
        st.log(interface_data)
        if interface_data is None:
            st.log("interface data retuned None")
            raise Exception("Interface data returned None")
        else:
            interface_data = interface_data[0]
            uptime = interface_data.get('uptime')
            downtime = interface_data.get('downtime')
            uptime_date = datetime.datetime.strptime(uptime, '%Y/%m/%d %H:%M:%S.%f')
            downtime_date = datetime.datetime.strptime(downtime, '%Y/%m/%d %H:%M:%S.%f')
            updown_diff_seconds = (uptime_date - downtime_date).total_seconds()
            current_down_seconds = (downtime_date - current_date1).total_seconds()
            current_up_seconds = (uptime_date - current_date1).total_seconds() 
            if interface_data.get('status') == "up" and  updown_diff_seconds < 60 and current_down_seconds < 60 and current_up_seconds < 60:
                st.log("status , uptime , downtime of interface conditions matched")
                st.log("Status is {} and Uptime and current time difference is {} and Current time and down time difference is {} and Uptime and Down time difference of the interface is {}".format(interface_data.get('status'),current_up_seconds,current_down_seconds,updown_diff_seconds))
            else:
                st.log("Atleast one condition failed")
                st.log("Status is {} and Uptime and current time difference is {} and Current time and down time difference is {} and Uptime and Down time difference of the interface is {}".format(interface_data.get('status'),current_up_seconds,current_down_seconds,updown_diff_seconds))
                raise Exception("Interface Flap after issuing reset port had actually didnot happened")
        st.log("Validating the util reset output")
        if isinstance(util_data, list):
            for data in util_data:
                if data.get('port') == reset_port:
                    is_port = True
                    st.log("The Reset message returned is successful and port {} was reset".format(reset_port))
                else:
                    st.log("The Reset message is successful but the reset input port {} and the parsed port {} didnot match".format(reset_port, data.get('port')))
                    raise Exception("The Reset message is successful but the reset input port {} and the parsed port {} didnot match".format(reset_port, data.get('port')))
                if data.get('status') == "OK":
                    is_status = True
                    st.log("Reset message returned as expected successfully and status {} reported ".format(data.get('status')))
                else:
                    st.log("Reset message not returned as expected and status {} reported ".format(data.get('status')))
                    raise Exception("Reset message not returned as expected and status {} reported ".format(data.get('status')))
        else:
            st.log("Reset data expected to be list but resulted {}".format(type(util_data)))
            raise Exception("Reset data expected to be list but resulted {}".format(type(util_data)))
        if is_port and is_status:
            st.log("Status is ok and Port is as expected")
            st.log("Report the test case as passed")
             
            return True
        else:
            st.log("Port or Status returned to be False")
            raise Exception("Port or Status retuned to be false")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
         
        return False


def ft_config_reload(dut):
    """
    Validate 'config reload' command 
    """

    try:
        st.log("Run config reload -y")
        st.log("running config before apply config reload")
        running_config_data1 = basic_obj.get_show_run_all(dut)
        if running_config_data1 is None:
            raise Exception("Running Config data returned None")
        reload_data = basic_obj.apply_config_reload(dut)
        if reload_data is None:
            raise Exception("Parsed data returned None")
        st.log("reload_data")
        st.log(reload_data)
        running_config_data2 = basic_obj.get_show_run_all(dut)
        st.log("running config after apply config reload")
        if running_config_data2 is None:
            raise Exception("Running Config after applying config reload data returned None")
        if running_config_data1 == running_config_data2:
            st.log("Config data")
            st.log("Show running config data before and after applying config reload matched")
            st.log("TEST CASE PASSED")             
            return True
        else:
            st.log("Config data before and after reload are different")
            raise Exception("Config data before {} and afer {} are not matched".format(running_config_data1, running_config_data2))
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def valueComparisions(minimum,value,maximum):
    print(minimum,value,maximum)
    print(float(minimum),float(value),float(maximum))
    if float(minimum) < float(value) < float(maximum):
        return True
    else:
        return False

def processRedisData(redisDomDetails):
    for element in redisDomDetails:
        temperature = element['temperature']
        voltage = element['voltage']
        temphighwarning = element['temphighwarning']
        templowwarning = element['templowwarning']
        vcchighwarning = element['vcchighwarning']
        vcclowwarning = element['vcclowwarning']
    return temperature,voltage,temphighwarning,templowwarning,vcchighwarning,vcclowwarning

def verifyVendorPresence(transceiverOutput):
    """
    Validate Vendor info 
    """
    for row in transceiverOutput:
        if row['vendor_date'] and row['vendor_oui']:
            st.log("All vendor fields exist")
            return True
        else:
            return False

def ft_xcvrd_info_in_db(dut,intf_list=[]):
    """
    Validate the below
        - transceiver information of all ports are in redis: redis-cli -n 6 keys TRANSCEIVER_INFO*
        - transceiver information of each connected port, for example: redis-cli -n 6 hgetall "TRANSCEIVER_INFO|Ethernet0"
        - TRANSCEIVER_DOM_SENSOR of all ports in redis: redis-cli -n 6 keys TRANSCEIVER_DOM_SENSOR*
        - TRANSCEIVER_DOM_SENSOR information of each connected ports for example: redis-cli -n 6 hgetall "TRANSCEIVER_DOM_SENSOR|Ethernet0"
    """

    global vars
    if intf_list == []:
        required_int = ['D{0}D{0}P1','D{0}D{0}P2']
        required_int = [i.format(dut[-1]) for i in required_int]
        intf_list = [vars[i]for i in required_int]

    #Comparision of Interfaces between test bed file and REDIS CLI Command
    interfacesTestBedFile = intf_list

    interfacesDatabase = [element['interface'] for element in basic_obj.get_redis_cli_interface(dut)]
    if interfacesTestBedFile.sort() != interfacesDatabase.sort():
        st.report_fail("Test case failed as interfaces from testbed file didnt match with Interfaces from redis database")

    #Verification of Vendor Fields
    for interface in interfacesDatabase:
        redisInterfaceDetails = basic_obj.get_interface_details_redis(dut, interface.split("Ethernet")[1])
        print(redisInterfaceDetails)
        if verifyVendorPresence(redisInterfaceDetails):
            st.log("All vendor fields exist for interface {} in redis".format(interface))
        else:
            raise Exception("Test case failed as vendor information is missing")

    #Comparision of Iterfaces between testbed file and DOM Sensor Command
    interfacesDOMSENSOR = [element['interface'] for element in basic_obj.get_redis_cli_interface_dom_sensors(vars.D1)]
    if interfacesTestBedFile.sort() != interfacesDOMSENSOR.sort():
        st.report_fail("Test case failed as interfaces from testbed file didnt match with Interfaces from redis database")
    #Verification of Temperature, voltage
    for interface in interfacesDOMSENSOR:
        redisDomDetails = basic_obj.get_redis_int_dom(dut, interface.split("Ethernet")[1])
        print(redisDomDetails)
        temperature, voltage, temphighwarning, templowwarning, vcchighwarning, vcclowwarning = processRedisData(redisDomDetails)
        if valueComparisions(templowwarning, temperature, temphighwarning):
            st.log("Temperature values are within the range")
        else:
            print("Type of error occured:", sys.exc_info()[0])
            raise Exception("Test case failed as Temperature values are not within range")
        if valueComparisions(vcclowwarning, voltage, vcchighwarning):
            st.log("Voltage values are within the range")
        else:
            print("Type of error occured:", sys.exc_info()[0])
            raise Exception("Test case failed as Voltage values are not within range")
            
    st.report_pass("test_case_passed")
 

def ft_external_controller_reachability(dut):


    #Gathering RP IP address from yaml file
    rp_ip_address = st.get_rp_ip_address(dut)
    print(rp_ip_address)

    #Gathering eth1 from LC
    lc_ifconfig_eth1 = basic_obj.ifconfig_eth(dut, 1)
    print(lc_ifconfig_eth1[0]['inet'])
    lc_eth1=lc_ifconfig_eth1[0]['inet']


    #Gathering eth1 from RP
    ssh_RP = connect_to_device(rp_ip_address, "cisco", "cisco123")
    if ssh_RP:
        st.log("Executing command - 'ifconfig eth1' in to the SSH session.")
        st.log(execute_command(ssh_RP, 'sudo ifconfig eth1'))
        RPoutput = execute_command(ssh_RP, 'sudo ifconfig eth1')
        RPoutput = RPoutput.split()
        RPeth1 = RPoutput[RPoutput.index('inet') + 1]
        st.wait(5, 'After executing "sudo ifconfig eth1" cmd on SSH session.')
        st.log("Forcefully disconnecting the SSH session..")
        ssh_disconnect(ssh_RP)
    else:
        raise Exception('SSH connection unsuccessful')

    #Verifying Internal reachability from RP to LC
    ssh_RP = connect_to_device(rp_ip_address, "cisco", "cisco123")
    if ssh_RP:
        st.log("Executing PING command in on RP")
        RPpingoutput = execute_command(ssh_RP, 'sudo ping {} -c 5'.format(lc_eth1))
        RPpingoutput = RPpingoutput.split("\n")
        for line in RPpingoutput:
            if "loss" in line:
                line= line.split()
                pingresult = line[line.index("loss,")-2]
        if pingresult == "0%":
            RPpingresult = True
        else:
            RPpingresult = False
        st.wait(5, 'After executing ping cmd on SSH session.')
        st.log("Forcefully disconnecting the SSH session..")
        ssh_disconnect(ssh_RP)
    else:
        raise Exception('SSH connection unsuccessful')

    #Verifying Internal reachability from LC to RP
    LCpingresult = ipfeature.ping(dut, lc_eth1)

    if RPpingresult and LCpingresult:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")
        
def verify_optics_presence_at_port(dut, port):
    """
    Validate 'optics present at port selected'
    param: dut
    param: port
    """
    try:
        st.log("Start of Optics Verification for selcted port {}".format(port))
        trans_presence_data = basic_obj.get_show_int_transceiver_presence(dut)
        if trans_presence_data is None:
            raise Exception("Parsed transciever presence output returned Null")
        for data in trans_presence_data:
            if data.get('port') == port and data.get('presence') != "Present" :
                st.log("Optics for port {} show status to be  {} which is not expected".format(data.get('port'),data.get('presence')))
                raise Exception("Optics for port {} show status to be  {} which is not expected".format(data.get('port'),data.get('presence')))
            else:
                st.log("Verification of the optics presence is successful for port {} with status {}".format(data.get('port'),data.get('presence')))
                return True
        st.log("End of Optics Verification for selected port {}".format(port))
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False
    
def get_current_date_on_dut(dut):
    """
    Validate 'Get current date in date strptime format from dut'
    param: dut
    """
    try:
        current_date = basic_obj.get_dut_date_time(dut)
        if current_date is None:
            raise Exception("The Parsed Date object retuned None")
        current_date1 = datetime.datetime.strptime(current_date, '%a %d %b %Y %I:%M:%S %p %Z')
        return current_date1
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return None

def verify_eeprom_status(dut,port,status_expected):
    """
    Verify the eeprom status if not detected
    param: dut
    param: port
    """
    try:
        transceiverOutput = basic_obj.get_sfputil_show_eeprom(dut)
        for row in transceiverOutput:
            if (row['interface'] == port):
                st.log("Interface port matched with the EEPROM OUPUT")
                if (row['status'] == status_expected):
                    st.log("Interfaces with  {} status matched which is  expected after executing sfp.py off ".format(row['status']))
                    st.log("Successfully Verified the eeprom status ")
                    return True
                else:
                    st.log("Interfaces with  {} status matched which is not expected after executing sfp.py off ".format(row['status']))
                    raise Exception("Interfaces with  {} status matched which is not expected after executing sfp.py off ".format(row['status']))
        st.log("sfp show eeprom not able to get the value of the {} port".format(port))
        raise Exception("sfp show eeprom not able to get the value of the {} port".format(port))
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False
    
def ft_optics_simulation(dut):
    """
    Validate 'sfp.py on {portnumber}' and 'sfp.py off {portnumber}' 
    """

    #Getting the low power mode data as object
    try:
        st.log("Run optics simulation")
        is_sfp_off = False
        port = vars.D1D2P1
        #Extract port number from the Port
        port_ethernet = port[0:8]
        port_number = port[8:]
        port_number = unicode(port_number, 'utf-8')
        if port_ethernet == "Ethernet" and port_number.isnumeric():
            st.log("Verification format for the port {} successful".format(port))
            st.log("Port number Verification and Storage successful")
        else:
            st.log("Port Verification format failed for the port {}".format(port))
            raise Exception("Port Verification format failed for the port {}".format(port))
        #Check if the optics is present at this port
        st.log("IN MAIN TEST CASE, Start of Optics Verification for selcted port {} ".format(port))
        if verify_optics_presence_at_port(dut,port):
            st.log("Verifier of Optics presence at Port {} returned True".format(port))
        else:
            st.log("Verifier of Optics presence at Port {} returned False".formart(port))
            raise Exception("Verifier of Optics presence at Port {} returned False".formart(port))
        st.log("IN MAIN TEST CASE,  End of Optics Verification for selected port {}".format(port))
        #Collect the current date and time 
        current_date =  get_current_date_on_dut(dut)
        #Turn off the optics with "sfp.py off {port-number}"
        optics_off = basic_obj.apply_optics_flap(dut, port_number,'off')
        #Check the status of Ethernet port if went down 
        st.log("Verifying the interface status output")
        interface_data = basic_obj.get_interface(dut, port)
        st.log(interface_data)
        if interface_data is None:
            st.log("interface data retuned None")
            raise Exception("Interface data returned None")
        else:
            interface_data = interface_data[0]
            uptime = interface_data.get('uptime')
            downtime = interface_data.get('downtime')
            downtime_date = datetime.datetime.strptime(downtime, '%Y/%m/%d %H:%M:%S.%f')
            st.log("downtime_date is {}".format(downtime_date))
            current_down_seconds = (downtime_date - current_date).total_seconds()
            if interface_data.get('status') == "down" and current_down_seconds < 60:
                st.log("status, downtime of interface conditions matched")
                st.log("Status is {} and  Current time and down time difference is {} ".format(interface_data.get('status'),current_down_seconds))
            else:
                st.log("Atleast one condition failed")
                st.log("Status is {} and Current time and down time difference is {} which didnot matched the expectation".format(interface_data.get('status'),current_down_seconds))
                raise Exception("Interface Flap after issuing reset port had actually didnot happened")
        #Check the sfputil show eeprom if Not detected
        st.log("CHECKING THE STATUS OF EEPROM")
        if verify_eeprom_status(dut,port,"not detected"):
            st.log("Verifier for eeprom status returned True")
            st.log("Verifier for eeprom is successful for the port {}".format(port))
        else:
            st.log("Verifier for eeprom expeceted to be not detected is not successful")
            raise Exception("Verifier for eeprom status expected to be Not dectected but retuned detected")
        #Collect the current date and time 
        current_date = get_current_date_on_dut(dut)
        st.log("TURNING ON THE SFP ON PORT {}".format(port))
        optics_on = basic_obj.apply_optics_flap(dut, port_number,'on')
        #Check the status of Ethernet port if went up
        st.log("Verifying the interface status output")
        interface_data = basic_obj.get_interface(dut, port)
        st.log(interface_data)
        if interface_data is None:
            st.log("interface data retuned None")
            raise Exception("Interface data returned None")
        else:
            interface_data = interface_data[0]
            uptime = interface_data.get('uptime')
            downtime = interface_data.get('downtime')
            uptime_date = datetime.datetime.strptime(uptime, '%Y/%m/%d %H:%M:%S.%f')
            current_up_seconds = (uptime_date - current_date).total_seconds()
            if interface_data.get('status') == "up" and current_up_seconds < 60:
                st.log("status, uptime of interface conditions matched")
                st.log("Status is {} and  Current time and up time difference is {} ".format(interface_data.get('status'),current_up_seconds))
            else:
                st.log("Atleast one condition failed")
                st.log("Status is {} and Current time and down time difference is {} which didnot matched the expectation".format(interface_data.get('status'),current_up_seconds))
                raise Exception("Interface Flap after issuing reset port had actually didnot happened")
        #Check the sfputil show eeprom if detected
        st.log("CHECKING THE STATUS OF EEPROM")
        if verify_eeprom_status(dut,port,"detected"):
            st.log("Verifier for eeprom status returned True")
            st.log("Verifier for eeprom is successful for the port {}".format(port))
        else:
            st.log("Verifier for eeprom expected to be detected is not successful")
            raise Exception("Verifier for eeprom status expected to be dectected but retuned Not detected")
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.log("Exception occured , need to set optics back so turn on optics to keep system in stable state")
        st.report_fail("test_case_failed")
        
def verify_optics_presence_at_port(dut, port):
    """
    Validate 'optics present at port selected'
    param: dut
    param: port
    """
    try:
        st.log("Start of Optics Verification for selcted port {}".format(port))
        trans_presence_data = basic_obj.get_show_int_transceiver_presence(dut)
        if trans_presence_data is None:
            raise Exception("Parsed transciever presence output returned Null")
        for data in trans_presence_data:
            if data.get('port') == port and data.get('presence') != "Present" :
                st.log("Optics for port {} show status to be  {} which is not expected".format(data.get('port'),data.get('presence')))
                raise Exception("Optics for port {} show status to be  {} which is not expected".format(data.get('port'),data.get('presence')))
            else:
                st.log("Verification of the optics presence is successful for port {} with status {}".format(data.get('port'),data.get('presence')))
                return True
        st.log("End of Optics Verification for selected port {}".format(port))
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False
    
def get_current_date_on_dut(dut):
    """
    Validate 'Get current date in date strptime format from dut'
    param: dut
    """
    try:
        current_date = basic_obj.get_dut_date_time(dut)
        if current_date is None:
            raise Exception("The Parsed Date object retuned None")
        current_date1 = datetime.datetime.strptime(current_date, '%a %d %b %Y %I:%M:%S %p %Z')
        return current_date1
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return None

def verify_eeprom_status(dut,port,status_expected):
    """
    Verify the eeprom status if not detected
    param: dut
    param: port
    """
    try:
        transceiverOutput = basic_obj.get_sfputil_show_eeprom(dut)
        for row in transceiverOutput:
            if (row['interface'] == port):
                st.log("Interface port matched with the EEPROM OUPUT")
                if (row['status'] == status_expected):
                    st.log("Interfaces with  {} status matched which is  expected after executing sfp.py off ".format(row['status']))
                    st.log("Successfully Verified the eeprom status ")
                    return True
                else:
                    st.log("Interfaces with  {} status matched which is not expected after executing sfp.py off ".format(row['status']))
                    raise Exception("Interfaces with  {} status matched which is not expected after executing sfp.py off ".format(row['status']))
        st.log("sfp show eeprom not able to get the value of the {} port".format(port))
        raise Exception("sfp show eeprom not able to get the value of the {} port".format(port))
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False
    

def verify_platform_ssdhealth(dut):
    """
    Verify platform ssdhealth
    """
    try:
        #Get platform ssdhealth as obj 
        result = basic_obj.get_platform_ssdhealth(dut)
        if result is None:
            st.log("Parsed ssdhealth result is not None")
            raise Exception("Parsed ssdhealth result is not None")
        #Check the validation with input and compare the values
        devicemodel = result.get('devicemodel').split(" ")[0]
        if result.get('devicemodel') is None or devicemodel != platform_details.get('devicemodel'):
            raise Exception("Parsed device model {} not matched the expectation {} result".format(devicemodel, platform_details.get('devicemodel')))
        if result.get('health') is None or result.get('health') != platform_details.get('health'):
            raise Exception("Parsed health val {} not matched with input health val".format(result.get('health'), platform_details.get('health')))
        if result.get('temperature') is None :
            raise Exception("Parsed temperature val {} not matched with input temperature val".format(result.get('temperature'))) 
        st.log("show platform ssdhealth completed")
        return True
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        return False

def ft_platform_ssdhealth(dut):
    """
    Validate 'show platform ssdhealth' command
    """


    try:
        st.log("IN TEST PLATFORM SSDHEALTH")
        if verify_platform_ssdhealth(dut):
            st.log("IN TEST PLATFORM SSDHEALTH")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
            st.report_pass("test_case_passed")
        else:
            st.log("IN TEST PLATFORM SSDHEALTH")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier ssdhealth returned false, reporting test case failed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")

def ft_show_environment(dut):
    """
    Validate 'show environment' command
    """

    try:
        st.log("IN SHOW ENVIRONMENT TEST")
        st.log("This testcase covers three test cases from the test plan")

        #Get platform name 
        platform_name = st.get_platform_type(dut)
        if platform_name is None:
            st.log("Platform name")
            st.log(platform_name)
            st.log("Platform name from the input test bed file retuned None {}")
            raise Exception("Platform name from the input test bed file retuned None")
        #Get object from the platform_name from my current file
        pdata_obj = get_platform_data(platform_name) 
        if pdata_obj is None:
            st.log("Platform object")
            st.log(pdata_obj)
            st.log("Platform object from the current object retuned None {}")
            raise Exception("Platform data object from the current file returned none to get data")

        environment_data = basic_obj.get_show_environment(dut)
        st.log(environment_data)

        if environment_data is None:
            st.log("Parsed env data returned null which is not expected and says env data is empty")
            raise Exception("Parsed env data retuned null")
         
        if isinstance(environment_data, list):
            for data in environment_data:
                if data.get('sensor') in pdata_obj.get('voltage_sensors'):
                    if((float(data.get('voltage')) > float(data.get('critical_voltage_min')) and float(data.get('voltage')) < float(data.get('critical_voltage_max'))) or (float(data.get('voltage')) < float(data.get('critical_voltage_min')) and float(data.get('voltage')) > float(data.get('critical_voltage_max')))):
                        st.log("Voltage {} matched to the expectation in the range between {} and {} for the sensor {}".format(data.get('voltage'), data.get('critical_voltage_min'), data.get('critical_voltage_max'), data.get('sensor')))
                    else:
                        st.log("Voltage {} not matched to the expectation in the range between {} and {} for the sensor {}".format(data.get('voltage'), data.get('critical_voltage_min'), data.get('critical_voltage_max'), data.get('sensor')))
                        raise Exception("Voltage {} matched to the expectation in the range between {} and {} for the sensor {}".format(data.get('voltage'), data.get('critical_voltage_min'), data.get('critical_voltage_max'), data.get('sensor')))
                if data.get('sensor') in pdata_obj.get('current_sensors'):
                    if(float(data.get('current')) < float(data.get('critical_current_max'))):
                        st.log("Current {} matched to the expectation in the range below  {} for the sensor {}".format(data.get('current'), data.get('critical_current_max'), data.get('sensor')))
                    else:
                        st.log("Current {} matched to the expectation in the range below  {} for the sensor {}".format(data.get('current'), data.get('critical_current_max'), data.get('sensor')))
                        raise Exception("Current {} matched to the expectation in the range below  {} for the sensor {}".format(data.get('current'), data.get('critical_current_max'), data.get('sensor')))
        else:
            st.log("Returned object expected to be list but returned type is {}".format(type(environment_data)))
            raise Exception("Environment data expected to be list but resulted {}".format(type(environment_data)))
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")

def verify_psu_oir_status(dut, psu_name, status):
    """
    Verify "PSU OIR SIMULATION"
    """
    vars = st.get_testbed_vars()
    dut = vars.D1
    try:
        st.log("IN SHOW PLATFORM PSUSTATUS")
        psu_data = basic_obj.get_platform_psustatus(dut)
        if psu_data is None:
            st.log("Result returned None")
        print(psu_data)
        is_psu_status = False
        #Check if the PSU Listed first is OK 
        if isinstance(psu_data, list):
            for row in psu_data:
                if row.get('psu') == psu_name:
                    st.log("found the row with fan name")
                    data = row
        else:
            st.log("Returned object expected to be dict but returned type is {}".format(type(psu_data)))
            raise Exception("Fan data expected to be dict but resulted {}".format(type(psu_data)))

        #Check if the status is "OK" for first PSU as of now 
        if data.get('voltage') == 'N/A' and data.get('current') == 'N/A' and data.get('led') == 'N/A' and data.get('power') == 'N/A' and data.get('status') == status:
            st.log("PSU Status is listed {} which is expected".format(data.get('status')))
            st.log("PSU Status is OK for PSU {}".format(data.get('psu')))
            st.log("Updating the psu_status boolean value to true if found one PSU")
            is_psu_status = True
        else:
            st.log("PSU Status is {} for PSU name {}".format(data.get('status'),data.get('psu')))
            st.log("Psu reported not present or not ok")
        if is_psu_status:
            st.log("Atleast one PSU status found Ok ")
            st.log("Verifier of PSU STatus successfully verified")
            st.log("Verifier returning true")
            st.log("EXITING VERIFIER")
            return True
        else:
            st.log("Atleast one PSU have not reported status to be OK or PRESENT , so reporting the test case to be failed")
            raise Exception("PSU Status is listed NOT PRESENT which is not expected")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")

def ft_psu_oir_simulation(dut):
    """
    Validate 'show platform psustatus' command
    """
    

    try:
        st.log("IN TEST PLATFORM PSUSTATUS VALID")
        psu_data = basic_obj.get_platform_psustatus(dut)
        st.log("IN TEST PLATFORM PSUSTATUS VALID")
        st.log("psustatus started")
        #Get platform psustatus as obj
        st.log("Get the show platform psustatus output")
        psu_data = basic_obj.get_platform_psustatus(dut)
        print("parsed result")
        print(psu_data)
        st.log("Starting validation on fan data output")        
        if psu_data is None:
            raise Exception("Parsed Fan data output returned None")
        #Verify psu status to be Ok, if not report failure
        if isinstance(psu_data, list):
            data = psu_data[0]
        else:
            st.log("Returned object expected to be dict but returned type is {}".format(type(psu_data)))
            raise Exception("Fan data expected to be dict but resulted {}".format(type(psu_data)))
        psu_name = data.get('psu')
        if verify_psu_oir_status(dut, psu_name, "OK"):
            st.log("IN TEST PLATFORM PSU OIR SIMULATION")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
            st.report_pass("test_case_passed")
        else:
            st.log("IN TEST PLATFORM PSU OIR SIMULATION")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier psustatus returned false, reporting test case failed")
        st.log("OVERWRITE THE THERMAL_ZONE.YAML file at the dut location /opt/cisco/etc")
        #Update the thermal_zone.yaml with power_devices attribute-psu0 presence feild to 0
        basic_obj.update_presence_in_thermalzone(dut, "power_devices")
        st.log("config reload")
        basic_obj.apply_config_reload(dut)
        st.log("Verify if the psu status after the simulation of off after the config  =reload")
        st.wait(60)
        if verify_psu_oir_status(dut, psu_name, "NOT PRESENT"):
            st.log("IN TEST PLATFORM PSU OIR SIMULATION")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
            st.report_pass("test_case_passed")
        else:
            st.log("IN TEST PLATFORM PSU OIR SIMULATION")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier psustatus returned false, reporting test case failed")  
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")
    finally:
        st.show(dut, 'sudo cp /tmp/thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)
        basic_obj.apply_config_reload(dut)

def verify_fan_status(dut, fan_name, status):
    """
    Verify "FAN OIR SIMULATION"
    """
    vars = st.get_testbed_vars()
    dut = vars.D1
    try:
        st.log("fan started")
        #Get platform fan as obj
        st.log("Get the show platform fan output")
        fan_data = basic_obj.get_platform_fan(dut)
        print("parsed result")
        print(fan_data)
        st.log("Starting validation on fan data output")        
        if fan_data is None:
            raise Exception("Parsed Fan data output returned None")
        #Verify fan status to be Ok, if not report failure
        if isinstance(fan_data, list):
            for row in fan_data:
                if row.get('fan') == fan_name:
                    st.log("found the row with fan name")
                    data = row
        else:
            st.log("Returned object expected to be dict but returned type is {}".format(type(fan_data)))
            raise Exception("Fan data expected to be dict but resulted {}".format(type(fan_data)))
        is_fan_status = False
        #Check if the Fan Listed first is OK 
        #Check if the status is "OK" for first Fan as of now 
        if data.get('presence').lower() == status.lower():
            st.log("Fan Status is listed {} which is expected".format(data.get('status')))
            st.log("Fan Status is OK for PSU {}".format(data.get('fan')))
            st.log("Updating the psu_status boolean value to true if found one fan")
            is_fan_status = True
        else:
            st.log("Fan Status is {} for Fan name {}".format(data.get('status'),data.get('fan')))
            st.log("Fan reported not present or not ok")
        if is_fan_status:
            st.log("Atleast one Fan status found Ok ")
            st.log("Verifier of Fan STatus successfully verified")
            st.log("Verifier returning true")
            st.log("EXITING VERIFIER")
            return True
        else:
            st.log("Atleast one Fan have not reported status to be OK or PRESENT , so reporting the test case to be failed")
            raise Exception("Fan Status is listed NOT PRESENT which is not expected")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")

def ft_fan_oir_simulation(dut):
    """
    Validate 'show platform fan' command
    """
    

    try:
        st.log("IN TEST PLATFORM FANSTATUS VALID")
        st.log("fan started")
        #Get platform fan as obj
        st.log("Get the show platform fan output")
        fan_data = basic_obj.get_platform_fan(dut)
        print("parsed result")
        print(fan_data)
        st.log("Starting validation on fan data output")        
        if fan_data is None:
            raise Exception("Parsed Fan data output returned None")
        #Verify fan status to be Ok, if not report failure
        if isinstance(fan_data, list):
            data = fan_data[0]
        else:
            st.log("Returned object expected to be dict but returned type is {}".format(type(fan_data)))
            raise Exception("Fan data expected to be dict but resulted {}".format(type(fan_data)))
        fan_name = data.get('fan')
        if verify_fan_status(dut, fan_name, "PRESENT"):
            st.log("IN TEST PLATFORM FAN OIR SIMULATION")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
            st.report_pass("test_case_passed")
        else:
            st.log("IN TEST PLATFORM FAN OIR SIMULATION")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier psustatus returned false, reporting test case failed")
        st.log("OVERWRITE THE THERMAL_ZONE.YAML file at the dut location /opt/cisco/etc")
        basic_obj.update_presence_in_thermalzone(dut, "cooling_devices")
        st.log("config reload")
        reload_data = basic_obj.apply_config_reload(dut)
        st.wait(60)
        st.log("Verify if the fan status after the simulation of off after the config  =reload")
        if verify_fan_status(dut, fan_name, "NOT PRESENT"):
            st.log("IN TEST PLATFORM Fan OIR SIMULATION")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING THE TEST CASE PASSED")
            st.report_pass("test_case_passed")
        else:
            st.log("IN TEST PLATFORM Fan OIR SIMULATION")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier fanstatus returned false, reporting test case failed")  
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")
    finally:
        st.show(dut, 'sudo cp /tmp/thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)
        basic_obj.apply_config_reload(dut)

def verify_thermal_fault_injection(dut, sensor_name):
    """
    Verify the thermal fault injection
    """

    high_th = platform_details.get("fault_thermal_induction").get("high_th")
    parsed_sensor_data =basic_obj.get_parsed_temp_output_grep_sensor_name(dut, sensor_name)
    original_th = parsed_sensor_data[1]
    #Start time 
    start_point = basic_obj.get_parsed_date_to_capture_syslog(dut)
    #Inject Alarm 
    cmd = "docker exec -ti pmon bash -c \"echo {} > /tmp/{}\"".format(high_th, sensor_name)
    st.show(dut, cmd,  skip_tmpl=True)
    #Wait for 62 sec 
    st.wait(62)
    #Check the value of show plat temp 
    parsed_sensor_data = basic_obj.get_parsed_temp_output_grep_sensor_name(dut, sensor_name)
    if parsed_sensor_data[0] != sensor_name:
        raise Exception("Parsed sensor name {} not matched the expectation to input sensor name {}".format(parsed_sensor_data[0],sensor_name))
    if parsed_sensor_data[1] != str(high_th):
        raise Exception("Parsed sensor temp value {} not matched the expectation to input high th {}".format(parsed_sensor_data[1],high_th))
    if parsed_sensor_data[-2] != "True":
        raise Exception("Parsed sensor warning {} not matched the expectation to expected sensor warning {}".format(parsed_sensor_data[-2],"true"))
    #Inject Clear Alarm 
    cmd = "docker exec -ti pmon bash -c \"rm /tmp/{}\"".format(sensor_name)
    st.show(dut, cmd,  skip_tmpl=True)
    #Wait for 62 sec
    st.wait(62)
    #Check the value of show plat temp 
    parsed_sensor_data =basic_obj.get_parsed_temp_output_grep_sensor_name(dut, sensor_name)
    if parsed_sensor_data[0] != sensor_name:
        raise Exception("Parsed sensor name {} not matched the expectation to input sensor name {}".format(parsed_sensor_data[0],sensor_name))
    if not ((float(parsed_sensor_data[1]) < float(original_th)+10) or (float(parsed_sensor_data[1]) > float(original_th)-10)):
        raise Exception("Parsed original temp value {} not matched the expectation to input temp value {}".format(parsed_sensor_data[1],original_th))
    if parsed_sensor_data[-2] != "False":
        raise Exception("Parsed warning {} not matched the expectation to input warning {}".format(parsed_sensor_data[-2],"false"))
    original_th = float(parsed_sensor_data[1])
    actual_high_th = parsed_sensor_data[2]
    st.wait(62)
    #Record Endtime
    end_point = basic_obj.get_parsed_date_to_capture_syslog(dut)    
    #Capture Syslog
    high_th = float(high_th)
    actual_high_th = float(actual_high_th) 
    warningfilterlog = "pmon#thermalctld: High temperature warning: {} current temperature {}C, high threshold {}C".format(sensor_name, high_th, actual_high_th)
    isAlarmMatchFound = basic_obj.capture_syslog_between_timestamps(dut, start_point, end_point, warningfilterlog)  
    if not isAlarmMatchFound:
        raise Exception("The High Temperature Warning Set syslog is not found")
    clearfilterlog = "pmon#thermalctld: High temperature warning cleared: {} temperature restored to {}C, high threshold {}C".format(sensor_name, original_th, actual_high_th)
    isClearMatchFound = basic_obj.capture_syslog_between_timestamps(dut, start_point, end_point, clearfilterlog)
    if not isClearMatchFound:
        raise Exception("The Clear Warning Set syslog is not found")
    return "Thermal Fault Injection Validation for the sensor {} successful".format(sensor_name)

def ft_temp_major_alarm(dut):
    """
    Verify alarm status and syslog entry incase of high temperature
    """

    try:
        st.log("IN TEST PLATFORM TEMP MAJOR ALARM ")
        list_of_sensors = platform_details.get("fault_thermal_induction").get("list_of_sensors")
        st.log("Input list of sensors are currently only three listed top of the file")
        for sensor_name in list_of_sensors:
            valid_result = verify_thermal_fault_injection(dut, sensor_name)
            if valid_result != "Thermal Fault Injection Validation for the sensor {} successful".format(sensor_name):
                raise Exception("Exception occured in the Parent validation check for the sensor ")
                st.report_fail("test_case_failed")        
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")


def ft_watchdog_arm_reload(dut):
    """
    Verify the watchdog arm 
    """

    try:
        st.log("IN TEST PLATFORM Fan Major alarm check")
        st.log("Get the platform.json inside the pmon container in dut for mathilda details")
        watchdog_status = basic_obj.get_watchdog_status(dut)
        if watchdog_status[0].get('status') == "Unarmed":
            st.log("Verified watchdog status is unarmed")
        else:
            raise Exception("Watchdog status not matched to expected")
        watchdog_arm_status = basic_obj.change_watchdog_status_to_arm(dut)
        no_of_seconds = watchdog_arm_status[0].get('no_of_seconds')
        st.wait(int(no_of_seconds))
        uptime_obj = basic_obj.get_uptime(dut)
        if not (int(uptime_obj[0].get('minutes')) >= 0 or int(uptime_obj[0].get('minutes')) <= 5):
            st.log("reload after watchdog status changed to arm is not successful")
            raise Exception("The reload is not successful after the watchod status change to armed")
        st.log("reload after watchdog status changed to arm is  successful")
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")

def ft_fan_tray_major_alarm(dut): 
    """
    Verify the faulty fan tray
    """

    try:
        st.log("IN TEST PLATFORM Fan Major alarm check")
        st.log("Get the platform.json inside the pmon container in dut for mathilda details")
        if verify_platform_fanstatus_valid(dut):
            st.log("IN TEST PLATFORM FAN VALIDgit ")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING validation of fan is successful")
        else:
            st.log("IN TEST PLATFORM FAN VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier fan returned false, reporting test case failed")
        #Start time 
        start_point = basic_obj.get_parsed_date_to_capture_syslog(dut)
        #Checking for fan tray failure 
        basic_obj.update_fan_tray_faulty_presence_in_thermalzone(dut, "cooling_devices")
        st.log("Reboot")
        st.reboot(dut)
        #Record Endtime
        end_point = basic_obj.get_parsed_date_to_capture_syslog(dut)
        st.wait(60) 
        #Capture Syslog
        fantrayfilterlog = "Nonfunctional fan trays; 1 of 3 fan trays not functioning correctly"
        isAlarmMatchFound = basic_obj.capture_syslog_between_timestamps(dut, start_point, end_point, fantrayfilterlog)  
        if not isAlarmMatchFound:
            raise Exception("The Fan syslog is not found")
        st.log("Fault Injection Validation for the sensor {} successful")
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")
    finally:
        st.show(dut, 'sudo cp /opt/cisco/thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)
        st.reboot(dut)

def get_total_number_of_fans(dut):
    """
    Get total number of fans
    """

    fan_data = basic_obj.get_platform_fan(dut)
    print("parsed result")
    print(fan_data)
    st.log("Starting validation on fan data output")        
    if fan_data is None:
        raise Exception("Parsed Fan data output returned None")
    #Verify fan status to be Ok, if not report failure
    if isinstance(fan_data, list):
        return len(fan_data)
    else:
        st.log("Returned object expected to be dict but returned type is {}".format(type(fan_data)))
        raise Exception("Fan data expected to be dict but resulted {}".format(type(fan_data)))

def ft_fan_major_alarm(dut):
    """
    Verify the faulty fan 
    """

    try:
        st.log("IN TEST PLATFORM Fan Major alarm check")
        st.log("Get the platform.json inside the pmon container in dut for mathilda details")
        if verify_platform_fanstatus_valid(dut):
            st.log("IN TEST PLATFORM FAN VALID")
            st.log("VERIFIER RETURNED TRUE")
            st.log("REPORTING validation of fan is successful")
            st.report_pass("test_case_passed")
        else:
            st.log("IN TEST PLATFORM FAN VALID")
            st.log("VERIFIER RETURNED FALSE")
            st.log("REPORTING THE TEST CASE FAILED")
            raise Exception("Verifier fan returned false, reporting test case failed")
        #Start time 
        start_point = basic_obj.get_parsed_date_to_capture_syslog(dut)
        #Checking for fan tray failure 
        basic_obj.update_fan_faulty_presence_in_thermalzone(dut, "cooling_devices")
        st.log("reboot the dut")
        st.reboot(dut)
        #Record Endtime
        end_point = basic_obj.get_parsed_date_to_capture_syslog(dut)
        st.wait(60)
        total_no_of_fans = get_total_number_of_fans(dut)     
        fanfilterlog = "Faulty fans: 3 of {} present fans faulty".format(total_no_of_fans)
        isAlarmMatchFound = basic_obj.capture_syslog_between_timestamps(dut, start_point, end_point, fanfilterlog)  
        if not isAlarmMatchFound:
            raise Exception("The Fan syslog is not found")
        st.log("Fault Injection Validation for the sensor {} successful")
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")
    finally:
        st.show(dut, 'sudo cp /opt/cisco/thermal_zone.yaml /opt/cisco/etc/thermal_zone.yaml',  skip_tmpl=True)
        st.reboot(dut)

def ft_board_led_status(dut):
    """
    Verify Board LED status
    """

    content = "import sonic_platform \nplatform = sonic_platform.platform.Platform() \nchassis = platform.get_chassis() \nchassis.test_status_led()"
    file_path = "/tmp/test.py"
    try:
        st.log("IN TEST PLATFORM TEMP MAJOR ALARM ")
        result = basic_obj.get_system_led_status(dut)
        if result.boot_status != '' and result.boot_status == "System is currently booting...":
            st.wait(120)
        result = basic_obj.get_system_led_status(dut)
        if result.boot_status == '' and result.led_status == "green":
            st.log("LED Status matched to expected green")
        else:
            raise Exception("The expect status of led didnot matched to expected green")
        #Create a file in the specified file_path and add the content to the file
        file_cmd = "sudo echo -e '{}' > {}".format(content, file_path)
        st.show(dut, file_cmd,  skip_tmpl=True)
        #Run the python file created on the specified file_path
        run_python_cmd = "sudo python3 {}".format(file_path)
        result = st.show(dut, run_python_cmd,  skip_tmpl=True)
        result = result.encode()
        #result should be parsed 
        parsed_ouput = result.split("\n")
        del parsed_ouput[-1]
        for data in parsed_ouput:
            parsed_data = data.split("-")
            if parsed_data[1].strip() != "Passed":
                st.log("{} is {}".format(parsed_data[0], parsed_data[1]))
                raise Exception("{} is {} not expected".format(parsed_data[0], parsed_data[1]))
            st.log("{} is {}".format(parsed_data[0], parsed_data[1]))
            st.log("Status resulted as expected")
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")
    finally:
        rm_file_cmd = "sudo rm {}".format(file_path)
        st.show(dut, rm_file_cmd,  skip_tmpl=True)

def ft_multi_npu_status(dut):
    """
    Verify MultiNPU status 
    """
  
    content = 'from sonic_py_common import device_info \nnpus_count = device_info.get_num_npus() \nprint("npus_count on the dut = {}".format(npus_count)) \nnpu_status = device_info.is_multi_npu() \nprint("npu_status on the dut = {}".format(npu_status))'
    file_path = "/tmp/test.py"
    try:
        #Create a file in the specified file_path and add the content to the file
        st.log("Check if the dut is multi npu or single npu")
        file_cmd = "sudo echo -e '{}' > {}".format(content, file_path)
        st.show(dut, file_cmd,  skip_tmpl=True)
        #Run the python file created on the specified file_path
        run_python_cmd = "sudo python3 {}".format(file_path)
        result = st.show(dut, run_python_cmd,  skip_tmpl=True)
        result = result.encode()
        parsed_result = result.split("\n")
        del parsed_result[-1]
        npu_count = int(parsed_result[0].split("=")[1].strip())
        npu_status = parsed_result[1].split("=")[1].strip()
        if npu_status == "True":
            st.log("Multi-npu verification successful")
            st.log("Multi npu status returns true")
        else:
            st.log("Multi-npu verification returned False")
            st.log("Not a Multi-NPU setup")
        npus_cmd = "fgrep -l NPU /sys/class/uio/*/name"
        output = st.show(dut, npus_cmd,  skip_tmpl=True)
        output = output.encode()
        parsed_output = output.split("\n")
        del parsed_output[-1]
        no_of_npus = len(parsed_output)
        st.log("Number of NPU's present is {}".format(no_of_npus))
        st.log("Number of NPU's displayed as above")
        if npu_count == no_of_npus:
            st.log("No of npus matched as per the expectation to {}".format(no_of_npus))
        else:
            raise Exception("No of npus not matched as expected {} and {}".format(no_of_npus, npu_count))
        st.report_pass("test_case_passed")
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed")
    finally:
        rm_file_cmd = "sudo rm {}".format(file_path)
        st.show(dut, rm_file_cmd,  skip_tmpl=True)


@pytest.mark.rp_and_lc
@pytest.mark.with_reboot
def test_ft_platform_idprom_with_reboot():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.both,ft_platform_idprom_with_reboot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.with_out_reboot
@pytest.mark.rp_and_lc
def test_ft_platform_idprom_valid():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.both,ft_platform_idprom_valid)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp_and_lc
@pytest.mark.with_reboot
def test_ft_platform_syseeprom_with_reboot():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.both,ft_platform_syseeprom_with_reboot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_platform_syseeprom_valid():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.both,ft_platform_syseeprom_valid)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_platform_inventory():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.both,ft_platform_inventory)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp
@pytest.mark.with_reboot
def test_ft_platform_psustatus_with_reboot():
    return_val = parallel.exec_foreach(True,data.rp_list,ft_platform_psustatus_with_reboot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp
@pytest.mark.with_out_reboot
def test_ft_platform_psustatus_valid():
    return_val = parallel.exec_foreach(True,data.rp_list,ft_platform_psustatus_valid)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp
@pytest.mark.with_reboot
def test_ft_platform_fanstatus_with_reboot():
    return_val = parallel.exec_foreach(True,data.rp_list,ft_platform_fanstatus_with_reboot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp
@pytest.mark.with_out_reboot
def test_ft_platform_fanstatus_valid():
    return_val = parallel.exec_foreach(True,data.rp_list,ft_platform_fanstatus_valid)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_platform_temperature_valid():
    return_val = parallel.exec_foreach(True,data.both,ft_platform_temperature_valid)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp_and_lc
@pytest.mark.with_reboot
def test_ft_platform_temperature_with_reboot():
    return_val = parallel.exec_foreach(True,data.both,ft_platform_temperature_with_reboot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_system_memory():
    return_val = parallel.exec_foreach(True,data.both,ft_show_system_memory)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_docker_ps():
    return_val = parallel.exec_foreach(True,data.both,ft_docker_ps)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot  
def test_ft_service_restart():
    return_val = parallel.exec_foreach(True,data.both,ft_service_restart)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_version():
    return_val = parallel.exec_foreach(True,data.both,ft_show_version)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_platform_summary():
    return_val = parallel.exec_foreach(True,data.both,ft_platform_summary)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")                                                                                        



@pytest.mark.rp_and_lc
@pytest.mark.with_reboot
def test_ft_platform_rebootcause():
    return_val = parallel.exec_foreach(True,data.both,ft_platform_rebootcause)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_platform_rebootcause_valid():
    return_val = parallel.exec_foreach(True,data.both,ft_platform_rebootcause_valid)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_users():
    return_val = parallel.exec_foreach(True,data.both,ft_users)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_boot():
    return_val = parallel.exec_foreach(True,data.both,ft_show_boot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_mgmt_vrf():
    return_val = parallel.exec_foreach(True,data.both,ft_show_mgmt_vrf)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_mgmt_int_address():
    return_val = parallel.exec_foreach(True,data.both,ft_show_mgmt_int_address)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")                                        



@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_services():
    return_val = parallel.exec_foreach(True,data.both,ft_show_services)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")



@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_cpu_usage():
    return_val = parallel.exec_foreach(True,data.both,ft_cpu_usage)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_memory_usage():
    return_val = parallel.exec_foreach(True,data.both,ft_memory_usage)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.lc
@pytest.mark.with_out_reboot
def test_ft_transceiver_status():
    return_val = parallel.exec_foreach(True,data.lc_list,ft_transceiver_status)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.lc
@pytest.mark.with_out_reboot
def test_ft_transceiver_vendor_presence():
    return_val = parallel.exec_foreach(True,data.lc_list,ft_transceiver_vendor_presence)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")



@pytest.mark.lc
@pytest.mark.with_out_reboot
def test_ft_show_int_transceiver_presence():
    return_val = parallel.exec_foreach(True,data.lc_list,ft_show_int_transceiver_presence)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.lc
@pytest.mark.with_reboot
def test_ft_optics_with_boot():
    return_val = parallel.exec_foreach(True,data.lc_list,ft_optics_with_boot)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.lc
@pytest.mark.with_out_reboot
def test_ft_sfputil_reset():
    return_val = parallel.exec_foreach(True,data.lc_list,ft_sfputil_reset)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.rp_and_lc
@pytest.mark.with_reboot
def test_ft_config_reload():
    return_val = parallel.exec_foreach(True,data.both,ft_config_reload)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_xcvrd_info_in_db():
    return_val = parallel.exec_foreach(True,data.lc_list,ft_xcvrd_info_in_db)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_external_controller_reachability():
    return_val = parallel.exec_foreach(True,data.both,ft_external_controller_reachability)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.lc
@pytest.mark.with_out_reboot
def test_ft_optics_simulation():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.lc_list,ft_optics_simulation)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")                                                                                        



@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_platform_ssdhealth():
    return_val = parallel.exec_foreach(True,data.both,ft_platform_ssdhealth)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.rp_and_lc
@pytest.mark.with_out_reboot
def test_ft_show_environment():
    if not data.Supported_HW:
        st.report_tc_unsupported("test_execution_skipped",'due to unsupported HW platform')
    return_val = parallel.exec_foreach(True,data.both,ft_show_environment)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")                        


@pytest.mark.rp
@pytest.mark.with_out_reboot
def test_ft_fan_oir_simulation():
    return_val = parallel.exec_foreach(True,data.rp_list,ft_fan_oir_simulation)
    if False in return_val[0]:
        st.error("return values are:")
        st.log(return_val)
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


                       
