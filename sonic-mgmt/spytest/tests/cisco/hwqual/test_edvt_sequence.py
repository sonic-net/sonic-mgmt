#!/usr/bin/env python3
"""
EDVT (Engineering Design Verification Test) Sequence Test Script

This script executes platform-specific EDVT test sequences based on product ID
and test type configuration from platform_edvt_cfg.py
"""

import pytest
import importlib
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st, tgapi
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg, get_platform_edvt_traffic_cfg_type
from tests.cisco.hwqual.platform_snt_cfg import platform_vrf_config, get_vrf_traffic_config

# Global test data
test_data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def test_edvt_sequence_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** EDVT SEQUENCE ***"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username

    if 'D1T1P1' in TBDataG:
        CfgDataG.D1T1P1 = TBDataG['D1T1P1']
    else:
        CfgDataG.D1T1P1 = None

    if 'D1T1P2' in TBDataG:
        CfgDataG.D1T1P2 = TBDataG['D1T1P2']
    else:
        CfgDataG.D1T1P2 = CfgDataG.D1T1P1

   # Initialize Platform Details
    CfgDataG.dut = TBDataG.D1
    CfgDataG.mgmt_ipv4=TBDataG.get("mgmt_ipv4").get(CfgDataG.dut)
    if hwqual_common.get_platform_details(CfgDataG) is False:
        return False

    CfgDataG['tz_yaml_data'] = {}
    res = hwqual_common.retrieve_thermal_zone_config_data(CfgDataG)
    if res['success'] == False:
        return False

    CfgDataG['vm_sensors'] = {}
    if hwqual_common.get_voltage_sensors_with_margining(CfgDataG) is False:
        return False

    CfgDataG['fan_data'] = {}
    if hwqual_common.get_thermal_zone_fan_data(CfgDataG) is False:
        return False

    # Retrieve platform edvt cfg 
    if CfgDataG.product_id not in platform_edvt_cfg["platforms"]:
        st.error(f"Product ID {product_id} not found in platform configuration")
        st.report_fail("test_case_failed", f"Unsupported product ID: {product_id}")
        return False

    platform_cfg = platform_edvt_cfg["platforms"][CfgDataG.product_id]
    CfgDataG.test_type = platform_cfg["test_type"]
    CfgDataG['noshut_timer'] = platform_cfg["noshut_timer"]
    CfgDataG['shut_noshut'] = platform_cfg["shut_noshut"]
    CfgDataG['exception_intf'] = platform_cfg['exception_intf']
    CfgDataG.util = platform_cfg.get("util")

    CfgDataG.traffic_cfg_type = get_platform_edvt_traffic_cfg_type(CfgDataG.product_id)
    if not CfgDataG.traffic_cfg_type:
        report_fail(f"{CfgDataG.logprefix} Missing platform_cfg attribute traffic_cfg_type for PID:{CfgDataG.product_id}")
        return False

    # Retrieve platform vrf configuration
    platform_vrf_cfg = get_platform_vrf_config(CfgDataG.product_id)
    if not platform_vrf_cfg:
        report_fail(f"{CfgDataG.logprefix} Missing platform_cfg information for PID:{CfgDataG.product_id}")
        return False

    CfgDataG.is_single_tgen_port = True
    if CfgDataG.D1T1P2 is not None and CfgDataG.D1T1P1 != CfgDataG.D1T1P2:
        CfgDataG.is_single_tgen_port = False

    CfgDataG.cfg_reload_timer = platform_vrf_cfg.get("cfg_reload_timer")
    # Initialize TGEN details
    if CfgDataG.is_single_tgen_port:
        CfgDataG.tg_handler = tgapi.get_handles(TBDataG, [TBDataG.T1D1P1])
    else:
        CfgDataG.tg_handler = tgapi.get_handles(TBDataG, [TBDataG.T1D1P1, TBDataG.T1D1P2])

    CfgDataG.tg = CfgDataG.tg_handler["tg"]
    CfgDataG.tg_ph1 = CfgDataG.tg_handler["tg_ph_1"]
    CfgDataG.T1D1P1_ipv4 = platform_vrf_cfg.get("tgenp1_ipv4")
    CfgDataG.T1D1P1_mac= platform_vrf_cfg.get("tgenp1_mac")
    CfgDataG.D1T1P1_ipv4 = platform_vrf_cfg.get("dutp1_ipv4")

    if not CfgDataG.is_single_tgen_port:
        CfgDataG.tg_ph2 = CfgDataG.tg_handler["tg_ph_2"]
        CfgDataG.T1D1P2_ipv4 = platform_vrf_cfg.get("tgenp2.ipv4")
        CfgDataG.T1D1P2_mac= platform_vrf_cfg.get("tgenp2_mac")
        CfgDataG.D1T1P2_ipv4 = platform_vrf_cfg.get("dutp2_ipv4")

    CfgDataG.is_ext_loop = hwqual_common.is_ext_loop_exist(CfgDataG)
    CfgDataG['results'] = {}

    yield

    pass

def get_platform_vrf_config(platform_id):
    """
    Retrieve configuration for a specific platform from platform_vrf_config

    Args:
        platform_id (str): Platform identifier (e.g., "8101-32FH-O")

    Returns:
        dict: Platform configuration or None if not found
    """
    try:
        platforms = platform_vrf_config.get("platforms", {})
        return platforms.get(platform_id)
    except Exception as e:
        st.error(f"{CfgDataG.logprefix} Failed to get platform config for {platform_id}: {e}")
        return None

def get_io_ports(platform_id):
    """
    Get default TX/RX ports for a platform

    Args:
        platform_id (str): Platform identifier

    Returns:
        tuple: (tx_port, rx_port) or (None, None) if not found
    """
    platform_cfg = get_platform_vrf_config(platform_id)
    if not platform_cfg:
        return None, None

    default_cfg = platform_cfg.get("io_ports", {})
    tx_port = default_cfg.get("tx_port")
    rx_port = default_cfg.get("rx_port")

    return tx_port, rx_port

def get_product_id():
    """
    Return product_id

    Returns:
        str: Product ID of the platform
    """
    # Dummy implementation - replace with actual platform query
    # Example: return st.show(dut, "show platform syseeprom | grep 'Product Name'")

    # For testing purposes, return one of the configured platforms
    return CfgDataG.product_id

def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def execute_edvt_test(test_grp, test_checks):
    """
    Common function to execute individual EDVT tests

    Args:
        test_grp (str): Name of the test being executed
        test_checks (list): List of check categories to execute

    Returns:
        bool: True if test passes, False otherwise
    """
    st.log(f"=" * 60)
    st.log(f"Executing EDVT Test Group: {test_grp}")
    st.log(f"Test Checks: {test_checks}")
    st.log(f"=" * 60)

    CfgDataG['results'][test_grp] = []
    try:
        for check_category in test_checks:
            st.log(f"{CfgDataG.logprefix} Running check category: {check_category}")

            # Execute checks based on category type
            if isinstance(check_category, dict):
                try:
                   # Build module path
                   module_path = f"tests.cisco.hwqual.{check_category['name']}"
                   function_name = check_category['name']

                   module = importlib.import_module(module_path)
                   check_function = getattr(module, function_name)
                   result = check_function(CfgDataG, check_category['checks'], CfgDataG['results'][test_grp])
                except ImportError as e:
                   st.error(f"Failed to import module {module_path}: {e}")
                   return False
                except AttributeError as e:
                   st.error(f"Function {function_name} not found in module {module_path}: {e}")
                   return False
                except Exception as e:
                   st.error(f"Error executing {function_name}: {e}")
                   return False
                #function_name = check_category['name']
                #st.log(f"Calling test function: {function_name}")
                #if function_name in globals():
                #    test_function = globals()[function_name]
                #    test_function()
                #else:
                #    st.error(f"Test function {function_name} not found")
                #    st.report_fail("test_case_failed", f"Function not found: {function_name}")
                #    return False
            else:
                st.log(f"  - Executing check: {check_category}")
                # Add actual test implementation here
                # Example: result = run_specific_check(check_category)

        st.log(f"✓ EDVT Test {test_grp} completed successfully")
        return True

    except Exception as e:
        st.error(f"✗ EDVT Test {test_grp} failed: {e}")
        return False

def edvt_sequence_default(test_config_dict):
    """
    Execute EDVT test sequence for 'default' test type

    Args:
        test_config_dict (dict): Test configuration dictionary for default type
    """
    st.log("Starting EDVT Sequence for DEFAULT test type")

    failed_tests = []

    # Execute each test in the configuration
    for test_name, test_checks in test_config_dict.items():
        st.log(f"\n--- Executing {test_name} ---")

        result = execute_edvt_test(test_name, test_checks)

        if not result:
            failed_tests.append(test_name)
            st.error(f"Test {test_name} failed")
        else:
            st.log(f"Test {test_name} passed")

    # Report final results
    if failed_tests:
        st.error(f"EDVT Sequence FAILED. Failed tests: {', '.join(failed_tests)}")
        st.report_fail("test_case_failed", f"EDVT default sequence failed: {failed_tests}")
    else:
        st.log("All EDVT tests passed successfully")
        st.report_pass("test_case_passed", "EDVT default sequence completed successfully")

def invoke_edvt_sequence(test_config_dict):
    """
    Execute EDVT test sequence for 'hwqual' test type

    Args:
        test_config_dict (dict): Test configuration dictionary for hwqual type
    """
    st.log("Starting EDVT Sequence for HWQUAL test type")

    failed_tests = []

    # Execute each test in the configuration
    for test_grp, test_checks in test_config_dict.items():
        st.log(f"\n{CfgDataG.logprefix} --- Executing Group: {test_grp} ---")

        result = execute_edvt_test(test_grp, test_checks)

        if not result:
            failed_tests.append(test_grp)
            st.error(f"Test {test_grp} failed")
        else:
            st.log(f"Test {test_grp} passed")

    # Report final results
    if failed_tests:
        st.error(f"EDVT Sequence FAILED. Failed tests: {', '.join(failed_tests)}")
        st.report_fail("test_case_failed", f"EDVT hwqual sequence failed: {failed_tests}")
    else:
        st.log("All EDVT tests passed successfully")
        st.report_pass("test_case_passed", "EDVT hwqual sequence completed successfully")

def edvt_sequence_security(test_config_dict):
    """
    Execute EDVT test sequence for 'security' test type

    Args:
        test_config_dict (dict): Test configuration dictionary for security type
    """
    st.log("Starting EDVT Sequence for SECURITY test type")

    failed_tests = []

    # Execute each test in the configuration
    for test_grp, test_checks in test_config_dict.items():
        st.log(f"\n--- Executing {test_grp} ---")

        result = execute_edvt_test(test_grp, test_checks)

        if not result:
            failed_tests.append(test_grp)
            st.error(f"Test {test_grp} failed")
        else:
            st.log(f"Test {test_grp} passed")

    # Report final results
    if failed_tests:
        st.error(f"EDVT Sequence FAILED. Failed tests: {', '.join(failed_tests)}")
        st.report_fail("test_case_failed", f"EDVT security sequence failed: {failed_tests}")
    else:
        st.log("All EDVT tests passed successfully")
        st.report_pass("test_case_passed", "EDVT security sequence completed successfully")

def test_edvt_sequence():
    """
    Main spytest test function to execute EDVT test sequences

    This function:
    1. Gets the product ID from the platform
    2. Determines the test type based on product ID
    3. Calls the appropriate test sequence function
    """
    st.log("=" * 80)
    st.log("Starting EDVT Test Sequence")
    st.log("=" * 80)

    try:
        # Step 1: Get product ID
        product_id = get_product_id()
        st.log(f"Detected Product ID: {product_id}")

        # Step 2: Get test type based on product ID
        if product_id not in platform_edvt_cfg["platforms"]:
            st.error(f"Product ID {product_id} not found in platform configuration")
            st.report_fail("test_case_failed", f"Unsupported product ID: {product_id}")
            return False

        platform_cfg = platform_edvt_cfg["platforms"][product_id]
        test_type = platform_cfg["test_type"]
        st.log(f"Test Type for {product_id}: {test_type}")

        # Step 3: Get test configuration for the test type
        if test_type not in platform_edvt_cfg["category"]:
            st.error(f"Test type {test_type} not found in category configuration")
            st.report_fail("test_case_failed", f"Unsupported test type: {test_type}")
            return False

        test_config_dict = platform_edvt_cfg["category"][test_type]
        st.log(f"{CfgDataG.logprefix} Test Groups: {list(test_config_dict.keys())}")
        if not invoke_edvt_sequence(test_config_dict):
            return False

        # Step 4: Call appropriate test function based on test type
        #function_name = f"edvt_sequence_{test_type}"
        #st.log(f"Calling test function: {function_name}")

        # Get function from globals and call it
        #if function_name in globals():
            #test_function = globals()[function_name]
            #test_function(test_config_dict)
        #else:
            #st.error(f"Test function {function_name} not found")
            #st.report_fail("test_case_failed", f"Function not found: {function_name}")
            #return False

        st.log("=" * 80)
        st.log("EDVT Test Sequence Completed Successfully")
        st.log("=" * 80)
        st.report_pass(f"{CfgDataG.logprefix} Test Passed", CfgDataG.dut)

    except Exception as e:
        st.error(f"EDVT Test Sequence failed with exception: {e}")
        st.report_fail("test_case_failed", f"EDVT sequence exception: {e}")

if __name__ == "__main__":
    # For standalone testing
    pytest.main([__file__, "-v", "-s"])
