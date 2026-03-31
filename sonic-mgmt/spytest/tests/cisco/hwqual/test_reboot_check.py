#!/usr/bin/env python3
"""
Temperature/Voltage/Current Sensor Warning Validation Script

This script parses sensor data and validates that no sensors
are in warning state, which could indicate thermal/volt/current issues or hardware problems.
"""

import re
import sys
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from datetime import datetime
from spytest.dicts import SpyTestDict
from apis.common.sonic_hooks import SonicHooks
from typing import List, Dict, Tuple, Optional
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg

@pytest.fixture(scope="module", autouse=True)
def reboot_check_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** SENSOR DATA *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"

    yield
    pass


def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def check_reboot_state(CfgDataG, reboot_type):
    '''
    '''
    match reboot_type:
        case "cold_reboot":
            st.reboot(CfgDataG.dut)
            st.tg_wait(60)
            
        case _:  # Default case
            st.error(f"Unknown test type: {reboot_type}")
            return False

    return True

def test_reboot_check(CfgDataG, reboot_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {reboot_check} check")

    for check_item in reboot_check:
        if not check_reboot_state(CfgDataG, check_item):
            report_fail(f"{CfgDataG.logprefix}: Validation of {check_item} failed")
            return False
        st.log(f"{CfgDataG.logprefix}: {check_item} data ok")

    return True
