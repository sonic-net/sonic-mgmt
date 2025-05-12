import random
import os
import time
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

import pytest
from spytest import st, tgapi, SpyTestDict
from spytest.testbed import Testbed
from spytest.rps import RPS
from spytest.infra import get_config
from spytest.framework import get_work_area

from apis.system.connection import connect_to_device
import apis.system.basic as basic_obj

def test_show_uefi_mode():
    dut1 = st.get_dut_names()[0]
    pattern = "Generic Mode"

    output = st.config(dut1, "/opt/cisco/crypto/bin/tamcli -a get-uefi-mode")
    if not pattern in output:
        st.log("The tam UEFI mode is invalid: {}".format(output))
        st.report_fail("test_case_failed", dut1)
    else:
        st.report_pass("test_case_passed", dut1)

def test_get_uefi_variable():
    dut1 = st.get_dut_names()[0]
    cisco_variable = [ 'PKCisco', 'KEKCisco', 'dbCisco']
    cust_variable  = [ 'PKCustomer', 'KEKCustomer', 'dbCustomer' ]
    dbx_variable = [ 'dbxCisco', 'dbxCustomer' ]
    get_variable_cmd = "/opt/cisco/crypto/bin/tamcli -a get-uefi-keys --brief --show -e {}"

    # Get variable on cisco variable
    for var in cisco_variable:
        cmd = get_variable_cmd.format(var)
        output = st.config(dut1, "{}|{}".format(cmd, "grep Subject:"))
        lines = output.split('\n')[:-1]
        st.log("{}".format(lines))
        for line in lines:
            if not "O = Cisco" in line:
                st.log("Subject of certificate line not expected: {}".format(line))
                st.report_fail("test_case_failed", dut1)
            else:
                st.report_pass("test_case_passed", dut1)

        output = st.config(dut1, "{}|{}".format(cmd, "grep Issuer:"))
        for line in lines:
            if not "O = Cisco" in line:
                st.log("Issuer of certificate line not expected: {}".format(line))
                st.report_fail("test_case_failed", dut1)
            else:
                st.report_pass("test_case_passed", dut1)

    # Get customer UEFI variable. It should be empty
    for var in cust_variable:
        cmd = get_variable_cmd.format(var)
        output = st.config(dut1, "{}".format(cmd))
        #Check for empty entry
        if "has no entries" in output:
            st.report_pass("test_case_passed", dut1)
        else:
            st.report_fail("test_case_failed", dut1)

    # Forbidden database also should be empty
    for var in dbx_variable:
        cmd = get_variable_cmd.format(var)
        output = st.config(dut1, "{}".format(cmd))
        #Check for empty entry
        if "has no entries" in output:
            st.report_pass("test_case_passed", dut1)
        else:
            st.report_fail("test_case_failed", dut1)
