import random
import os
import time
import json
import subprocess

import pytest
from spytest import st, tgapi, SpyTestDict
from spytest.testbed import Testbed
from spytest.rps import RPS
from spytest.infra import get_config
from spytest.framework import get_work_area

from apis.system.connection import connect_to_device

def run_cmd(cmd, dut):
    st.log(cmd, dut)
    try:
        proc = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        st.log('Exception: {}'.format(e), dut)
        return (False, None)
    return (True, proc.decode().rstrip('\n'))

def get_service_status(dut, service):
    """
        do a "ps -aux" and get the status of the given service.
    """
    output = st.config(dut, "ps -aef | grep -w {} | grep -v grep".format(service))
    if output:
        return "active"
    else:
        return "inactive"    

def check_exit_status_service(dut, service):
    """
        Use this api for systemd service which are not deamon
        do a "systemctl show -p ExecMainStatus <service>
    """
    command="systemctl show -p ExecMainStatus {}".format(service)
    output = st.config(dut, command)
    
    return output

def check_sudi_identification(dut):
    """
    1. Get cert chain from DUT (Root CA, Intermediate CA, Leaf SUDI cert)
    2. Verify Root CA with fixed hash
    3. Verify Inetrmediate CA from root CA
    4. Verify SUDI cert from Intermediate CA
    5. Send Quote for signing
    6. Verify signed quote from SUDI cert
    """

    st.log("Verify SUDI", dut)
    md5sum_rootca = "489062c647ad2ffee08970beb71edccb"
    root_cert="CISCO-8000-SUDI-ROOT-CA.pem"
    subca_cert="CISCO-8000-SUDI-SUB-CA.pem"
    sudi_cert="CISCO-8000-SUDI.pem"
    l_quote_file = "/data/quote.txt"
    l_quote_file_signed = "/data/quote.txt.sig"

    # Precondition
    st.config(dut, "rm -rf /opt/cisco/etc/crypto", skip_error_check=True)
    if os.path.exists("/data/tests/{}".format(root_cert)):
        os.remove("/data/tests/{}".format(root_cert))
    if os.path.exists("/data/tests/{}".format(subca_cert)):
        os.remove("/data/tests/{}".format(subca_cert))
    if os.path.exists("/data/tests/{}".format(sudi_cert)):
        os.remove("/data/tests/{}".format(sudi_cert))
    if os.path.exists(l_quote_file):
        os.remove(l_quote_file)
    if os.path.exists(l_quote_file_signed):
        os.remove(l_quote_file_signed)

    # Get SUDI cert
    st.config(dut, "/opt/cisco/crypto/bin/tamcli -a get-cert-chain", skip_error_check=True)
    st.config(dut, "cp /opt/cisco/etc/crypto/{} /tmp".format(root_cert), skip_error_check=True)
    st.config(dut, "cp /opt/cisco/etc/crypto/{} /tmp".format(subca_cert), skip_error_check=True)
    st.config(dut, "cp /opt/cisco/etc/crypto/{} /tmp".format(sudi_cert), skip_error_check=True)
    st.config(dut, "chmod 777 /tmp/{}".format(root_cert), skip_error_check=True)
    st.config(dut, "chmod 777 /tmp/{}".format(subca_cert), skip_error_check=True)
    st.config(dut, "chmod 777 /tmp/{}".format(sudi_cert), skip_error_check=True)

    st.download_file_from_dut(dut, "/tmp/{}".format(root_cert), root_cert)
    st.download_file_from_dut(dut, "/tmp/{}".format(subca_cert), subca_cert)
    st.download_file_from_dut(dut, "/tmp/{}".format(sudi_cert), sudi_cert)

    # Verify ROOT-CA cert
    st.log("Verify ROOT-CA - start", dut)
    status,op=run_cmd("md5sum /data/tests/{}".format(root_cert), dut)
    if md5sum_rootca not in op: 
       st.error("Verify ROOT-CA - failed", dut)
       st.error("Checksum of root ca does not match", dut)
       st.log(op, dut)
       return False
    st.log("Verify ROOT-CA - Successful", dut)

    # Verify SUB-CA cert
    st.log("Verify SUB-CA - start", dut)
    l_rootca_cert = "/data/tests/{}".format(root_cert)
    l_subca_cert = "/data/tests/{}".format(subca_cert)
    l_sudi_cert = "/data/tests/{}".format(sudi_cert)
    l_sudi_pub_key = "/data/tests/sudi_pub.key"
    status,op=run_cmd("openssl verify -CAfile {} {}".format(l_rootca_cert, l_subca_cert), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify SUB-CA - failed", dut)
       st.log(op, dut)
       return False
    st.log("Verify SUB-CA - Successful", dut)

    # Verify SUDI cert
    st.log("Verify SUDI - start", dut)
    status,op=run_cmd("openssl verify -CAfile {} -untrusted {} {}".format(l_rootca_cert, l_subca_cert, l_sudi_cert), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify SUDI - failed", dut)
       st.log(op, dut)
       return False
    st.log("Verify SUDI - Successful", dut)

    # Sign quote
    quote = "SUDI-TEST-QUOTE"
    st.log("Sign quote - start", dut)
    r_quote_file = "/tmp/quote.txt"
    r_quote_file_signed = "/tmp/quote.txt.sig"

    st.config(dut, "rm -rf {}".format(r_quote_file), skip_error_check=True)
    st.config(dut, "rm -rf {}".format(r_quote_file_signed), skip_error_check=True)
    st.config(dut, "echo '{}' > {}".format(quote, r_quote_file), skip_error_check=True)
    st.config(dut, "/opt/cisco/crypto/bin/tamcli -a  sudi-sign -i {}".format(r_quote_file), skip_error_check=True)
    st.download_file_from_dut(dut, r_quote_file_signed, l_quote_file_signed)
    os.system("echo '{}' > {}".format(quote, l_quote_file))
    st.log("Sign quote - Done", dut)

    # Extract sudi pub key and verify signed quote
    st.log("Verify signed quote - start", dut)
    status,op=run_cmd("openssl x509 -pubkey -noout -in {} > {}".format(l_sudi_cert, l_sudi_pub_key), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify signed quote - extract pub key failed", dut)
       st.log(op, dut)
       return False

    status,op=run_cmd("openssl dgst -sha256 -verify {} -signature {} {}".format(l_sudi_pub_key, l_quote_file_signed, l_quote_file), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify signed quote - failed", dut)
       st.log(op, dut)
       return False
    st.log("Verify signed quote - Successful", dut)

    # Cleanup
    if os.path.exists("/data/tests/{}".format(root_cert)):
        os.remove("/data/tests/{}".format(root_cert))
    if os.path.exists("/data/tests/{}".format(subca_cert)):
        os.remove("/data/tests/{}".format(subca_cert))
    if os.path.exists("/data/tests/{}".format(sudi_cert)):
        os.remove("/data/tests/{}".format(sudi_cert))
    if os.path.exists(l_quote_file):
        os.remove(l_quote_file)
    if os.path.exists(l_quote_file_signed):
        os.remove(l_quote_file_signed)

    return True

def test_verify_sudi():
    # Initialize the DUTs
    dut1 = st.get_dut_names()[0]

    # check tams service process status
    assert (get_service_status(dut1, "tams_proc"), "active", "The service:tams_proc is not running")

    # check tam-mgmt service exit status
    assert (check_exit_status_service(dut1, "platform-tam-mgmt"), "ExecMainStatus=0", "The TAM mgmt service is in failed state")

    # Get cert chain and verify
    assert (check_sudi_identification(dut1), True, "SUDI verification failed")
