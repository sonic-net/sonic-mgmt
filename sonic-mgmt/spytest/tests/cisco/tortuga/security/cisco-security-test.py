import random
import os
import sys
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

md5sum_rootca = "489062c647ad2ffee08970beb71edccb"
root_cert="CISCO-8000-SUDI-ROOT-CA.pem"
subca_cert="CISCO-8000-SUDI-SUB-CA.pem"
sudi_cert="CISCO-8000-SUDI.pem"

script_dir = os.path.dirname(os.path.realpath(__file__))
l_rootca_cert = "{}/{}".format(script_dir, root_cert)
l_subca_cert = "{}/{}".format(script_dir, subca_cert)
l_sudi_cert = "{}/{}".format(script_dir, sudi_cert)
l_sudi_pub_key = "{}/sudi_pub.key".format(script_dir)

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
        return True 
    else:
        return False 

def init_sudi_test_setup(dut):
    st.config(dut, "rm -rf /opt/cisco/etc/crypto", skip_error_check=True)
    if os.path.exists(l_rootca_cert):
        os.remove(l_rootca_cert)
    if os.path.exists(l_subca_cert):
        os.remove(l_subca_cert)
    if os.path.exists(l_sudi_cert):
        os.remove(l_sudi_cert)

def check_file_presence(dut, test_task_name, file_path_list):
    '''
    Helper function to check if the list of files are present inside the docker 
    container. Logs the presence status to the log file.
    '''
    for file_path in file_path_list:
        if os.path.isfile(file_path):
            st.log("The file '{}' exists.".format(file_path), dut)
        else:
            st.log("The file '{}' does not exist or it's not a file.".format(file_path), dut)
            st.error("{} - failed - due to missing file.".format(test_task_name), dut)
         
def get_sudi_cert_chain_verify(dut):
    """
    1. Get cert chain from DUT (Root CA, Intermediate CA, Leaf SUDI cert)
    2. Verify Root CA with fixed hash
    3. Verify Inetrmediate CA from root CA
    4. Verify SUDI cert from Intermediate CA
    """
    init_sudi_test_setup(dut)

    # Get SUDI cert
    st.config(dut, "/opt/cisco/crypto/bin/tamcli -a get-cert-chain", skip_error_check=True)
    st.config(dut, "cp /opt/cisco/etc/crypto/{} /tmp".format(root_cert), skip_error_check=True)
    st.config(dut, "cp /opt/cisco/etc/crypto/{} /tmp".format(subca_cert), skip_error_check=True)
    st.config(dut, "cp /opt/cisco/etc/crypto/{} /tmp".format(sudi_cert), skip_error_check=True)
    st.config(dut, "chmod 777 /tmp/{}".format(root_cert), skip_error_check=True)
    st.config(dut, "chmod 777 /tmp/{}".format(subca_cert), skip_error_check=True)
    st.config(dut, "chmod 777 /tmp/{}".format(sudi_cert), skip_error_check=True)

    st.download_file_from_dut(dut, "/tmp/{}".format(root_cert), l_rootca_cert)
    st.download_file_from_dut(dut, "/tmp/{}".format(subca_cert), l_subca_cert)
    st.download_file_from_dut(dut, "/tmp/{}".format(sudi_cert), l_sudi_cert)
    # Verify ROOT-CA cert
    st.log("Verify ROOT-CA - start", dut)
    status,op=run_cmd("md5sum {}".format(l_rootca_cert), dut)
    if md5sum_rootca not in op: 
       st.error("Verify ROOT-CA - failed", dut)
       st.error("Checksum of root ca does not match", dut)
       st.log(op, dut)
       return False
    st.log("Verify ROOT-CA - Successful", dut)

    # Verify SUB-CA cert
    st.log("Verify SUB-CA - start", dut)
    check_file_presence(dut, test_task_name="Verify SUB-CA", file_path_list=[l_rootca_cert, l_subca_cert])
    status,op=run_cmd("openssl verify -CAfile {} {}".format(l_rootca_cert, l_subca_cert), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify SUB-CA - failed", dut)
       st.log(op, dut)
       return False
    st.log("Verify SUB-CA - Successful", dut)

    # Verify SUDI cert
    st.log("Verify SUDI - start", dut)
    check_file_presence(dut, test_task_name="Verify SUDI", file_path_list=[l_rootca_cert, l_subca_cert, l_sudi_cert])
    status,op=run_cmd("openssl verify -CAfile {} -untrusted {} {}".format(l_rootca_cert, l_subca_cert, l_sudi_cert), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify SUDI - failed", dut)
       st.log(op, dut)
       return False
    st.log("Verify SUDI - Successful", dut)
    return True


def sudi_platform_identity_verify(dut):
    idprom_data = basic_obj.get_platform_idprom(dut)
    st.log(idprom_data)
    sn = idprom_data['chassis_serial']
    pid = idprom_data['product_id']
    output = st.config(dut, "/opt/cisco/crypto/bin/tamcli -a authenticate-udi -p {} -n {}".format(pid, sn))
    if "platform authentication successful" in output:
        return True
    else:
        return False

def sudi_platform_identity_verify_wrong_pid(dut):
    idprom_data = basic_obj.get_platform_idprom(dut)
    st.log(idprom_data)
    sn = idprom_data['chassis_serial']
    wrongpid = "8101-32FH-O-O"
    output = st.config(dut, "/opt/cisco/crypto/bin/tamcli -a authenticate-udi -p {} -n {}".format(wrongpid, sn))
    if "TAM_ERROR_DEVICE_UDI_AUTHENTICATION_FAILURE" in output:
        return True
    else:
        return False

def sudi_platform_identity_verify_wrong_sn(dut):
    idprom_data = basic_obj.get_platform_idprom(dut)
    st.log(idprom_data)
    sn = "123456"
    pid = idprom_data['product_id']
    output = st.config(dut, "/opt/cisco/crypto/bin/tamcli -a authenticate-udi -p {} -n {}".format(pid, sn))
    if "TAM_ERROR_DEVICE_UDI_AUTHENTICATION_FAILURE" in output:
        return True
    else:
        return False

def sudi_sign_signature_quote_verify(dut, quote, hash_type):
    """
    1. Send Quote for signing
    2. Verify signed quote from SUDI cert
    """
    # Precondition
    l_quote_file = "{}/quote.txt".format(script_dir)
    l_quote_file_signed = "{}/quote.txt.sig".format(script_dir)
    if os.path.exists(l_quote_file):
        os.remove(l_quote_file)
    if os.path.exists(l_quote_file_signed):
        os.remove(l_quote_file_signed)

    # Sign quote
    st.log("Sign quote - start", dut)
    r_quote_file = "/tmp/quote.txt"
    r_quote_file_signed = "/tmp/quote.txt.sig"

    st.config(dut, "rm -rf {}".format(r_quote_file), skip_error_check=True)
    st.config(dut, "rm -rf {}".format(r_quote_file_signed), skip_error_check=True)
    st.config(dut, "echo '{}' > {}".format(quote, r_quote_file), skip_error_check=True)
    st.config(dut, "/opt/cisco/crypto/bin/tamcli -a  sudi-sign -i {} -o {} -d {}".format(r_quote_file, r_quote_file_signed, hash_type), skip_error_check=True)
    st.download_file_from_dut(dut, r_quote_file_signed, l_quote_file_signed)
    os.system("echo '{}' > {}".format(quote, l_quote_file))
    st.log("Sign quote - Done", dut)

    # Extract sudi pub key and verify signed quote
    st.log("Verify signed quote - start", dut)
    check_file_presence(dut, test_task_name="Verify signed quote", file_path_list=[l_sudi_cert])
    status,op=run_cmd("openssl x509 -pubkey -noout -in {} > {}".format(l_sudi_cert, l_sudi_pub_key), dut)
    check_file_presence(dut, test_task_name="Verify signed quote", file_path_list=[l_sudi_pub_key])
    st.log(op, dut)
    if not status:
       st.error("Verify signed quote - extract pub key failed", dut)
       st.log(op, dut)
       return False

    check_file_presence(dut, test_task_name="Verify signed quote", file_path_list=[l_sudi_pub_key, l_quote_file_signed, l_quote_file])
    status,op=run_cmd("openssl dgst -{} -verify {} -signature {} {}".format(hash_type, l_sudi_pub_key, l_quote_file_signed, l_quote_file), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify signed quote - failed", dut)
       st.log(op, dut)
       return False
    st.log("Verify signed quote - Successful", dut)

    return True

def sudi_sign_signature_digest_verify(dut, digest, hash_type):
    """
    1. Send Quote for signing
    2. Verify signed digest from SUDI cert
    """
    # Precondition
    l_digest_file = "{}/sudi-digest.txt".format(script_dir)
    l_digest_file_signed = "{}/sudi-digest.sig".format(script_dir)
    if os.path.exists(l_digest_file):
        os.remove(l_digest_file)
    if os.path.exists(l_digest_file_signed):
        os.remove(l_digest_file_signed)
    st.log("Sign digest - start", dut)
    r_digest_file = "/tmp/sudi-digest"
    r_digest_file_signed = "/tmp/sudi-digest.sig"
    st.config(dut, "rm -rf {}".format(r_digest_file), skip_error_check=True)
    st.config(dut, "rm -rf {}".format(r_digest_file_signed), skip_error_check=True)

    status,op=run_cmd("echo '{}' | openssl dgst -{} -binary -out {}".format(digest, hash_type, l_digest_file), dut)
    check_file_presence(dut, test_task_name="Verify signed quote", file_path_list=[l_digest_file])
    st.log(op, dut)
    if not status:
       st.error("Create {} digest - failed".format(hash_type), dut)
       return False

    # Upload digest file 
    st.upload_file_to_dut(dut, l_digest_file, r_digest_file)

    # Request to sign the digest
    cmdname = "/opt/cisco/crypto/bin/tamcli -a  sudi-sign-digest"
    st.config(dut, "{} -i {} -o {} -d {}".format(cmdname, r_digest_file, r_digest_file_signed, hash_type), skip_error_check=True)
    st.download_file_from_dut(dut, r_digest_file_signed, l_digest_file_signed)

    # Verify
    cmd = "openssl pkeyutl -verify"
    l_sudi_cert_file = "{}/{}".format(script_dir, sudi_cert)
    check_file_presence(dut, test_task_name="Verify signed digest", file_path_list=[l_digest_file, l_digest_file_signed, l_sudi_cert_file])
    status,op=run_cmd("{} -in {} -sigfile {} -inkey {} -certin -asn1parse -pkeyopt digest:{}".format(cmd, l_digest_file, l_digest_file_signed, l_sudi_cert_file, hash_type), dut)
    st.log(op, dut)
    if not status:
       st.error("Verify signed digest - failed", dut)
       st.log(op, dut)
       return False
    return True

def test_verify_sudi_service():
    # Initialize the DUTs
    dut1 = st.get_dut_names()[0]
    # check tams service process status
    if get_service_status(dut1, "tams_proc"): 
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_verify_sudi_cert_chain():
    # Initialize the DUTs
    dut1 = st.get_dut_names()[0]
    # Get cert chain and verify
    assert (get_sudi_cert_chain_verify(dut1), True, "SUDI verification failed")
    if get_sudi_cert_chain_verify(dut1): 
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_quote_sha1():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_quote_verify(dut1, message, "sha1"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_quote_sha256():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_quote_verify(dut1, message, "sha256"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_quote_sha384():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_quote_verify(dut1, message, "sha384"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_quote_sha512():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_quote_verify(dut1, message, "sha512"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_digest_sha1():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_digest_verify(dut1, message, "sha1"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_digest_sha256():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_digest_verify(dut1, message, "sha256"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_digest_sha384():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_digest_verify(dut1, message, "sha384"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_sign_verify_digest_sha512():
    dut1 = st.get_dut_names()[0]
    message = "Test quote signing"
    if sudi_sign_signature_digest_verify(dut1, message, "sha512"):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_udi_authentication():
    dut1 = st.get_dut_names()[0]
    if sudi_platform_identity_verify(dut1):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_udi_authentication_wrong_pid():
    dut1 = st.get_dut_names()[0]
    if sudi_platform_identity_verify_wrong_pid(dut1):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_udi_authentication_wrong_sn():
    dut1 = st.get_dut_names()[0]
    if sudi_platform_identity_verify_wrong_sn(dut1):
        st.report_pass("test_case_passed", dut1)
    else:
        st.report_fail("test_case_failed", dut1)

def test_sudi_cert_validity():
    dut1 = st.get_dut_names()[0]
    with open(l_sudi_cert, 'rb') as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Check if the certificate has expired
    current_time = datetime.utcnow()
    if cert.not_valid_before <= current_time <= cert.not_valid_after:
        st.log("The certificate is currently valid.")
        st.report_pass("test_case_passed", dut1)
    else:
        st.log("The certificate is expired or not yet valid.")
        st.report_fail("test_case_failed", dut1)

def test_show_sudi_command():
    dut1 = st.get_dut_names()[0]
    idprom_data = basic_obj.get_platform_idprom(dut1)
    st.log(idprom_data)
    sn = idprom_data['chassis_serial']
    pid = idprom_data['product_id']

    output = st.config(dut1, "/opt/cisco/crypto/bin/tamcli -a get-sudi-cert --show")
    if not sn in output:
        st.log("The certificate does not have serial number {}".format(sn))
        st.report_fail("test_case_failed", dut1)

    if not pid in output:
        st.log("The certificate does not have pid".format(pid))
        st.report_fail("test_case_failed", dut1)

    st.report_pass("test_case_passed", dut1)

def test_tam_service_restart():
    dut1 = st.get_dut_names()[0]
    try:
        basic_obj.service_operations(dut1, "platform-tam-server", action="restart")
        basic_obj.service_operations(dut1, "platform-tam-mgmt", action="restart")
        st.wait(30)
        if not get_service_status(dut1, "tams_proc"):
            st.log("Failed to start tam server")
            raise Exception("Failed to start tam server")
        if not sudi_sign_signature_digest_verify(dut1, "Hello Test", "sha512"):
            st.log("Failed to sudi sign verification")
            raise Exception("Failed to sudi sign verification")
        st.report_pass("test_case_passed", dut1)
    except Exception as err:
        st.log("Exception occured")
        st.log(err)
        print("Type of error occured:", sys.exc_info()[0])
        st.report_fail("test_case_failed", dut1)
