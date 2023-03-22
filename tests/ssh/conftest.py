import imp
import subprocess
import pytest
import logging

logger = logging.getLogger(__name__)

# enc_ciphers list
PERMITTED_ENC_CIPHERS = [
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr"
]

# MACs list
PERMITTED_MACS = [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com"
]

# Kexs list
PERMITTED_KEXS = [
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521"
]

def generate_ssh_ciphers(request, typename):
    if typename == "enc":
        remote_cmd = "ssh -Q cipher"
        permitted_list = PERMITTED_ENC_CIPHERS
    elif typename == "mac":
        remote_cmd = "ssh -Q mac"
        permitted_list = PERMITTED_MACS
    elif typename == "kex":
        remote_cmd = "ssh -Q kex"
        permitted_list = PERMITTED_KEXS

    testbed_name = request.config.option.testbed
    testbed_file = request.config.option.testbed_file
    testbed_module = imp.load_source('testbed', 'common/testbed.py')
    tbinfo = testbed_module.TestbedInfo(testbed_file).testbed_topo.get(testbed_name, None)

    dut_name = tbinfo['duts'][0]
    inv_name = tbinfo['inv_name'] if 'inv_name' in list(tbinfo.keys()) else 'lab'

    ansible_cmd = "ansible -m shell -i ../ansible/{} {} -a".format(inv_name, dut_name)
    cmd = ansible_cmd.split()
    cmd.append(remote_cmd)
    logger.debug('cmd:\n{}'.format(cmd))

    try:
        raw_output = subprocess.check_output(cmd, shell=False, stderr=subprocess.STDOUT, universal_newlines=True)
        cipher_list = raw_output.split("rc=0 >>", 1)[1].split()
        logger.debug('cipher full list: {}'.format(cipher_list))
        cipher_param_list = permitted_list
        for cipher in cipher_list:
            if cipher in permitted_list:
                continue
            else:
                cipher_param_list.append(pytest.param(cipher, marks=pytest.mark.xfail))

        return cipher_param_list
    except subprocess.CalledProcessError as e:
        logger.error('Failed to get DUT\'s {} ciphers full list: {}'.format(typename, e.output))

def pytest_generate_tests(metafunc):
    if 'enum_dut_ssh_enc_cipher' in metafunc.fixturenames:
        metafunc.parametrize('enum_dut_ssh_enc_cipher', generate_ssh_ciphers(metafunc, "enc"))
    elif 'enum_dut_ssh_mac' in metafunc.fixturenames:
        metafunc.parametrize('enum_dut_ssh_mac', generate_ssh_ciphers(metafunc, "mac"))
    elif 'enum_dut_ssh_kex' in metafunc.fixturenames:
        metafunc.parametrize('enum_dut_ssh_kex', generate_ssh_ciphers(metafunc, "kex"))
