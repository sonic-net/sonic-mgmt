import imp
import subprocess
import pytest
import logging

logger = logging.getLogger(__name__)

# enc_ciphers list
permitted_enc_ciphers = [
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr"
]

default_enc_ciphers = [
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com"
]

# MACs list
permitted_macs = [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com"
]

default_macs = [
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com,umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1"
]

# Kexs list
permitted_kexs = [
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521"
]

default_kexs = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1"
]

def generate_ssh_ciphers(request, typename):
    if typename == "enc":
        remote_cmd = "ssh -Q cipher"
        permitted_list = permitted_enc_ciphers
        default_list = default_enc_ciphers
    elif typename == "mac":
        remote_cmd = "ssh -Q mac"
        permitted_list = permitted_macs
        default_list = default_macs
    elif typename == "kex":
        remote_cmd = "ssh -Q kex"
        permitted_list = permitted_kexs
        default_list = default_kexs

    testbed_name = request.config.option.testbed
    testbed_file = request.config.option.testbed_file
    testbed_module = imp.load_source('testbed', 'common/testbed.py')
    tbinfo = testbed_module.TestbedInfo(testbed_file).testbed_topo.get(testbed_name, None)

    dut_name = tbinfo['duts'][0]
    inv_name = tbinfo['inv_name']

    ansible_cmd = "ansible -m shell -i ../ansible/{} {} -a".format(inv_name, dut_name)
    cmd = ansible_cmd.split()
    cmd.append(remote_cmd)
    logger.debug('cmd:\n{}'.format(cmd))

    try:
        raw_output = subprocess.check_output(cmd, shell=False, stderr=subprocess.STDOUT, universal_newlines=True).decode('utf-8')
        cipher_list = raw_output.split("rc=0 >>", 1)[1].split()
        logger.info('cipher full list:\n{}'.format(cipher_list))
        cipher_param_list = permitted_list
        for cipher in cipher_list:
            if cipher in permitted_list:
                continue
            elif cipher in default_list:
                cipher_param_list.append(pytest.param(cipher, marks=pytest.mark.xfail))
            else:
                cipher_param_list.append(pytest.param(cipher, marks=pytest.mark.xfail(strict=True)))

        return cipher_param_list
    except subprocess.CalledProcessError as e:
        logger.error('Failed to get DUT\'s {} ciphers full list: {}'.format(typrname, e.output))

def pytest_generate_tests(metafunc):
    if 'enum_dut_ssh_enc_cipher' in metafunc.fixturenames:
        metafunc.parametrize('enum_dut_ssh_enc_cipher', generate_ssh_ciphers(metafunc, "enc"))
    elif 'enum_dut_ssh_mac' in metafunc.fixturenames:
        metafunc.parametrize('enum_dut_ssh_mac', generate_ssh_ciphers(metafunc, "mac"))
    elif 'enum_dut_ssh_kex' in metafunc.fixturenames:
        metafunc.parametrize('enum_dut_ssh_kex', generate_ssh_ciphers(metafunc, "kex"))
