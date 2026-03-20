import pytest
import re


class _ContainerNames:
    """Mutable container names — use `cn` instance so fixture updates are visible across all imports."""
    name = "acms"
    sidecar = "k8s_acms_sidecar_ds"
    watchdog = "k8s_acms_watchdog_ds"


cn = _ContainerNames()
container_name = cn.name
sidecar_container_name = cn.sidecar
watchdog_container_name = cn.watchdog

TEST_DATA_CLOUD = [
    {
        "cloudtype": "Public",
        "region_list": ["useast", "japaneast", "asiaeast"]
    },
    {
        "cloudtype": "FairFax",
        "region_list": ["usgoveast", "usgovsc", "usgovsw"]
    },
    {
        "cloudtype": "Mooncake",
        "region_list": ["chinaeast", "chinaeast2", "chinaeast3"]
    }
]


def create_acms_conf(region, cloudtype, duthost, filename):
    # Get ground truth from DUT
    dut_command = "docker exec %s cat /acms/acms_secrets.ini" % container_name
    ret = duthost.shell(dut_command)
    assert ret["rc"] == 0, "Failed to read acms_secrets.ini"
    text = ret["stdout"]
    if cloudtype.lower() == "FairFax".lower():
        url_pattern = "dsms.dsms.core.usgovcloudapi.net"
    elif cloudtype.lower() == "Mooncake".lower():
        url_pattern = "dsms.dsms.core.chinacloudapi.cn"
    elif cloudtype.lower() == "Public".lower():
        url_pattern = "dsms.dsms.core.windows.net"
    else:
        pytest.skip("Unsupported cloud type: %s" % cloudtype)
    new_url = "https://%s-%s" % (region, url_pattern)
    text = re.sub("FullHttpsDsmsUrl=.*", "FullHttpsDsmsUrl="+new_url, text)
    curr_bootstrap_cert = "/etc/sonic/credentials/sonic_acms_bootstrap-%s.pfx" % region
    # Mirror start.py logic: call convert_bootstrap_cert_for_openssl3 to get the actual cert path
    # (may return a converted path under openssl3_conv/ for OpenSSL 3.x compatibility).
    # If the function does not exist (older image), use curr_bootstrap_cert directly.
    python_script = "\n".join([
        "import sys, os",
        'if os.path.isfile("/usr/local/bin/start.py"):',
        '    sys.path.insert(0, "/usr/local/bin")',
        'curr_bootstrap_cert = "%s"' % curr_bootstrap_cert,
        "try:",
        "    from start import convert_bootstrap_cert_for_openssl3",
        "    converted_cert = convert_bootstrap_cert_for_openssl3(curr_bootstrap_cert)",
        "    print(converted_cert if converted_cert is not None else curr_bootstrap_cert)",
        "except ImportError:",
        "    print(curr_bootstrap_cert)",
    ])
    dut_command = "docker exec %s python3 -c '%s'" % (container_name, python_script)
    ret = duthost.shell(dut_command, module_ignore_errors=True)
    assert ret["rc"] == 0 and ret["stdout"].strip(), \
        "Failed to get cert path from convert_bootstrap_cert_for_openssl3: %s" % ret["stderr"]
    cert_path = ret["stdout"].strip()
    text = re.sub("BootstrapCert=.*", "BootstrapCert="+cert_path, text)
    duthost.copy(content=text, dest=filename)
    return


def create_dsms_conf(duthost, filename):
    text = '''
[ACMS]
HasBootstrapped=yes
LastPollSuccess=yes
'''
    duthost.copy(content=text, dest=filename)
    return


def generate_pfx_cert(duthost, cert_name, expire=3650):
    """
    Generate a pfx cert file on the DUT acms container.
    """
    command = "docker exec %s openssl genrsa -out /tmp/%s.key 2048" % (container_name, cert_name)
    duthost.shell(command, module_ignore_errors=True)
    command = "docker exec %s openssl req -new -x509 -key /tmp/%s.key -out /tmp/%s.crt \
              -subj '/CN=test.server.restapi.sonic' -days %d" % (container_name, cert_name, cert_name, expire)
    duthost.shell(command, module_ignore_errors=True)
    command = "docker exec %s openssl pkcs12 -export -out /tmp/%s.pfx -inkey /tmp/%s.key \
              -in /tmp/%s.crt -password pass:" % (container_name, cert_name, cert_name, cert_name)
    duthost.shell(command, module_ignore_errors=True)


def host_generate_pfx_cert(duthost, cert_name, expire=3650):
    """
    Generate a pfx cert file on the DUT host.
    """
    command = "openssl genrsa -out /tmp/%s.key 2048" % (cert_name)
    duthost.shell(command, module_ignore_errors=True)
    command = "openssl req -new -x509 -key /tmp/%s.key -out /tmp/%s.crt \
              -subj '/CN=test.server.restapi.sonic' -days %d" % (cert_name, cert_name, expire)
    duthost.shell(command, module_ignore_errors=True)
    command = "openssl pkcs12 -export -out /tmp/%s.pfx -inkey /tmp/%s.key \
              -in /tmp/%s.crt -password pass:" % (cert_name, cert_name, cert_name)
    duthost.shell(command, module_ignore_errors=True)
