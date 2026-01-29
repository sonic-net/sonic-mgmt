import pytest
import re

container_name = "acms"
sidecar_container_name = "acms_sidecar"
watchdog_container_name = "acms_watchdog"

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
    cert_path = "/etc/sonic/credentials/sonic_acms_bootstrap-%s.pfx" % region
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
    Generate a pfx cert file on the DUT.
    """
    command = "docker exec acms openssl genrsa -out /tmp/%s.key 2048" % (cert_name)
    duthost.shell(command, module_ignore_errors=True)
    command = "docker exec acms openssl req -new -x509 -key /tmp/%s.key -out /tmp/%s.crt \
              -subj '/CN=test.server.restapi.sonic' -days %d" % (cert_name, cert_name, expire)
    duthost.shell(command, module_ignore_errors=True)
    command = "docker exec acms openssl pkcs12 -export -out /tmp/%s.pfx -inkey /tmp/%s.key \
              -in /tmp/%s.crt -password pass:" % (cert_name, cert_name, cert_name)
    duthost.shell(command, module_ignore_errors=True)
