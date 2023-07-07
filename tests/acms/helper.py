import pytest
import os
import re

container_name = "acms"

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
