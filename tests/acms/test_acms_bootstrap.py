import logging
import pytest

from tests.acms.helper import container_name, create_acms_conf, host_generate_pfx_cert, TEST_DATA_CLOUD


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


@pytest.mark.parametrize("test_data", TEST_DATA_CLOUD)
def test_acms_bootstrap(duthosts, rand_one_dut_hostname, creds, test_data):
    """
    Test ACMS bootstrap functionality with internal image.
    Use invalid bootstrap certificate to access 5 DSMS endpoint.
    - HTTP_1_1_REQUIRED, CURL compatibility issue.
    - HTTP code 401, DSMS endpoint rejects invalid certificate, expected behavior.
    - HTTP code 503, DSMS service not available, try next endpoint
    """
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    if ("http" not in http_proxy):
        pytest.skip("ACMS does not work without http proxy: " + http_proxy)
    duthost = duthosts[rand_one_dut_hostname]
    host_generate_pfx_cert(duthost, "acms")
    dut_command = "docker exec %s supervisorctl stop start" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl stop acms" % container_name
    duthost.shell(dut_command, module_ignore_errors=True)
    cloudtype = test_data["cloudtype"]
    region_list = test_data["region_list"]
    for region in region_list:
        dut_command = "rm /var/opt/msft/client/*"
        duthost.shell(dut_command, module_ignore_errors=True)
        dut_command = "rm /etc/sonic/credentials/sonic_acms_bootstrap-*"
        duthost.shell(dut_command, module_ignore_errors=True)
        dut_command = "cp /tmp/acms.pfx /etc/sonic/credentials/sonic_acms_bootstrap-%s.pfx" % region
        duthost.shell(dut_command, module_ignore_errors=True)
        create_acms_conf(region, cloudtype, duthost, "/var/opt/msft/client/acms_secrets.ini")
        dut_command = 'docker exec -e http_proxy="%s" -e https_proxy="%s" %s \
                        acms -Bootstrap -Dependant client -BaseDirPath /var/opt/msft/ -Console yes' \
                        % (http_proxy, https_proxy, container_name)
        command_result = duthost.shell(dut_command, module_ignore_errors=True)
        stdout = command_result['stdout']
        if "HTTP_1_1_REQUIRED" in stdout:
            pytest.fail("CURL error: cloud %s, region %s, HTTP_1_1_REQUIRED" % (cloudtype, region))
        if "CurlErrorCode=58" in stdout or "could not parse PKCS12" in stdout:
            pytest.fail("PKCS12 cert parse error: cloud %s, region %s, "
                        "bootstrap cert is incompatible with ACMS OpenSSL version" % (cloudtype, region))
        if "code 401" in stdout or "response:401" in stdout:
            logger.info("Code 401: cloud %s, region %s rejects the bootstrap certificate" % (cloudtype, region))
            return
        if "code 503" in stdout:
            logger.info("Code 503: cloud %s, region %s service not available" % (cloudtype, region))
        elif "CurlErrorCode=56" in stdout or "CONNECT tunnel failed" in stdout:
            logger.info("Proxy error: cloud %s, region %s, CONNECT tunnel blocked by proxy" % (cloudtype, region))
        else:
            logger.info("Unknown error: cloud %s, region %s, %s" % (cloudtype, region, stdout))
    pytest.fail("All regions failed: " + ','.join(region_list))
