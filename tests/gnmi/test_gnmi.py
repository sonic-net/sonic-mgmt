import pytest
import logging

from .helper import gnmi_capabilities, gnmi_set, add_gnmi_client_common_name, del_gnmi_client_common_name, dump_gnmi_log

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_capabilities(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI capabilities
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost)
    assert ret == 0, msg
    assert "sonic-db" in msg, msg
    assert "JSON_IETF" in msg, msg


@pytest.fixture(scope="function")
def setup_invalid_client_cert_cname(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "invalid.cname")

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: {}".format(keys))

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def gnmi_create_vnet(duthost, ptfhost, cert=None):
    file_name = "vnet.txt"
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    msg = ""
    try:
        gnmi_set(duthost, ptfhost, [], update_list, [], cert)
    except Exception as e:
        logger.info("Failed to set: " + str(e))
        msg = str(e)

    dump_gnmi_log(duthost)

    return msg


def test_gnmi_authorize_failed_with_invalid_cname(duthosts,
                                                  rand_one_dut_hostname,
                                                  ptfhost,
                                                  setup_invalid_client_cert_cname):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    msg = gnmi_create_vnet(duthost, ptfhost)

    assert "Unauthenticated" in msg


@pytest.fixture(scope="function")
def setup_crl_server_on_ptf(ptfhost):
    ptfhost.shell('nohup python /root/crl_server.py &')

    yield

    ptfhost.shell("pkill -9 -f 'python /root/crl_server.py'")


def test_gnmi_authorize_failed_with_revoked_cert(duthosts,
                                                 rand_one_dut_hostname,
                                                 ptfhost,
                                                 setup_crl_server_on_ptf):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    msg = gnmi_create_vnet(duthost, ptfhost, "gnmiclient.revoked")

    assert "Unauthenticated" in msg
