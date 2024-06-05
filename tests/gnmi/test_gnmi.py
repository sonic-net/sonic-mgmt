import pytest
import logging

from .helper import gnmi_capabilities, gnmi_set, set_gnmi_client_common_name, del_gnmi_client_common_name

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
    set_gnmi_client_common_name(duthost, "invalid.cname")

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    set_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def test_gnmi_authorize_failed_with_invalid_cname(duthosts, rand_one_dut_hostname, localhost, setup_invalid_client_cert_cname):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "port.txt"
    update_list = ["/sonic-db:CONFIG_DB/localhost/PORTABC/Ethernet100/admin_status:@./%s" % (file_name)]

    # GNMI set request with invalid path
    text = "\"down\""
    with open(file_name, 'w') as file:
        file.write(text)

    ret, msg = gnmi_set(duthost, localhost, [], update_list, [])
    assert ret != 0
    assert "Set failed: rpc error: code = Unauthenticated" in msg