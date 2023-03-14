import logging
import pytest

from .helper import gnmi_set, gnmi_get

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_appldb_01(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI native write with ApplDB
    Update DASH_VNET_TABLE
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "vnet.txt"
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/DASH_VNET_TABLE:@./%s" % (file_name)]
    ret, msg = gnmi_set(duthost, localhost, [], update_list, [])
    assert ret == 0, msg
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/_DASH_VNET_TABLE/Vnet1/vni"]
    ret1, msg_list1 = gnmi_get(duthost, localhost, path_list1)
    ret2, msg_list2 = gnmi_get(duthost, localhost, path_list2)
    output = ""
    if ret1 == 0:
        output = msg_list1[0]
    if ret2 == 0:
        output = msg_list2[0]
    assert output == "\"1000\"", output

    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/DASH_VNET_TABLE/Vnet1"]
    ret, msg = gnmi_set(duthost, localhost, delete_list, [], [])
    assert ret == 0, msg
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/_DASH_VNET_TABLE/Vnet1/vni"]
    ret1, msg_list1 = gnmi_get(duthost, localhost, path_list1)
    ret2, msg_list2 = gnmi_get(duthost, localhost, path_list2)
    assert ret1 != 0 and ret2 != 0, msg_list1[0] + msg_list2[0]
