import logging
import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("rand_one_dut_hostname")
]


def test_gnmi_appldb_01(gnmi_tls):  # noqa: F811
    '''
    Verify GNMI native write with ApplDB
    Update DASH_VNET_TABLE
    '''
    client = gnmi_tls.pygnmi_client
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    # Add DASH_VNET_TABLE
    update_list = [("/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", text)]
    client.set(update=update_list)
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    output = None
    try:
        msg_list1 = client.get(path_list1)["notification"][0]["update"]
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        output = msg_list1[0]["val"]
    try:
        msg_list2 = client.get(path_list2)["notification"][0]["update"]
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        output = msg_list2[0]["val"]
    assert output == "1000", "Unexpected output: '{}'".format(output)

    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1"]
    client.set(delete=delete_list)
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    try:
        msg_list1 = client.get(path_list1)["notification"][0]["update"]
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + str(msg_list1[0]["val"]))
    try:
        msg_list2 = client.get(path_list2)["notification"][0]["update"]
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + str(msg_list2[0]["val"]))
