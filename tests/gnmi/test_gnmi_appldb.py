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
    prefix = "sonic-db:APPL_DB/localhost"
    # Add DASH_VNET_TABLE
    client.set(update=[("DASH_VNET_TABLE", {
        "Vnet1": {"vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2"}
    })], prefix=prefix)
    # Check gnmi_get result
    path_list1 = ["DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["_DASH_VNET_TABLE/Vnet1/vni"]
    output = None
    try:
        result1 = client.get(path_list1, prefix=prefix)
        value1 = result1["notification"][0]["update"][0]["val"]
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        output = value1
    try:
        result2 = client.get(path_list2, prefix=prefix)
        value2 = result2["notification"][0]["update"][0]["val"]
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        output = value2
    assert output == "1000", "Unexpected output: '{}'".format(output)

    # Remove DASH_VNET_TABLE
    client.set(delete=["DASH_VNET_TABLE/Vnet1"], prefix=prefix)
    # Check gnmi_get result
    try:
        result1 = client.get(path_list1, prefix=prefix)
        value1 = result1["notification"][0]["update"][0]["val"]
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + str(value1))
    try:
        result2 = client.get(path_list2, prefix=prefix)
        value2 = result2["notification"][0]["update"][0]["val"]
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + str(value2))
