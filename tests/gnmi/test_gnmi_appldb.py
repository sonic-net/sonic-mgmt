import time
import logging
import pytest

from .helper import gnmi_set, gnmi_get

logger = logging.getLogger(__name__)

GNMI_GET_RETRY_COUNT = 3
GNMI_GET_RETRY_INTERVAL = 10

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def test_gnmi_appldb_01(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write with ApplDB
    Update DASH_VNET_TABLE
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "vnet.txt"
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    gnmi_set(duthost, ptfhost, [], update_list, [])
    # Check gnmi_get result with retry for gNMI service readiness
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    output = None
    for attempt in range(GNMI_GET_RETRY_COUNT):
        try:
            msg_list1 = gnmi_get(duthost, ptfhost, path_list1)
        except Exception as e:
            logger.info("Failed to read path1 (attempt %d/%d): %s",
                        attempt + 1, GNMI_GET_RETRY_COUNT, str(e))
        else:
            output = msg_list1[0]
            break
        try:
            msg_list2 = gnmi_get(duthost, ptfhost, path_list2)
        except Exception as e:
            logger.info("Failed to read path2 (attempt %d/%d): %s",
                        attempt + 1, GNMI_GET_RETRY_COUNT, str(e))
        else:
            output = msg_list2[0]
            break
        if attempt < GNMI_GET_RETRY_COUNT - 1:
            logger.info("Retrying gNMI GET after %ds wait...", GNMI_GET_RETRY_INTERVAL)
            time.sleep(GNMI_GET_RETRY_INTERVAL)
    assert output == "\"1000\"", \
        "gNMI APPL_DB read failed on {} after {} retries: output='{}'".format(
            duthost.hostname, GNMI_GET_RETRY_COUNT, output)

    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1"]
    gnmi_set(duthost, ptfhost, delete_list, [], [])
    # Check gnmi_get result
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    try:
        msg_list1 = gnmi_get(duthost, ptfhost, path_list1)
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + msg_list1[0])
    try:
        msg_list2 = gnmi_get(duthost, ptfhost, path_list2)
    except Exception as e:
        logger.info("Failed to read path2: " + str(e))
    else:
        pytest.fail("Remove DASH_VNET_TABLE failed: " + msg_list2[0])
