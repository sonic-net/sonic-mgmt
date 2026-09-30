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
    Smoke test GNMI native Set/Get/Delete with ApplDB over managed TLS.
    '''
    client = gnmi_tls.pygnmi_client
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    # Add DASH_VNET_TABLE
    update_list = [("/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", text)]
    client.set(update=update_list)
    # Read using either supported table layout.
    path_list1 = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1/vni"]
    path_list2 = ["/sonic-db:APPL_DB/localhost/_DASH_VNET_TABLE/Vnet1/vni"]
    try:
        client.get(path_list1)
    except Exception as e:
        logger.info("Failed to read path1: " + str(e))
        client.get(path_list2)

    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE/Vnet1"]
    client.set(delete=delete_list)
