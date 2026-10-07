import json
import logging
import pytest
import uuid

from dash_api.vnet_pb2 import Vnet
from pygnmi.create_gnmi_path import gnmi_path_generator
from pygnmi.spec.v080 import gnmi_pb2

from tests.gnmi_benchmark.helpers import gnmi_connection
from .tls_setup import gnmi_server_context

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


@pytest.fixture(scope="module")
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost, ptfhost, vrf_config,
                      setup_vrf_configuration, setup_gnmi_ntp_client_server):
    duthost = duthosts[rand_one_dut_hostname]
    with gnmi_server_context(duthost, localhost, ptfhost, vrf_config) as server:
        yield server


def get_vnet_proto(vni, guid):
    pb = Vnet()
    pb.vni = int(vni)
    pb.guid.value = bytes.fromhex(uuid.UUID(guid).hex)
    return pb.SerializeToString()


def test_gnmi_appldb_01(duthosts, rand_one_dut_hostname, ptfhost, setup_gnmi_server):
    '''
    Verify GNMI native write with ApplDB
    Update DASH_VNET_TABLE
    '''
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    metadata = cfg_facts["DEVICE_METADATA"]["localhost"]
    subtype = metadata.get('subtype', None)
    type = metadata.get('type', None)
    logger.info("type {}, subtype {}".format(type, subtype))
    if type != "LeafRouter" or subtype != 'SmartSwitch':
        pytest.skip("This test is supported only on smartswitch platforms")
    # Locate the first online DPU
    # Name    Description    Physical-Slot    Oper-Status    Admin-Status    Serial
    # ------  -------------  ---------------  -------------  --------------  --------
    # DPU0            N/A              N/A         Online              up       N/A
    target = None
    result = duthost.show_and_parse("show chassis module status")
    for dpu_status_line in result:
        if dpu_status_line["oper-status"] == "Online":
            target = dpu_status_line["name"].lower()
            logger.info("target is {}".format(target))
            break
    assert target is not None, "Can't locate online DPU"
    # Get redis port
    result = duthost.shell("cat /var/run/redis%s/sonic-db/database_config.json" % target)
    data = json.loads(result['stdout'])
    redis_port = data['INSTANCES']['redis']['port']
    file_name = "vnet.txt"
    vni = "1000"
    guid = str(uuid.uuid4())
    proto = get_vnet_proto(vni, guid)
    with open(file_name, 'wb') as file:
        file.write(proto)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/%s/DASH_VNET_TABLE/Vnet1" % target]
    request = gnmi_pb2.SetRequest(update=[gnmi_pb2.Update(
        path=gnmi_path_generator(update_list[0]), val=gnmi_pb2.TypedValue(proto_bytes=proto))])
    with gnmi_connection(setup_gnmi_server) as (_, client):
        client.Set(request, timeout=30)
    # Verify APPL_DB
    int_cmd = "redis-cli --raw -p %s -n 0 hget \"DASH_VNET_TABLE:Vnet1\" pb" % redis_port
    int_cmd += " | dash_api_utils --table_name DASH_VNET_TABLE"
    result = duthost.shell('docker exec database bash -c "%s"' % int_cmd)
    vnet_config = json.loads(result["stdout"])
    assert str(vnet_config["vni"]) == vni, "DASH_VNET_TABLE is wrong: " + result["stdout"]
    logger.info("DASH_VNET_TABLE is updated: {}".format(result["stdout"]))
    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/%s/DASH_VNET_TABLE/Vnet1" % target]
    request = gnmi_pb2.SetRequest(delete=[gnmi_path_generator(path) for path in delete_list])
    with gnmi_connection(setup_gnmi_server) as (_, client):
        client.Set(request, timeout=30)
    # Verify APPL_DB
    int_cmd = "redis-cli --raw -p %s -n 0 hgetall \"DASH_VNET_TABLE:Vnet1\"" % redis_port
    result = duthost.shell('docker exec database bash -c "%s"' % int_cmd)
    assert "pb" not in result["stdout"], "DASH_VNET_TABLE is wrong: " + result["stdout"]
    logger.info("DASH_VNET_TABLE is removed: {}".format(result["stdout"]))
