import json
import logging
import pytest
import uuid
from .helper import gnmi_set
from dash_api.vnet_pb2 import Vnet

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def get_vnet_proto(vni, guid):
    pb = Vnet()
    pb.vni = int(vni)
    pb.guid.value = bytes.fromhex(uuid.UUID(guid).hex)
    return pb.SerializeToString()


def test_gnmi_appldb_01(duthosts, rand_one_dut_hostname, ptfhost):
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
    result = duthost.shell("show chassis module status")
    headers = result['stdout_lines'][0].split()
    name_idx = None
    oper_status_idx = None
    for i, header in enumerate(headers):
        if header == "Name":
            name_idx = i
        if header == "Oper-Status":
            oper_status_idx = i
    assert name_idx is not None, "Can't locate Name in the headers"
    assert oper_status_idx is not None, "Can't locate Oper-Status in the headers"
    for line in result['stdout_lines']:
        module_status = line.split()
        if module_status[oper_status_idx] == "Online":
            target = module_status[name_idx].lower()
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
    update_list = ["/sonic-db:APPL_DB/%s/DASH_VNET_TABLE/Vnet1:$/root/%s" % (target, file_name)]
    gnmi_set(duthost, ptfhost, [], update_list, [])
    # Verify APPL_DB
    int_cmd = "redis-cli --raw -p %s -n 0 hget \"DASH_VNET_TABLE:Vnet1\" pb" % redis_port
    int_cmd += " | dash_api_utils --table_name DASH_VNET_TABLE"
    result = duthost.shell('docker exec database bash -c "%s"' % int_cmd)
    vnet_config = json.loads(result["stdout"])
    assert str(vnet_config["vni"]) == vni, "DASH_VNET_TABLE is wrong: " + result["stdout"]
    logger.info("DASH_VNET_TABLE is updated: {}".format(result["stdout"]))
    # Remove DASH_VNET_TABLE
    delete_list = ["/sonic-db:APPL_DB/%s/DASH_VNET_TABLE/Vnet1" % target]
    gnmi_set(duthost, ptfhost, delete_list, [], [])
    # Verify APPL_DB
    int_cmd = "redis-cli --raw -p %s -n 0 hgetall \"DASH_VNET_TABLE:Vnet1\"" % redis_port
    result = duthost.shell('docker exec database bash -c "%s"' % int_cmd)
    assert "pb" not in result["stdout"], "DASH_VNET_TABLE is wrong: " + result["stdout"]
    logger.info("DASH_VNET_TABLE is removed: {}".format(result["stdout"]))
