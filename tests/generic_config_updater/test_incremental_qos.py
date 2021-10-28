import logging
import json
import time
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic("mellanox")
]


logger = logging.getLogger(__name__)


BACKUP_CONFIG_DB_CMD = "sudo cp /etc/sonic/config_db.json /etc/sonic/config_db.json.incremental_qos_orig"
RESTORE_CONFIG_DB_CMD = "sudo cp /etc/sonic/config_db.json.incremental_qos_orig /etc/sonic/config_db.json"
DELETE_BACKUP_CONFIG_DB_CMD = "sudo rm /etc/sonic/config_db.json.incremental_qos_orig"
INCREMENTAL_QOS_TEST_FILE_LIST = []


def verifyOrchagentRunningOrAssert(duthost):
    """
    Verifies that orchagent is running, asserts otherwise

    Args: 
        duthost: Device Under Test (DUT)
    """
    result = duthost.shell(argv=["pgrep", "orchagent"])
    orchagent_pids = result['stdout'].splitlines()
    pytest_assert(len(orchagent_pids) == duthost.num_asics(), "Orchagent is not running")
    for pid in orchagent_pids:
        pytest_assert(int(pid) > 0, "Orchagent is not running")


@pytest.fixture(scope="module")
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for incremental qos config update tst

    Args:
        duthost: DUT host object
    """
    
    logger.info("Backing up config_db.json")
    duthost.shell(BACKUP_CONFIG_DB_CMD)
    verifyOrchagentRunningOrAssert(duthost)

    yield

    verifyOrchagentRunningOrAssert(duthost)
    logger.info("Restoring config_db.json")
    duthost.shell(RESTORE_CONFIG_DB_CMD)
    duthost.shell(DELETE_BACKUP_CONFIG_DB_CMD)

    for temp_file in INCREMENTAL_QOS_TEST_FILE_LIST:
        duthost.shell('rm -rf {}'.format(temp_file))

    logger.info("TEARDOWN COMPLETED")


def prepare_configdb_field(duthost, key, field, value):
    """
    Prepares config db by setting BUFFER_POOL key and field to specified value. If value is empty, delete the current entry. 

    Args:
        duthost: DUT host object
        key: BUFFER_POOL table key to configure
        field: BUFFER_POOL table field to configure
        value: BUFFER_POOL table value to be set
    """
    logger.info("Setting configdb field: {} to value: {}".format(field, value))
   
    if value:
        cmd = "redis-cli -n 4 hset \"BUFFER_POOL|{}\" \"{}\" \"{}\" ".format(key, field, value)
    else:
        cmd = "redis-cli -n 4 del \"BUFFER_POOL|{}\" \"{}\" ".format(key, field)
   
    verifyOrchagentRunningOrAssert(duthost)


def ensure_patch_application(duthost, patch_path):
    """
    Applies patch at specified path, and asserts for successful application

    
    Args:
        duthost: DUT host object
        patch_path: path of JSON patch to be applied
    """
    cmds = 'config apply-patch {}'.format(patch_path)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds)

    pytest_assert("Patch applied successfully" in output['stdout'], "Please check if json file is validated")


DUT_ADD_HEADROOM_JSON_FILE='/tmp/add_headroom_pool.json'
INCREMENTAL_QOS_TEST_FILE_LIST.append(DUT_ADD_HEADROOM_JSON_FILE)
def test_set_nonexistent_headroom_pool(duthost):
    prepare_configdb_field("ingress_lossless_pool", "xoff", "")
    
    add_headroom_pool_json = [
        {
            "op": "add",
            "path": "/BUFFER_POOL/ingress_lossless_pool/xoff",
            "value": "567"
        }
    ]  

    duthost.copy(content=json.dumps(add_headroom_pool_json, indent=4), dest=DUT_ADD_HEADROOM_JSON_FILE)

    ensure_patch_application(DUT_ADD_HEADROOM_JSON_FILE)


DUT_REPLACE_HEADROOM_JSON_FILE='/tmp/replace_headroom_pool.json'
INCREMENTAL_QOS_TEST_FILE_LIST.append(DUT_REPLACE_HEADROOM_JSON_FILE)
def test_replace_existing_headroom_pool(duthost):
    prepare_configdb_field("ingress_lossless_pool", "xoff", "567")

    set_headroom_pool_json = [
        {
            "op": "replace",
            "path": "/BUFFER_POOL/ingress_lossless_pool/xoff",
            "value": "678"
        }
    ]

    duthost.copy(content=json.dumps(set_headroom_pool_json, indent=4), dest=DUT_REPLACE_HEADROOM_JSON_FILE)

    ensure_patch_application(DUT_REPLACE_HEADROOM_JSON_FILE)


DUT_DEL_HEADROOM_JSON_FILE='/tmp/del_headroom_pool.json'
INCREMENTAL_QOS_TEST_FILE_LIST.append(DUT_DEL_HEADROOM_JSON_FILE)
def test_del_existing_headroom_pool(duthost):
    prepare_configdb_field("ingress_lossless_pool", "xoff", "567")

    del_headroom_pool_json = [
        {
            "op": "remove",
            "path": "/BUFFER_POOL/ingress_lossless_pool/xoff"
        }
    ]

    duthost.copy(content=json.dumps(del_headroom_pool_json, indent=4), dest=DUT_DEL_HEADROOM_JSON_FILE)

    ensure_patch_application(DUT_DEL_HEADROOM_JSON_FILE)


def test_del_nonexistent_headroom_pool(duthost):
    prepare_configdb_field("ingress_lossless_pool", "xoff")

    del_headroom_pool_json = [
        {
            "op": "remove",
            "path": "/BUFFER_POOL/ingress_lossless_pool/xoff"
        }
    ]

    duthost.copy(content=json.dumps(del_headroom_pool_json, indent=4), dest=DUT_DEL_HEADROOM_JSON_FILE)

    ensure_patch_application(DUT_DEL_HEADROOM_JSON_FILE)


DUT_ADD_POOL_JSON_FILE='/tmp/add_pool.json'
INCREMENTAL_QOS_TEST_FILE_LIST.append(DUT_ADD_POOL_JSON_FILE)
def test_set_nonexistent_pool_size_ingress(duthost):
    prepare_configdb_field("ingress_lossless_pool", "size", "")

    set_pool_size_json = [
        {
            "op": "add",
            "path": "/BUFFER_POOL/ingress_lossless_pool/size",
            "value": "567"
        }
    ]

    duthost.copy(content=json.dumps(set_pool_size_json, indent=4), dest=DUT_ADD_POOL_JSON_FILE)

    ensure_patch_application(DUT_ADD_POOL_JSON_FILE)


def test_replace_existing_pool_size_ingress(duthost):
    prepare_configdb_field("ingress_lossless_pool", "size", "567")

    set_pool_size_json = [
        {
            "op": "replace",
            "path": "/BUFFER_POOL/ingress_lossless_pool/size",
            "value": "678"
        }
    ]

    duthost.copy(content=json.dumps(set_pool_size_json, indent=4), dest=DUT_ADD_POOL_JSON_FILE)

    ensure_patch_application(DUT_ADD_POOL_JSON_FILE)


DUT_DEL_POOL_JSON_FILE='/tmp/del_pool.json'
INCREMENTAL_QOS_TEST_FILE_LIST.append(DUT_DEL_POOL_JSON_FILE)
def test_del_existing_pool_size_ingress(duthost):
    prepare_configdb_field("ingress_lossless_pool", "size", "567")

    del_pool_size_json = [
        {
            "op": "remove",
            "path": "/BUFFER_POOL/ingress_lossless_pool/size"
        }
    ]

    duthost.copy(content=json.dumps(del_pool_size_json, indent=4), dest=DUT_DEL_POOL_JSON_FILE)

    ensure_patch_application(DUT_DEL_POOL_JSON_FILE)


def test_del_nonexistent_pool_size_ingress(duthost):
    prepare_configdb_field("ingress_lossless_pool", "size", "")

    del_pool_size_json = [
        {
            "op": "remove", 
            "path": "/BUFFER_POOL/ingress_lossless_pool/size"
        }
    ]

    duthost.copy(content=json.dumps(del_pool_size_json, indent=4), dest=DUT_DEL_POOL_JSON_FILE)

    ensure_patch_application(DUT_DEL_POOL_JSON_FILE)


def test_set_nonexistent_pool_size_egress(duthost):
    prepare_configdb_field("egress_lossy_pool", "size", "")

    set_pool_size_json = [
        {
            "op": "replace",
            "path": "/BUFFER_POOL/egress_lossy_pool/size",
            "value": "567"
        }
    ]

    duthost.copy(content=json.dumps(set_pool_size_json, indent=4), dest=DUT_ADD_POOL_JSON_FILE)

    ensure_patch_application(DUT_ADD_POOL_JSON_FILE)



def test_replace_existing_pool_size_egress(duthost):
    prepare_configdb_field("egress_lossy_pool", "size", "567")

    set_pool_size_json = [
        {
            "op": "replace",
            "path": "/BUFFER_POOL/egress_lossy_pool/size",
            "value": "678"
        }
    ]

    duthost.copy(content=json.dumps(set_pool_size_json, indent=4), dest=DUT_ADD_POOL_JSON_FILE)

    ensure_patch_application(DUT_ADD_POOL_JSON_FILE)


def test_del_nonexistent_pool_size_egress(duthost):
    prepare_configdb_field("egress_lossy_pool", "size", "")

    del_pool_size_json = [
        {
            "op": "remove", 
            "path": "/BUFFER_POOL/egress_lossy_pool/size"
        }
    ]

    duthost.copy(content=json.dumps(del_pool_size_json, indent=4), dest=DUT_DEL_POOL_JSON_FILE)

    ensure_patch_application(DUT_DEL_POOL_JSON_FILE)


def test_del_existing_pool_size_egress(duthost):
    prepare_configdb_field("egress_lossy_pool", "size", "567")

    del_pool_size_json = [
        {
            "op": "remove", 
            "path": "/BUFFER_POOL/egress_lossy_pool/size"
        }
    ]

    duthost.copy(content=json.dumps(del_pool_size_json, indent=4), dest=DUT_DEL_POOL_JSON_FILE)

    ensure_patch_application(DUT_DEL_POOL_JSON_FILE)



