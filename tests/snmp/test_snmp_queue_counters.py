import pytest
import json
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert

CFG_DB_PATH = "/etc/sonic/config_db.json"
ORIG_CFG_DB = "/etc/sonic/orig_config_db.json"
UNICAST_CTRS = 4
MULTICAST_CTRS = 4
BUFFER_QUEUES_REMOVED = 2

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def load_new_cfg(duthost, data):
    duthost.copy(content=json.dumps(data, indent=4), dest=CFG_DB_PATH)
    config_reload(duthost, config_source='config_db', safe_reload=True)


def get_queue_ctrs(duthost, cmd):
    return len(duthost.shell(cmd)["stdout_lines"])


def test_snmp_queue_counters(duthosts,
                             enum_rand_one_per_hwsku_frontend_hostname,
                             creds_all_duts):
    """
    Test SNMP queue counters
      - Set "create_only_config_db_buffers" to true in config db, to create
      only relevant counters
      - Remove one of the buffer queues, Ethernet0|3-4 is chosen arbitrary
      - Using snmpwalk compare number of queue counters on Ethernet0, assuming
      there will be 8 less after removing the buffer. (Assuming unicast only,
      4 counters for each queue in this case)
    This test covers the issue: 'The feature "polling only configured ports
    buffer queue" will break SNMP'
    https://github.com/sonic-net/sonic-buildimage/issues/17448
    """

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    Ethernet0_queue_cntrs_oid = '1.3.6.1.4.1.9.9.580.1.5.5.1.4.1'
    get_bfr_queue_cntrs_cmd \
        = "docker exec snmp snmpwalk -v2c -c {} {} {}".format(
            creds_all_duts[duthost.hostname]['snmp_rocommunity'], hostip,
            Ethernet0_queue_cntrs_oid)
    # Generate sonic-cfggen commands for multi-asic and single-asic duts
    nslist = duthost.get_asic_namespace_list()
    if duthost.sonichost.is_multi_asic and nslist is not None:
        cmd = "sonic-cfggen -n asic0 -d --print-data > {}".format(ORIG_CFG_DB)
    else:
        cmd = "sonic-cfggen -d --print-data > {}".format(ORIG_CFG_DB)

    duthost.shell(cmd)
    data = json.loads(duthost.shell("cat {}".format(ORIG_CFG_DB),
                                    verbose=False)['stdout'])
    buffer_queue_to_del = None
    # Get appropriate buffer queue value to delete for Ethernet0|3-4 in case of multi-asic
    if duthost.sonichost.is_multi_asic:
        buffer_queues = list(data['BUFFER_QUEUE'].keys())
        iface_to_check = buffer_queues[0].split('|')[0]
        iface_buffer_queues = [bq for bq in buffer_queues if any(val in iface_to_check for val in bq.split('|'))]
        for queue in iface_buffer_queues:
            if 'asic0' in queue and queue.split('|')[-1] == '3-4':
                buffer_queue_to_del = queue
                break
    else:
        buffer_queue_to_del = "Ethernet0|3-4"

    # Add create_only_config_db_buffers entry to device metadata to enable
    # counters optimization and get number of queue counters of Ethernet0 prior
    # to removing buffer queues
    data['DEVICE_METADATA']["localhost"]["create_only_config_db_buffers"] \
        = "true"
    load_new_cfg(duthost, data)
    queue_counters_cnt_pre = get_queue_ctrs(duthost, get_bfr_queue_cntrs_cmd)

    # Remove buffer queue and reload and get number of queue counters of
    # Ethernet0 after removing two buffer queues
    del data['BUFFER_QUEUE'][buffer_queue_to_del]
    load_new_cfg(duthost, data)
    queue_counters_cnt_post = get_queue_ctrs(duthost, get_bfr_queue_cntrs_cmd)

    unicast_expected_diff = BUFFER_QUEUES_REMOVED * UNICAST_CTRS
    multicast_expected_diff = unicast_expected_diff + (BUFFER_QUEUES_REMOVED
                                                       * MULTICAST_CTRS)
    pytest_assert((queue_counters_cnt_pre - queue_counters_cnt_post)
                  in [unicast_expected_diff, multicast_expected_diff],
                  "Queue counters actual count {} differs from expected values {}, {}".
                  format(queue_counters_cnt_post, (queue_counters_cnt_pre - unicast_expected_diff),
                         (queue_counters_cnt_pre - multicast_expected_diff)))


@pytest.fixture(scope="module")
def teardown(duthost):
    """
    Teardown procedure for all test function
    :param duthost: DUT host object
    """
    yield
    # Cleanup
    duthost.copy(src=ORIG_CFG_DB, dest=CFG_DB_PATH)
    config_reload(duthost, config_source='config_db', safe_reload=True)
