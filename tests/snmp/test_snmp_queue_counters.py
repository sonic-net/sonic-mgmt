import pytest
import json
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

CFG_DB_PATH = "/etc/sonic/config_db.json"
ORIG_CFG_DB = "/etc/sonic/orig_config_db.json"
UNICAST_CTRS = 4
MULTICAST_CTRS = 4

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def load_new_cfg(duthost, data):
    duthost.copy(content=json.dumps(data, indent=4), dest=CFG_DB_PATH)
    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


def get_queue_ctrs(duthost, cmd):
    return len(duthost.shell(cmd)["stdout_lines"])


def check_snmp_cmd_output(duthost, cmd):
    out_len = len(duthost.shell(cmd)["stdout_lines"])
    if out_len > 1:
        return True
    else:
        return False


def get_queue_cntrs_oid(interface):
    """
    @summary: Returns queue_cntrs_oid value based on the interface chosen
              for single/multi-asic sonic host.
    Args:
        interface: Asic interface selected
    Returns:
        queue_cntrs_oid
    """
    intf_num = interface.split('Ethernet')[1]
    queue_cntrs_oid = '1.3.6.1.4.1.9.9.580.1.5.5.1.4.{}'.format(int(intf_num) + 1)
    return queue_cntrs_oid


def get_asic_interface(inter_facts):
    """
    @summary: Returns interface dynamically based on the asic chosen
              for single/multi-asic sonic host.
    """
    ansible_inter_facts = inter_facts['ansible_interface_facts']
    interface = None
    for key, v in ansible_inter_facts.items():
        # Exclude internal interfaces
        if 'IB' in key or 'Rec' in key or 'BP' in key:
            continue
        if 'Ether' in key and v['active']:
            interface = key
            break

    return interface


def test_snmp_queue_counters(duthosts,
                             enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
                             creds_all_duts):
    """
    Test SNMP queue counters
      - Set "create_only_config_db_buffers" to true in config db, to create
      only relevant counters
      - Remove one of the buffer queues for asic interface chosen, <interface>|3-4 is chosen arbitrary
      - Using snmpwalk compare number of queue counters on the interface, assuming
      there will be 8 less after removing the buffer. (Assuming unicast only,
      4 counters for each queue in this case)
    This test covers the issue: 'The feature "polling only configured ports
    buffer queue" will break SNMP'
    https://github.com/sonic-net/sonic-buildimage/issues/17448
    """

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ORIG_CFG_DB, CFG_DB_PATH
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    asic = duthost.asic_instance(enum_frontend_asic_index)
    int_facts = asic.interface_facts()['ansible_facts']
    interface = get_asic_interface(int_facts)
    if interface is None:
        pytest.skip("No active interface present on the asic {}".format(asic))
    queue_cntrs_oid = get_queue_cntrs_oid(interface)

    get_queue_stat_cmd = "queuestat -p {}".format(interface)
    get_bfr_queue_cntrs_cmd \
        = "docker exec snmp snmpwalk -v2c -c {} {} {}".format(
            creds_all_duts[duthost.hostname]['snmp_rocommunity'], hostip,
            queue_cntrs_oid)
    # Generate sonic-cfggen and queue stat commands for multi-asic and single-asic duts
    if duthost.sonichost.is_multi_asic and asic is not None:
        ORIG_CFG_DB = "/etc/sonic/orig_config_db{}.json".format(asic.asic_index)
        CFG_DB_PATH = "/etc/sonic/config_db{}.json".format(asic.asic_index)
        cmd = "sonic-cfggen -n {} -d --print-data > {}".format(asic.namespace, ORIG_CFG_DB)
        get_queue_stat_cmd = "queuestat -n {} -p {}".format(asic.namespace, interface)
    else:
        cmd = "sonic-cfggen -d --print-data > {}".format(ORIG_CFG_DB)

    duthost.shell(cmd)
    data = json.loads(duthost.shell("cat {}".format(ORIG_CFG_DB),
                                    verbose=False)['stdout'])
    buffer_queue_to_del = None

    # Get appropriate buffer queue value to delete
    buffer_queues = list(data['BUFFER_QUEUE'].keys())
    iface_buffer_queues = [bq for bq in buffer_queues if any(val in interface for val in bq.split('|'))]
    if iface_buffer_queues:
        buffer_queue_to_del = iface_buffer_queues[0]
    else:
        pytest_assert(False, "Buffer Queue list can't be empty if valid interface is selected.")

    # Add create_only_config_db_buffers entry to device metadata to enable
    # counters optimization and get number of queue counters of Ethernet0 prior
    # to removing buffer queues
    data['DEVICE_METADATA']["localhost"]["create_only_config_db_buffers"] \
        = "true"
    load_new_cfg(duthost, data)
    stat_queue_counters_cnt_pre = (get_queue_ctrs(duthost, get_queue_stat_cmd) - 2) * UNICAST_CTRS
    wait_until(60, 20, 0, check_snmp_cmd_output, duthost, get_bfr_queue_cntrs_cmd)
    queue_counters_cnt_pre = get_queue_ctrs(duthost, get_bfr_queue_cntrs_cmd)

    # snmpwalk output should get info for same number of buffers as queuestat -p dose
    pytest_assert((queue_counters_cnt_pre == stat_queue_counters_cnt_pre),
                  "Snmpwalk Queue counters actual count {} differs from expected queue stat count values {}".
                  format(queue_counters_cnt_pre, stat_queue_counters_cnt_pre))

    # Remove buffer queue and reload and get number of queue counters of selected interface
    del data['BUFFER_QUEUE'][buffer_queue_to_del]
    load_new_cfg(duthost, data)
    stat_queue_counters_cnt_post = (get_queue_ctrs(duthost, get_queue_stat_cmd) - 2) * UNICAST_CTRS
    wait_until(60, 20, 0, check_snmp_cmd_output, duthost, get_bfr_queue_cntrs_cmd)
    queue_counters_cnt_post = get_queue_ctrs(duthost, get_bfr_queue_cntrs_cmd)
    pytest_assert((queue_counters_cnt_post == stat_queue_counters_cnt_post),
                  "Snmpwalk Queue counters actual count {} differs from expected queue stat count values {}".
                  format(queue_counters_cnt_post, stat_queue_counters_cnt_post))

    # For broadcom-dnx voq chassis, number of voq are fixed (static), which cannot be modified dynamically
    # Hence, make sure the queue counters before deletion and after deletion are same for broadcom-dnx voq chassis
    if duthost.facts.get("platform_asic") == "broadcom-dnx" and duthost.sonichost.is_multi_asic:
        pytest_assert((queue_counters_cnt_pre == queue_counters_cnt_post),
                      "Queue counters actual count {} differs from expected values {}".
                      format(queue_counters_cnt_post, queue_counters_cnt_pre))
    # check for other duts
    else:
        range_str = str(buffer_queue_to_del.split('|')[-1])
        buffer_queues_removed = int(range_str.split('-')[1]) - int(range_str.split('-')[0]) + 1
        unicast_expected_diff = buffer_queues_removed * UNICAST_CTRS
        multicast_expected_diff = unicast_expected_diff + (buffer_queues_removed
                                                           * MULTICAST_CTRS)
        pytest_assert((queue_counters_cnt_pre - queue_counters_cnt_post)
                      in [unicast_expected_diff, multicast_expected_diff],
                      "Queue counters actual count {} differs from expected values {}, {}".
                      format(queue_counters_cnt_post, (queue_counters_cnt_pre - unicast_expected_diff),
                             (queue_counters_cnt_pre - multicast_expected_diff)))


@pytest.fixture(autouse=True, scope="module")
def teardown(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Teardown procedure for all test function
    param duthosts: duthosts object
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    # Cleanup
    duthost.copy(src=ORIG_CFG_DB, dest=CFG_DB_PATH, remote_src=True)
    config_reload(duthost, config_source='config_db', safe_reload=True)
