import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts
from tests.common.helpers.sonic_db import redis_get_keys

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_snmp_queues(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts,
                     collect_techsupport_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("interfaces not present on supervisor node")
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    q_keys = redis_get_keys(duthost, "CONFIG_DB", "QUEUE|*")

    if q_keys is None:
        pytest.skip("No queues configured on interfaces")

    q_interfaces = set()
    # get interfaces which has configured queues
    for key in q_keys:
        intf = key.split('|')
        # 'QUEUE|Ethernet*|2'
        if len(intf) == 3:
            q_interfaces.add(intf[1])

    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c",
                                community=creds_all_duts[duthost.hostname]["snmp_rocommunity"],
                                wait=True)['ansible_facts']

    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['description']:
            intf = v['description'].split(':')
            # 'ARISTA*:Ethernet*'
            if len(intf) == 2:
                if intf[1] in q_interfaces and 'queues' not in v:
                    pytest.fail("port %s does not have queue counters" % v['name'])
