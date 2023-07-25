import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_snmp_queues(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts,
                     collect_techsupport_all_duts):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    q_keys = []

    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    for asic_id in duthost.get_asic_ids():
        namespace = duthost.get_namespace_from_asic_id(asic_id)
        sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
        q_keys_ns = duthost.shell('{} CONFIG_DB KEYS "QUEUE|*"'.format(sonic_db_cmd),
                                  module_ignore_errors=False)['stdout_lines']
        if q_keys_ns:
            q_keys.extend(q_keys_ns)

    if not q_keys:
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

    for k, v in list(snmp_facts['snmp_interfaces'].items()):
        if "Ethernet" in v['description']:
            intf = v['description'].split(':')
            # 'ARISTA*:Ethernet*'
            if len(intf) == 2:
                if intf[1] in q_interfaces and 'queues' not in v:
                    pytest.fail(
                        "port %s does not have queue counters" % v['name'])
