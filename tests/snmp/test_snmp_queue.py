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
    direction_type = '2'  # direction_type in OID is set to 2 to denote "egress".

    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    port_name_to_alias_map = {}
    port_name_to_ns = {}

    for asic_id in duthost.get_asic_ids():
        namespace = duthost.get_namespace_from_asic_id(asic_id)
        config_facts_ns = duthost.config_facts(host=duthost.hostname, source="running",
                                               namespace=namespace)['ansible_facts']
        asic = duthost.asic_instance(asic_id)
        q_keys_ns = asic.run_sonic_db_cli_cmd('CONFIG_DB KEYS "QUEUE|*"')['stdout_lines']
        if q_keys_ns:
            q_keys.extend(q_keys_ns)
        if config_facts_ns and 'port_name_to_alias_map' in config_facts_ns:
            port_name_to_alias_map.update(config_facts_ns['port_name_to_alias_map'])
            for port_name in config_facts_ns['port_name_to_alias_map']:
                port_name_to_ns[port_name] = namespace

    if not q_keys:
        pytest.skip("No queues configured on interfaces")

    # Get alias : port_name map
    alias_port_name_map = {k: v for v, k in port_name_to_alias_map.items()}

    q_interfaces = dict()  # {intf_name : set(queue_indexes)}
    # get interfaces which has configured queues
    for key in q_keys:
        intf_idx = 0
        queue_idx = 0
        intf = key.split('|')
        # 'QUEUE|Ethernet*|2'
        if len(intf) == 3:
            intf_idx = 1
            queue_idx = 2
        # Voq chassis 'QUEUE|<hostname>|<asic_ns>|Ethernet*|2'
        elif len(intf) == 5:
            # Choose only interfaces on current linecard.
            if intf[1] == duthost.hostname:
                intf_idx = 3
                queue_idx = 4
        if intf_idx != 0:
            if intf[intf_idx] not in q_interfaces:
                q_interfaces[intf[intf_idx]] = set()
            q_interfaces[intf[intf_idx]].add(intf[queue_idx])

    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c",
                                community=creds_all_duts[duthost.hostname]["snmp_rocommunity"],
                                wait=True)['ansible_facts']

    snmp_ifnames = [alias_port_name_map[v['name']]
                    for k, v in list(snmp_facts['snmp_interfaces'].items()) if v['name'] in alias_port_name_map]

    for intf in q_interfaces:
        assert intf in snmp_ifnames, "Port {} with QUEUE config is not present in snmp interfaces".format(intf)

    for k, v in snmp_facts['snmp_interfaces'].items():
        # v['name'] is  alias for example Ethernet1/1
        if v['name'] in alias_port_name_map:
            intf = alias_port_name_map[v['name']]

            # Expect all interfaces to have queue counters
            assert 'queues' in v, "Port {} does not have queue counters".format(intf)

            # Check if queue index in QUEUE table in config_db
            # is present in SNMP result
            if intf in q_interfaces:
                for queue_idx in q_interfaces[intf]:
                    # queue_idx starts with 0, queue_idx in OID starts with 1
                    # Increment queue_idx by 1 to form the right OID.
                    snmp_q_idx = int(queue_idx) + 1
                    if str(snmp_q_idx) not in v['queues'][direction_type]:
                        pytest.fail("Expected queue index %d not present in \
                                     SNMP result for interface %s" % (snmp_q_idx, v['name']))
            # compare number of unicast queues in CLI to the number of queue indexes in
            # SNMP result
            if port_name_to_ns[intf]:
                show_cli = 'show queue counters -n {} {} | grep "UC" | wc -l'.format(port_name_to_ns[intf], intf)
            else:
                show_cli = 'show queue counters {} | grep "UC" | wc -l'.format(intf)
            result = duthost.shell(show_cli)
            assert len(v['queues'][direction_type].keys()) == int(result[u'stdout']),\
                   "Port {} does not have expected number of queue \
                   indexes in SNMP result".format(intf)
