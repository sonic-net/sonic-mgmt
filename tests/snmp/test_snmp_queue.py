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
    port_name_to_alias_map = {}

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

    if not q_keys:
        pytest.skip("No queues configured on interfaces")

    # Get alias : port_name map
    alias_port_name_map = {k: v for v, k in port_name_to_alias_map.items()}

    q_interfaces = set()
    # get interfaces which has configured queues
    for key in q_keys:
        intf = key.split('|')
        # 'QUEUE|Ethernet*|2'
        if len(intf) == 3:
            q_interfaces.add(intf[1])
        # Packet chassis 'QUEUE|<hostname>|<asic_ns>|Ethernet*|2'
        elif len(intf) == 5:
            q_interfaces.add(intf[3])

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
            if intf in q_interfaces and 'queues' not in v:
                pytest.fail("port %s does not have queue counters" % v['name'])
