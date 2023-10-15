import logging
import re
import pytest
from tests.common.helpers.snmp_helpers import get_snmp_facts

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'm0', 'mx'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, enum_rand_one_per_hwsku_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("LLDP not supported on supervisor node")
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)


@pytest.mark.bsl
def test_snmp_lldp(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts, tbinfo):
    """
    Test checks for ieee802_1ab MIBs:
     - lldpLocalSystemData  1.0.8802.1.1.2.1.3
     - lldpLocPortTable     1.0.8802.1.1.2.1.3.7
     - lldpLocManAddrTable     1.0.8802.1.1.2.1.3.8

     - lldpRemTable  1.0.8802.1.1.2.1.4.1
     - lldpRemManAddrTable  1.0.8802.1.1.2.1.4.2

    For local data check if every OID has value
    For remote values check for availability for at least 80% of minigraph neighbors
    (similar to lldp test)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("LLDP not supported on supervisor node")
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']

    snmp_facts = get_snmp_facts(
        localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    mg_facts = {}
    for asic_id in duthost.get_asic_ids():
        mg_facts_ns = duthost.asic_instance(
            asic_id).get_extended_minigraph_facts(tbinfo)['minigraph_neighbors']
        if mg_facts_ns is not None:
            mg_facts.update(mg_facts_ns)

    logger.info('snmp_lldp: {}'.format(snmp_facts['snmp_lldp']))
    for k in ['lldpLocChassisIdSubtype', 'lldpLocChassisId', 'lldpLocSysName', 'lldpLocSysDesc']:
        assert snmp_facts['snmp_lldp'][k]
        assert "No Such Object currently exists" not in snmp_facts['snmp_lldp'][k]

    # Check if lldpLocPortTable is present for all ports
    for k, v in list(snmp_facts['snmp_interfaces'].items()):
        if "Ethernet" in v['name'] or "eth" in v['name']:
            for oid in ['lldpLocPortIdSubtype', 'lldpLocPortId', 'lldpLocPortDesc']:
                assert oid in v
                assert "No Such Object currently exists" not in v[oid]

    # Check if lldpLocManAddrTable is present
    for k in ['lldpLocManAddrLen',
              'lldpLocManAddrIfSubtype',
              'lldpLocManAddrIfId',
              'lldpLocManAddrOID']:
        assert snmp_facts['snmp_lldp'][k]
        assert "No Such Object currently exists" not in snmp_facts['snmp_lldp'][k]

    minigraph_lldp_nei = []
    for k, v in list(mg_facts.items()):
        if "server" not in v['name'].lower():
            minigraph_lldp_nei.append(k)
    logger.info('minigraph_lldp_nei: {}'.format(minigraph_lldp_nei))

    # Check if lldpRemTable is present
    active_intf = []
    for k, v in list(snmp_facts['snmp_interfaces'].items()):
        if "lldpRemChassisIdSubtype" in v and \
           "lldpRemChassisId" in v and \
           "lldpRemPortIdSubtype" in v and \
           "lldpRemPortId" in v and \
           "lldpRemPortDesc" in v and \
           "lldpRemSysName" in v and \
           "lldpRemSysDesc" in v and \
           "lldpRemSysCapSupported" in v and \
           "lldpRemSysCapEnabled" in v:
            active_intf.append(k)
    logger.info('lldpRemTable: {}'.format(active_intf))

    assert len(active_intf) >= len(minigraph_lldp_nei) * 0.8

    # skip neighbors that do not send chassis information via lldp
    lldp_facts = {}
    for asic_id in duthost.get_asic_ids():
        lldp_facts_ns = duthost.lldpctl_facts(asic_instance_id=asic_id)[
            'ansible_facts']['lldpctl']
        if lldp_facts_ns is not None:
            lldp_facts.update(lldp_facts_ns)
    pattern = re.compile(r'^eth0|^Ethernet-IB')
    nei = [k for k, v in list(lldp_facts.items()) if not re.match(
        pattern, k) and 'mgmt-ip' in v['chassis']]
    logger.info(
        "neighbors {} send chassis management IP information".format(nei))

    # Check if lldpRemManAddrTable is present
    active_intf = []
    for k, v in list(snmp_facts['snmp_interfaces'].items()):
        if "lldpRemManAddrIfSubtype" in v and \
           "lldpRemManAddrIfId" in v and \
           "lldpRemManAddrOID" in v and \
           v['name'] != 'eth0' and 'Etherent-IB' not in v['name']:
            active_intf.append(k)
    logger.info('lldpRemManAddrTable: {}'.format(active_intf))

    assert len(active_intf) == len(nei)
