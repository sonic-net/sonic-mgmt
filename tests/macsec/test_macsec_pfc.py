import pytest
import logging

from tests.common.fixtures.conn_graph_facts import conn_graph_facts      # noqa: F401
from tests.common.fixtures.conn_graph_facts import get_graph_facts
from tests.common.helpers.pfc_counters import run_test
from tests.common.helpers.pfc_counters import leaf_fanouts               # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


@pytest.fixture(scope='module')
def enum_fanout_graph_facts_macsec(localhost, macsec_duthost, conn_graph_facts):    # noqa: F811
    """Build fanout graph facts for the MACsec DUT.

    Duplicates the standard ``enum_fanout_graph_facts`` but uses macsec_duthost,
    so that ``run_test`` receives fanout info for the macsec DUT
    """
    facts = {}
    dev_conn = conn_graph_facts.get('device_conn', {})
    if not dev_conn:
        return facts
    for _, val in list(dev_conn.get(macsec_duthost.hostname, {}).items()):
        fanout = val["peerdevice"]
        if fanout not in facts:
            facts[fanout] = {
                k: v[fanout] for k, v in list(
                    get_graph_facts(macsec_duthost, localhost, fanout).items()
                )
            }
    return facts


@pytest.fixture(scope='module', autouse=True)
def enable_flex_port_counter_macsec(macsec_duthost):
    """Ensure flex counter for PORT is enabled so PFC counters are collected.
    Duplicated from tests/qos/test_pfc_counters.py but modified to use macsec_duthost
    """
    get_cmd = ('sonic-db-cli CONFIG_DB hget '
               '"FLEX_COUNTER_TABLE|PORT" "FLEX_COUNTER_STATUS"')
    status = macsec_duthost.shell(get_cmd)['stdout']
    if status == 'enable':
        yield
        return
    set_cmd = ('sonic-db-cli CONFIG_DB hset '
               '"FLEX_COUNTER_TABLE|PORT" "FLEX_COUNTER_STATUS" "{}"')
    logger.info("Enable flex counter for port")
    macsec_duthost.shell(set_cmd.format('enable'))
    yield
    logger.info("Disable flex counter for port")
    macsec_duthost.shell(set_cmd.format('disable'))


def test_pfc_pause_on_macsec_link(macsec_duthost, fanouthosts,
                                  conn_graph_facts,                  # noqa: F811
                                  enum_fanout_graph_facts_macsec,    # noqa: F811
                                  leaf_fanouts,                      # noqa: F811
                                  macsec_setup, wait_mka_establish):
    """Verify PFC pause frames are received and counted on MACsec-enabled links.

    PFC frames (ethertype 0x8808, dest 01:80:C2:00:00:01) are IEEE 802.1AE
    control frames and are transmitted unencrypted even on MACsec-protected
    links.  This test validates that the DUT correctly receives and accounts
    for these unencrypted PFC frames by checking Rx PFC counters.
    """
    run_test(fanouthosts, macsec_duthost, conn_graph_facts,
             enum_fanout_graph_facts_macsec, leaf_fanouts)
