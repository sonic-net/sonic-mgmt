"""DUT-side bootstrap for MACsec on PortChannel-member ports.

After `config reload` / `config load_minigraph --override_config`, CONFIG_DB
has `PORT.<p>.macsec` and `PORTCHANNEL_MEMBER|<pc>|<p>` set for the same
ports.  On images without the wpa_supplicant CP state-machine fix
(sonic-net/sonic-wpa-supplicant#122) MKA can wedge on a port that is already
a PortChannel member, so the MACsec session never establishes and the
PortChannel stays partially up.

Recovery helper for that case, run from the sonic-mgmt controller side so
tests that trigger a config reload can recover MACsec without re-running
ansible.  With the fix present MKA comes up unaided and this is a no-op.

Sequence per PC-member macsec port:
    1. DEL PORTCHANNEL_MEMBER|<pc>|<p>  — detach port from LAG.
    2. HDEL + HSET PORT|<p>.macsec  — macsecmgrd does not watch
       PORTCHANNEL_MEMBER, so re-poke the binding to force re-evaluation.
    3. Wait STATE_DB MACSEC_PORT_TABLE|<p>.state == 'ok'  — MKA negotiates.
    4. HSET PORTCHANNEL_MEMBER|<pc>|<p> NULL NULL  — reattach.
LACP then forms over the already-active MACsec tunnel.

No-op when:
    - macsec feature is not enabled in CONFIG_DB.FEATURE.macsec.state.
    - No PORT.<p>.macsec entries reference a port that's also a
      PORTCHANNEL_MEMBER.
"""

import logging
import time

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def _macsec_feature_enabled(duthost):
    out = duthost.shell(
        "sonic-db-cli CONFIG_DB HGET 'FEATURE|macsec' state",
        module_ignore_errors=True,
    )
    return out["stdout"].strip() == "enabled"


def _collect_pc_member_macsec_ports(duthost):
    """Return [(port, pc, profile), ...] for every PORT.macsec port that's also a PC member."""
    pc_member_keys = duthost.shell(
        "sonic-db-cli CONFIG_DB KEYS 'PORTCHANNEL_MEMBER|*'",
        module_ignore_errors=True,
    )["stdout"].splitlines()

    port_to_pc = {}
    for key in pc_member_keys:
        parts = key.split("|")
        if len(parts) == 3:
            _, pc, port = parts
            port_to_pc[port] = pc

    if not port_to_pc:
        return []

    port_keys = duthost.shell(
        "sonic-db-cli CONFIG_DB KEYS 'PORT|*'",
        module_ignore_errors=True,
    )["stdout"].splitlines()

    pairs = []
    for key in port_keys:
        if "|" not in key:
            continue
        port = key.split("|", 1)[1]
        if port not in port_to_pc:
            continue
        macsec_val = duthost.shell(
            "sonic-db-cli CONFIG_DB HGET '{}' macsec".format(key),
            module_ignore_errors=True,
        )["stdout"].strip()
        if macsec_val:
            pairs.append((port, port_to_pc[port], macsec_val))

    return sorted(pairs)


def bootstrap_pc_member_macsec(duthost, timeout=600, grace=120):
    """Detach → re-poke PORT.macsec → wait MKA → reattach every PC-member macsec port.

    Collection is host-namespace only (single-ASIC DUTs); on multi-ASIC DUTs
    this no-ops, matching the golden-config merge's single-ASIC scope.

    grace is how long MKA gets to come up unaided before any port is touched;
    with the wpa_supplicant fix every port reaches state=ok in this window and
    the function returns without flapping a LAG.  timeout is the MKA budget
    for the ports that still need the dance (MKA runs in parallel on all
    detached ports, so one shared deadline).

    Returns:
        list of (port, pc) pairs that were processed.  Empty if no-op.

    Raises:
        RuntimeError when any port never reaches MACSEC_PORT_TABLE.state=ok
        (ports are still reattached first so the LAG is not left broken).
    """
    if not _macsec_feature_enabled(duthost):
        logger.info("macsec feature disabled — skipping PC bootstrap")
        return []

    triples = _collect_pc_member_macsec_ports(duthost)
    if not triples:
        logger.info("No PortChannel-member macsec ports found — skipping PC bootstrap")
        return []

    grace_deadline = time.time() + grace
    pending = [
        t for t in triples
        if not wait_until(max(grace_deadline - time.time(), 1), 5, 0,
                          duthost.iface_macsec_ok, t[0])
    ]
    if not pending:
        logger.info("MACsec PC bootstrap: MKA already ok on %s — nothing to do", triples)
        return []
    triples = pending

    logger.info("MACsec PC bootstrap: detaching %s", triples)
    for port, pc, _ in triples:
        duthost.shell(
            "sonic-db-cli CONFIG_DB DEL 'PORTCHANNEL_MEMBER|{}|{}'".format(pc, port)
        )

    # Brief settle so orchagent observes the DEL before macsecmgrd retries.
    time.sleep(5)

    # macsecmgrd does not watch PORTCHANNEL_MEMBER; re-poke the PORT.macsec
    # binding so it re-evaluates the now-standalone port (mirrors the playbook).
    for port, _, _ in triples:
        duthost.shell("sonic-db-cli CONFIG_DB HDEL 'PORT|{}' macsec".format(port))
    time.sleep(2)
    for port, _, profile in triples:
        duthost.shell(
            "sonic-db-cli CONFIG_DB HSET 'PORT|{}' macsec '{}'".format(port, profile)
        )

    # One shared deadline: MKA negotiates concurrently on every detached port.
    # iface_macsec_ok resolves the port's namespace on multi-ASIC hosts.
    deadline = time.time() + timeout
    failed = [
        port for port, _, _ in triples
        if not wait_until(max(deadline - time.time(), 1), 2, 0,
                          duthost.iface_macsec_ok, port)
    ]

    logger.info("MACsec PC bootstrap: reattaching %s", triples)
    for port, pc, _ in triples:
        duthost.shell(
            "sonic-db-cli CONFIG_DB HSET 'PORTCHANNEL_MEMBER|{}|{}' NULL NULL".format(pc, port)
        )

    if len(failed) < len(triples):
        # Let LACP re-form over MACsec before callers save config / start BGP.
        time.sleep(15)

    if failed:
        raise RuntimeError(
            "MACsec PC bootstrap: MACSEC_PORT_TABLE state != ok for {} "
            "within {}s".format(failed, timeout)
        )

    return [(port, pc) for port, pc, _ in triples]
