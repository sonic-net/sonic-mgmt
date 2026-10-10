"""Remote-Side Port Resolution helper (see
``docs/testplan/transceiver/test_plan.md`` § Remote-Side Port Resolution).

Resolves the peer device/port for a local transceiver port via the
sonic-mgmt connection graph (``conn_graph_facts``). Only the "peer is a
distinct, controllable SONiC DUT present in this testbed" case is
supported here -- self-loopback (peer == the DUT under test) and non-DUT
peers (fanout switches, servers reached via a Y-cable) are reported as
unresolved so callers that need to issue config CLI on the peer (e.g. a
peer-side link flap) can skip cleanly instead of guessing at a device they
cannot control.

A port with no (or an incomplete) connection graph entry is a testbed
configuration error, not a topology limitation, and raises
``PeerResolutionError`` so the caller can fail with a clear message.
"""
import logging

logger = logging.getLogger(__name__)


class PeerResolutionError(Exception):
    """The connection graph has no usable peer entry for a port."""


def resolve_peer_duthost_port(duthost, duthosts, conn_graph_facts, port):
    """Resolve the peer ``(duthost, port)`` for ``port`` on ``duthost``.

    Args:
        duthost: SONiC DUT host fixture the local port under test lives on.
        duthosts: the multi-DUT collection fixture (``tests/conftest.py``),
            used to resolve the peer device name to a host object.
        conn_graph_facts: the ``conn_graph_facts`` fixture.
        port: local logical interface name.

    Returns:
        tuple: ``(peer_duthost, peer_port)`` if the peer is a distinct
        SONiC DUT present in ``duthosts``, else ``(None, None)``.

    Raises:
        PeerResolutionError: ``port`` has no connection graph entry, or the
            entry is missing ``peerdevice``/``peerport``.
    """
    dev_conn = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})
    link = dev_conn.get(port)
    if not link:
        raise PeerResolutionError(
            f"{duthost.hostname}:{port} has no connection graph entry"
        )

    peer_device = link.get("peerdevice")
    peer_port = link.get("peerport")
    if not peer_device or not peer_port:
        raise PeerResolutionError(
            f"{duthost.hostname}:{port} connection graph entry is missing "
            f"peerdevice/peerport: {link}"
        )

    if peer_device == duthost.hostname:
        logger.info(
            "%s: peer device is the DUT itself (self-loopback) - no peer DUT",
            port,
        )
        return None, None

    peer_hostnames = {dh.hostname for dh in duthosts}
    if peer_device not in peer_hostnames:
        logger.info(
            "%s: peer device '%s' is not a SONiC DUT in this testbed "
            "(fanout switch or server) - no peer DUT",
            port, peer_device,
        )
        return None, None

    return duthosts[peer_device], peer_port
