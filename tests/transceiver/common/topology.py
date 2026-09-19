"""Topology helpers shared by transceiver scenario tests."""
from collections import namedtuple

import pytest

from tests.common.platform.interface_utils import (
    get_dev_conn,
    get_lport_to_first_subport_mapping,
)


PeerInfo = namedtuple("PeerInfo", ("host", "device", "port", "primary_port"))


def resolve_remote_peer(
    duthost,
    duthosts,
    conn_graph_facts,
    local_port,
):
    """Return ``(PeerInfo, error)`` for a port's connection-graph peer."""
    try:
        asic = duthost.get_port_asic_instance(local_port)
    except pytest.fail.Exception as error:
        return None, "{} ASIC lookup failed: {}".format(local_port, error)
    except Exception as error:
        return None, "{} ASIC lookup failed: {}".format(local_port, error)
    if asic is None:
        return None, "{} has no ASIC instance".format(local_port)

    try:
        _portmap, dut_conn = get_dev_conn(
            duthost,
            conn_graph_facts,
            asic.asic_index,
        )
    except Exception as error:
        return None, "{} ASIC-scoped connection lookup failed: {}".format(
            local_port,
            error,
        )
    peer_entry = dut_conn.get(local_port)
    if not peer_entry:
        return None, "{} has no remote peer in conn_graph_facts".format(
            local_port,
        )

    peer_device = peer_entry.get("peerdevice")
    peer_port = peer_entry.get("peerport")
    if not peer_device or not peer_port:
        return None, "{} peer entry missing peerdevice/peerport: {}".format(
            local_port,
            peer_entry,
        )

    if peer_device == duthost.hostname:
        peer_host = duthost
    else:
        try:
            peer_host = duthosts[peer_device]
        except (KeyError, TypeError):
            return None, (
                "{} peer device {} is not available as a DUT host".format(
                    local_port,
                    peer_device,
                )
            )

    try:
        peer_mapping = get_lport_to_first_subport_mapping(peer_host)
    except Exception as error:
        return None, "{} peer device {} mapping failed: {}".format(
            local_port,
            peer_device,
            error,
        )
    if peer_port not in peer_mapping:
        return None, (
            "{} peer port {}:{} is missing from that DUT's logical-port "
            "mapping".format(
                local_port,
                peer_device,
                peer_port,
            )
        )
    peer_primary = peer_mapping[peer_port]

    return PeerInfo(peer_host, peer_device, peer_port, peer_primary), None
