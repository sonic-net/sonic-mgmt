"""Topology helpers shared by transceiver scenario tests."""
import json
from collections import Counter, namedtuple

import pytest

from tests.common.platform.interface_utils import (
    get_dev_conn,
    get_lport_to_first_subport_mapping,
)


PeerConnection = namedtuple("PeerConnection", ("device", "port", "alias"), defaults=(None,))
PeerInfo = namedtuple("PeerInfo", ("host", "device", "port", "primary_port"))
_LPORT_TO_FIRST_SUBPORT_MAPPING_BY_HOST = {}


def _get_lport_to_first_subport_mapping(duthost):
    """Return the cached logical-to-primary-subport mapping for one DUT."""
    hostname = duthost.hostname
    if hostname not in _LPORT_TO_FIRST_SUBPORT_MAPPING_BY_HOST:
        mapping = get_lport_to_first_subport_mapping(duthost)
        _LPORT_TO_FIRST_SUBPORT_MAPPING_BY_HOST[hostname] = mapping
    return _LPORT_TO_FIRST_SUBPORT_MAPPING_BY_HOST[hostname]


def resolve_peer_connection(duthost, conn_graph_facts, local_port):
    """Return ``(PeerConnection, error)`` without accessing the remote device."""
    return resolve_peer_connections(duthost, conn_graph_facts, [local_port])[local_port]


def resolve_peer_connections(duthost, conn_graph_facts, local_ports):
    """Return per-port ``(PeerConnection, error)`` pairs with one graph lookup per ASIC.

    Reuse ASIC-scoped connections only within this call. Lookup failures are
    reported for every affected port without preventing other ASICs resolving.
    """
    results = {}
    ports_by_asic = {}
    for local_port in local_ports:
        try:
            asic = duthost.get_port_asic_instance(local_port)
        except (pytest.fail.Exception, Exception) as error:
            results[local_port] = None, "{} ASIC lookup failed: {}".format(local_port, error)
            continue
        if asic is None:
            results[local_port] = None, "{} has no ASIC instance".format(local_port)
            continue
        ports_by_asic.setdefault(asic.asic_index, []).append(local_port)

    for asic_index, ports in ports_by_asic.items():
        try:
            _portmap, dut_conn = get_dev_conn(duthost, conn_graph_facts, asic_index)
        except Exception as error:
            for local_port in ports:
                results[local_port] = None, "{} ASIC-scoped connection lookup failed: {}".format(
                    local_port, error,
                )
            continue
        for local_port in ports:
            peer_entry = dut_conn.get(local_port)
            if not peer_entry:
                results[local_port] = None, "{} has no remote peer in conn_graph_facts".format(local_port)
                continue

            peer_device = peer_entry.get("peerdevice")
            peer_port = peer_entry.get("peerport")
            if not peer_device or not peer_port:
                results[local_port] = None, "{} peer entry missing peerdevice/peerport: {}".format(
                    local_port, peer_entry,
                )
                continue
            results[local_port] = PeerConnection(peer_device, peer_port), None
    return results


def resolve_lldp_peer_aliases(peer_host, connections, namespaces=None):
    """Enrich local-port connections using one running-config read per peer ASIC.

    Reuse supplied namespaces, or discover them through SONiC's frontend
    namespace API without initializing a full DUT host.
    Missing ports and ambiguous aliases are per-port errors. Read failures
    propagate to the caller, which reports them for the affected peer's ports.
    """
    if namespaces is None:
        result = peer_host.command(argv=[
            "python3", "-c",
            "import json; from sonic_py_common import multi_asic; "
            + "print(json.dumps(multi_asic.get_front_end_namespaces()))",
        ])
        namespaces = json.loads(result["stdout"])
    if (not isinstance(namespaces, list) or not namespaces
            or any(namespace is not None and not isinstance(namespace, str) for namespace in namespaces)):
        raise ValueError(f"Invalid or empty peer frontend namespace list: {namespaces!r}")

    aliases = {}
    for namespace in namespaces:
        facts = peer_host.config_facts(
            host=peer_host.hostname, source="running", namespace=namespace, verbose=False,
        )["ansible_facts"]
        namespace_aliases = facts["port_name_to_alias_map"]
        duplicate_ports = aliases.keys() & namespace_aliases.keys()
        if duplicate_ports:
            raise ValueError("Peer logical ports occur in multiple ASICs: {}".format(sorted(duplicate_ports)))
        aliases.update(namespace_aliases)

    alias_counts = Counter(alias for alias in aliases.values() if alias)
    results = {}
    for local_port, peer in connections.items():
        if peer.port not in aliases:
            results[local_port] = None, f"peer port {peer.device}:{peer.port} is missing from running configuration"
            continue
        alias = aliases[peer.port]
        if alias and (alias_counts[alias] > 1 or (alias in aliases and alias != peer.port)):
            results[local_port] = None, f"peer port {peer.device}:{peer.port} has ambiguous alias {alias!r}"
            continue
        results[local_port] = peer._replace(alias=alias or None), None
    return results


def resolve_remote_peer(
    duthost,
    duthosts,
    conn_graph_facts,
    local_port,
):
    """Return ``(PeerInfo, error)``, requiring a DUT host and remote port mapping."""
    connection, error = resolve_peer_connection(duthost, conn_graph_facts, local_port)
    if error is not None:
        return None, error
    peer_device, peer_port = connection.device, connection.port

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
        peer_mapping = _get_lport_to_first_subport_mapping(peer_host)
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
