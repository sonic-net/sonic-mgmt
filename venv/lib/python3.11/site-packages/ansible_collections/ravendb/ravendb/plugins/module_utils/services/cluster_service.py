# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ClusterTopology:
    def __init__(self, members, watchers, promotables):
        self.members = members
        self.watchers = watchers
        self.promotables = promotables


def fetch_topology_http(leader_url, tls, timeout=10):
    import requests
    cert, verify = tls.to_requests_tuple()
    endpoint = leader_url.rstrip('/') + "/cluster/topology"

    r = requests.get(endpoint, cert=cert, verify=verify, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    topo = data.get("Topology") or data.get("topology") or data

    def _to_map(g):
        if isinstance(g, dict):
            return dict((str(k), ("" if v is None else str(v))) for k, v in g.items())
        return {}

    members = _to_map(topo.get("Members") or topo.get("members"))
    watchers = _to_map(topo.get("Watchers") or topo.get("watchers"))
    promotables = _to_map(topo.get("Promotables") or topo.get("promotables"))

    return ClusterTopology(members, watchers, promotables)


def fetch_topology(ctx):
    """
    Fetch cluster topology using RavenDB Python Client.
    Returns ClusterTopology.
    """
    from ravendb.serverwide.commands import GetClusterTopologyCommand
    cmd = GetClusterTopologyCommand()
    ctx.store.get_request_executor().execute_command(cmd)
    return cmd.result.topology


def collect_tags(topology):
    all_nodes = getattr(topology, "all_nodes", None) or {}
    if all_nodes:
        return sorted(all_nodes.keys())

    members = getattr(topology, "members", None) or {}
    promotables = getattr(topology, "promotables", None) or {}
    watchers = getattr(topology, "watchers", None) or {}
    return sorted(set(list(members.keys()) + list(promotables.keys()) + list(watchers.keys())))
