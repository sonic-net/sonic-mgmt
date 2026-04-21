# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.core.result import ModuleResult
from ansible_collections.ravendb.ravendb.plugins.module_utils.core import messages as msg
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.cluster_service import fetch_topology_http
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import node_service


class NodeReconciler(object):
    """
    Reconciles a node's presence in a cluster).
    """
    def __init__(self, ctx):
        self.ctx = ctx

    def ensure_present(self, spec, tls, check_mode):
        topology = fetch_topology_http(spec.leader_url, tls)
        present, role, existing_tag, existing_url = node_service.node_in_topology(topology, spec.tag, spec.url)
        if present:
            return ModuleResult.ok(msg=msg.node_already_present(existing_tag, role, existing_url), changed=False)

        if check_mode:
            return ModuleResult.ok(msg=msg.node_would_add(spec.tag, spec.node_type), changed=True)

        try:
            node_service.add_node(self.ctx, spec.tag, spec.url, is_watcher=spec.is_watcher, tls=tls)
        except Exception as e:
            return ModuleResult.error(msg=msg.failed_add_node(spec.tag, str(e)))

        return ModuleResult.ok(msg=msg.node_added(spec.tag, spec.node_type), changed=True)
