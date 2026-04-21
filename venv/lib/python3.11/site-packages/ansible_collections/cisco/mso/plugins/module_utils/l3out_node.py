# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, delete_none_values


class L3OutNode:
    def __init__(self, details, l3out_mso_template, l3out_object, pod_id, node_id):
        self.pod_id = pod_id
        self.node_id = node_id
        self.node_router_id = details.get("node_router_id")
        self.node_group_policy = details.get("node_group_policy")
        self.use_router_id_as_loopback = details.get("use_router_id_as_loopback")
        self.node_loopback_ip = details.get("node_loopback_ip")
        self.node = l3out_mso_template.get_l3out_node(l3out_object.details, self.pod_id, self.node_id)
        self.path = "/l3outTemplate/l3outs/{0}/nodes/{1}".format(l3out_object.index, self.node.index if self.node else "-")

    def construct_node_payload(self):
        return delete_none_values(
            {
                "group": self.node_group_policy,
                "podID": self.pod_id,
                "nodeID": self.node_id,
                "routerID": self.node_router_id,
                "useRouteIDAsLoopback": self.use_router_id_as_loopback,
                "loopbackIPs": [self.node_loopback_ip] if self.node_loopback_ip else None,
            }
        )

    def update_ops(self, ops):
        if self.node:
            self.set_node_replace_ops(ops)
        else:
            self.set_node_add_op(ops)

    def set_node_replace_ops(self, ops):
        remove_data = []
        node_payload = self.construct_node_payload()
        if node_payload.get("useRouteIDAsLoopback") is True or node_payload.get("loopbackIPs") == [""]:
            remove_data.append("loopbackIPs")
        append_update_ops_data(ops, self.node.details, self.path, node_payload, remove_data)

    def set_node_add_op(self, ops):
        ops.append(self.get_node_add_op())

    def get_node_add_op(self):
        return {"op": "add", "path": self.path, "value": self.construct_node_payload()}

    def get_node_remove_op(self):
        return {"op": "remove", "path": self.path}
