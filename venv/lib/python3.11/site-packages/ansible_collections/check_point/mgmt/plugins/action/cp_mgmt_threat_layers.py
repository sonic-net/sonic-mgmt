# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The module file for cp_mgmt_threat_layers
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible.module_utils.connection import Connection

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    CheckPointRequest,
    map_params_to_obj,
    map_obj_to_params,
    sync_show_params_with_add_params,
    remove_unwanted_key,
    contains_show_identifier_param,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.check_point.mgmt.plugins.modules.cp_mgmt_threat_layers import (
    DOCUMENTATION,
)


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_call_object = "threat-layer"
        self.api_call_object_plural_version = "threat-layers"
        self.module_return = "mgmt_threat_layers"
        self.key_transform = {
            "add_default_rule": "add-default-rule",
            "details_level": "details-level",
            "ignore_warnings": "ignore-warnings",
            "ignore_errors": "ignore-errors",
        }

    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=DOCUMENTATION,
            schema_format="doc",
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            self._result["failed"] = True
            self._result["msg"] = errors

    def search_for_existing_rules(
        self, conn_request, api_call_object, search_payload=None, state=None
    ):
        result = conn_request.post(api_call_object, state, data=search_payload)
        return result

    def search_for_resource_name(self, conn_request, payload):
        search_result = []
        round_trip = False

        search_payload = utils.remove_empties(payload)
        if search_payload.get("round_trip"):
            round_trip = True
        if search_payload.get("round_trip") is not None:
            del search_payload["round_trip"]
        search_payload = map_params_to_obj(search_payload, self.key_transform)
        if not contains_show_identifier_param(search_payload):
            search_result = self.search_for_existing_rules(
                conn_request,
                self.api_call_object_plural_version,
                search_payload,
                "gathered",
            )
            if search_result.get("code") == 200:
                search_result = search_result["response"][
                    self.api_call_object_plural_version
                ]
                return search_result
        else:
            search_result = self.search_for_existing_rules(
                conn_request, self.api_call_object, search_payload, "gathered"
            )
            if round_trip:
                search_result = sync_show_params_with_add_params(
                    search_result["response"], self.key_transform
                )
            elif search_result.get("code") and search_result["code"] == 200:
                search_result = search_result["response"]
            search_result = map_obj_to_params(
                search_result,
                self.key_transform,
                self.module_return,
            )
        if search_result.get("code") and search_result["code"] != 200:
            if (
                search_result.get("response")
                and "object_not_found" in search_result["response"]["code"]
                and "not found" in search_result["response"]["message"]
            ):
                search_result = {}
            elif "object_not_found" in search_result.get(
                "code"
            ) and "not found" in search_result.get("message"):
                search_result = {}
        return search_result

    def delete_module_api_config(self, conn_request, module_config_params):
        config = {}
        before = {}
        after = {}
        result = {}
        changed = False
        round_trip = False
        ckp_session_uid = None
        payload = utils.remove_empties(module_config_params)
        if payload.get("round_trip"):
            round_trip = True
            del payload["round_trip"]
        remove_from_response = ["uid", "read-only", "domain"]
        if round_trip:
            search_payload = {"name": payload["name"], "round_trip": True}
        else:
            search_payload = {"name": payload["name"]}
        search_result = self.search_for_resource_name(
            conn_request, search_payload
        )
        if search_result:
            if round_trip:
                search_result = remove_unwanted_key(
                    search_result, remove_from_response
                )
            before = search_result
        result = conn_request.post(
            self.api_call_object, self._task.args["state"], data=payload
        )
        if before:
            config.update({"before": before, "after": after})
        else:
            config.update({"before": before})
        if result.get("changed"):
            changed = True
            ckp_session_uid = result["checkpoint_session_uid"]

        return config, changed, ckp_session_uid

    def configure_module_api(self, conn_request, module_config_params):
        config = {}
        before = {}
        after = {}
        result = {}
        changed = False
        round_trip = False
        ckp_session_uid = None
        # Add to the THIS list for the value which needs to be excluded
        # from HAVE params when compared to WANT param like 'ID' can be
        # part of HAVE param but may not be part of your WANT param
        remove_from_response = ["uid", "read-only", "domain"]
        remove_from_set = ["add-default-rule"]
        payload = utils.remove_empties(module_config_params)
        if payload.get("round_trip"):
            round_trip = True
            del payload["round_trip"]
        if payload.get("name"):
            if round_trip:
                search_payload = {"name": payload["name"], "round_trip": True}
            else:
                search_payload = {"name": payload["name"]}
            search_result = self.search_for_resource_name(
                conn_request, search_payload
            )
            if search_result:
                if round_trip:
                    search_result = remove_unwanted_key(
                        search_result, remove_from_response
                    )
                before = search_result
        payload = map_params_to_obj(payload, self.key_transform)
        delete_params = {
            "name": payload["name"],
        }
        result = conn_request.post(
            self.api_call_object,
            self._task.args["state"],
            data=payload,
            remove_keys=remove_from_set,
            delete_params=delete_params,
        )
        if result.get("changed"):
            if round_trip:
                search_result = sync_show_params_with_add_params(
                    result["response"], self.key_transform
                )
            else:
                search_result = map_obj_to_params(
                    result["response"],
                    self.key_transform,
                    self.module_return,
                )
            if round_trip:
                search_result = remove_unwanted_key(
                    search_result, remove_from_response
                )
            after = search_result
            ckp_session_uid = result["checkpoint_session_uid"]
            changed = True
        config.update({"before": before, "after": after})

        return config, changed, ckp_session_uid

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._check_argspec()
        self._result["checkpoint_session_uid"] = None
        if self._result.get("failed"):
            return self._result
        conn = Connection(self._connection.socket_path)
        conn_request = CheckPointRequest(connection=conn, task_vars=task_vars)
        if self._task.args["state"] == "gathered":
            if self._task.args.get("config"):
                self._result["gathered"] = self.search_for_resource_name(
                    conn_request, self._task.args["config"]
                )
            else:
                self._result["gathered"] = self.search_for_resource_name(
                    conn_request, dict()
                )
        elif (
            self._task.args["state"] == "merged"
            or self._task.args["state"] == "replaced"
        ):
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                    self._result["checkpoint_session_uid"],
                ) = self.configure_module_api(
                    conn_request, self._task.args["config"]
                )
        elif self._task.args["state"] == "deleted":
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                    self._result["checkpoint_session_uid"],
                ) = self.delete_module_api_config(
                    conn_request, self._task.args["config"]
                )
        if self._result.get("checkpoint_session_uid") is None:
            del self._result["checkpoint_session_uid"]

        return self._result
