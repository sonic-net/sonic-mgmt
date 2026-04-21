#
# Copyright 2022 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

"""
The module file for qradar_log_sources_management
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import json

from copy import copy

from ansible.errors import AnsibleActionFail
from ansible.module_utils.connection import Connection
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.plugins.action import ActionBase
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import (
    QRadarRequest,
    find_dict_in_list,
    list_to_dict,
    remove_unsupported_keys_from_payload_dict,
)
from ansible_collections.ibm.qradar.plugins.modules.qradar_log_sources_management import (
    DOCUMENTATION,
)


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_object = "/api/config/event_sources/log_source_management/log_sources"
        self.api_object_types = (
            "/api/config/event_sources/log_source_management/log_source_types?filter="
        )
        self.api_object_search = (
            "/api/config/event_sources/log_source_management/log_sources?filter="
        )
        self.api_return = "log_sources_management"
        self.module_return = "qradar_log_sources_management"
        self.supported_params = [
            "name",
            "description",
            "type_name",
            "type_id",
            "identifier",
            "protocol_type_id",
            "enabled",
            "gateway",
            "internal",
            "target_event_collector_id",
            "coalesce_events",
            "store_event_payload",
            "language_id",
            "group_ids",
            "requires_deploy",
            "status",
            "average_eps",
            "protocol_parameters",
        ]

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

    def set_log_source_values(self, qradar_request, config_params):
        # find log source types details
        if config_params.get("type_name"):
            api_object = self.api_object_types + "{0}".format(
                quote('name="{0}"'.format(config_params["type_name"])),
            )
            code, log_source_type_found = qradar_request.get(api_object)
        if config_params.get("type_id"):
            log_source_type_found = []
            if config_params.get("group_ids"):
                del config_params["group_ids"]
        elif log_source_type_found and not config_params.get("type_id"):
            config_params["type_id"] = log_source_type_found[0]["id"]
            config_params.pop("type_name")
        else:
            raise AnsibleActionFail(
                "Incompatible type provided, please consult QRadar Documentation for Log Source Types!",
            )

        if log_source_type_found:
            if config_params.get("protocol_type_id"):
                found_dict_in_list, _fdil_index = find_dict_in_list(
                    log_source_type_found[0]["protocol_types"],
                    "protocol_id",
                    config_params["protocol_type_id"],
                )
                if not found_dict_in_list:
                    config_params.fail_json(
                        msg="Incompatible protocol_type_id provided, please consult QRadar Documentation for Log Source Types",
                    )
            elif log_source_type_found[0].get("protocol_types"):
                # Set it to the default as provided by the QRadar Instance
                protocol_type_id = 0
                for each in log_source_type_found[0]["protocol_types"]:
                    if each.get("protocol_id") == 0 and each.get("documented"):
                        protocol_type_id = 0
                        break
                    elif each.get("documented"):
                        protocol_type_id = each["protocol_id"]
                config_params["protocol_type_id"] = protocol_type_id

            config_params["protocol_parameters"] = [
                {
                    "id": config_params["protocol_type_id"],
                    "name": "identifier",
                    "value": config_params["identifier"],
                },
            ]
            config_params.pop("identifier")
        return config_params

    def search_for_resource_name(
        self,
        qradar_request,
        search_resource_by_names=None,
    ):
        search_result = []
        if isinstance(search_resource_by_names, list):
            for each in search_resource_by_names:
                each = utils.remove_empties(each)
                query_api_object = self.api_object_search + "{0}".format(
                    quote('name="{0}"'.format(each["name"])),
                )
                code, log_source_exists = qradar_request.get(query_api_object)
                if log_source_exists and (code >= 200 and code < 300):
                    search_result.append(log_source_exists[0])
        elif isinstance(search_resource_by_names, str):
            query_api_object = self.api_object_search + "{0}".format(
                quote('name="{0}"'.format(search_resource_by_names)),
            )
            code, log_source_exists = qradar_request.get(query_api_object)
            if log_source_exists and (code >= 200 and code < 300):
                search_result.append(log_source_exists[0])
                return search_result[0]
        else:
            code, log_source_exists = qradar_request.get(self.api_object)
            if log_source_exists and (code >= 200 and code < 300):
                search_result = log_source_exists
        return search_result

    def delete_module_api_config(self, qradar_request, module_config_params):
        config = {}
        before = []
        after = []
        changed = False
        for each in module_config_params:
            each = utils.remove_empties(each)
            log_source_exists = self.search_for_resource_name(
                qradar_request,
                each["name"],
            )
            if log_source_exists:
                before.append(log_source_exists)
                query_object = self.api_object + "/{0}".format(
                    log_source_exists["id"],
                )
                code, qradar_return_data = qradar_request.delete(query_object)
                if code >= 200 and code < 300:
                    changed = True
                    config.update({"before": before, "after": after})
            else:
                config.update({"before": before})
        return config, changed

    def configure_module_api(self, conn_request, module_config_params):
        config = {}
        before = []
        after = []
        changed = False
        temp_request_param = []
        for each in module_config_params:
            each = utils.remove_empties(each)
            each = self.set_log_source_values(conn_request, each)
            search_result = self.search_for_resource_name(
                conn_request,
                each["name"],
            )
            if search_result:
                if search_result["name"] == each["name"]:
                    temp_each = copy(each)
                    temp_search_result = copy(search_result)
                    list_to_dict(temp_each)
                    list_to_dict(temp_search_result)
                    diff = utils.dict_diff(temp_search_result, temp_each)
                if diff:
                    if self._task.args["state"] == "merged":
                        each = utils.remove_empties(
                            utils.dict_merge(search_result, each),
                        )
                        temp_request_param.append(each)
                    elif self._task.args["state"] == "replaced":
                        query_object = self.api_object + "/{0}".format(
                            search_result["id"],
                        )
                        code, qradar_return_data = conn_request.delete(
                            query_object,
                        )
                        temp_request_param.append(each)
                else:
                    after.append(search_result)
                before.append(search_result)
            else:
                each = utils.remove_empties(each)
                temp_request_param.append(each)
        if temp_request_param:
            code, response = conn_request.create_update(
                self.api_object,
                data=json.dumps(temp_request_param),
            )
            if code >= 200 and code < 300:
                changed = True
                search_result = self.search_for_resource_name(conn_request)
                for each in temp_request_param:
                    for every in search_result:
                        if each["name"] == every["name"]:
                            after.append(every)
                            break
            elif code >= 400:
                raise AnsibleActionFail(
                    "Failed with http_response: {0} and message: {1}".format(
                        response["http_response"]["message"],
                        response["message"],
                    ),
                )
            config.update({"before": before, "after": after})
        else:
            config.update({"before": before})

        return config, changed

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        if self._task.args.get("config"):
            self._task.args["config"] = remove_unsupported_keys_from_payload_dict(
                self._task.args["config"],
                self.supported_params,
            )
            self._check_argspec()
        if self._result.get("failed"):
            return self._result
        conn = Connection(self._connection.socket_path)
        conn_request = QRadarRequest(connection=conn, task_vars=task_vars)
        if self._task.args["state"] == "gathered":
            if self._task.args.get("config"):
                self._result["gathered"] = self.search_for_resource_name(
                    conn_request,
                    self._task.args["config"],
                )
            else:
                self._result["gathered"] = conn_request.get(self.api_object)
        elif self._task.args["state"] == "merged" or self._task.args["state"] == "replaced":
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.configure_module_api(
                    conn_request,
                    self._task.args["config"],
                )
        elif self._task.args["state"] == "deleted":
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.delete_module_api_config(
                    conn_request,
                    self._task.args["config"],
                )

        return self._result
