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
The module file for qradar_analytics_rules
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import json

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import Connection
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.plugins.action import ActionBase
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ibm.qradar.plugins.module_utils.qradar import (
    QRadarRequest,
    remove_unsupported_keys_from_payload_dict,
)
from ansible_collections.ibm.qradar.plugins.modules.qradar_analytics_rules import DOCUMENTATION


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = True
        self._result = None
        self.api_object = "/api/analytics/rules"
        self.api_return = "rules_management"
        self.module_return = "qradar_analytics_rules"
        self.supported_params = [
            "id",
            "name",
            "enabled",
            "owner",
            "fields",
            "range",
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

    def search_for_resource(self, qradar_request, search_for_resource=None):
        """The fn TC of GATHER operation
        :param qradar_request: Qradar connection request
        :param search_for_resource: Module input config with either ID, NAME, or RANGE with field input
        :rtype: A dict
        :returns: dict with module prams transformed having API expected params
        """
        if search_for_resource.get("id"):
            api_obj_url = self.api_object + "/{0}".format(
                search_for_resource["id"],
            )
        elif search_for_resource.get("name"):
            api_obj_url = self.api_object + "?filter={0}".format(
                quote(
                    'name="{0}"'.format(to_text(search_for_resource["name"])),
                ),
            )
        elif search_for_resource.get("range"):
            api_obj_url = self.api_object
        if search_for_resource.get("fields"):
            fields = ",".join(search_for_resource["fields"])
            fields_url = "?fields={0}".format(quote("{0}".format(fields)))
            api_obj_url += fields_url
        code, rule_source_exists = qradar_request.get(api_obj_url)
        if (
            rule_source_exists
            and len(rule_source_exists) == 1
            and (search_for_resource.get("name") and not search_for_resource.get("id"))
        ):
            rule_source_exists = rule_source_exists[0]
        return rule_source_exists

    def delete_module_api_config(self, qradar_request, module_config_params):
        """The fn TC of DELETE operation
        :param qradar_request: Qradar connection request
        :param module_config_params: Module input config
        :rtype: A dict
        :returns: Delete output with before and after dict
        """
        config = {}
        before = {}
        after = {}
        changed = False
        rule_exists = self.search_for_resource(
            qradar_request,
            module_config_params,
        )
        if rule_exists:
            changed = True
            before = rule_exists
            code, qradar_return_data = qradar_request.delete(
                self.api_object + "/{0}".format(rule_exists["id"]),
            )
            config.update({"before": before, "after": after})
        else:
            config.update({"before": before})
        return config, changed

    def configure_module_api(self, qradar_request, module_config_params):
        """The fn TC of MERGE operation
        :param qradar_request: Qradar connection request
        :param module_config_params: Module input config
        :rtype: A dict
        :returns: Merge output with before and after dict
        """
        config = {}
        before = {}
        changed = False

        rule_exists = self.search_for_resource(
            qradar_request,
            module_config_params,
        )
        if rule_exists:
            if isinstance(rule_exists, list):
                for each in rule_exists:
                    if each.get("origin") == "OVERRIDE":
                        rule_exists = each
                        break
            before = rule_exists
            module_config_params = utils.remove_empties(module_config_params)
            diff = utils.dict_diff(rule_exists, module_config_params)
            if diff:
                changed = True
                qradar_return_data = qradar_request.post_by_path(
                    self.api_object + "/{0}".format(rule_exists["id"]),
                    data=json.dumps(diff),
                )
                if qradar_return_data[0] >= 200:
                    config.update(
                        {"before": before, "after": qradar_return_data[1]},
                    )
            else:
                config.update({"before": before})
        return config, changed

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        headers = None
        if self._task.args.get("config"):
            self._task.args["config"] = remove_unsupported_keys_from_payload_dict(
                self._task.args["config"],
                self.supported_params,
            )
            self._check_argspec()
        if self._result.get("failed"):
            return self._result
        if self._task.args["config"].get("range"):
            headers = {
                "Content-Type": "application/json",
                "Range": "items={0}".format(
                    self._task.args["config"]["range"],
                ),
            }
        conn = Connection(self._connection.socket_path)
        if headers:
            conn_request = QRadarRequest(
                connection=conn,
                headers=headers,
                task_vars=task_vars,
            )
        else:
            conn_request = QRadarRequest(connection=conn, task_vars=task_vars)
        if self._task.args["state"] == "gathered":
            if self._task.args.get("config"):
                self._result["gathered"] = self.search_for_resource(
                    conn_request,
                    self._task.args["config"],
                )
        elif self._task.args["state"] == "merged":
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
