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
The module file for splunk_correlation_searches
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import json

from ansible.errors import AnsibleActionFail
from ansible.module_utils.connection import Connection
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.plugins.action import ActionBase
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.splunk.es.plugins.module_utils.splunk import (
    SplunkRequest,
    map_obj_to_params,
    map_params_to_obj,
    remove_get_keys_from_payload_dict,
    set_defaults,
)
from ansible_collections.splunk.es.plugins.modules.splunk_correlation_searches import DOCUMENTATION


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_object = "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
        self.module_name = "correlation_searches"
        self.key_transform = {
            "disabled": "disabled",
            "name": "name",
            "description": "description",
            "search": "search",
            "action.correlationsearch.annotations": "annotations",
            "request.ui_dispatch_app": "ui_dispatch_context",
            "dispatch.earliest_time": "time_earliest",
            "dispatch.latest_time": "time_latest",
            "cron_schedule": "cron_schedule",
            "realtime_schedule": "scheduling",
            "schedule_window": "schedule_window",
            "schedule_priority": "schedule_priority",
            "alert.digest_mode": "trigger_alert",
            "alert_type": "trigger_alert_when",
            "alert_comparator": "trigger_alert_when_condition",
            "alert_threshold": "trigger_alert_when_value",
            "alert.suppress": "suppress_alerts",
            "alert.suppress.period": "throttle_window_duration",
            "alert.suppress.fields": "throttle_fields_to_group_by",
        }

    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=utils.remove_empties(self._task.args),
            schema=DOCUMENTATION,
            schema_format="doc",
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            self._result["failed"] = True
            self._result["msg"] = errors

    def fail_json(self, msg):
        """Replace the AnsibleModule fail_json here
        :param msg: The message for the failure
        :type msg: str
        """
        msg = msg.replace("(basic.py)", self._task.action)
        raise AnsibleActionFail(msg)

    # need to store 'annotations' and 'throttle_fields_to_group_by'
    # since merging in the parsed form will eliminate any differences
    # This is because these fields are getting converted from strings
    # to lists/dictionaries, and so these fields need to be compared
    # as such
    def save_params(self, want_conf):
        param_store = {}
        if "annotations" in want_conf:
            param_store["annotations"] = want_conf["annotations"]
        if "throttle_fields_to_group_by" in want_conf:
            param_store["throttle_fields_to_group_by"] = want_conf["throttle_fields_to_group_by"]

        return param_store

    def map_params_to_object(self, config):
        res = {}

        res["app"] = config["acl"]["app"]
        res.update(map_params_to_obj(config["content"], self.key_transform))
        res.update(map_params_to_obj(config, self.key_transform))

        if "scheduling" in res:
            if res["scheduling"]:
                res["scheduling"] = "realtime"
            else:
                res["scheduling"] = "continuous"

        if "trigger_alert" in res:
            if res["trigger_alert"]:
                res["trigger_alert"] = "once"
            else:
                res["trigger_alert"] = "for each result"

        if "throttle_fields_to_group_by" in res:
            res["throttle_fields_to_group_by"] = res["throttle_fields_to_group_by"].split(",")

        if "annotations" in res:
            res["annotations"] = json.loads(res["annotations"])

            custom = []

            # need to check for custom annotation frameworks
            for k, v in res["annotations"].items():
                if k in {"cis20", "nist", "mitre_attack", "kill_chain_phases"}:
                    continue
                entry = {}
                entry["framework"] = k
                entry["custom_annotations"] = v
                custom.append(entry)

            if custom:
                for entry in custom:
                    res["annotations"].pop(entry["framework"])
                res["annotations"]["custom"] = custom

        return res

    def map_objects_to_params(self, want_conf):
        res = {}

        # setting parameters that enable correlation search
        res["action.correlationsearch.enabled"] = "1"
        res["is_scheduled"] = True
        res["dispatch.rt_backfill"] = True
        res["action.correlationsearch.label"] = want_conf["name"]

        res.update(map_obj_to_params(want_conf, self.key_transform))

        if "realtime_schedule" in res:
            if res["realtime_schedule"] == "realtime":
                res["realtime_schedule"] = True
            else:
                res["realtime_schedule"] = False

        if "alert.digest_mode" in res:
            if res["alert.digest_mode"] == "once":
                res["alert.digest_mode"] = True
            else:
                res["alert.digest_mode"] = False

        if "alert.suppress.fields" in res:
            res["alert.suppress.fields"] = ",".join(
                res["alert.suppress.fields"],
            )

        if (
            "action.correlationsearch.annotations" in res
            and "custom" in res["action.correlationsearch.annotations"]
        ):
            for ele in res["action.correlationsearch.annotations"]["custom"]:
                res["action.correlationsearch.annotations"][ele["framework"]] = ele[
                    "custom_annotations"
                ]
            res["action.correlationsearch.annotations"].pop("custom")
            res["action.correlationsearch.annotations"] = json.dumps(
                res["action.correlationsearch.annotations"],
            )

        return res

    def search_for_resource_name(self, conn_request, correlation_search_name):
        query_dict = conn_request.get_by_path(
            "{0}/{1}".format(
                self.api_object,
                quote(correlation_search_name),
            ),
        )

        search_result = {}

        if query_dict:
            search_result = self.map_params_to_object(query_dict["entry"][0])

        return search_result

    def delete_module_api_config(self, conn_request, config):
        before = []
        after = None
        changed = False
        for want_conf in config:
            search_by_name = self.search_for_resource_name(
                conn_request,
                want_conf["name"],
            )

            if search_by_name:
                before.append(search_by_name)
                url = "{0}/{1}".format(
                    self.api_object,
                    quote(want_conf["name"]),
                )
                conn_request.delete_by_path(
                    url,
                )
                changed = True
                after = []

        res_config = {}
        res_config["after"] = after
        res_config["before"] = before

        return res_config, changed

    def configure_module_api(self, conn_request, config):
        before = []
        after = []
        changed = False
        # Add to the THIS list for the value which needs to be excluded
        # from HAVE params when compared to WANT param like 'ID' can be
        # part of HAVE param but may not be part of your WANT param
        defaults = {}
        remove_from_diff_compare = []
        for want_conf in config:
            have_conf = self.search_for_resource_name(
                conn_request,
                want_conf["name"],
            )

            if have_conf:
                want_conf = set_defaults(want_conf, defaults)
                want_conf = utils.remove_empties(want_conf)
                diff = utils.dict_diff(have_conf, want_conf)

                # Check if have_conf has extra parameters
                if self._task.args["state"] == "replaced":
                    diff2 = utils.dict_diff(want_conf, have_conf)
                    if len(diff) or len(diff2):
                        diff.update(diff2)

                if diff:
                    name = want_conf["name"]
                    before.append(have_conf)
                    if self._task.args["state"] == "merged":
                        # need to store 'annotations' and 'throttle_group_by_field'
                        # since merging in the parsed form will eliminate any differences
                        param_store = self.save_params(want_conf)

                        want_conf = utils.remove_empties(
                            utils.dict_merge(have_conf, want_conf),
                        )
                        want_conf = remove_get_keys_from_payload_dict(
                            want_conf,
                            remove_from_diff_compare,
                        )

                        # restoring parameters
                        want_conf.update(param_store)

                        changed = True

                        payload = self.map_objects_to_params(want_conf)

                        url = "{0}/{1}".format(
                            self.api_object,
                            quote(name),
                        )
                        api_response = conn_request.create_update(
                            url,
                            data=payload,
                        )
                        response_json = self.map_params_to_object(
                            api_response["entry"][0],
                        )

                        after.append(response_json)
                    elif self._task.args["state"] == "replaced":
                        self.delete_module_api_config(
                            conn_request=conn_request,
                            config=[want_conf],
                        )
                        changed = True

                        payload = self.map_objects_to_params(want_conf)

                        url = "{0}/{1}".format(
                            self.api_object,
                            quote(name),
                        )

                        # while creating new correlation search, this is how to set the 'app' field
                        if "app" in want_conf:
                            url = url.replace(
                                "SplunkEnterpriseSecuritySuite",
                                want_conf["app"],
                            )

                        api_response = conn_request.create_update(
                            url,
                            data=payload,
                        )
                        response_json = self.map_params_to_object(
                            api_response["entry"][0],
                        )

                        after.append(response_json)
                else:
                    before.append(have_conf)
                    after.append(have_conf)
            else:
                changed = True
                want_conf = utils.remove_empties(want_conf)
                name = want_conf["name"]
                payload = self.map_objects_to_params(want_conf)

                url = "{0}/{1}".format(
                    self.api_object,
                    quote(name),
                )

                # while creating new correlation search, this is how to set the 'app' field
                if "app" in want_conf:
                    url = url.replace(
                        "SplunkEnterpriseSecuritySuite",
                        want_conf["app"],
                    )

                api_response = conn_request.create_update(
                    url,
                    data=payload,
                )
                response_json = self.map_params_to_object(
                    api_response["entry"][0],
                )

                after.extend(before)
                after.append(response_json)
        if not changed:
            after = None

        res_config = {}
        res_config["after"] = after
        res_config["before"] = before

        return res_config, changed

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)

        self._check_argspec()
        if self._result.get("failed"):
            return self._result

        self._result[self.module_name] = {}

        # config is retrieved as a string; need to deserialise
        config = self._task.args.get("config")

        conn = Connection(self._connection.socket_path)

        conn_request = SplunkRequest(
            action_module=self,
            connection=conn,
            not_rest_data_keys=["state"],
        )

        if self._task.args["state"] == "gathered":
            if config:
                self._result["changed"] = False
                self._result["gathered"] = []
                for item in config:
                    result = self.search_for_resource_name(
                        conn_request,
                        item["name"],
                    )
                    if result:
                        self._result["gathered"].append(result)
                for item in config:
                    self._result["gathered"].append(
                        self.search_for_resource_name(
                            conn_request,
                            item["name"],
                        ),
                    )
        elif self._task.args["state"] == "merged" or self._task.args["state"] == "replaced":
            (
                self._result[self.module_name],
                self._result["changed"],
            ) = self.configure_module_api(conn_request, config)
            if self._result[self.module_name]["after"] is None:
                self._result[self.module_name].pop("after")

        elif self._task.args["state"] == "deleted":
            (
                self._result[self.module_name],
                self._result["changed"],
            ) = self.delete_module_api_config(conn_request, config)
            if self._result[self.module_name]["after"] is None:
                self._result[self.module_name].pop("after")

        return self._result
