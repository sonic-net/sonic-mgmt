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
The module file for adaptive_response_notable_events
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
from ansible_collections.splunk.es.plugins.modules.splunk_adaptive_response_notable_events import (
    DOCUMENTATION,
)


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_object = "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
        self.module_name = "adaptive_response_notable_events"
        self.key_transform = {
            "action.notable.param.default_owner": "default_owner",
            "action.notable.param.default_status": "default_status",
            "action.notable.param.drilldown_name": "drilldown_name",
            "action.notable.param.drilldown_search": "drilldown_search",
            "action.notable.param.drilldown_earliest_offset": "drilldown_earliest_offset",
            "action.notable.param.drilldown_latest_offset": "drilldown_latest_offset",
            "action.notable.param.extract_artifacts": "extract_artifacts",
            "action.notable.param.investigation_profiles": "investigation_profiles",
            "action.notable.param.next_steps": "next_steps",
            "action.notable.param.recommended_actions": "recommended_actions",
            "action.notable.param.rule_description": "description",
            "action.notable.param.rule_title": "name",
            "action.notable.param.security_domain": "security_domain",
            "action.notable.param.severity": "severity",
            "name": "correlation_search_name",
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

    # need to store 'recommended_actions','extract_artifacts','next_steps' and 'investigation_profiles'
    # since merging in the parsed form will eliminate any differences
    def save_params(self, want_conf):
        param_store = {}
        if "recommended_actions" in want_conf:
            param_store["recommended_actions"] = want_conf["recommended_actions"]
        if "extract_artifacts" in want_conf:
            param_store["extract_artifacts"] = want_conf["extract_artifacts"]
        if "next_steps" in want_conf:
            param_store["next_steps"] = want_conf["next_steps"]
        if "investigation_profiles" in want_conf:
            param_store["investigation_profiles"] = want_conf["investigation_profiles"]

        return param_store

    # responsible for correctly setting certain parameters depending on the state being triggered.
    # These parameters are responsible for enabling and disabling notable response actions
    def create_metadata(self, metadata, mode="add"):
        if mode == "add":
            if "actions" in metadata:
                if metadata["actions"] == "notable":
                    pass
                elif (
                    len(metadata["actions"].split(",")) > 0 and "notable" not in metadata["actions"]
                ):
                    metadata["actions"] = metadata["actions"] + ", notable"
                else:
                    metadata["actions"] = "notable"
            metadata["action.notable"] = "1"
        elif mode == "delete":
            if "actions" in metadata:
                if metadata["actions"] == "notable":
                    metadata["actions"] = ""
                elif len(metadata["actions"].split(",")) > 0 and "notable" in metadata["actions"]:
                    tmp_list = metadata["actions"].split(",")
                    tmp_list.remove(" notable")
                    metadata["actions"] = ",".join(tmp_list)
            metadata["action.notable"] = "0"

        return metadata

    def map_params_to_object(self, config):
        res = {}
        res["correlation_search_name"] = config["name"]

        res.update(map_params_to_obj(config["content"], self.key_transform))

        if "extract_artifacts" in res:
            res["extract_artifacts"] = json.loads(res["extract_artifacts"])

        if "investigation_profiles" in res:
            if res["investigation_profiles"] == "{}":
                res.pop("investigation_profiles")
            else:
                res["investigation_profiles"] = json.loads(
                    res["investigation_profiles"],
                )
                investigation_profiles = []
                for keys in res["investigation_profiles"].keys():
                    investigation_profiles.append(keys.split("profile://")[1])
                res["investigation_profiles"] = investigation_profiles

        if "recommended_actions" in res:
            res["recommended_actions"] = res["recommended_actions"].split(",")

        if "next_steps" in res:
            next_steps = json.loads(res["next_steps"])["data"]

            next_steps = next_steps.split("]][[")
            # trimming trailing characters
            next_steps[0] = next_steps[0].strip("[")
            next_steps[-1] = next_steps[-1].strip("]")

            res["next_steps"] = []
            for element in next_steps:
                res["next_steps"].append(element.split("|")[1])

        if "default_status" in res:
            mapping = {
                "0": "unassigned",
                "1": "new",
                "2": "in progress",
                "3": "pending",
                "4": "resolved",
                "5": "closed",
            }
            res["default_status"] = mapping[res["default_status"]]

        # need to store correlation search details for populating future request payloads
        metadata = {}
        metadata["search"] = config["content"]["search"]
        metadata["actions"] = config["content"]["actions"]

        return res, metadata

    def map_objects_to_params(self, metadata, want_conf):
        res = {}

        res.update(map_obj_to_params(want_conf, self.key_transform))
        res.update(self.create_metadata(metadata))

        if "action.notable.param.extract_artifacts" in res:
            res["action.notable.param.extract_artifacts"] = json.dumps(
                res["action.notable.param.extract_artifacts"],
            )

        if "action.notable.param.recommended_actions" in res:
            res["action.notable.param.recommended_actions"] = ",".join(
                res["action.notable.param.recommended_actions"],
            )

        if "action.notable.param.investigation_profiles" in res:
            investigation_profiles = {}
            for element in res["action.notable.param.investigation_profiles"]:
                investigation_profiles["profile://" + element] = {}
            res["action.notable.param.investigation_profiles"] = json.dumps(
                investigation_profiles,
            )

        if "action.notable.param.next_steps" in res:
            next_steps = ""
            for next_step in res["action.notable.param.next_steps"]:
                next_steps += "[[action|{0}]]".format(next_step)

            # NOTE: version:1 appears to be hard coded when you create this via the splunk web UI
            next_steps_dict = {"version": 1, "data": next_steps}
            res["action.notable.param.next_steps"] = json.dumps(
                next_steps_dict,
            )

        if "action.notable.param.default_status" in res:
            mapping = {
                "unassigned": "0",
                "new": "1",
                "in progress": "2",
                "pending": "3",
                "resolved": "4",
                "closed": "5",
            }
            res["action.notable.param.default_status"] = mapping[
                res["action.notable.param.default_status"]
            ]

        # need to remove 'name', otherwise the API call will try to modify the correlation search
        res.pop("name")

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
            search_result, metadata = self.map_params_to_object(
                query_dict["entry"][0],
            )
        else:
            raise AnsibleActionFail(
                "Correlation Search '{0}' doesn't exist".format(
                    correlation_search_name,
                ),
            )

        return search_result, metadata

    # Since there is no delete operation associated with an action,
    # The delete operation will unset the relevant fields
    def delete_module_api_config(self, conn_request, config):
        before = []
        after = None
        changed = False
        for want_conf in config:
            search_by_name, metadata = self.search_for_resource_name(
                conn_request,
                want_conf["correlation_search_name"],
            )
            search_by_name = utils.remove_empties(search_by_name)

            # Compare obtained values with a dict representing values in a 'deleted' state
            diff_cmp = {
                "correlation_search_name": want_conf["correlation_search_name"],
                "drilldown_earliest_offset": "$info_min_time$",
                "drilldown_latest_offset": "$info_max_time$",
            }

            # if the obtained values are different from 'deleted' state values
            if search_by_name and search_by_name != diff_cmp:
                before.append(search_by_name)
                payload = {
                    "action.notable.param.default_owner": "",
                    "action.notable.param.default_status": "",
                    "action.notable.param.drilldown_name": "",
                    "action.notable.param.drilldown_search": "",
                    "action.notable.param.drilldown_earliest_offset": "$info_min_time$",
                    "action.notable.param.drilldown_latest_offset": "$info_max_time$",
                    "action.notable.param.extract_artifacts": "{}",
                    "action.notable.param.investigation_profiles": "{}",
                    "action.notable.param.next_steps": "",
                    "action.notable.param.recommended_actions": "",
                    "action.notable.param.rule_description": "",
                    "action.notable.param.rule_title": "",
                    "action.notable.param.security_domain": "",
                    "action.notable.param.severity": "",
                }
                payload.update(self.create_metadata(metadata, mode="delete"))
                url = "{0}/{1}".format(
                    self.api_object,
                    quote(want_conf["correlation_search_name"]),
                )
                conn_request.create_update(
                    url,
                    data=payload,
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
        defaults = {
            "drilldown_earliest_offset": "$info_min_time$",
            "drilldown_latest_offset": "$info_max_time$",
            "extract_artifacts": {
                "asset": [
                    "src",
                    "dest",
                    "dvc",
                    "orig_host",
                ],
                "identity": [
                    "src_user",
                    "user",
                    "src_user_id",
                    "src_user_role",
                    "user_id",
                    "user_role",
                    "vendor_account",
                ],
            },
            "investigation_profiles": "{}",
        }
        remove_from_diff_compare = []
        for want_conf in config:
            have_conf, metadata = self.search_for_resource_name(
                conn_request,
                want_conf["correlation_search_name"],
            )
            correlation_search_name = want_conf["correlation_search_name"]

            if "notable" in metadata["actions"]:
                want_conf = set_defaults(want_conf, defaults)
                want_conf = utils.remove_empties(want_conf)
                diff = utils.dict_diff(have_conf, want_conf)

                # Check if have_conf has extra parameters
                if self._task.args["state"] == "replaced":
                    diff2 = utils.dict_diff(want_conf, have_conf)
                    if len(diff) or len(diff2):
                        diff.update(diff2)

                if diff:
                    before.append(have_conf)
                    if self._task.args["state"] == "merged":
                        # need to store 'recommended_actions','extract_artifacts'
                        # 'next_steps' and 'investigation_profiles'
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

                        payload = self.map_objects_to_params(
                            metadata,
                            want_conf,
                        )

                        url = "{0}/{1}".format(
                            self.api_object,
                            quote(correlation_search_name),
                        )
                        api_response = conn_request.create_update(
                            url,
                            data=payload,
                        )
                        response_json, metadata = self.map_params_to_object(
                            api_response["entry"][0],
                        )

                        after.append(response_json)
                    elif self._task.args["state"] == "replaced":
                        self.delete_module_api_config(
                            conn_request=conn_request,
                            config=[want_conf],
                        )
                        changed = True

                        payload = self.map_objects_to_params(
                            metadata,
                            want_conf,
                        )

                        url = "{0}/{1}".format(
                            self.api_object,
                            quote(correlation_search_name),
                        )
                        api_response = conn_request.create_update(
                            url,
                            data=payload,
                        )
                        response_json, metadata = self.map_params_to_object(
                            api_response["entry"][0],
                        )

                        after.append(response_json)
                else:
                    before.append(have_conf)
                    after.append(have_conf)
            else:
                changed = True
                want_conf = utils.remove_empties(want_conf)
                payload = self.map_objects_to_params(metadata, want_conf)

                url = "{0}/{1}".format(
                    self.api_object,
                    quote(correlation_search_name),
                )
                api_response = conn_request.create_update(
                    url,
                    data=payload,
                )

                response_json, metadata = self.map_params_to_object(
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
                self._result[self.module_name]["gathered"] = []
                for item in config:
                    self._result[self.module_name]["gathered"].append(
                        self.search_for_resource_name(
                            conn_request,
                            item["correlation_search_name"],
                        )[0],
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
