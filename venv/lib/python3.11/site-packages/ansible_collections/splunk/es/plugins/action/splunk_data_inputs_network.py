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
The module file for data_inputs_network
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.errors import AnsibleActionFail
from ansible.module_utils.connection import Connection
from ansible.module_utils.six.moves.urllib.parse import quote_plus
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
)
from ansible_collections.splunk.es.plugins.modules.splunk_data_inputs_network import DOCUMENTATION


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_object = "servicesNS/nobody/search/data/inputs"
        self.module_return = "data_inputs_network"
        self.key_transform = {
            "name": "name",
            "connection_host": "connection_host",
            "disabled": "disabled",
            "index": "index",
            "host": "host",
            "no_appending_timestamp": "no_appending_timestamp",
            "no_priority_stripping": "no_priority_stripping",
            "rawTcpDoneTimeout": "raw_tcp_done_timeout",
            "restrictToHost": "restrict_to_host",
            "queue": "queue",
            "SSL": "ssl",
            "source": "source",
            "sourcetype": "sourcetype",
            "token": "token",
            "password": "password",
            "requireClientCert": "require_client_cert",
            "rootCA": "root_ca",
            "serverCert": "server_cert",
            "cipherSuite": "cipher_suite",
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

    def map_params_to_object(self, config, datatype=None):
        res = {}

        res["name"] = config["name"]
        res.update(map_params_to_obj(config["content"], self.key_transform))

        # API returns back "index", even though it can't be set within /tcp/cooked
        if datatype:
            if datatype == "cooked" and "index" in res:
                res.pop("index")
            elif datatype == "splunktcptoken":
                if "index" in res:
                    res.pop("index")
                if "host" in res:
                    res.pop("host")
                if "disabled" in res:
                    res.pop("disabled")

        return res

    # This function is meant to construct the URL and handle GET, POST and DELETE calls
    # depending on th context. The URLs constructed and handled are:
    # /tcp/raw[/{name}]
    # /tcp/cooked[/{name}]
    # /tcp/splunktcptoken[/{name}]
    # /tcp/ssl[/{name}]
    # /udp[/{name}]
    def request_by_path(
        self,
        conn_request,
        protocol,
        datatype=None,
        name=None,
        req_type="get",
        payload=None,
    ):
        query_dict = None
        url = ""

        if protocol == "tcp":
            if not datatype:
                raise AnsibleActionFail("No datatype specified for TCP input")

            # In all cases except "ssl" datatype, creation of objects is handled
            # by a POST request to the parent directory. Therefore name shouldn't
            # be included in the URL.
            if not name or (req_type == "post_create" and datatype != "ssl"):
                name = ""

            url = "{0}/{1}/{2}/{3}".format(
                self.api_object,
                protocol,
                datatype,
                quote_plus(str(name)),
            )
            # if no "name" was provided
            if url[-1] == "/":
                url = url[:-1]

        elif protocol == "udp":
            if datatype:
                raise AnsibleActionFail("Datatype specified for UDP input")
            if not name or req_type == "post_create":
                name = ""

            url = "{0}/{1}/{2}".format(
                self.api_object,
                protocol,
                quote_plus(str(name)),
            )
            # if no "name" was provided
            if url[-1] == "/":
                url = url[:-1]
        else:
            raise AnsibleActionFail(
                "Incompatible protocol specified. Please specify 'tcp' or 'udp'",
            )

        if req_type == "get":
            query_dict = conn_request.get_by_path(url)
        elif req_type == "post_create":
            query_dict = conn_request.create_update(url, data=payload)
        elif req_type == "post_update":
            payload.pop("name")
            query_dict = conn_request.create_update(url, data=payload)
        elif req_type == "delete":
            query_dict = conn_request.delete_by_path(url)

        return query_dict

    def search_for_resource_name(self, conn_request, protocol, datatype, name):
        query_dict = self.request_by_path(
            conn_request,
            protocol,
            datatype,
            name,
        )

        search_result = {}

        if query_dict:
            search_result = self.map_params_to_object(
                query_dict["entry"][0],
                datatype,
            )

            # Adding back protocol and datatype fields for better clarity
            search_result["protocol"] = protocol
            if datatype:
                search_result["datatype"] = datatype
                if datatype == "ssl":
                    search_result["name"] = name

        return search_result

    # If certain parameters are present, Splunk appends the value of those parameters
    # to the name. Therefore this causes idempotency to fail. This function looks for
    # said parameters and conducts checks to see if the configuration already exists.
    def parse_config(self, conn_request, want_conf):
        old_name = None
        protocol = want_conf["protocol"]
        datatype = want_conf.get("datatype")

        if not want_conf.get("name"):
            raise AnsibleActionFail("No name specified for merge action")
        else:
            # Int values confuse diff
            want_conf["name"] = str(want_conf["name"])

            old_name = want_conf["name"]

            if (
                want_conf.get("restrict_to_host")
                and old_name.split(":")[0] == want_conf["restrict_to_host"]
            ):
                old_name = old_name.split(":")[1]

            # If "restrictToHost" parameter is set, the value of this parameter is appended
            # to the numerical name meant to represent port number
            if (
                want_conf.get("restrict_to_host")
                and want_conf["restrict_to_host"] not in want_conf["name"]
            ):
                want_conf["name"] = "{0}:{1}".format(
                    want_conf["restrict_to_host"],
                    want_conf["name"],
                )

            # If datatype is "splunktcptoken", the value "splunktcptoken://" is appended
            # to the name
            elif (
                datatype
                and datatype == "splunktcptoken"
                and "splunktcptoken://" not in want_conf["name"]
            ):
                want_conf["name"] = "{0}{1}".format(
                    "splunktcptoken://",
                    want_conf["name"],
                )

        name = want_conf["name"]

        # If the above parameters are present, but the object doesn't exist
        # the value of the parameters shouldn't be prepended to the name.
        # Otherwise Splunk returns 400. This check is takes advantage of this
        # and sets the correct name.
        have_conf = None
        try:
            have_conf = self.search_for_resource_name(
                conn_request,
                protocol,
                datatype,
                name,
            )
            # while creating new conf, we need to only use numerical values
            # splunk will later append param value to it.
            if not have_conf:
                want_conf["name"] = old_name
        except AnsibleActionFail:
            want_conf["name"] = old_name
            have_conf = self.search_for_resource_name(
                conn_request,
                protocol,
                datatype,
                old_name,
            )

        # SSL response returns a blank "name" parameter, which causes problems
        if datatype == "ssl":
            have_conf["name"] = want_conf["name"]

        return have_conf, protocol, datatype, name, old_name

    def delete_module_api_config(self, conn_request, config):
        before = []
        after = None
        changed = False
        for want_conf in config:
            if not want_conf.get("name"):
                raise AnsibleActionFail("No name specified")

            have_conf, protocol, datatype, name, _old_name = self.parse_config(
                conn_request,
                want_conf,
            )

            if protocol == "tcp" and datatype == "ssl":
                raise AnsibleActionFail("Deleted state not supported for SSL")

            if have_conf:
                before.append(have_conf)
                self.request_by_path(
                    conn_request,
                    protocol,
                    datatype,
                    name,
                    req_type="delete",
                )
                changed = True
                after = []

        ret_config = {}
        ret_config["before"] = before
        ret_config["after"] = after

        return ret_config, changed

    def configure_module_api(self, conn_request, config):
        before = []
        after = []
        changed = False

        for want_conf in config:
            # Add to the THIS list for the value which needs to be excluded
            # from HAVE params when compared to WANT param like 'ID' can be
            # part of HAVE param but may not be part of your WANT param
            remove_from_diff_compare = [
                "datatype",
                "protocol",
                "cipher_suite",
            ]

            have_conf, protocol, datatype, name, old_name = self.parse_config(
                conn_request,
                want_conf,
            )

            if protocol == "tcp" and datatype == "ssl" and self._task.args["state"] == "replaced":
                raise AnsibleActionFail("Replaced state not supported for SSL")

            if have_conf:
                want_conf = utils.remove_empties(want_conf)
                diff = utils.dict_diff(have_conf, want_conf)

                # Check if have_conf has extra parameters
                if self._task.args["state"] == "replaced":
                    diff2 = utils.dict_diff(want_conf, have_conf)
                    if len(diff) or len(diff2):
                        diff.update(diff2)

                if diff:
                    diff = remove_get_keys_from_payload_dict(
                        diff,
                        remove_from_diff_compare,
                    )
                    if diff:
                        before.append(have_conf)
                        if self._task.args["state"] == "merged":
                            want_conf = utils.remove_empties(
                                utils.dict_merge(have_conf, want_conf),
                            )
                            want_conf = remove_get_keys_from_payload_dict(
                                want_conf,
                                remove_from_diff_compare,
                            )
                            changed = True

                            payload = map_obj_to_params(
                                want_conf,
                                self.key_transform,
                            )
                            api_response = self.request_by_path(
                                conn_request,
                                protocol,
                                datatype,
                                name,
                                req_type="post_update",
                                payload=payload,
                            )
                            response_json = self.map_params_to_object(
                                api_response["entry"][0],
                                datatype,
                            )

                            # Adding back protocol and datatype fields for better clarity
                            response_json["protocol"] = protocol
                            if datatype:
                                response_json["datatype"] = datatype

                            after.append(response_json)
                        elif self._task.args["state"] == "replaced":
                            api_response = self.request_by_path(
                                conn_request,
                                protocol,
                                datatype,
                                name,
                                req_type="delete",
                            )

                            changed = True
                            payload = map_obj_to_params(
                                want_conf,
                                self.key_transform,
                            )
                            # while creating new conf, we need to only use numerical values
                            # splunk will later append param value to it.
                            payload["name"] = old_name

                            api_response = self.request_by_path(
                                conn_request,
                                protocol,
                                datatype,
                                name,
                                req_type="post_create",
                                payload=payload,
                            )
                            response_json = self.map_params_to_object(
                                api_response["entry"][0],
                                datatype,
                            )

                            # Adding back protocol and datatype fields for better clarity
                            response_json["protocol"] = protocol
                            if datatype:
                                response_json["datatype"] = datatype

                            after.append(response_json)
                    else:
                        before.append(have_conf)
                        after.append(have_conf)
                else:
                    before.append(have_conf)
                    after.append(have_conf)
            else:
                changed = True
                want_conf = utils.remove_empties(want_conf)

                payload = map_obj_to_params(want_conf, self.key_transform)

                api_response = self.request_by_path(
                    conn_request,
                    protocol,
                    datatype,
                    name,
                    req_type="post_create",
                    payload=payload,
                )
                response_json = self.map_params_to_object(
                    api_response["entry"][0],
                    datatype,
                )

                # Adding back protocol and datatype fields for better clarity
                response_json["protocol"] = protocol
                if datatype:
                    response_json["datatype"] = datatype

                after.extend(before)
                after.append(response_json)
        if not changed:
            after = None

        ret_config = {}
        ret_config["before"] = before
        ret_config["after"] = after

        return ret_config, changed

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._check_argspec()
        if self._result.get("failed"):
            return self._result

        config = self._task.args.get("config")

        conn = Connection(self._connection.socket_path)

        conn_request = SplunkRequest(
            connection=conn,
            action_module=self,
        )

        if self._task.args["state"] == "gathered":
            if config:
                self._result["gathered"] = []
                self._result["changed"] = False
                for item in config:
                    if item.get("name"):
                        result = self.search_for_resource_name(
                            conn_request,
                            item["protocol"],
                            item.get("datatype"),
                            item.get("name"),
                        )
                        if result:
                            self._result["gathered"].append(result)
                    else:
                        response_list = self.request_by_path(
                            conn_request,
                            item["protocol"],
                            item.get("datatype"),
                            None,
                        )["entry"]
                        self._result["gathered"] = []
                        for response_dict in response_list:
                            self._result["gathered"].append(
                                self.map_params_to_object(response_dict),
                            )
            else:
                raise AnsibleActionFail("No protocol specified")

        elif self._task.args["state"] == "merged" or self._task.args["state"] == "replaced":
            if config:
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.configure_module_api(conn_request, config)
                if not self._result[self.module_return]["after"]:
                    self._result[self.module_return].pop("after")

        elif self._task.args["state"] == "deleted":
            if config:
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.delete_module_api_config(conn_request, config)
                if self._result[self.module_return]["after"] is None:
                    self._result[self.module_return].pop("after")

        return self._result
