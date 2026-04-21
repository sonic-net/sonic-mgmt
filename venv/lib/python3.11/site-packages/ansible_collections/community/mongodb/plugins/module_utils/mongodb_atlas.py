# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from collections import defaultdict

from ansible.module_utils.urls import fetch_url

try:
    from urllib import quote
except ImportError:
    # noinspection PyCompatibility, PyUnresolvedReferences
    from urllib.parse import (
        quote,
    )  # pylint: disable=locally-disabled, import-error, no-name-in-module


class AtlasAPIObject:
    module = None

    def __init__(
        self, module, object_name, group_id, path, data, data_is_array=False
    ):
        self.module = module
        self.path = path
        self.data = data
        self.group_id = group_id
        self.object_name = object_name
        self.data_is_array = data_is_array

        self.module.params["url_username"] = self.module.params["api_username"]
        self.module.params["url_password"] = self.module.params["api_password"]

    def call_url(self, path, data="", method="GET"):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.data_is_array and data != "":
            data = "[" + data + "]"

        url = (
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/"
            + self.group_id
            + path
        )
        rsp, info = fetch_url(
            module=self.module,
            url=url,
            data=data,
            headers=headers,
            method=method,
        )

        content = ""
        error = ""
        if rsp and info["status"] not in (204, 404):
            content = json.loads(rsp.read())
        if info["status"] >= 400:
            try:
                content = json.loads(info["body"])
                error = content["reason"]
                if "detail" in content:
                    error += ". Detail: " + content["detail"]
            except ValueError:
                error = info["msg"]
        if info["status"] < 0:
            error = info["msg"]
        return {"code": info["status"], "data": content, "error": error}

    def exists(self):
        additional_path = ""
        if self.path == "/databaseUsers":
            additional_path = "/admin"
        ret = self.call_url(
            path=self.path
            + additional_path
            + "/"
            + quote(self.data[self.object_name], "")
        )
        if ret["code"] == 200:
            return True
        return False

    def create(self):
        ret = self.call_url(
            path=self.path,
            data=self.module.jsonify(self.data),
            method="POST",
        )
        return ret

    def delete(self):
        additional_path = ""
        if self.path == "/databaseUsers":
            additional_path = "/admin"
        ret = self.call_url(
            path=self.path
            + additional_path
            + "/"
            + quote(self.data[self.object_name], ""),
            method="DELETE",
        )
        return ret

    def modify(self):
        additional_path = ""
        if self.path == "/databaseUsers":
            additional_path = "/admin"
        ret = self.call_url(
            path=self.path
            + additional_path
            + "/"
            + quote(self.data[self.object_name], ""),
            data=self.module.jsonify(self.data),
            method="PATCH",
        )
        return ret

    def diff(self):
        additional_path = ""
        if self.path == "/databaseUsers":
            additional_path = "/admin"
        ret = self.call_url(
            path=self.path
            + additional_path
            + "/"
            + quote(self.data[self.object_name], ""),
            method="GET",
        )

        data_from_atlas = json.loads(self.module.jsonify(ret["data"]))
        data_from_task = json.loads(self.module.jsonify(self.data))

        diff = defaultdict(dict)
        for key, value in data_from_atlas.items():
            if key in data_from_task.keys() and value != data_from_task[key]:
                diff["before"][key] = "{val}".format(val=value)
                diff["after"][key] = "{val}".format(val=data_from_task[key])
        return diff

    def update(self, state):
        changed = False
        diff_result = {"before": "", "after": ""}
        if self.exists():
            diff_result.update({"before": "state: present\n"})
            if state == "absent":
                if self.module.check_mode:
                    diff_result.update({"after": "state: absent\n"})
                    self.module.exit_json(
                        changed=True,
                        object_name=self.data[self.object_name],
                        diff=diff_result,
                    )
                else:
                    try:
                        ret = self.delete()
                        if ret["code"] == 204 or ret["code"] == 202:
                            changed = True
                            diff_result.update({"after": "state: absent\n"})
                        else:
                            self.module.fail_json(
                                msg="bad return code while deleting: %d. Error message: %s"
                                % (ret["code"], ret["error"])
                            )
                    except Exception as e:
                        self.module.fail_json(
                            msg="exception when deleting: " + str(e)
                        )

            else:
                diff_result.update(self.diff())
                if self.module.check_mode:
                    if diff_result["after"] != "":
                        changed = True
                    self.module.exit_json(
                        changed=changed,
                        object_name=self.data[self.object_name],
                        data=self.data,
                        diff=diff_result,
                    )
                if diff_result["after"] != "":
                    if self.path == "/whitelist":
                        ret = self.create()
                    else:
                        ret = self.modify()
                    if ret["code"] == 200 or ret["code"] == 201:
                        changed = True
                    else:
                        self.module.fail_json(
                            msg="bad return code while modifying: %d. Error message: %s"
                            % (ret["code"], ret["error"])
                        )

        else:
            diff_result.update({"before": "state: absent\n"})
            if state == "present":
                if self.module.check_mode:
                    changed = True
                    diff_result.update({"after": "state: created\n"})
                else:
                    try:
                        ret = self.create()
                        if ret["code"] == 201:
                            changed = True
                            diff_result.update({"after": "state: created\n"})
                        else:
                            self.module.fail_json(
                                msg="bad return code while creating: %d. Error message: %s"
                                % (ret["code"], ret["error"])
                            )
                    except Exception as e:
                        self.module.fail_json(
                            msg="exception while creating: " + str(e)
                        )
        return changed, diff_result
