#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type
import json

from copy import copy
from ssl import CertificateError

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import Connection, ConnectionError
from ansible.module_utils.six import iteritems
from ansible.module_utils.six.moves.urllib.parse import quote_plus


BASE_HEADERS = {"Content-Type": "application/json", "Version": "9.1"}


def find_dict_in_list(some_list, key, value):
    text_type = False
    try:
        to_text(value)
        text_type = True
    except TypeError:
        pass
    for some_dict in some_list:
        if key in some_dict:
            if text_type:
                if to_text(some_dict[key]).strip() == to_text(value).strip():
                    return some_dict, some_list.index(some_dict)
            else:
                if some_dict[key] == value:
                    return some_dict, some_list.index(some_dict)
    return None


def set_offense_values(module, qradar_request):
    if module.params["closing_reason"]:
        found_closing_reason = qradar_request.get_by_path(
            "api/siem/offense_closing_reasons?filter={0}".format(
                quote_plus(
                    'text="{0}"'.format(module.params["closing_reason"]),
                ),
            ),
        )
        if found_closing_reason:
            module.params["closing_reason_id"] = found_closing_reason[0]["id"]
        else:
            module.fail_json(
                "Unable to find closing_reason text: {0}".format(
                    module.params["closing_reason"],
                ),
            )

    if module.params["status"]:
        module.params["status"] = module.params["status"].upper()


def remove_unsupported_keys_from_payload_dict(payload, supported_key_list):
    """The fn to remove the unsupported keys from payload
    :param payload: Payload from response
    :param supported_key_list: Module supported params
    :rtype: A dict
    :returns: payload with only supported and module expected params
    """
    temp_payload = []
    for each in payload:
        temp_dict = copy(each)
        if isinstance(each, dict):
            for every_key in each.keys():
                if every_key not in supported_key_list:
                    temp_dict.pop(every_key)
            temp_payload.append(temp_dict)
    if temp_payload:
        return temp_payload
    return payload


def list_to_dict(input_dict):
    """The fn to convert list of dict to dict
    :param input_dict: input list having list of dict
    :rtype: A dict
    :returns: dict with converted all list to dict type
    """
    if isinstance(input_dict, dict):
        for k, v in iteritems(input_dict):
            if isinstance(v, dict):
                list_to_dict(v)
            elif isinstance(v, list):
                temp_dict = {}
                for each in v:
                    if isinstance(each, dict):
                        if each.get("id") or each.get("id") == 0:
                            each.pop("id")
                        each_key_values = "_".join(
                            [str(x) for x in each.values()],
                        )
                        temp_dict.update({each_key_values: each})
                        input_dict[k] = temp_dict


class QRadarRequest(object):
    def __init__(
        self,
        module=None,
        connection=None,
        headers=None,
        not_rest_data_keys=None,
        task_vars=None,
    ):
        self.module = module
        if module:
            # This will be removed, once all of the available modules
            # are moved to use action plugin design, as otherwise test
            # would start to complain without the implementation.
            self.connection = Connection(self.module._socket_path)
        elif connection:
            self.connection = connection
            try:
                self.connection.load_platform_plugins("ibm.qradar.qradar")
                self.connection.set_options(var_options=task_vars)
            except ConnectionError:
                raise
        # This allows us to exclude specific argspec keys from being included by
        # the rest data that don't follow the qradar_* naming convention
        if not_rest_data_keys:
            self.not_rest_data_keys = not_rest_data_keys
        else:
            self.not_rest_data_keys = []
        self.not_rest_data_keys.append("validate_certs")
        self.headers = headers if headers else BASE_HEADERS

    def _httpapi_error_handle(self, method, uri, payload=None):
        # FIXME - make use of handle_httperror(self, exception) where applicable
        #   https://docs.ansible.com/ansible/latest/network/dev_guide/developing_plugins_network.html#developing-plugins-httpapi
        code = 99999
        response = {}
        try:
            code, response = self.connection.send_request(
                method,
                uri,
                payload=payload,
                headers=self.headers,
            )
        except ConnectionError as e:
            self.module.fail_json(
                msg="connection error occurred: {0}".format(e),
            )
        except CertificateError as e:
            self.module.fail_json(
                msg="certificate error occurred: {0}".format(e),
            )
        except ValueError as e:
            try:
                self.module.fail_json(
                    msg="certificate not found: {0}".format(e),
                )
            except AttributeError:
                pass

        if code == 404:
            if (
                to_text("Object not found") in to_text(response)
                or to_text("Could not find object") in to_text(response)
                or to_text("No offense was found") in to_text(response)
            ):
                return {}
            if to_text("The rule does not exist.") in to_text(
                response["description"],
            ):
                return code, {}

        if code == 409:
            if "code" in response:
                if response["code"] in [1002, 1004]:
                    # https://www.ibm.com/support/knowledgecenter/SS42VS_7.3.1/com.ibm.qradar.doc/9.2--staged_config-deploy_status-POST.html
                    # Documentation says we should get 1002, but I'm getting 1004 from QRadar
                    return response
                else:
                    self.module.fail_json(
                        msg="qradar httpapi returned error {0} with message {1}".format(
                            code,
                            response,
                        ),
                    )
        elif not (code >= 200 and code < 300):
            try:
                self.module.fail_json(
                    msg="qradar httpapi returned error {0} with message {1}".format(
                        code,
                        response,
                    ),
                )
            except AttributeError:
                pass

        return code, response

    def get(self, url, **kwargs):
        return self._httpapi_error_handle("GET", url, **kwargs)

    def put(self, url, **kwargs):
        return self._httpapi_error_handle("PUT", url, **kwargs)

    def post(self, url, **kwargs):
        return self._httpapi_error_handle("POST", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._httpapi_error_handle("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._httpapi_error_handle("DELETE", url, **kwargs)

    def get_data(self):
        """
        Get the valid fields that should be passed to the REST API as urlencoded
        data so long as the argument specification to the module follows the
        convention:
            - the key to the argspec item does not start with qradar_
            - the key does not exist in the not_data_keys list
        """
        try:
            qradar_data = {}
            for param in self.module.params:
                if (self.module.params[param]) is not None and (
                    param not in self.not_rest_data_keys
                ):
                    qradar_data[param] = self.module.params[param]
            return qradar_data

        except TypeError as e:
            self.module.fail_json(
                msg="invalid data type provided: {0}".format(e),
            )

    def post_by_path(self, rest_path, data=None):
        """
        POST with data to path
        """
        if data is None:
            data = json.dumps(self.get_data())
        elif data is False:
            # Because for some reason some QRadar REST API endpoint use the
            # query string to modify state
            return self.post("/{0}".format(rest_path))
        return self.post("/{0}".format(rest_path), payload=data)

    def create_update(self, rest_path, data=None):
        """
        Create or Update a file/directory monitor data input in qradar
        """
        if data is None:
            data = json.dumps(self.get_data())
        # return self.post("/{0}".format(rest_path), payload=data)
        return self.patch("/{0}".format(rest_path), payload=data)  # PATCH
