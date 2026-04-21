# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
#
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: mso
short_description: MSO Ansible HTTPAPI Plugin.
description:
  - This MSO plugin provides the HTTPAPI transport methods needed to initiate
    a connection to MSO, send API requests and process the
    response.
version_added: "1.2.0"
options:
  login_domain:
    description:
    - The login domain name to use for authentication.
    - The default value is Local.
    type: string
    env:
    - name: ANSIBLE_HTTPAPI_LOGIN_DOMAIN
    vars:
    - name: ansible_httpapi_login_domain
"""

import json
import re
import traceback

from ansible.module_utils.six import PY3
from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase
from copy import copy


CONNECTION_MAP = {"username": "remote_user", "timeout": "persistent_command_timeout"}
RESET_KEYS = ["username", "password", "login_domain", "host", "port"]
CONNECTION_KEYS = RESET_KEYS + ["use_proxy", "use_ssl", "timeout", "validate_certs"]


class HttpApi(HttpApiBase):
    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.platform = "cisco.mso"
        self.headers = {"Content-Type": "application/json"}
        self.params = {}
        self.auth = None
        self.backup_hosts = None
        self.host_counter = 0

        self.error = None
        self.method = "GET"
        self.path = ""
        self.status = -1
        self.info = {}

        self.connection_parameters = {}

    def get_platform(self):
        return self.platform

    def set_params(self, params):
        self.params = params

    def set_backup_hosts(self):
        try:
            list_of_hosts = re.sub(r"[[\]]", "", self.connection.get_option("host")).split(",")
            # ipaddress.ip_address(list_of_hosts[0])
            return list_of_hosts
        except Exception:
            return []

    def login(self, username, password):
        """Log in to MSO"""
        # Perform login request
        self.connection.queue_message("vvvv", "Starting Login to {0}".format(self.connection.get_option("host")))

        method = "POST"
        path = "/mso/api/v1/auth/login"
        full_path = self.connection.get_option("host") + path

        payload = {"username": username, "password": password}
        if self.connection_parameters["login_domain"] is not None and self.connection_parameters["login_domain"] != "Local":
            payload["domainId"] = self._get_login_domain_id(self.connection_parameters["login_domain"])

        data = json.dumps(payload)
        try:
            payload.pop("password")
            self.connection.queue_message("vvvv", "login() - connection.send({0}, {1}, {2}, {3})".format(path, payload, method, self.headers))
            response, response_data = self.connection.send(path, data, method=method, headers=self.headers)
            # Handle MSO response
            self.status = response.getcode()
            if self.status != 201:
                self.connection.queue_message("vvvv", "login status incorrect status={0}".format(self.status))
                json_response = self._response_to_json(response_data)
                self.error = dict(code=self.status, message="Authentication failed: {0}".format(json_response))
                raise ConnectionError(json.dumps(self._verify_response(response, method, full_path, response_data)))
            self.connection._auth = {"Authorization": "Bearer {0}".format(self._response_to_json(response_data).get("token"))}

        except ConnectionError:
            self.connection.queue_message("vvvv", "login() - ConnectionError Exception")
            raise
        except Exception as e:
            self.connection.queue_message("vvvv", "login() - Generic Exception")
            self.error = dict(code=self.status, message="Authentication failed: Request failed: {0}".format(e))
            raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))

    def logout(self):
        method = "DELETE"
        path = "/mso/api/v1/auth/logout"

        try:
            self.connection.send(path, {}, method=method, headers=self.headers)
        except Exception as e:
            self.error = dict(code=self.status, message="Error on attempt to logout from MSO. {0}".format(e))
            raise ConnectionError(json.dumps(self._verify_response(None, method, self.connection.get_option("host") + path, None)))
        self.connection._auth = None

    def send_request(self, method, path, data=None):
        """This method handles all MSO REST API requests other than login"""

        self.error = None
        self.path = ""
        self.status = -1
        self.info = {}
        self.method = "GET"

        if data is None:
            data = {}

        self.connection.queue_message("vvvv", "send_request method called")

        self.set_connection_parameters()

        # Perform some very basic path input validation.
        path = str(path)
        if path[0] != "/":
            self.error = dict(code=self.status, message="Value of <path> does not appear to be formated properly")
            raise ConnectionError(json.dumps(self._verify_response(None, method, path, None)))
        full_path = self.connection.get_option("host") + path
        try:
            self.connection.queue_message("vvvv", "send_request() - connection.send({0}, {1}, {2}, {3})".format(path, data, method, self.headers))
            response, rdata = self.connection.send(path, data, method=method, headers=self.headers)
        except ConnectionError:
            self.connection.queue_message("vvvv", "login() - ConnectionError Exception")
            raise
        except Exception as e:
            self.connection.queue_message("vvvv", "send_request() - Generic Exception")
            if self.error is None:
                self.error = dict(code=self.status, message="MSO HTTPAPI send_request() Exception: {0} - {1}".format(e, traceback.format_exc()))
            raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))
        return self._verify_response(response, method, full_path, rdata)

    def set_connection_parameters(self):
        connection_parameters = {}
        for key in CONNECTION_KEYS:
            if key == "login_domain":
                value = self.params.get(key) if self.params.get(key) is not None else self.get_option(CONNECTION_MAP.get(key, key))
                self.set_option(key, value)
            else:
                value = self.params.get(key) if self.params.get(key) is not None else self.connection.get_option(CONNECTION_MAP.get(key, key))
                self.connection.set_option(CONNECTION_MAP.get(key, key), value)

            connection_parameters[key] = value
            if value != self.connection_parameters.get(key) and key in RESET_KEYS:
                self.connection._connected = False
                self.connection.queue_message("vvvv", "set_connection_parameters() - resetting connection due to '{0}' change".format(key))

        if self.connection_parameters != connection_parameters:
            self.connection_parameters = copy(connection_parameters)
            connection_parameters.pop("password")
            msg = "set_connection_parameters() - changed connection parameters {0}".format(connection_parameters)
            self.connection.queue_message("vvvv", msg)

    def _verify_response(self, response, method, path, data):
        """Process the return code and response object from MSO"""
        response_data = None
        response_code = -1
        self.info.update(dict(url=path))
        if data is not None:
            response_data = self._response_to_json(data)
        if response is not None:
            response_code = response.getcode()
            path = response.geturl()
            self.info.update(self._get_formated_info(response))

            # Handle possible MSO error information
            if response_code not in [200, 201, 202, 204]:
                self.error = dict(code=self.status, message=response_data)

        self.info["method"] = method
        if self.error is not None:
            self.info["error"] = self.error

        self.info["body"] = response_data

        return self.info

    def _response_to_json(self, response_data):
        """Convert response_data to json format"""
        try:
            response_value = response_data.getvalue()
        except Exception:
            response_value = response_data
        response_text = to_text(response_value)
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except Exception as e:
            # Expose RAW output for troubleshooting
            self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
            self.info["raw"] = response_text
            return

    def _get_login_domain_id(self, domain_name):
        """Get a domain and return its id"""
        if domain_name is None:
            return None

        method = "GET"
        path = "/mso/api/v1/auth/login-domains"
        full_path = self.connection.get_option("host") + path

        # TODO: Replace response by -
        response, data = self.connection.send(path, None, method=method, headers=self.headers)

        if data is not None:
            response_data = self._response_to_json(data)
            domains = response_data.get("domains")
            if domains is not None:
                for domain in domains:
                    if domain.get("name") == domain_name:
                        if "id" in domain:
                            return domain.get("id")
                        else:
                            self.error = dict(code=-1, message="Login domain lookup failed for domain '{0}': {1}".format(domain_name, domain))
                            raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))
                self.error = dict(code=-1, message="Login domain '{0}' is not a valid domain name.".format(domain_name))
                raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))
            else:
                self.error = dict(code=-1, message="Key 'domains' missing from data")
                raise ConnectionError(json.dumps(self._verify_response(None, method, full_path, None)))

    def _get_formated_info(self, response):
        """The code in this function is based out of Ansible fetch_url code
        at https://github.com/ansible/ansible/blob/devel/lib/ansible/module_utils/urls.py"""
        info = dict(msg="OK (%s bytes)" % response.headers.get("Content-Length", "unknown"), url=response.geturl(), status=response.getcode())
        # Lowercase keys, to conform to py2 behavior, so that py3 and py2 are predictable
        info.update(dict((k.lower(), v) for k, v in response.info().items()))

        # Don't be lossy, append header values for duplicate headers
        # In Py2 there is nothing that needs done, py2 does this for us
        if PY3:
            temp_headers = {}
            for name, value in response.headers.items():
                # The same as above, lower case keys to match py2 behavior, and create more consistent results
                name = name.lower()
                if name in temp_headers:
                    temp_headers[name] = ", ".join((temp_headers[name], value))
                else:
                    temp_headers[name] = value
            info.update(temp_headers)
        return info
