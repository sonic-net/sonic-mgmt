# Copyright (c) 2020 Cisco and/or its affiliates.
# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: aci
author:
- Shreyas Srish (@shrsr)
short_description: Ansible ACI HTTPAPI Plugin.
description:
  - This ACI plugin provides the HTTPAPI methods needed to initiate
    a connection to the APIC, send API requests and process the
    response from the controller.
"""

import ast
import base64
import json
import os
import re

from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase
from copy import copy, deepcopy

# Optional, only used for APIC signature-based authentication
try:
    from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign

    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

# Signature-based authentication using cryptography
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

CONNECTION_MAP = {"username": "remote_user", "timeout": "persistent_command_timeout"}
RESET_KEYS = ["username", "password", "port"]
CONNECTION_KEYS = RESET_KEYS + ["timeout", "use_proxy", "use_ssl", "validate_certs"]


class HttpApi(HttpApiBase):
    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.params = None
        self.result = {}
        self.backup_hosts = None
        self.connection_error_check = False
        self.connection_parameters = {}
        self.current_host = None
        self.provided_hosts = None
        self.inventory_hosts = None

    def set_params(self, params):
        self.params = params

    # Login function is executed until connection to a host is established or until all the hosts in the list are exhausted
    def login(self, username, password):
        """Log in to APIC"""
        # Perform login request
        self.connection.queue_message("debug", "Establishing login for {0} to {1}".format(username, self.connection.get_option("host")))
        method = "POST"
        path = "/api/aaaLogin.json"
        payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
        data = json.dumps(payload)
        self.connection._connected = True
        try:
            response, response_data = self.connection.send(path, data, method=method)
            self.connection._auth = {"Cookie": response.headers.get("Set-Cookie")}
            self.connection.queue_message("debug", "Connection to {0} was successful".format(self.connection.get_option("host")))
        except Exception as exc_login:
            self.connection._connected = False
            exc_login.path = path
            raise

    def set_parameters(self):
        connection_parameters = {}
        for key in CONNECTION_KEYS:
            value = self.params.get(key) if self.params.get(key) is not None else self.connection.get_option(CONNECTION_MAP.get(key, key))
            if key == "username" and value is None:
                value = "admin"
            self.connection.set_option(CONNECTION_MAP.get(key, key), value)
            if key == "timeout" and self.connection.get_option("persistent_connect_timeout") <= value:
                self.connection.set_option("persistent_connect_timeout", value + 30)

            connection_parameters[key] = value
            if self.connection_parameters and value != self.connection_parameters.get(key) and key in RESET_KEYS:
                self.connection._connected = False
                self.connection.queue_message("debug", "Re-setting connection due to change in the {0}".format(key))

        if self.params.get("private_key") is not None:
            self.connection.set_option("session_key", None)
            connection_parameters["certificate_name"] = self.params.get("certificate_name")
            connection_parameters["private_key"] = self.params.get("private_key")
        elif self.connection.get_option("session_key") is not None and self.params.get("password") is None:
            connection_parameters["certificate_name"] = list(self.connection.get_option("session_key").keys())[0]
            connection_parameters["private_key"] = list(self.connection.get_option("session_key").values())[0]
        else:
            if self.connection_parameters.get("private_key") is not None:
                self.connection._connected = False
                self.connection.queue_message(
                    "debug", "Re-setting connection due to change from private/session key authentication to password authentication"
                )
            self.connection.set_option("session_key", None)
            connection_parameters["private_key"] = None
            connection_parameters["certificate_name"] = None

        if self.connection_parameters != connection_parameters:
            self.connection_parameters = copy(connection_parameters)

        self.set_hosts()

    def set_hosts(self):
        if self.params.get("host") is not None:
            hosts = ast.literal_eval(self.params.get("host")) if "[" in self.params.get("host") else self.params.get("host").split(",")
        else:
            if self.inventory_hosts is None:
                self.inventory_hosts = re.sub(r"[[\]]", "", self.connection.get_option("host")).split(",")
            hosts = self.inventory_hosts

        if self.provided_hosts is None:
            self.provided_hosts = deepcopy(hosts)
            self.connection.queue_message("debug", "Provided Hosts: {0}".format(self.provided_hosts))
            self.backup_hosts = deepcopy(hosts)
            self.current_host = self.backup_hosts.pop(0)
            self.connection.queue_message("debug", "Initializing operation on {0}".format(self.current_host))
        elif self.provided_hosts != hosts:
            self.provided_hosts = deepcopy(hosts)
            self.connection.queue_message("debug", "Provided Hosts have changed: {0}".format(self.provided_hosts))
            self.backup_hosts = deepcopy(hosts)
            try:
                self.backup_hosts.pop(self.backup_hosts.index(self.current_host))
                self.connection.queue_message("debug", "Connected host {0} found in the provided hosts. Continuing with it.".format(self.current_host))
            except Exception:
                self.current_host = self.backup_hosts.pop(0)
                self.connection._connected = False
                self.connection.queue_message("debug", "Initializing operation on {0}".format(self.current_host))
        self.connection.set_option("host", self.current_host)

    # One API call is made via each call to send_request from aci.py in module_utils
    # As long as a host is active in the list the API call will go through
    def send_request(self, method, path, data):
        """This method handles all APIC REST API requests other than login"""

        self.set_parameters()

        if self.connection_parameters.get("private_key") is not None:
            try:
                self.connection._auth = {"Cookie": "{0}".format(self.cert_auth(method, path, data).get("Cookie"))}
                self.connection._connected = True
            except Exception as exc_response:
                self.connection._connected = False
                return self._return_info("", method, self.validate_url(self.connection._url + path), str(exc_response))

        try:
            if self.connection._connected is False:
                self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))
            self.connection.queue_message("debug", "Sending {0} request to {1}".format(method, self.connection._url + path))
            response, response_data = self.connection.send(path, data, method=method)
            self.connection.queue_message(
                "debug", "Received response from {0} for {1} operation with HTTP: {2}".format(self.connection.get_option("host"), method, response.getcode())
            )
        except Exception as exc_response:
            self.connection.queue_message("debug", "Connection to {0} has failed: {1}".format(self.connection.get_option("host"), exc_response))
            if len(self.backup_hosts) == 0:
                self.provided_hosts = None
                self.connection._connected = False
                error = dict(
                    code=-1, text="No hosts left in the cluster to continue operation! Error on final host {0}".format(self.connection.get_option("host"))
                )
                if "path" in dir(exc_response):
                    path = exc_response.path
                return self._return_info("", method, self.validate_url(self.connection._url + path), str(exc_response), error=error)
            else:
                self.current_host = self.backup_hosts.pop(0)
                self.connection.queue_message("debug", "Switching host from {0} to {1}".format(self.connection.get_option("host"), self.current_host))
                self.connection.set_option("host", self.current_host)
            # recurse through function for retrying the request
            return self.send_request(method, path, data)
        # return statement executed upon each successful response from the request function
        return self._verify_response(response, method, path, response_data)

    # Built-in-function
    def handle_httperror(self, exc):
        self.connection.queue_message("debug", "Failed to receive response from {0} with {1}".format(self.connection.get_option("host"), exc))
        if exc.code == 401:
            raise ConnectionError(exc)
        elif exc.code == 403 and self.connection_parameters.get("private_key") is None:
            self.connection._auth = None
            self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))
            return True
        return exc

    def validate_url(self, url):
        validated_url = re.match(r"^.*?\.json|^.*?\.xml", url).group(0)
        if self.connection_parameters.get("port") is None:
            return validated_url.replace(re.match(r"(https?:\/\/.*)(:\d*)\/?(.*)", url).group(2), "")
        else:
            return validated_url

    def _verify_response(self, response, method, path, response_data):
        """Process the return code and response object from APIC"""
        response_value = self._get_response_value(response_data)
        response_code = response.getcode()
        path = self.validate_url(response.url)
        # Response check to remain consistent with fetch_url's response
        if str(response) == "HTTP Error 400: Bad Request":
            msg = "{0}".format(response)
        else:
            msg = "{0} ({1} bytes)".format(response.msg, len(response_value))
        return self._return_info(response_code, method, path, msg, respond_data=response_value)

    def _get_response_value(self, response_data):
        """Extract string data from response_data returned from APIC"""
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        """Convert response_text to json format"""
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except Exception:
            return "Invalid JSON response: {0}".format(response_text)

    def _return_info(self, response_code, method, path, msg, respond_data=None, error=None):
        """Format success/error data and return with consistent format"""
        info = {}
        info["status"] = response_code
        info["method"] = method
        info["url"] = path
        info["msg"] = msg
        if error is not None:
            info["error"] = error
        else:
            info["error"] = {}
        # Response check to trigger key error if response_data is invalid
        if respond_data is not None:
            info["body"] = respond_data
        return info

    def cert_auth(self, method, path, payload=""):
        """Perform APIC signature-based authentication, not the expected SSL client certificate authentication."""

        if payload is None:
            payload = ""

        headers = dict()

        try:
            if HAS_CRYPTOGRAPHY:
                key = self.connection_parameters.get("private_key").encode()
                sig_key = serialization.load_pem_private_key(
                    key,
                    password=None,
                    backend=default_backend(),
                )
            else:
                sig_key = load_privatekey(FILETYPE_PEM, self.connection_parameters.get("private_key"))
        except Exception:
            private_key_file_path = os.path.abspath(os.path.join(self.params.get("working_directory"), self.connection_parameters.get("private_key")))
            if os.path.exists(private_key_file_path):
                try:
                    permission = "r"
                    if HAS_CRYPTOGRAPHY:
                        permission = "rb"
                    with open(private_key_file_path, permission) as fh:
                        private_key_content = fh.read()
                except Exception:
                    raise ConnectionError("Cannot open private key file {0}".format(private_key_file_path))
                try:
                    if HAS_CRYPTOGRAPHY:
                        sig_key = serialization.load_pem_private_key(private_key_content, password=None, backend=default_backend())
                    else:
                        sig_key = load_privatekey(FILETYPE_PEM, private_key_content)
                except Exception:
                    raise ConnectionError("Cannot load private key file {0}".format(self.connection_parameters.get("private_key")))
                if self.connection_parameters.get("certificate_name") is None:
                    self.connection_parameters["certificate_name"] = os.path.basename(os.path.splitext(self.connection_parameters.get("private_key"))[0])
            else:
                raise ConnectionError(
                    "Provided private key {0} does not appear to be a private key or provided file does not exist.".format(private_key_file_path)
                )
        if self.connection_parameters.get("certificate_name") is None:
            self.connection_parameters["certificate_name"] = self.connection.get_option("remote_user")
        sig_request = method + path + payload
        if HAS_CRYPTOGRAPHY:
            sig_signature = sig_key.sign(sig_request.encode(), padding.PKCS1v15(), hashes.SHA256())
        else:
            sig_signature = sign(sig_key, sig_request, "sha256")
        sig_dn = "uni/userext/user-{0}/usercert-{1}".format(self.connection.get_option("remote_user"), self.connection_parameters.get("certificate_name"))
        headers["Cookie"] = (
            "APIC-Certificate-Algorithm=v1.0; "
            + "APIC-Certificate-DN={0}; ".format(sig_dn)
            + "APIC-Certificate-Fingerprint=fingerprint; "
            + "APIC-Request-Signature={0}".format(to_native(base64.b64encode(sig_signature)))
        )
        return headers
