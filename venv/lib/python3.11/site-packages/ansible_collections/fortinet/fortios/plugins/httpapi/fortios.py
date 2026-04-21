# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: fortios
short_description: HttpApi Plugin for Fortinet FortiOS Appliance or VM
description:
  - This HttpApi plugin provides methods to connect to Fortinet FortiOS Appliance or VM via REST API
author:
  - Miguel Angel Munoz (@magonzalez)
version_added: "2.0.0"
"""

import json
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.basic import to_text
from ansible.module_utils.six.moves import urllib
import re

# import requests
from datetime import datetime


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)

        self._conn = connection
        self._system_version = None
        self._ansible_fos_version = "v6.0.0"
        self._ansible_galaxy_version = "2.4.2"
        self._log = None
        self._logged_in = False
        self._api_login = False
        self._session_key = None
        self._cookie = None
        self._ccsrf_token = None

    def set_custom_option(self, k, v):
        # _options is defined at https://github.com/ansible/ansible/blob/devel/lib/ansible/plugins/__init__.py#L60
        # seems to be an ansible bug that the value can be defined in the doc above but not set/get
        self._options[k] = v

    def log(self, msg):
        log_enabled = self._options.get("enable_log", False)
        if not log_enabled:
            return
        if not self._log:
            self._log = open("/tmp/fortios.ansible.log", "w")
            self._log.write("All set options:")
            self._log.write(str(self.get_options()) + "\n")
        log_message = str(datetime.now())
        log_message += ": " + str(msg) + "\n"
        self._log.write(log_message)
        self._log.flush()

    def get_access_token(self):
        """get pre issued access token for API access or session_key from API based authentication."""
        # token = self._options.get('access_token') if 'access_token' in self._options else None
        token = self._options.get("access_token", None)
        if token:
            return token

        # Read from session_key as dict in ausible host files, e.g: ansible_httpapi_session_key={"access_token":"XXX"}
        if self._conn.get_option("session_key"):
            token_from_session = self._conn.get_option("session_key").get(
                "access_token", None
            )
            if token_from_session:
                return token_from_session

        return self._session_key

    def set_become(self, become_context):
        """
        Elevation is not required on Fortinet devices - Skipped
        :param become_context: Unused input.
        :return: None
        """
        return None

    def login(self, username, password):
        """Call a defined login endpoint to receive an authentication token.
        try API based authentication first and fall back to web based auth."""

        if self._logged_in:
            self.log("Already logged in, skipping")
            return

        if (username is None or password is None) and self.get_access_token() is None:
            raise Exception("Please provide access token or username/password to login")

        if self.get_access_token() is not None:
            self.log("login with access token")
            self._logged_in = True
            self.send_request(url="/logincheck")
            status, dummy = self.send_request(url="/api/v2/monitor/system/status")

            if status == 401:
                raise Exception("Invalid access token. Please check")

            self.log("login with access token succeeded")
            return

        self.log("login with username and password, try API based auth first")
        auth_payload = {
            "username": username,
            "secretkey": str(password),
            "password": str(password),
            "ack_post_disclaimer": True,
            "ack_pre_disclaimer": True,
            "request_key": True,
        }
        status_code, result_data = self.send_request(
            url="/api/v2/authentication",
            should_pre_login=False,
            data=json.dumps(auth_payload),
            method="POST",
        )
        self.log(
            "API based auth returned status code %s, data: %s"
            % (status_code, result_data)
        )
        if status_code in [401, 404]:
            self.log("API based auth login attempt failed, fall back to /logincheck")
            data = (
                "username="
                + urllib.parse.quote(username)
                + "&secretkey="
                + urllib.parse.quote(password)
                + "&ajax=1"
            )
            dummy, result_data = self.send_request(
                url="/logincheck", should_pre_login=False, data=data, method="POST"
            )
            self.log(
                "/logincheck with user: %s %s"
                % (username, "succeeds" if result_data[0] == "1" else "fails")
            )
            if result_data[0] != "1":
                raise Exception("Wrong credentials. Please check")
            self._logged_in = True
        else:
            self.log(
                "API based auth with user: %s %s"
                % (username, "succeeds" if "LOGIN_SUCCESS" in result_data else "fails")
            )
            if "LOGIN_SUCCESS" not in result_data:
                raise Exception(
                    "API based auth failed: wrong credentials. Please check"
                )
            self._logged_in = True
            self._api_login = True
            try:
                json_result_data = json.loads(result_data)
                self._session_key = json_result_data["session_key"]
            except Exception:
                # some older fortios version may pass session key through cookies
                self.log(
                    "no session_key obtained from response body, fallback to parse headers, data %s"
                    % (result_data)
                )
                # pass

        self.update_system_version()

    def logout(self):
        """Call to implement session logout."""

        if self._api_login:
            self.log("logout with API based auth")
            self.send_request(url="/api/v2/authentication", method="DELETE")
        else:
            self.send_request(url="/logout", method="POST")
            self.log("logout with basic based auth")

    def update_auth(self, response, response_text):
        """
        Get cookies and obtain value for csrftoken/session_key that will be used on next requests
        :param response: Response given by the server.
        :param response_text Unused_input.
        :return: Dictionary containing headers
        """
        headers = {
            "Accept": "application/json",
        }

        access_token = self.get_access_token()
        if access_token is not None:
            self.log("using access token - no auth update needed: %s" % access_token)
            headers["Authorization"] = "Bearer " + access_token
            return headers
        if self._cookie or self._ccsrf_token:
            self.log(
                "using existing cookie: %s; ccsrf_token %s"
                % (self._cookie, self._ccsrf_token)
            )
            headers["Cookie"] = self._cookie
            headers["x-csrftoken"] = self._ccsrf_token
            return headers

        # cookies = response.raw.headers.get_all("Set-Cookie")
        # self.log('all cookies returned from server: %s' % to_text(cookies))
        raw_cookies = []
        cookie_dict = {}
        for attr, val in response.getheaders():
            if attr.lower() == "set-cookie" and "APSCOOKIE_" in val:
                headers["Cookie"] = val
            elif attr.lower() == "set-cookie" and "session_key" in val:
                session_key = re.search(r"_(\d+=\".*\")", val)
                if session_key:
                    cookie_dict["session_key"] = session_key.group(1)
                    # self.log("found session_key in cookie: %s" % session_key.group(1))
                    # self._session_key = session_key.group(1)
                else:
                    raw_cookies.append(val.split(";")[0])
            elif attr.lower() == "set-cookie" and (
                "ccsrftoken" in val or "ccsrf_token" in val
            ):
                csrftoken_search = re.search("(.*)", val)
                self.log(
                    "csrftoken returned from server: %s, filtered %s"
                    % (
                        to_text(val),
                        to_text(csrftoken_search.group(1) if csrftoken_search else ""),
                    )
                )
                if csrftoken_search:
                    token = val.split(";")[0].split("=")[1]
                    # headers['x-csrftoken'] = csrftoken_search.group(1)
                    # self._ccsrf_token = csrftoken_search.group(1)
                    headers["x-csrftoken"] = token
                    self._ccsrf_token = token
            elif attr.lower() == "set-cookie" and "ccsrf_token" in val:
                token = val.split(";")[0].split("=")[1]
                headers["x-csrftoken"] = token
                self._ccsrf_token = token
            elif attr.lower() == "set-cookie":
                self.log(
                    "other raw cookie returned from server: %s"
                    % to_text(val.split(";")[0])
                )
                raw_cookies.append(val.split(";")[0])

        if len(cookie_dict) > 0:
            cookie = ""
            for key, value in cookie_dict.items():
                cookie += key + "_" + value + "; "
            if "Cookie" in headers:
                cookie += "; " + headers["Cookie"]
            headers["Cookie"] = cookie
            self._cookie = cookie
            self.log("Updated Cookie: %s" % (self._cookie))

        if len(raw_cookies) > 0:
            raw_cookie = "; ".join(raw_cookies)
            if "Cookie" in headers:
                raw_cookie += "; " + headers["Cookie"]
            headers["Cookie"] = raw_cookie
            self._cookie = headers["Cookie"]
            self.log("Added raw Cookie: %s" % (self._cookie))

        self.log("updated auth headers: %s" % (headers.items()))
        return headers

    def handle_httperror(self, exc):
        """
        propogate exceptions to users
        :param exc: Exception
        """
        self.log("Exception thrown from handling http: " + to_text(exc))

        return exc

    def _concat_token(self, url):
        if self.get_access_token():
            token_pair = "access_token=" + self.get_access_token()
            return url + "&" + token_pair if "?" in url else url + "?" + token_pair
        return url

    def _concat_params(self, url, params):
        if not params or not len(params):
            return url
        url = url + "?" if "?" not in url else url
        for param_key in params:
            param_value = params[param_key]
            if url[-1] == "?":
                url += "%s=%s" % (param_key, param_value)
            else:
                url += "&%s=%s" % (param_key, param_value)
        return url

    def send_request(self, **message_kwargs):
        """
        Responsible for actual sending of data to the connection httpapi base plugin.
        :param should_pre_login: should perform login in place instead of having connection obj to trigger.
            this is required because for httpapi update_auth can only update headers but /api/v2/authentication
            returns sessio_key in resp body.
        :param message_kwargs: A formatted dictionary containing request info: url, data, method

        :return: Status code and response data.
        """
        if not self._logged_in and message_kwargs.get("should_pre_login", True):
            self.log("perform pre request login")
            # trigger automated login call by httpapi
            self.connection.send("/api/v2/monitor/system/status", data={}, method="GET")

        url = message_kwargs.get("url", "/")
        data = message_kwargs.get("data", "")
        method = message_kwargs.get("method", "GET")
        params = message_kwargs.get("params", {})
        headers = message_kwargs.get("headers", {})

        if self.get_access_token() is not None:
            # url = self._concat_token(message_kwargs.get("url", "/"))
            headers["Authorization"] = f"Bearer {self.get_access_token()}"

        url = self._concat_params(url, params)
        self.log(
            "Sending request: METHOD:%s URL:%s DATA:%s HEADERS:%s"
            % (method, url, data, headers)
        )
        # import epdb; epdb.serve()

        try:
            response, response_data = self.connection.send(
                url, data, method=method, headers=headers
            )

            json_formatted = to_text(response_data.getvalue())

            self.log(
                "response status: %s, data: %s...<truncated>"
                % (to_text(response.status), json_formatted[:200])
            )

            return response.status, json_formatted
        except Exception as err:
            raise Exception("Error in send_request", err)

    def update_system_version(self):
        """
        retrieve the system status of fortigate device
        """
        self.log("checking system_version")
        check_system_status = self._options.get("check_system_status", True)
        if not check_system_status or self._system_version:
            return
        url = "/api/v2/monitor/system/status"
        status, result = self.send_request(url=url)
        self.log("system status returned status code %s, data: %s" % (status, result))
        result_json = json.loads(result)
        self._system_version = result_json.get("version", "undefined")
        self.log("system version: %s" % (self._system_version))
        self.log("ansible version: %s" % (self._ansible_fos_version))

    def get_system_version(self):
        self.update_system_version()
        self.log("returning system version: %s" % (self._system_version))
        return self._system_version
