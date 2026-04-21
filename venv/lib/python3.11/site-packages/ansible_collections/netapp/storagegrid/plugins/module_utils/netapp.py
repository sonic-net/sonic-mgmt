# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2020, NetApp Ansible Team <ng-ansibleteam@netapp.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import missing_required_lib

COLLECTION_VERSION = "21.15.0"

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


POW2_BYTE_MAP = dict(
    # Here, 1 kb = 1024
    bytes=1,
    b=1,
    kb=1024,
    mb=1024**2,
    gb=1024**3,
    tb=1024**4,
    pb=1024**5,
    eb=1024**6,
    zb=1024**7,
    yb=1024**8,
)


def na_storagegrid_host_argument_spec():
    return dict(
        api_url=dict(required=True, type="str"),
        validate_certs=dict(required=False, type="bool", default=True),
        auth_token=dict(required=True, type="str", no_log=True),
    )


class SGRestAPI(object):
    def __init__(self, module, timeout=60):
        self.module = module
        self.auth_token = self.module.params["auth_token"]
        self.api_url = self.module.params["api_url"]
        self.verify = self.module.params["validate_certs"]
        self.timeout = timeout
        self.check_required_library()
        self.sg_version = dict(major=-1, minor=-1, full="", valid=False)

    def check_required_library(self):
        if not HAS_REQUESTS:
            self.module.fail_json(msg=missing_required_lib("requests"))

    def send_request(self, method, api, params=None, json=None, files=None):
        """send http request and process reponse, including error conditions"""
        url = "%s/%s" % (self.api_url, api)
        status_code = None
        content = None
        json_dict = None
        json_error = None
        error_details = None
        headers = {
            "Authorization": "Bearer {}".format(self.auth_token),
            "Cache-Control": "no-cache",
        }

        def get_json(response):
            """extract json, and error message if present"""
            try:
                json = response.json()

            except ValueError:
                return None, None
            success_code = [200, 201, 202, 204]
            if response.status_code not in success_code:
                error = json.get("message")
            else:
                error = None
            return json, error

        try:
            if files:
                headers["Content-Type"] = "multipart/form-data"
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    json=json,
                    files=files,
                    verify=self.verify,
                    params=params,
                )
            else:
                headers["Content-Type"] = "application/json"
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    json=json,
                    verify=self.verify,
                    params=params,
                )

            # check if response is binary file
            content_type = response.headers.get("content-type", "").lower()
            if "application/zip" in content_type or "octet-stream" in content_type:
                return response.content, None

            # If the response was successful, no Exception will be raised
            # Add status_code to the json_dict
            json_dict, json_error = get_json(response)
            if json_dict is None:
                json_dict = {}
            json_dict["status_code"] = response.status_code
        except requests.exceptions.HTTPError as err:
            __, json_error = get_json(response)
            if json_error is None:
                error_details = str(err)
        except requests.exceptions.ConnectionError as err:
            error_details = str(err)
        except Exception as err:
            error_details = str(err)
        if json_error is not None:
            error_details = json_error

        return json_dict, error_details

    # If an error was reported in the json payload, it is handled below
    def get(self, api, params=None):
        method = "GET"
        return self.send_request(method, api, params)

    def post(self, api, data=None, params=None, files=None):
        method = "POST"
        return self.send_request(method, api, params, json=data, files=files)

    def patch(self, api, data, params=None):
        method = "PATCH"
        return self.send_request(method, api, params, json=data)

    def put(self, api, data, params=None):
        method = "PUT"
        return self.send_request(method, api, params, json=data)

    def delete(self, api, data, params=None):
        method = "DELETE"
        return self.send_request(method, api, params, json=data)

    def get_sg_product_version(self, api_root="grid"):
        method = "GET"
        api = "api/v3/%s/config/product-version" % api_root
        message, error = self.send_request(method, api, params={})
        if error:
            self.module.fail_json(msg=error)
        self.set_version(message)

    def set_version(self, message):
        try:
            product_version = message.get("data", "not found").get("productVersion", "not_found")
        except AttributeError:
            self.sg_version["valid"] = False
            return

        self.sg_version["major"], self.sg_version["minor"] = list(map(int, product_version.split(".")[0:2]))
        self.sg_version["full"] = product_version
        self.sg_version["valid"] = True

    def get_sg_version(self):
        if self.sg_version["valid"]:
            return self.sg_version["major"], self.sg_version["minor"]
        return -1, -1

    def meets_sg_minimum_version(self, minimum_major, minimum_minor):
        return self.get_sg_version() >= (minimum_major, minimum_minor)

    def requires_sg_version(self, module_or_option, version):
        return "%s requires StorageGRID %s or later." % (module_or_option, version)

    def fail_if_not_sg_minimum_version(self, module_or_option, minimum_major, minimum_minor):
        version = self.get_sg_version()
        if version < (minimum_major, minimum_minor):
            msg = "Error: " + self.requires_sg_version(module_or_option, "%d.%d" % (minimum_major, minimum_minor))
            msg += "  Found: %s.%s." % version
            self.module.fail_json(msg=msg)
