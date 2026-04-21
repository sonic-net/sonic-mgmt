# Copyright (c) 2025 Markus Bergholz
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import json

from ansible.module_utils.urls import Request
from ansible_collections.community.dns.plugins.module_utils.argspec import ArgumentSpec


try:
    from urllib.error import HTTPError
except ImportError:
    # Python 2.x fallback:
    from urllib2 import HTTPError  # type: ignore


def create_adguardhome_argument_spec(required_if=None, additional_argument_specs=None):
    argument_spec = {
        'username': {'type': 'str', 'required': True},
        'password': {'type': 'str', 'required': True, 'no_log': True},
        'host': {'type': 'str', 'required': True},
        'validate_certs': {'type': 'bool', 'default': True},
    }

    if additional_argument_specs:
        argument_spec.update(additional_argument_specs)

    return ArgumentSpec(
        required_if=required_if,
        argument_spec=argument_spec
    )


class AdGuardHomeAPIHandler:
    def __init__(self, params, fail_json):
        host = params.get('host')
        self.url = host + "/control/rewrite"

        self.validate_certs = params.get('validate_certs')
        self.fail_json = fail_json
        self.r = Request(
            validate_certs=params.get('validate_certs'),
            url_username=params.get('username'),
            url_password=params.get('password'),
            force_basic_auth=True,
            headers={"Content-Type": "application/json"}
        )

    def list(self):
        try:
            response = self.r.open(
                'GET',
                self.url + "/list"
            )

            return json.loads(response.read().decode('utf-8'))

        except HTTPError as e:
            self.fail_json(msg=e.read())

    def add_or_delete(self, domain, answer, method, target):
        """
        the delete api requires the matching answer value.
        but because we make the answer value optional, it's
        taken from previous `find_and_compare` function.
        """
        if method == "add":
            answer_value = answer
        else:
            answer_value = target["answer"] if answer is None else answer

        data = json.dumps({
            "domain": domain,
            "answer": answer_value
        }).encode('utf-8')
        try:
            self.r.open(
                'POST',
                self.url + "/" + method,
                data=data,
            )
            return True

        except HTTPError as e:
            self.fail_json(msg=e.read())

    def update(self, domain, answer, target):
        data = json.dumps({
            "target": target,
            "update": {
                "domain": domain,
                "answer": answer
            }
        }).encode('utf-8')
        try:
            self.r.open(
                "PUT",
                self.url + "/update",
                data=data,
            )
            return True

        except HTTPError as e:
            self.fail_json(msg=e.read())
