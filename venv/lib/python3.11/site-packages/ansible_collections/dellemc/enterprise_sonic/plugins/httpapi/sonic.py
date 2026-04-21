# (c) 2019 Red Hat Inc.
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

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
---
name: sonic
short_description: HttpApi Plugin for devices supporting Restconf SONIC API
description:
  - This HttpApi plugin provides methods to connect to Restconf SONIC API endpoints.
version_added: 1.0.0
options:
  root_path:
    type: str
    description:
      - Specifies the location of the Restconf root.
    default: '/restconf'
    vars:
      - name: ansible_httpapi_restconf_root
"""

import json
import time
import re

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.plugins.httpapi import HttpApiBase
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list

CONTENT_TYPE = 'application/yang-data+json'


class HttpApi(HttpApiBase):
    def send_request(self, data, **message_kwargs):
        if data:
            data = json.dumps(data)

        path = '/'.join([self.get_option('root_path').rstrip('/'), message_kwargs.get('path', '').lstrip('/')])

        headers = {
            'Content-Type': message_kwargs.get('content_type') or CONTENT_TYPE,
            'Accept': message_kwargs.get('accept') or CONTENT_TYPE,
        }
        response, response_data = self.connection.send(path, data, headers=headers, method=message_kwargs.get('method'))

        return handle_response(response, response_data, message_kwargs)

    def get(self, command):
        return self.send_request(path=command, data=None, method='get')

    def edit_config(self, requests, suppr_ntf_excp=True):
        """Send a list of http requests to remote device and return results
        """
        if requests is None:
            raise ValueError("'requests' value is required")

        responses = list()
        for req in to_list(requests):
            try:
                response = self.send_request(**req)
            except ConnectionError as exc:
                if suppr_ntf_excp and req.get('method') == 'get' and re.search("[nN]ot [fF]ound.*code': 404", str(exc)):
                    # 'code': 404, 'error-message': 'Resource not found'
                    response = [{}, {}]
                else:
                    raise ConnectionError(to_text(exc, errors='surrogate_then_replace'))
            responses.append(response)
        return responses

    def edit_config_reboot(self, requests):
        """Send a list of http requests to remote device and allow time for reboot
        """
        if requests is None:
            raise ValueError("'requests' value is required")

        for req in to_list(requests):
            try:
                response = self.send_request(**req)
            except Exception as exc:
                if 'command timeout triggered' not in str(exc):
                    raise Exception(to_text(exc, errors='surrogate_then_replace'))
                else:
                    time.sleep(300)

    def get_capabilities(self):
        result = {}
        result['rpc'] = []
        result['network_api'] = 'sonic_rest'

        return json.dumps(result)


def handle_response(response, response_data, request_data):
    response_data = response_data.read()
    try:
        if not response_data:
            response_data = ""
        else:
            response_data = json.loads(response_data.decode('utf-8'))
    except ValueError:
        pass

    if isinstance(response, HTTPError):
        if response_data:
            if 'errors' in response_data:
                errors = response_data['errors']['error']
                error_text = '\n'.join((error['error-message'] for error in errors))
            else:
                error_text = response_data
            error_text.update({u'code': response.code})
            error_text.update({u'request_data': request_data})
            raise ConnectionError(error_text, code=response.code)
        raise ConnectionError(to_text(response), code=response.code)
    return response.getcode(), response_data
