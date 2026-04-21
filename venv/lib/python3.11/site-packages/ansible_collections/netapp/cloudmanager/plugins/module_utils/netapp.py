# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2017-2021, NetApp Ansible Team <ng-ansibleteam@netapp.com>
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

"""
netapp.py: wrapper around send_requests and other utilities
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import logging
import time
from ansible.module_utils.basic import missing_required_lib

try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'

COLLECTION_VERSION = "21.24.0"
PROD_ENVIRONMENT = {
    'CLOUD_MANAGER_HOST': 'cloudmanager.cloud.netapp.com',
    'AUTH0_DOMAIN': 'netapp-cloud-account.auth0.com',
    'SA_AUTH_HOST': 'cloudmanager.cloud.netapp.com/auth/oauth/token',
    'AUTH0_CLIENT': 'Mu0V1ywgYteI6w1MbD15fKfVIUrNXGWC',
    'AMI_FILTER': 'Setup-As-Service-AMI-Prod*',
    'AWS_ACCOUNT': '952013314444',
    'GCP_IMAGE_PROJECT': 'netapp-cloudmanager',
    'GCP_IMAGE_FAMILY': 'cloudmanager',
    'CVS_HOST_NAME': 'https://api.services.cloud.netapp.com'
}
STAGE_ENVIRONMENT = {
    'CLOUD_MANAGER_HOST': 'staging.cloudmanager.cloud.netapp.com',
    'AUTH0_DOMAIN': 'staging-netapp-cloud-account.auth0.com',
    'SA_AUTH_HOST': 'staging.cloudmanager.cloud.netapp.com/auth/oauth/token',
    'AUTH0_CLIENT': 'O6AHa7kedZfzHaxN80dnrIcuPBGEUvEv',
    'AMI_FILTER': 'Setup-As-Service-AMI-*',
    'AWS_ACCOUNT': '282316784512',
    'GCP_IMAGE_PROJECT': 'tlv-automation',
    'GCP_IMAGE_FAMILY': 'occm-automation',
    'CVS_HOST_NAME': 'https://staging.api.services.cloud.netapp.com'
}

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
    mb=1024 ** 2,
    gb=1024 ** 3,
    tb=1024 ** 4,
    pb=1024 ** 5,
    eb=1024 ** 6,
    zb=1024 ** 7,
    yb=1024 ** 8
)


LOG = logging.getLogger(__name__)
LOG_FILE = '/tmp/cloudmanager_apis.log'


def cloudmanager_host_argument_spec():

    return dict(
        refresh_token=dict(required=False, type='str', no_log=True),
        sa_client_id=dict(required=False, type='str', no_log=True),
        sa_secret_key=dict(required=False, type='str', no_log=True),
        environment=dict(required=False, type='str', choices=['prod', 'stage'], default='prod'),
        feature_flags=dict(required=False, type='dict')
    )


def has_feature(module, feature_name):
    feature = get_feature(module, feature_name)
    if isinstance(feature, bool):
        return feature
    module.fail_json(msg="Error: expected bool type for feature flag: %s, found %s" % (feature_name, type(feature)))


def get_feature(module, feature_name):
    ''' if the user has configured the feature, use it
        otherwise, use our default
    '''
    default_flags = dict(
        trace_apis=False,                       # if True, append REST requests/responses to /tmp/cloudmanager_apis.log
        trace_headers=False,                    # if True, and if trace_apis is True, include <large> headers in trace
        show_modified=True,
        simulator=False,                        # if True, it is running on simulator
    )

    if module.params['feature_flags'] is not None and feature_name in module.params['feature_flags']:
        return module.params['feature_flags'][feature_name]
    if feature_name in default_flags:
        return default_flags[feature_name]
    module.fail_json(msg="Internal error: unexpected feature flag: %s" % feature_name)


class CloudManagerRestAPI(object):
    """ wrapper around send_request """
    def __init__(self, module, timeout=60):
        self.module = module
        self.timeout = timeout
        self.refresh_token = self.module.params['refresh_token']
        self.sa_client_id = self.module.params['sa_client_id']
        self.sa_secret_key = self.module.params['sa_secret_key']
        self.environment = self.module.params['environment']
        if self.environment == 'prod':
            self.environment_data = PROD_ENVIRONMENT
        elif self.environment == 'stage':
            self.environment_data = STAGE_ENVIRONMENT
        self.url = 'https://'
        self.api_root_path = None
        self.check_required_library()
        if has_feature(module, 'trace_apis'):
            logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')
        self.log_headers = has_feature(module, 'trace_headers')     # requires trace_apis to do anything
        self.simulator = has_feature(module, 'simulator')
        self.token_type, self.token = self.get_token()

    def check_required_library(self):
        if not HAS_REQUESTS:
            self.module.fail_json(msg=missing_required_lib('requests'))

    def format_client_id(self, client_id):
        return client_id if client_id.endswith('clients') else client_id + 'clients'

    def build_url(self, api):
        # most requests are sent to Cloud Manager, but for connectors we need to manage VM instances using AWS, Azure, or GCP APIs
        if api.startswith('http'):
            return api
        # add host if API starts with / and host is not already included in self.url
        prefix = self.environment_data['CLOUD_MANAGER_HOST'] if self.environment_data['CLOUD_MANAGER_HOST'] not in self.url and api.startswith('/') else ''
        return self.url + prefix + api

    def send_request(self, method, api, params, json=None, data=None, header=None, authorized=True):
        ''' send http request and process response, including error conditions '''
        url = self.build_url(api)
        headers = {
            'Content-type': "application/json",
            'Referer': "Ansible_NetApp",
        }
        if authorized:
            headers['Authorization'] = self.token_type + " " + self.token
        if header is not None:
            headers.update(header)
        for __ in range(3):
            json_dict, error_details, on_cloud_request_id = self._send_request(method, url, params, json, data, headers)
            # we observe this error with DELETE on agents-mgmt/agent (and sometimes on GET)
            if error_details is not None and 'Max retries exceeded with url:' in error_details:
                time.sleep(5)
            else:
                break
        return json_dict, error_details, on_cloud_request_id

    def _send_request(self, method, url, params, json, data, headers):
        json_dict = None
        json_error = None
        error_details = None
        on_cloud_request_id = None
        response = None
        status_code = None

        def get_json(response):
            ''' extract json, and error message if present '''
            error = None
            try:
                json = response.json()
            except ValueError:
                return None, None
            success_code = [200, 201, 202]
            if response.status_code not in success_code:
                error = json.get('message')
                self.log_error(response.status_code, 'HTTP error: %s' % error)
            return json, error

        self.log_request(method=method, url=url, params=params, json=json, data=data, headers=headers)
        try:
            response = requests.request(method, url, headers=headers, timeout=self.timeout, params=params, json=json, data=data)
            status_code = response.status_code
            if status_code >= 300 or status_code < 200:
                self.log_error(status_code, 'HTTP status code error: %s' % response.content)
                return response.content, str(status_code), on_cloud_request_id
            # If the response was successful, no Exception will be raised
            json_dict, json_error = get_json(response)
            if response.headers.get('OnCloud-Request-Id', '') != '':
                on_cloud_request_id = response.headers.get('OnCloud-Request-Id')
        except requests.exceptions.HTTPError as err:
            self.log_error(status_code, 'HTTP error: %s' % err)
            error_details = str(err)
        except requests.exceptions.ConnectionError as err:
            self.log_error(status_code, 'Connection error: %s' % err)
            error_details = str(err)
        except Exception as err:
            self.log_error(status_code, 'Other error: %s' % err)
            error_details = str(err)
        if json_error is not None:
            self.log_error(status_code, 'Endpoint error: %d: %s' % (status_code, json_error))
            error_details = json_error
        if response:
            self.log_debug(status_code, response.content)
        return json_dict, error_details, on_cloud_request_id

    # If an error was reported in the json payload, it is handled below
    def get(self, api, params=None, header=None):
        method = 'GET'
        return self.send_request(method=method, api=api, params=params, json=None, header=header)

    def post(self, api, data, params=None, header=None, gcp_type=False, authorized=True):
        method = 'POST'
        if gcp_type:
            return self.send_request(method=method, api=api, params=params, data=data, header=header)
        else:
            return self.send_request(method=method, api=api, params=params, json=data, header=header, authorized=authorized)

    def patch(self, api, data, params=None, header=None):
        method = 'PATCH'
        return self.send_request(method=method, api=api, params=params, json=data, header=header)

    def put(self, api, data, params=None, header=None):
        method = 'PUT'
        return self.send_request(method=method, api=api, params=params, json=data, header=header)

    def delete(self, api, data, params=None, header=None):
        method = 'DELETE'
        return self.send_request(method=method, api=api, params=params, json=data, header=header)

    def get_token(self):
        if self.sa_client_id is not None and self.sa_client_id != "" and self.sa_secret_key is not None and self.sa_secret_key != "":
            response, error, ocr_id = self.post(self.environment_data['SA_AUTH_HOST'],
                                                data={"grant_type": "client_credentials", "client_secret": self.sa_secret_key,
                                                      "client_id": self.sa_client_id, "audience": "https://api.cloud.netapp.com"},
                                                authorized=False)
        elif self.refresh_token is not None and self.refresh_token != "":
            response, error, ocr_id = self.post(self.environment_data['AUTH0_DOMAIN'] + '/oauth/token',
                                                data={"grant_type": "refresh_token", "refresh_token": self.refresh_token,
                                                      "client_id": self.environment_data['AUTH0_CLIENT'],
                                                      "audience": "https://api.cloud.netapp.com"},
                                                authorized=False)
        else:
            self.module.fail_json(msg='Missing refresh_token or sa_client_id and sa_secret_key')

        if error:
            self.module.fail_json(msg='Error acquiring token: %s, %s' % (str(error), str(response)))
        token = response['access_token']
        token_type = response['token_type']

        return token_type, token

    def wait_on_completion(self, api_url, action_name, task, retries, wait_interval):
        while True:
            cvo_status, failure_error_message, error = self.check_task_status(api_url)
            if error is not None:
                return error
            if cvo_status == -1:
                return 'Failed to %s %s, error: %s' % (task, action_name, failure_error_message)
            elif cvo_status == 1:
                return None         # success
            # status value 0 means pending
            if retries == 0:
                return 'Taking too long for %s to %s or not properly setup' % (action_name, task)
            time.sleep(wait_interval)
            retries = retries - 1

    def check_task_status(self, api_url):
        headers = {
            'X-Agent-Id': self.format_client_id(self.module.params['client_id'])
        }

        network_retries = 3
        while True:
            result, error, dummy = self.get(api_url, None, header=headers)
            if error is not None:
                if network_retries <= 0:
                    return 0, '', error
                time.sleep(1)
                network_retries -= 1
            else:
                response = result
                break
        return response['status'], response['error'], None

    def log_error(self, status_code, message):
        LOG.error("%s: %s", status_code, message)

    def log_debug(self, status_code, content):
        LOG.debug("%s: %s", status_code, content)

    def log_request(self, method, params, url, json, data, headers):
        contents = {
            'method': method,
            'url': url,
            'json': json,
            'data': data
        }
        if params:
            contents['params'] = params
        if self.log_headers:
            contents['headers'] = headers
        self.log_debug('sending', repr(contents))
