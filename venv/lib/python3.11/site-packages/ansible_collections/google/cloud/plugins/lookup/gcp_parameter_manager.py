# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    name: gcp_parameter_manager
    author: Google Inc. (@googlecloudplatform)

    short_description: Get Parameters from Google Cloud as a Lookup plugin
    description:
    - retrieve parameter keys in parameter Manager for use in playbooks
    - see https://cloud.google.com/iam/docs/service-account-creds for details on creating
      credentials for Google Cloud and the format of such credentials
    - once a parameter value is retreived, it is returned decoded.  It is up to the developer
      to maintain secrecy of this value once returned.
    - if location option is defined, then it deals with the regional parameters of the
      location

    options:
        key:
            description:
            - the name of the parameter to look up in parameter Manager
            type: str
            required: True
            aliases:
            - name
            - parameter
            - parameter_id
        project:
            description:
            - The name of the google cloud project
            - defaults to OS env variable GCP_PROJECT if not present
            type: str
        location:
            description:
            - If provided, it defines the location of the regional parameter.
            type: str
        render_secret:
            description:
            - support for rendering secrets
            - defaults to false if not present
            type: bool
        auth_kind:
            description:
            - the type of authentication to use with Google Cloud (i.e. serviceaccount or machineaccount)
            - defaults to OS env variable GCP_AUTH_KIND if not present
            type: str
        version:
            description:
            - the version name of your parameter to retrieve
            type: str
            required: False
        service_account_email:
            description:
            - email associated with the service account
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_EMAIL if not present
            type: str
            required: False
        service_account_file:
            description:
            - JSON Credential file obtained from Google Cloud
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_FILE if not present
            - see https://cloud.google.com/iam/docs/service-account-creds for details
            type: str
            required: False
        service_account_info:
            description:
            - JSON Object representing the contents of a service_account_file obtained from Google Cloud
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_INFO if not present
            type: dict
            required: False
        access_token:
            description:
            - support for GCP Access Token
            - defaults to OS env variable GCP_ACCESS_TOKEN if not present
            type: str
            required: False
        on_error:
            description:
            - how to handle errors
            - strict means raise an exception
            - warn means warn, and return none
            - ignore means just return none
            type: str
            required: False
            choices:
            - 'strict'
            - 'warn'
            - 'ignore'
            default: 'strict'
        scopes:
            description:
            - Authenticaiton scopes for Google parameter Manager
            type: list
            elements: str
            default: ["https://www.googleapis.com/auth/cloud-platform"]
'''


EXAMPLES = '''
- name: Test parameter using env variables for credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', version='test_version') }}"

- name: Test parameter using explicit credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', version='test_version', project='project', auth_kind='serviceaccount',
                    service_account_file='file.json') }}"

- name: Test getting specific version of a parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', version='test-version') }}"

- name: Test getting latest version of a parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key') }}"

- name: Test render specific version of a parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', version='test-version', render_secret=True) }}"

- name: Test render latest version of a parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', render_secret=True) }}"

- name: Test regional parameter using env variables for credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', location='us-central1', version='test_version') }}"

- name: Test regional parameter using explicit credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', location='us-central1', version='test_version', project='project',
                    auth_kind='serviceaccount', service_account_file='file.json') }}"

- name: Test getting specific version of a regional parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', location='us-central1', version='test_version') }}"

- name: Test getting latest version of a regional parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', location='us-central1') }}"

- name: Test render specific version of a regional parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', location='us-central1', version='test_version', render_secret=True) }}"

- name: Test render latest version of a regional parameter
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_parameter_manager', key='parameter_key', location='us-central1', render_secret=True) }}"
'''

RETURN = '''
    _raw:
        description: the contents of the parameter requested (please use "no_log" to not expose this parameter)
        type: list
        elements: str
'''


################################################################################
# Imports
################################################################################

import os
import base64

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
        GcpSession,
    )
    HAS_GOOGLE_CLOUD_COLLECTION = True
except ImportError:
    HAS_GOOGLE_CLOUD_COLLECTION = False


class GcpLookupException(Exception):
    pass


class GcpMockModule(object):
    def __init__(self, params):
        self.params = params

    def fail_json(self, *args, **kwargs):
        raise AnsibleError(kwargs["msg"])

    def raise_for_status(self, response):
        try:
            response.raise_for_status()
        except getattr(requests.exceptions, "RequestException"):
            self.fail_json(msg="GCP returned error: %s" % response.json())


class LookupModule(LookupBase):
    def run(self, terms=None, variables=None, **kwargs):
        self._display = Display()
        if not HAS_GOOGLE_CLOUD_COLLECTION:
            raise AnsibleError(
                """gcp_parameter lookup needs a supported version of the google.cloud
                collection installed. Use `ansible-galaxy collection install google.cloud`
                to install it"""
            )
        self.set_options(var_options=variables, direct=kwargs)
        params = {
            "key": self.get_option("key"),
            "location": self.get_option("location"),
            "version": self.get_option("version"),
            "access_token": self.get_option("access_token"),
            "scopes": self.get_option("scopes"),
            "render_secret": self.get_option("render_secret"),
            "on_error": self.get_option("on_error")
        }

        params['name'] = params['key']

        # support GCP_* env variables for some parameters
        for param in ["project", "auth_kind", "service_account_file", "service_account_info", "service_account_email", "access_token"]:
            params[param] = self.fallback_from_env(param)

        self._display.vvv(msg=f"Module Parameters: {params}")
        fake_module = GcpMockModule(params)
        result = self.get_parameter(fake_module)
        return [base64.b64decode(result)]

    def fallback_from_env(self, arg):
        if self.get_option(arg):
            return self.get_option(arg)
        else:
            env_name = f"GCP_{arg.upper()}"
            if env_name in os.environ:
                self.set_option(arg, os.environ[env_name])
            return self.get_option(arg)

    def raise_error(self, module, msg):
        if module.params.get('on_error') == 'strict':
            raise GcpLookupException(msg)
        elif module.params.get('on_error') == 'warn':
            self._display.warning(msg)

        return None

    def get_latest_version(self, module, auth):
        url = (self.make_url_prefix(module) + "parameters/{name}/versions?orderBy=create_time desc&filter=disabled=false").format(
            **module.params
        )
        response = auth.get(url)
        self._display.vvv(msg=f"List Version Response: {response.status_code} for {response.request.url}: {response.json()}")
        if response.status_code != 200:
            self.raise_error(module, f"unable to list versions of parameter {response.status_code}")
        version_list = response.json()
        if "parameterVersions" in version_list and len(version_list["parameterVersions"]) > 0:
            # Extract name from the first index
            version_name = version_list["parameterVersions"][0]["name"]
            return version_name.split('/')[-1]
        else:
            self.raise_error(module, f"unable to list parameter versions via {response.request.url}: {response.json()}")

    def get_parameter(self, module):
        auth = GcpSession(module, "parametermanager")

        if module.params.get('project') is None:
            self.raise_error(module, "The project is required. Please specify the Google Cloud project to use.")

        if module.params.get('version') == 'latest' or module.params.get('version') is None:
            module.params['version'] = self.get_latest_version(module, auth)

        if module.params.get('render_secret') is None:
            module.params['render_secret'] = False

        # there was an error listing parameter versions
        if module.params.get('version') is None:
            return ''

        if module.params.get('render_secret') is not None:
            url = (self.make_url_prefix(module) + "parameters/{name}/versions/{version}:render").format(
                **module.params
            )
        else:
            url = (self.make_url_prefix(module) + "parameters/{name}/versions/{version}").format(
                **module.params
            )
        response = auth.get(url)
        self._display.vvv(msg=f"Response: {response.status_code} for {response.request.url}: {response.json()}")
        if response.status_code != 200:
            self.raise_error(module, f"Failed to lookup parameter value via {response.request.url} {response.status_code}")
            return ''

        response_json = response.json()
        if module.params.get('render_secret') is not None:
            if 'renderedPayload' not in response_json:
                self.raise_error(module, "The parameter version is disabled or the response does not contain the 'renderedPayload' field.")
                return ''
            return response_json['renderedPayload']
        else:
            if 'payload' not in response_json or 'data' not in response_json['payload']:
                self.raise_error(module, "The parameter version is disabled or the response does not contain the 'data' field.")
                return ''
            return response_json['payload']['data']

    def make_url_prefix(self, module):
        if module.params.get('location') and module.params.get('location') != 'global':
            return "https://parametermanager.{location}.rep.googleapis.com/v1/projects/{project}/locations/{location}/"
        return "https://parametermanager.googleapis.com/v1/projects/{project}/locations/global/"
