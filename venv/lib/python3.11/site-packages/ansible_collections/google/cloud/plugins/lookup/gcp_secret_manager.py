# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    author: Google Inc. (@googlecloudplatform)
    name: gcp_secret_manager
    short_description: Get Secrets from Google Cloud as a Lookup plugin
    description:
    - retrieve secret keys in Secret Manager for use in playbooks
    - see https://cloud.google.com/iam/docs/service-account-creds for details on creating
      credentials for Google Cloud and the format of such credentials
    - once a secret value is retreived, it is returned decoded.  It is up to the developer
      to maintain secrecy of this value once returned.
    - if location option is defined, then it deals with the regional secrets of the
      location
    requirements:
    - python >= 2.6
    - requests >= 2.18.4
    - google-auth >= 1.3.0

    options:
        key:
            description:
            - the name of the secret to look up in Secret Manager
            type: str
            required: True
            aliases:
            - name
            - secret
            - secret_id
        project:
            description:
            - The name of the google cloud project
            - defaults to OS env variable GCP_PROJECT if not present
            type: str
        location:
            description:
            - If provided, it defines the location of the regional secret.
            type: str
        auth_kind:
            description:
            - the type of authentication to use with Google Cloud (i.e. serviceaccount or machineaccount)
            - defaults to OS env variable GCP_AUTH_KIND if not present
            type: str
        version:
            description:
            - the version name of your secret to retrieve
            type: str
            default: latest
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
        service_account_contents:
            description:
            - JSON Object representing the contents of a service_account_file obtained from Google Cloud
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_CONTENTS if not present
            aliases:
            - service_account_info
            type: str
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
            - Authenticaiton scopes for Google Secret Manager
            type: list
            elements: str
            default: ["https://www.googleapis.com/auth/cloud-platform"]
'''

EXAMPLES = '''
- name: Test secret using env variables for credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key') }}"

- name: Test secret using explicit credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', project='project', auth_kind='serviceaccount', service_account_file='file.json') }}"

- name: Test getting specific version of a secret (old version)
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', version='1') }}"

- name: Test getting specific version of a secret (new version)
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', version='2') }}"

- name: Test regional secret using env variables for credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', location='us-central1') }}"

- name: Test regional secret using explicit credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', location='us-central1', project='project', auth_kind='serviceaccount',
                    service_account_file='file.json') }}"

- name: Test getting specific version of a regional secret (old version)
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', location='us-central1', version='1') }}"

- name: Test getting specific version of a regional secret (new version)
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', location='us-central1', version='2') }}"
'''

RETURN = '''
    _raw:
        description: the contents of the secret requested (please use "no_log" to not expose this secret)
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
                """gcp_secret lookup needs a supported version of the google.cloud
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
            "on_error": self.get_option("on_error")
        }

        params['name'] = params['key']

        # support GCP_* env variables for some parameters
        for param in ["project", "auth_kind", "service_account_file", "service_account_contents", "service_account_email", "access_token"]:
            params[param] = self.fallback_from_env(param)

        self._display.vvv(msg=f"Module Parameters: {params}")
        fake_module = GcpMockModule(params)
        result = self.get_secret(fake_module)
        return [base64.b64decode(result).decode("utf-8")]

    def fallback_from_env(self, arg):
        if self.get_option(arg):
            return self.get_option(arg)
        else:
            env_name = f"GCP_{arg.upper()}"
            if env_name in os.environ:
                self.set_option(arg, os.environ[env_name])
            return self.get_option(arg)

    # set version to the latest version because
    # we can't be sure that "latest" is always going
    # to be set if secret versions get disabled
    # see https://issuetracker.google.com/issues/286489671
    def get_latest_version(self, module, auth):
        url = (self.make_url_prefix(module) + "secrets/{name}/versions?filter=state:ENABLED").format(
            **module.params
        )
        response = auth.get(url)
        self._display.vvv(msg=f"List Version Response: {response.status_code} for {response.request.url}: {response.json()}")
        if response.status_code >= 500:  # generic server error
            self.raise_error(
                module,
                f"server error encountered while looking for secret '{module.params['name']}', code: {response.status_code}"
            )
        elif response.status_code >= 400:  # generic client request error
            self.raise_error(
                module,
                f"client error encountered while looking for secret '{module.params['name']}', code: {response.status_code}"
            )
        elif response.status_code >= 300:  # all other possible errors
            self.raise_error(
                module,
                f"unable to list versions for secret '{module.params['name']}', code: {response.status_code}"
            )
        else:
            pass
        version_list = response.json()
        if "versions" in version_list:
            versions_numbers = []
            for version in version_list['versions']:
                versions_numbers.append(version['name'].split('/')[-1])
            return sorted(versions_numbers, key=int)[-1]
        else:
            self.raise_error(module, f"Unable to list secret versions via {response.request.url}: {response.json()}")

    def raise_error(self, module, msg):
        if module.params['on_error'] == 'strict':
            raise GcpLookupException(msg)
        elif module.params['on_error'] == 'warn':
            self._display.warning(msg)

        return None

    def get_secret(self, module):
        auth = GcpSession(module, "secretmanager")
        if module.params['version'] == "latest":
            module.params['calc_version'] = self.get_latest_version(module, auth)
        else:
            module.params['calc_version'] = module.params['version']

        # there was an error listing secret versions
        if module.params['calc_version'] is None:
            return ''

        url = (self.make_url_prefix(module) + "secrets/{name}/versions/{calc_version}:access").format(
            **module.params
        )
        response = auth.get(url)
        self._display.vvv(msg=f"Response: {response.status_code} for {response.request.url}: {response.json()}")
        if response.status_code != 200:
            self.raise_error(module, f"Failed to lookup secret value via {response.request.url} {response.status_code}")
            return ''

        return response.json()['payload']['data']

    def make_url_prefix(self, module):
        if module.params['location']:
            return "https://secretmanager.{location}.rep.googleapis.com/v1/projects/{project}/locations/{location}/"
        return "https://secretmanager.googleapis.com/v1/projects/{project}/"
