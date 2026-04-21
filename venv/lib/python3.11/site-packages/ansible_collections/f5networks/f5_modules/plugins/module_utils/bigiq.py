# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import os

from .common import (
    F5BaseClient, F5ModuleError
)
from .constants import (
    LOGIN, BASE_HEADERS
)
from .icontrol import iControlRestSession


class F5RestClient(F5BaseClient):
    def __init__(self, *args, **kwargs):
        super(F5RestClient, self).__init__(*args, **kwargs)
        self.provider = self.merge_provider_params()
        self.headers = BASE_HEADERS
        self.access_token = None
        self.refresh_token = None

    @property
    def api(self):
        if self._client:
            return self._client
        session, err = self.connect_via_token_auth()
        if err:
            raise F5ModuleError(err)
        self._client = session
        return session

    def connect_via_token_auth(self):
        provider = self.provider['auth_provider'] or 'local'

        url = "https://{0}:{1}{2}".format(
            self.provider['server'], self.provider['server_port'], LOGIN
        )
        payload = {
            'username': self.provider['user'],
            'password': self.provider['password'],
        }

        # - local is a special provider that is baked into the system and
        #   has no loginReference
        if provider != 'local':
            login_ref = self.get_login_ref(provider)
            payload.update(login_ref)

        session = iControlRestSession(
            validate_certs=self.provider['validate_certs']
        )

        response = session.post(
            url,
            json=payload,
            headers=self.headers
        )

        if response.status not in [200]:
            return None, response.content
        self.access_token = response.json()['token']['token']
        self.refresh_token = response.json()['refreshToken']['token']
        session.request.headers['X-F5-Auth-Token'] = self.access_token
        return session, None

    def get_login_ref(self, provider):
        info = self.read_provider_info_from_device()
        uuids = [os.path.basename(os.path.dirname(x['link'])) for x in info['providers'] if '-' in x['link']]
        if provider in uuids:
            link = self._get_login_ref_by_id(info, provider)
            if not link:
                raise F5ModuleError(
                    "Provider with the UUID {0} was not found.".format(provider)
                )
            return dict(
                loginReference=dict(
                    link=link
                )
            )
        names = [os.path.basename(os.path.dirname(x['link'])) for x in info['providers'] if '-' in x['link']]
        if names.count(provider) > 1:
            raise F5ModuleError(
                "Ambiguous auth_provider name provided. Please specify a specific provider name or UUID."
            )
        link = self._get_login_ref_by_name(info, provider)
        if not link:
            raise F5ModuleError(
                "Provider with the name '{0}' was not found.".format(provider)
            )
        return dict(
            loginReference=dict(
                link=link
            )
        )

    @staticmethod
    def _get_login_ref_by_id(info, provider):
        provider = '/' + provider + '/'
        for x in info['providers']:
            if x['link'].find(provider) > -1:
                return x['link']

    @staticmethod
    def _get_login_ref_by_name(info, provider):
        for x in info['providers']:
            if x['name'] == provider:
                return x['link']
        return None

    def read_provider_info_from_device(self):
        uri = "https://{0}:{1}/info/system".format(
            self.provider['server'], self.provider['server_port']
        )
        session = iControlRestSession()
        session.verify = self.provider['validate_certs']

        resp = session.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return response

    def reconnect(self):
        url = "https://{0}:{1}/mgmt/shared/authn/exchange".format(
            self.provider['server'], self.provider['server_port']
        )
        payload = {
            'refreshToken': {
                'token': self.refresh_token
            }
        }

        session = iControlRestSession(
            validate_certs=self.provider['validate_certs']
        )

        response = session.post(
            url,
            json=payload,
            headers=BASE_HEADERS
        )

        if response.status not in [200]:
            raise F5ModuleError('Failed to refresh token, server returned: {0}'.format(response.content))
        self.access_token = response.json()['token']['token']
        self.refresh_token = response.json()['refreshToken']['token']
        session.request.headers['X-F5-Auth-Token'] = self.access_token
        self._client = session
