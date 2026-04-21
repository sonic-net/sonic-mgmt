# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

'''Python versions supported: >=3.8'''

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within the community.hashi_vault collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import (
    HashiVaultAuthMethodBase,
    HashiVaultValueError,
)


class HashiVaultAuthMethodAwsIam(HashiVaultAuthMethodBase):
    '''HashiVault option group class for auth: userpass'''

    NAME = 'aws_iam'
    OPTIONS = [
        'aws_profile',
        'aws_access_key',
        'aws_secret_key',
        'aws_security_token',
        'region',
        'aws_iam_server_id',
        'role_id',
    ]

    def __init__(self, option_adapter, warning_callback, deprecate_callback):
        super(HashiVaultAuthMethodAwsIam, self).__init__(option_adapter, warning_callback, deprecate_callback)

    def validate(self):
        params = {
            'access_key': self._options.get_option_default('aws_access_key'),
            'secret_key': self._options.get_option_default('aws_secret_key'),
        }

        session_token = self._options.get_option_default('aws_security_token')
        if session_token:
            params['session_token'] = session_token

        mount_point = self._options.get_option_default('mount_point')
        if mount_point:
            params['mount_point'] = mount_point

        role = self._options.get_option_default('role_id')
        if role:
            params['role'] = role

        region = self._options.get_option_default('region')
        if region:
            params['region'] = region

        header_value = self._options.get_option_default('aws_iam_server_id')
        if header_value:
            params['header_value'] = header_value

        if not (params['access_key'] and params['secret_key']):
            try:
                import boto3
                import botocore
            except ImportError:
                raise HashiVaultValueError("boto3 is required for loading a profile or IAM role credentials.")

            profile = self._options.get_option_default('aws_profile')
            try:
                session_credentials = boto3.session.Session(profile_name=profile).get_credentials()
            except botocore.exceptions.ProfileNotFound:
                raise HashiVaultValueError("The AWS profile '%s' was not found." % profile)

            if not session_credentials:
                raise HashiVaultValueError("No AWS credentials supplied or available.")

            params['access_key'] = session_credentials.access_key
            params['secret_key'] = session_credentials.secret_key
            if session_credentials.token:
                params['session_token'] = session_credentials.token

        self._auth_aws_iam_login_params = params

    def authenticate(self, client, use_token=True):
        params = self._auth_aws_iam_login_params
        try:
            response = client.auth.aws.iam_login(use_token=use_token, **params)
        except (NotImplementedError, AttributeError):
            self.warn("HVAC should be updated to version 0.9.3 or higher. Deprecated method 'auth_aws_iam' will be used.")
            client.auth_aws_iam(use_token=use_token, **params)

        return response
