# -*- coding: utf-8 -*-
# Copyright (c) 2022 Junrui Chen (@jchenship)
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


class HashiVaultAuthMethodAzure(HashiVaultAuthMethodBase):
    '''HashiVault auth method for Azure'''

    NAME = 'azure'
    OPTIONS = [
        'role_id',
        'jwt',
        'mount_point',
        'azure_tenant_id',
        'azure_client_id',
        'azure_client_secret',
        'azure_resource',
    ]

    def __init__(self, option_adapter, warning_callback, deprecate_callback):
        super(HashiVaultAuthMethodAzure, self).__init__(
            option_adapter, warning_callback, deprecate_callback
        )

    def validate(self):
        params = {
            'role': self._options.get_option_default('role_id'),
            'jwt': self._options.get_option_default('jwt'),
        }
        if not params['role']:
            raise HashiVaultValueError(
                'role_id is required for azure authentication.'
            )

        # if mount_point is not provided, it will use the default value defined
        # in hvac library (e.g. `azure`)
        mount_point = self._options.get_option_default('mount_point')
        if mount_point:
            params['mount_point'] = mount_point

        # if jwt exists, use provided jwt directly, otherwise trying to get jwt
        # from azure service principal or managed identity
        if not params['jwt']:
            azure_tenant_id = self._options.get_option_default('azure_tenant_id')
            azure_client_id = self._options.get_option_default('azure_client_id')
            azure_client_secret = self._options.get_option_default('azure_client_secret')

            # the logic of getting azure scope is from this function
            # https://github.com/Azure/azure-cli/blob/azure-cli-2.39.0/src/azure-cli-core/azure/cli/core/auth/util.py#L72
            # the reason we expose resource instead of scope is resource is
            # more aligned with the vault azure auth config here
            # https://www.vaultproject.io/api-docs/auth/azure#resource
            azure_resource = self._options.get_option('azure_resource')
            azure_scope = azure_resource + "/.default"

            try:
                import azure.identity
            except ImportError:
                raise HashiVaultValueError(
                    "azure-identity is required for getting access token from azure service principal or managed identity."
                )

            if azure_client_id and azure_client_secret:
                # service principal
                if not azure_tenant_id:
                    raise HashiVaultValueError(
                        'azure_tenant_id is required when using azure service principal.'
                    )
                azure_credentials = azure.identity.ClientSecretCredential(
                    azure_tenant_id, azure_client_id, azure_client_secret
                )
            elif azure_client_id:
                # user assigned managed identity
                azure_credentials = azure.identity.ManagedIdentityCredential(
                    client_id=azure_client_id
                )
            else:
                # system assigned managed identity
                azure_credentials = azure.identity.ManagedIdentityCredential()

            params['jwt'] = azure_credentials.get_token(azure_scope).token

        self._auth_azure_login_params = params

    def authenticate(self, client, use_token=True):
        params = self._auth_azure_login_params
        response = client.auth.azure.login(use_token=use_token, **params)
        return response
