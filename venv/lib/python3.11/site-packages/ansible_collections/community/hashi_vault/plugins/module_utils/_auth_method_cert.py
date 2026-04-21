# -*- coding: utf-8 -*-
# Copyright (c) 2021 Devon Mar (@devon-mar)
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultAuthMethodBase


class HashiVaultAuthMethodCert(HashiVaultAuthMethodBase):
    """HashiVault option group class for auth: cert"""

    NAME = "cert"
    OPTIONS = ["cert_auth_public_key", "cert_auth_private_key", "mount_point", "role_id"]

    def __init__(self, option_adapter, warning_callback, deprecate_callback):
        super(HashiVaultAuthMethodCert, self).__init__(option_adapter, warning_callback, deprecate_callback)

    def validate(self):
        self.validate_by_required_fields("cert_auth_public_key", "cert_auth_private_key")

    def authenticate(self, client, use_token=True):
        options = self._options.get_filled_options(*self.OPTIONS)

        params = {
            "cert_pem": options["cert_auth_public_key"],
            "key_pem": options["cert_auth_private_key"],
        }

        if "mount_point" in options:
            params["mount_point"] = options["mount_point"]
        if "role_id" in options:
            params["name"] = options["role_id"]

        try:
            response = client.auth.cert.login(use_token=use_token, **params)
        except NotImplementedError:
            raise NotImplementedError("cert authentication requires HVAC version 0.10.12 or higher.")

        return response
