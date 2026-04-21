# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within the community.hashi_vault collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import (
    HashiVaultHelper,
    HashiVaultHVACError,
    HashiVaultOptionAdapter,
)
from ansible_collections.community.hashi_vault.plugins.module_utils._connection_options import HashiVaultConnectionOptions
from ansible_collections.community.hashi_vault.plugins.module_utils._authenticator import HashiVaultAuthenticator


class HashiVaultModule(AnsibleModule):
    def __init__(self, *args, **kwargs):
        if 'hashi_vault_custom_retry_callback' in kwargs:
            callback = kwargs.pop('hashi_vault_custom_retry_callback')
        else:
            callback = self._generate_retry_callback

        super(HashiVaultModule, self).__init__(*args, **kwargs)

        try:
            self.helper = HashiVaultHelper()
        except HashiVaultHVACError as exc:
            self.fail_json(
                msg=exc.msg,
                exception=exc.error
            )

        self.adapter = HashiVaultOptionAdapter.from_dict(self.params)
        self.connection_options = HashiVaultConnectionOptions(option_adapter=self.adapter, retry_callback_generator=callback)
        self.authenticator = HashiVaultAuthenticator(option_adapter=self.adapter, warning_callback=self.warn, deprecate_callback=self.deprecate)

    @classmethod
    def generate_argspec(cls, **kwargs):
        spec = HashiVaultConnectionOptions.ARGSPEC.copy()
        spec.update(HashiVaultAuthenticator.ARGSPEC.copy())
        spec.update(**kwargs)

        return spec

    def _generate_retry_callback(self, retry_action):
        '''returns a Retry callback function for modules'''
        def _on_retry(retry_obj):
            if retry_obj.total > 0:
                if retry_action == 'warn':
                    self.warn('community.hashi_vault: %i %s remaining.' % (retry_obj.total, 'retry' if retry_obj.total == 1 else 'retries'))
                else:
                    pass

        return _on_retry
