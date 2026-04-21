# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within the community.hashi_vault collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.plugins import AnsiblePlugin
from ansible import constants as C
from ansible.utils.display import Display

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import (
    HashiVaultHelper,
    HashiVaultHVACError,
    HashiVaultOptionAdapter,
)

from ansible_collections.community.hashi_vault.plugins.module_utils._connection_options import HashiVaultConnectionOptions
from ansible_collections.community.hashi_vault.plugins.module_utils._authenticator import HashiVaultAuthenticator


display = Display()


class HashiVaultPlugin(AnsiblePlugin):
    def __init__(self):
        super(HashiVaultPlugin, self).__init__()

        try:
            self.helper = HashiVaultHelper()
        except HashiVaultHVACError as exc:
            from ansible.errors import AnsibleError
            raise AnsibleError(exc.msg)

        self._options_adapter = HashiVaultOptionAdapter.from_ansible_plugin(self)
        self.connection_options = HashiVaultConnectionOptions(self._options_adapter, self._generate_retry_callback)
        self.authenticator = HashiVaultAuthenticator(self._options_adapter, display.warning, display.deprecated)

    def _generate_retry_callback(self, retry_action):
        '''returns a Retry callback function for plugins'''
        def _on_retry(retry_obj):
            if retry_obj.total > 0:
                if retry_action == 'warn':
                    display.warning('community.hashi_vault: %i %s remaining.' % (retry_obj.total, 'retry' if retry_obj.total == 1 else 'retries'))
                else:
                    pass

        return _on_retry

    def process_deprecations(self, collection_name='community.hashi_vault'):
        '''processes deprecations related to the collection'''

        # TODO: this is a workaround for deprecations not being shown in lookups
        # See:
        #  - https://github.com/ansible/ansible/issues/73051
        #  - https://github.com/ansible/ansible/pull/73058
        #  - https://github.com/ansible/ansible/pull/73239
        #  - https://github.com/ansible/ansible/pull/73240
        #
        # If a fix is backported to 2.9, this should be removed.
        # Otherwise, we'll have to test with fixes that are available and see how we
        # can determine whether to execute this conditionally.

        # nicked from cli/__init__.py
        # with slight customizations to help filter out relevant messages
        # (relying on the collection name since it's a valid attrib and we only have 1 plugin at this time)

        # warn about deprecated config options

        for deprecated in list(C.config.DEPRECATED):
            name = deprecated[0]
            why = deprecated[1]['why']
            if deprecated[1].get('collection_name') != collection_name:
                continue

            if 'alternatives' in deprecated[1]:
                alt = ', use %s instead' % deprecated[1]['alternatives']
            else:
                alt = ''
            ver = deprecated[1].get('version')
            date = deprecated[1].get('date')
            collection_name = deprecated[1].get('collection_name')
            display.deprecated("%s option, %s%s" % (name, why, alt), version=ver, date=date, collection_name=collection_name)

            # remove this item from the list so it won't get processed again by something else
            C.config.DEPRECATED.remove(deprecated)
