# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import base64

from ansible import constants as C
from ansible.plugins.action import ActionBase
from ansible.utils.vars import merge_hash

from ansible_collections.community.docker.plugins.module_utils._scramble import unscramble


class ActionModule(ActionBase):
    # Set to True when transferring files to the remote
    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._supports_async = True

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        self._task.args['_max_file_size_for_diff'] = C.MAX_FILE_SIZE_FOR_DIFF

        result = merge_hash(result, self._execute_module(task_vars=task_vars, wrap_async=self._task.async_val))

        if u'diff' in result and result[u'diff'].get(u'scrambled_diff'):
            # Scrambling is not done for security, but to avoid no_log screwing up the diff
            diff = result[u'diff']
            key = base64.b64decode(diff.pop(u'scrambled_diff'))
            for k in (u'before', u'after'):
                if k in diff:
                    diff[k] = unscramble(diff[k], key)

        return result
