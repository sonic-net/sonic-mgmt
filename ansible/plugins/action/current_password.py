from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.action import ActionBase

import sys

# If the version of the Python interpreter is greater or equal to 3, set the unicode variable to the str class.
if sys.version_info[0] >= 3:
    unicode = str


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        super(ActionModule, self).run(tmp, task_vars)
        module_args = self._task.args.copy()
        self._connection.reset()
        module_return = self._execute_module(
            module_name='command',
            module_args=module_args,
            task_vars=task_vars,
            tmp=tmp
        )
        module_return["current_password_hash"] = self._connection.get_option("current_password_hash")
        return module_return
