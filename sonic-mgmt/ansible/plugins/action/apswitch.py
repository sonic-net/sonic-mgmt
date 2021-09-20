from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils._text import to_text

import ast

class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        self._display.vvv('ActionModule run')

        result = super(ActionModule, self).run(tmp, task_vars)

        _template = self._task.args.get('template', None)
        _host     = self._task.args.get('host', None)
        _login    = self._task.args.get('login', None)
        _enable   = boolean(self._task.args.get('enable', 'yes'))
        _bash     = boolean(self._task.args.get('bash', 'no'))
        _su       = boolean(self._task.args.get('su', 'no'))
        _root     = boolean(self._task.args.get('root', 'no'))
        _reboot   = boolean(self._task.args.get('reboot', 'no'))
        _timeout  = self._task.args.get('timeout', None)
        _os_name  = self._task.args.get('os_name', '')

        if (type(_login) == unicode):
            _login = ast.literal_eval(_login)

        login = { 'user': [], 'enable': _login['enable'] }
        for passwd in reversed(_login['passwd']):
            login['user'].append((_login['user'], passwd))

        if _timeout is None:
            _timeout = 30

        if _template is not None:
            if self._task._role is not None:
                _template = self._loader.path_dwim_relative(self._task._role._role_path, 'templates', _template)
            else:
                _template = self._loader.path_dwim_relative(self._loader.get_basedir(), 'templates', _template)

            f = open(_template, 'r')
            template_data = to_text(f.read())
            f.close()

            _template = self._templar.template(template_data)

        self._display.vvv(self._connection.transport)
        result['stdout'] = self._connection.exec_command(template=_template,
                                      host=_host,
                                      login=login,
                                      enable=_enable,
                                      bash=_bash,
                                      su=_su,
                                      root=_root,
                                      reboot=_reboot,
                                      timeout=_timeout,
                                      os_name=_os_name)

        return result

