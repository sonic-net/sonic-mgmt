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
        _install  = boolean(self._task.args.get('install', 'no'))
        _url      = self._task.args.get('url', None)
        _timeout  = self._task.args.get('timeout', None)
        _nretry   = int(self._task.args.get('retry', 1))

        if _timeout is None:
            _timeout = 300

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
                                      url=_url,
                                      install=_install,
                                      timeout=_timeout,
                                      retry=_nretry)

        return result

