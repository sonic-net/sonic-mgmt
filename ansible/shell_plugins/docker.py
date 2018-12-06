from __future__ import (absolute_import, division)
__metaclass__ = type

import os
import re
import pipes
import ansible.constants as C
import time
import random
import shlex
import getopt
from ansible.compat.six import text_type
from ansible.plugins.shell.sh import ShellModule as sh
from ansible.errors import AnsibleError, AnsibleConnectionFailure, AnsibleFileNotFound

class ShellModule(sh):

    def __init__(self, *args, **kwargs):
        super(ShellModule, self).__init__(*args, **kwargs)
        self.dtemps = []

    def join_path(self, *args):
        ## HACK! HACK! HACK!
        ## We observe the interactions between ShellModule and ActionModule, and
        ## find the temporary directories Ansible created on remote machine. So we
        ## collect them and copied to docker container in build_module_command
        if len(args) >= 2 and (args[0].startswith('/home/') or args[0].startswith('/root/'))  and args[1] == '':
            self.dtemps.append(args[0])

        return super(ShellModule, self).join_path(*args)

    def build_module_command(self, env_string, shebang, cmd, arg_path=None, rm_tmp=None):
        # assert(self.container_name)
        argv = shlex.split(shebang.replace("#!", ""))
        assert(argv[0] == 'docker')
        assert(argv[1] == 'exec')
        opts, args = getopt.getopt(argv[2:], 'i')
        self.container_name = args[0]

        # Inject environment variable before python in the shebang string
        assert(args[1].endswith('python'))
        args[1] = 'env {0} {1}'.format(env_string, args[1])
        argv_env = argv[0:2] + [o for opt in opts for o in opt] + args
        shebang_env = ' '.join(argv_env)

        ## Note: Docker cp behavior
        ##   DEST_PATH exists and is a directory
        ##   SRC_PATH does end with /.
        ##     the content of the source directory is copied into this directory
        ## Ref: https://docs.docker.com/engine/reference/commandline/cp/
        pre = ''.join('docker exec {1} mkdir -p {0}; docker cp {0}/. {1}:{0}; '
            .format(dtemp, self.container_name) for dtemp in self.dtemps)

        if rm_tmp:
            post = ''.join('docker exec {1} rm -rf {0}; '
                .format(dtemp, self.container_name) for dtemp in self.dtemps)
        else:
            post = ''

        return pre + super(ShellModule, self).build_module_command('', shebang_env, cmd, arg_path, rm_tmp) + '; ' + post

    def checksum(self, path, python_interp):
        """
        Return the command to calculate the checksum for the file in ansible controlled machine
        Arguments:
          path:
            the file path
          python_interp:
            the path for the python interpreter
        Example:
          path:
            /zebra.conf
          python_interp:
            docker exec -i debian python
          cmd:
            rc=flag; [ -r /zebra.conf ] || rc=2; [ -f /zebra.conf ] || rc=1; [ -d /zebra.conf ] && rc=3; python -V 2>/dev/null || rc=4; [ x"$rc" != "xflag" ] && echo "${rc}  "/zebra.conf && exit 0; (python -c '...' 2>/dev/null)  || (echo '0  '/zebra.conf)
          returns:
            docker exec -i debian  sh -c "rc=flag; [ -r /zebra.conf ] || rc=2; [ -f /zebra.conf ] || rc=1; [ -d /zebra.conf ] && rc=3; python -V 2>/dev/null || rc=4; [ x\"\$rc\" != \"xflag\" ] && echo \"\${rc}  \"/zebra.conf && exit 0; (python -c '...' 2>/dev/null) || (echo '0  '/zebra.conf)"
        """
        ## Super class implements this function by sh commands and python scripts
        ## If python_interp is modified to 'docker CONTAINER python', it will only influence the python
        ## script part in super class. Instead we should influence both
        simple_interp = 'python'
        assert(python_interp.startswith('docker exec '))
        assert(python_interp.endswith(' ' + simple_interp))

        docker_prefix = re.sub(simple_interp, '', python_interp)
        cmd = super(ShellModule, self).checksum(path, simple_interp)
        ## Escape the cmd:
        ##   " --> \"
        cmd_escaped = cmd.replace('"', '\\"')
        ##   $ --> \$
        cmd_escaped = cmd_escaped.replace('$', '\\$')
        return '%s sh -c "%s"' % (docker_prefix, cmd_escaped)
