from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
from ansible.errors import AnsibleError, AnsibleActionFail, AnsibleActionSkip
from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.module_utils.six import string_types
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible.utils.hashing import checksum, md5, secure_hash
from ansible.utils.path import makedirs_safe, is_subpath

display = Display()


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        ''' handler for fetch_no_slurp operations '''
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        try:
            if self._play_context.check_mode:
                raise AnsibleActionSkip('check mode not (yet) supported for this module')

            source = self._task.args.get('src', None)
            original_dest = dest = self._task.args.get('dest', None)
            flat = boolean(self._task.args.get('flat'), strict=False)
            fail_on_missing = boolean(self._task.args.get('fail_on_missing', True), strict=False)
            validate_checksum = boolean(self._task.args.get('validate_checksum', True), strict=False)

            msg = ''
            # validate source and dest are strings FIXME: use basic.py and module specs
            if not isinstance(source, string_types):
                msg = "Invalid type supplied for source option, it must be a string"

            if not isinstance(dest, string_types):
                msg = "Invalid type supplied for dest option, it must be a string"

            if source is None or dest is None:
                msg = "src and dest are required"

            if msg:
                raise AnsibleActionFail(msg)

            source = self._connection._shell.join_path(source)
            source = self._remote_expand_user(source)

            remote_stat = {}
            remote_checksum = None

            try:
                remote_stat = self._execute_remote_stat(source, all_vars=task_vars, follow=True)
            except AnsibleError as ae:
                result['changed'] = False
                result['file'] = source
                if fail_on_missing:
                    result['failed'] = True
                    result['msg'] = to_text(ae)
                else:
                    result['msg'] = "%s, ignored" % to_text(ae, errors='surrogate_or_replace')

                return result

            remote_checksum = remote_stat.get('checksum')
            if remote_stat.get('exists'):
                if remote_stat.get('isdir'):
                    result['failed'] = True
                    result['changed'] = False
                    result['msg'] = "remote file is a directory, fetch cannot work on directories"

                    # Historically, these don't fail because you may want to transfer
                    # a log file that possibly MAY exist but keep going to fetch other
                    # log files. Today, this is better achieved by adding
                    # ignore_errors or failed_when to the task.  Control the behaviour
                    # via fail_when_missing
                    if not fail_on_missing:
                        result['msg'] += ", not transferring, ignored"
                        del result['changed']
                        del result['failed']

                    return result

            # calculate the destination name
            if os.path.sep not in self._connection._shell.join_path('a', ''):
                source = self._connection._shell._unquote(source)
                source_local = source.replace('\\', '/')
            else:
                source_local = source

            # ensure we only use file name, avoid relative paths
            if not is_subpath(dest, original_dest):
                # TODO: ? dest = os.path.expanduser(dest.replace(('../','')))
                raise AnsibleActionFail("Detected directory traversal, expected to be" +
                                        "contained in '%s' but got '%s'" % (original_dest, dest))

            if flat:
                if os.path.isdir(to_bytes(dest, errors='surrogate_or_strict')) and not dest.endswith(os.sep):
                    raise AnsibleActionFail("dest is an existing directory, use a trailing slash if you want to" +
                                            "fetch src into that directory")
                if dest.endswith(os.sep):
                    # if the path ends with "/", we'll use the source filename as the
                    # destination filename
                    base = os.path.basename(source_local)
                    dest = os.path.join(dest, base)
                if not dest.startswith("/"):
                    # if dest does not start with "/", we'll assume a relative path
                    dest = self._loader.path_dwim(dest)
            else:
                # files are saved in dest dir, with a subdir for each host, then the filename
                if 'inventory_hostname' in task_vars:
                    target_name = task_vars['inventory_hostname']
                else:
                    target_name = self._play_context.remote_addr
                dest = "%s/%s/%s" % (self._loader.path_dwim(dest), target_name, source_local)

            dest = os.path.normpath(dest)

            # calculate checksum for the local file
            local_checksum = checksum(dest)

            if remote_checksum != local_checksum:
                # create the containing directories, if needed
                makedirs_safe(os.path.dirname(dest))

                # fetch the file and check for changes
                self._connection.fetch_file(source, dest)

                new_checksum = secure_hash(dest)
                # For backwards compatibility. We'll return None on FIPS enabled systems
                try:
                    new_md5 = md5(dest)
                except ValueError:
                    new_md5 = None

                if validate_checksum and new_checksum != remote_checksum:
                    result.update(dict(failed=True, md5sum=new_md5,
                                       msg="checksum mismatch", file=source, dest=dest, remote_md5sum=None,
                                       checksum=new_checksum, remote_checksum=remote_checksum))
                else:
                    result.update({'changed': True, 'md5sum': new_md5, 'dest': dest,
                                   'remote_md5sum': None, 'checksum': new_checksum,
                                   'remote_checksum': remote_checksum})
            else:
                # For backwards compatibility. We'll return None on FIPS enabled systems
                try:
                    local_md5 = md5(dest)
                except ValueError:
                    local_md5 = None
                result.update(dict(changed=False, md5sum=local_md5, file=source, dest=dest, checksum=local_checksum))

        finally:
            self._remove_tmp_path(self._connection._shell.tmpdir)

        return result
