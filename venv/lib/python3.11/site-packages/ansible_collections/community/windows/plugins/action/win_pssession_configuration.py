# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time

from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.playbook.task import Task
from ansible.utils.display import Display
display = Display()


def clean_async_result(reference_keys, obj):
    for key in reference_keys:
        obj.pop(key)
    return obj


class ActionModule(ActionBase):
    _default_async_timeout = 300
    _default_async_poll = 1

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._supports_async = False
        check_mode = self._task.check_mode
        async_timeout = self._task.args.get('async_timeout', self._default_async_timeout)
        async_poll = self._task.args.get('async_poll', self._default_async_poll)

        result = super(ActionModule, self).run(tmp, task_vars)

        if async_poll <= 0:
            raise AnsibleError("The 'async_poll' option must be greater than 0, got: %i" % async_poll)

        # build the wait_for_connection object for later use
        wait_for_connection_task = self._task.copy()
        wait_for_connection_task.args = {
            'timeout': async_timeout,
            'sleep': async_poll,
        }
        wait_connection_action = self._shared_loader_obj.action_loader.get(
            'wait_for_connection',
            task=wait_for_connection_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj
        )

        # if it's not in check mode, call the module async so the WinRM restart doesn't kill ansible
        if not check_mode:
            self._task.async_val = async_timeout
            self._task.poll = async_poll

        result = status = self._execute_module(
            task_vars=task_vars,
            module_args=self._task.args
        )
        display.vvvv("Internal Async Result: %r" % status)

        # if we're in check mode (not doing async) return the result now
        if check_mode:
            return result

        # turn off async so we don't run the following actions as async
        self._task.async_val = 0

        # build the async_status object
        async_status_load_params = dict(
            action='async_status jid=%s' % status['ansible_job_id'],
            environment=self._task.environment
        )
        async_status_task = Task().load(async_status_load_params)
        async_status_action = self._shared_loader_obj.action_loader.get(
            'async_status',
            task=async_status_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj
        )

        # build an async_status mode=cleanup object
        async_cleanup_load_params = dict(
            action='async_status mode=cleanup jid=%s' % status['ansible_job_id'],
            environment=self._task.environment
        )
        async_cleanup_task = Task().load(async_cleanup_load_params)
        async_cleanup_action = self._shared_loader_obj.action_loader.get(
            'async_status',
            task=async_cleanup_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj
        )

        # Retries here is a fallback in case the module fails in an unexpected way
        # which can sometimes not properly set the failed field in the return.
        # It is not related to async retries.
        # Without this, that situation would cause an infinite loop.
        max_retries = 3
        retries = 0
        while not check_mode:
            try:
                # check up on the async job
                job_status = async_status_action.run(task_vars=task_vars)
                display.vvvv("Async Job Status: %r" % job_status)

                if job_status.get('failed', False):
                    raise AnsibleError(job_status.get('msg', job_status))

                if job_status.get('finished', False):
                    result = job_status
                    break

                time.sleep(self._task.poll)

            except BaseException as e:
                retries += 1
                if retries >= max_retries:
                    display.vvvv("Max retries reached.")
                    raise e
                display.vvvv("Retrying (%s of %s)" % (retries, max_retries))
                display.vvvv("Falling back to wait_for_connection: %r" % e)
                wait_connection_action.run(task_vars=task_vars)

        try:
            # let's try to clean up after our implicit async
            job_status = async_cleanup_action.run(task_vars=task_vars)
            if job_status.get('failed', False):
                display.vvvv("Clean up of async status failed on the remote host: %r" % job_status.get('msg', job_status))
        except BaseException as e:
            # let's swallow errors during implicit cleanup to aovid interrupting what was otherwise a successful run
            display.vvvv("Clean up of async status failed on the remote host: %r" % e)

        return clean_async_result(status.keys(), result)
