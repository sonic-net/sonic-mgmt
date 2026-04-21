# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note: This utility is considered private, and can only be referenced from inside the vmware.vmware collection.
#       It may be made public at a later date

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import time
import traceback
from random import randint

from ansible.module_utils.common.text.converters import to_text

PYVMOMI_IMP_ERR = None
try:
    from pyVmomi import vim
    HAS_PYVMOMI = True
except ImportError:
    PYVMOMI_IMP_ERR = traceback.format_exc()
    HAS_PYVMOMI = False


class TaskError(Exception):
    def __init__(self, message, **kwargs):
        self.__dict__.update(kwargs)
        super(TaskError, self).__init__(message)


class RunningTaskMonitor():
    def __init__(self, task):
        self.task = task

    def wait_for_completion(self, max_backoff=64, timeout=3600, vm=None, answers=None):
        """
        Wait for given task using exponential back-off algorithm.

        Args:
            task: VMware task object
            max_backoff: Maximum amount of sleep time in seconds
            timeout: Timeout for the given task in seconds

        Returns: Tuple with True and result for successful task
        Raises: TaskError on failure
        """
        failure_counter = 0
        start_time = time.time()
        question_handler = VmQuestionHandler(vm, answers)

        while True:
            if vm:
                question_handler.handle_vm_questions()

            if time.time() - start_time >= timeout:
                raise TaskError("Timeout waiting for running task to complete in VMWare")

            if self.is_task_finished_with_success():
                out = {
                    'completion_time': self.task.info.completeTime,
                    'state': self.task.info.state,
                    'result': self.task.info.result,
                    'entity_name': self.task.info.entityName,
                    'error': self.task.info.error
                }
                return True, out

            sleep_time = min(2 ** failure_counter + randint(1, 1000) / 1000, max_backoff)
            time.sleep(sleep_time)
            failure_counter += 1

    def is_task_finished_with_success(self):
        if self.task.info.state == vim.TaskInfo.State.success:
            return True

        if self.task.info.state == vim.TaskInfo.State.error:
            host_thumbprint = getattr(self.task.info.error, 'thumbprint', None)
            error_msg = 'Not Defined'
            try:
                error_msg = self.task.info.error.msg
            except AttributeError:
                error_msg = self.task.info.error
            finally:
                raise TaskError(error_msg, host_thumbprint=host_thumbprint, parent_error=self.task.info.error) from self.task.info.error

        if self.task.info.state in [vim.TaskInfo.State.running, vim.TaskInfo.State.queued]:
            return False


class VmQuestionHandler():
    def __init__(self, vm, answers=None):
        self.vm = vm
        self.answers = answers

    def handle_vm_questions(self):
        """
        Handles a virtual machine that is waiting for a question to be answered.
        See https://knowledge.broadcom.com/external/article/311492/answering-a-virtual-machine-related-ques.html
        for an example of what this looks like in the UI.
        """
        if hasattr(self.vm, "runtime") and self.vm.runtime.question:
            if not self.answers:
                raise TaskError("Unanswered VM question: '%s'" % to_text(self.vm.runtime.question.text))

        responses = self.format_vm_question_responses()
        self.send_vm_question_responses(responses)

    def format_vm_question_responses(self):
        """
        Creates a dictionary of responses to send to a VM waiting with questions.

        Args:
            vm: Virtual machine management object
            answers: Answer contents

        Returns: Dict with answer id and number
        Raises: TaskError on failure
        """
        response_list = {}
        responses = []
        if not self.answers:
            return responses

        for message in self.vm.runtime.question.message:
            response_list[message.id] = {}
            for choice in self.vm.runtime.question.choice.choiceInfo:
                response_list[message.id].update({
                    choice.label: choice.key
                })

        try:
            for answer in self.answers:
                responses.append({
                    "id": self.vm.runtime.question.id,
                    "response_num": response_list[answer["question"]][answer["response"]]
                })
        except KeyError:
            raise TaskError("Could not find %s or %s in the response list" % (answer["question"], answer["response"]))

        return responses

    def send_vm_question_responses(self, responses):
        """
        Answer against the question for unlocking a virtual machine.

        Args:
            vm: Virtual machine management object
            responses: Answer contents to unlock a virtual machine
        """
        for response in responses:
            try:
                self.vm.AnswerVM(response["id"], response["response_num"])
            except Exception as e:
                raise TaskError("Answer failed: %s" % to_text(e))
