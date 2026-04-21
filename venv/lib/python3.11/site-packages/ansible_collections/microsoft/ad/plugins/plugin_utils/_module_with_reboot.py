# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Run module with reboot handler

This code contains the skeleton needed for action plugins to run a module with
an automatic reboot handler. Right now it should only be used in this
collection as the interface is not final and count be subject to change.
"""

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import typing as t

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible.utils.vars import merge_hash

from ._reboot import reboot_host

display = Display()


class ActionModuleWithReboot(ActionBase):
    """Action Plugin with Auto Reboot.

    An action plugin that can be used to automatically reboot the host after
    running a module. By default it checks for the return value reboot_required
    and reboots the host if it is present.

    There are method that can be overloaded in the sub class to control the
    behaviour like retries, whether to reboot, etc.
    """

    def _ad_should_reboot(self, result: t.Dict[str, t.Any]) -> bool:
        """Check whether a reboot is to be done

        Called after the module is run and is used to check if the reboot
        should be performed. The default check is to see if reboot_required
        was returned by the module.

        Args:
            result: The module result.

        Returns:
            bool: Whether to do a reboot or not.
        """
        return result.get("reboot_required", False)

    def _ad_should_rerun(self, result: t.Dict[str, t.Any]) -> bool:
        """Check whether to rerun the module.

        Called after the reboot is completed and used to check whether the
        module should be rerun. The default is to not rerun the module.

        Args:
            result: The module result.

        Returns:
            bool: Whether to rerun the module again.
        """
        return False

    def _ad_process_result(self, result: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
        """Called at the end of the run.

        Called at the end of the plugin run for the sub class to edit the
        result as needed. The default is for the result to be returned as is.

        Args:
            result: The module result.

        Returns:
            Dict[str, Any]: The final result to return.
        """
        return result

    def _ad_set_rebooted(
        self,
        result: t.Dict[str, t.Any],
        reboot_result: t.Dict[str, t.Any],
    ) -> None:
        """Called when a reboot is done.

        Called when the reboot has been performed. The sub class can use this
        to edit the result or do additional checks as needed. The default is to
        set the reboot_required return value to False if it is in the module
        result.

        Args:
            result: The module result.
            reboot_result: The result from the reboot
        """
        if "reboot_required" in result:
            result["reboot_required"] = False

    def run(
        self,
        tmp: t.Optional[str] = None,
        task_vars: t.Optional[t.Dict[str, t.Any]] = None,
    ) -> t.Dict[str, t.Any]:
        self._supports_check_mode = True
        self._supports_async = True

        result = super().run(tmp=tmp, task_vars=task_vars)
        del tmp

        wrap_async = self._task.async_val and not self._connection.has_native_async
        reboot = self._task.args.get("reboot", False)
        reboot_timeout = self._task.args.get("reboot_timeout", 600)

        if self._task.async_val > 0 and reboot:
            return {
                "failed": True,
                "msg": "async is not supported for this task when reboot=true",
                "changed": False,
            }

        invocation = None
        while True:
            module_res = self._execute_module(
                task_vars=task_vars,
                wrap_async=wrap_async,
            )
            invocation = module_res.pop("invocation", None)

            if reboot and self._ad_should_reboot(module_res):
                previous_boot_time = module_res.pop("_previous_boot_time", None)

                if self._task.check_mode:
                    reboot_res = {}
                else:
                    reboot_res = reboot_host(
                        self._task.action,
                        self._connection,
                        reboot_timeout=reboot_timeout,
                        previous_boot_time=previous_boot_time,
                    )

                if reboot_res.get("failed", False):
                    module_res = {
                        "changed": module_res.get("changed", False),
                        "failed": True,
                        "msg": "Failed to reboot after module returned reboot_required, see reboot_result and module_result for more details",
                        "reboot_result": reboot_res,
                        "module_result": module_res,
                    }
                    break

                # Regardless of the module result this needs to be True as a
                # reboot happened.
                module_res["changed"] = True
                self._ad_set_rebooted(module_res, reboot_res)

                if self._ad_should_rerun(module_res) and not self._task.check_mode:
                    display.vv(
                        "Module result has indicated it should rerun after a reboot has occurred, rerunning"
                    )
                    continue

            break

        # Make sure the invocation details from the module are still present.
        if invocation is not None:
            module_res["invocation"] = invocation

        result = merge_hash(result, module_res)

        return self._ad_process_result(result)


class DomainPromotionWithReboot(ActionModuleWithReboot):
    """Domain Promotion Action Plugin with Auto Reboot.

    An action plugin that runs a task that can promote the target Windows host
    to a domain controller. It implements the common reboot handling for that
    particular task.
    """

    def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
        super().__init__(*args, **kwargs)
        self._ran_once = False

    def _ad_should_rerun(self, result: t.Dict[str, t.Any]) -> bool:
        ran_once = self._ran_once
        self._ran_once = True

        if ran_once or not result.get("_do_action_reboot", False):
            return False

        if self._task.check_mode:
            # Assume that on a rerun it will not have failed and that it
            # ran successful.
            result["failed"] = False
            result.pop("msg", None)
            return False

        else:
            return True

    def _ad_process_result(self, result: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
        result.pop("_do_action_reboot", None)

        return result
