from __future__ import absolute_import, division, print_function

__metaclass__ = type


from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    prepare_rule_params_for_execute_module,
    check_if_to_publish_for_action,
)


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):

        module = super(ActionModule, self).run(tmp, task_vars)

        result = self._execute_module(
            module_name="check_point.mgmt.cp_mgmt_access_rules",
            module_args=self._task.args,
            task_vars=task_vars,
            tmp=tmp,
        )

        if "msg" in result.keys():
            raise AnsibleActionFail(result["msg"])

        module_args = self._task.args

        fields = {"position", "layer", "auto_publish_session"}
        rules_list = module_args["rules"]
        for rule in rules_list:
            for field in fields:
                if field in rule.keys():
                    raise AnsibleActionFail(
                        "Unsupported parameter " + field + " for rule"
                    )
        # check_fields_for_rule_action_module(module_args)
        rules_list = self._task.args["rules"]
        position = 1
        below_rule_name = None

        for rule in rules_list:
            (
                rule,
                position,
                below_rule_name,
            ) = prepare_rule_params_for_execute_module(
                rule=rule,
                module_args=module_args,
                position=position,
                below_rule_name=below_rule_name,
            )

            result["rule: " + rule["name"]] = self._execute_module(
                module_name="check_point.mgmt.cp_mgmt_access_rule",
                module_args=rule,
                task_vars=task_vars,
                tmp=tmp,
                wrap_async=False,
            )
            if (
                "changed" in result["rule: " + rule["name"]].keys()
                and result["rule: " + rule["name"]]["changed"] is True
            ):
                result["changed"] = True
            if (
                "failed" in result["rule: " + rule["name"]].keys()
                and result["rule: " + rule["name"]]["failed"] is True
            ):
                temp = result["rule: " + rule["name"]].copy()
                result = {}
                result["rule: " + rule["name"]] = temp
                result["failed"] = True
                result["discard:"] = self._execute_module(
                    module_name="check_point.mgmt.cp_mgmt_discard",
                    module_args={},
                    task_vars=task_vars,
                    tmp=tmp,
                )
                break
        if check_if_to_publish_for_action(result, module_args):
            result["publish:"] = self._execute_module(
                module_name="check_point.mgmt.cp_mgmt_publish",
                module_args={},
                task_vars=task_vars,
                tmp=tmp,
            )

        return result
