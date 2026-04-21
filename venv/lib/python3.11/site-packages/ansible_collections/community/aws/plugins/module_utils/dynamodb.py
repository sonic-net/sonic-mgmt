# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

try:
    import botocore
except ImportError:
    pass  # Handled by AnsibleAWSModule

from ansible_collections.community.aws.plugins.module_utils.base import BaseWaiterFactory


class DynamodbWaiterFactory(BaseWaiterFactory):
    def __init__(self, module):
        # the AWSRetry wrapper doesn't support the wait functions (there's no
        # public call we can cleanly wrap)
        client = module.client("dynamodb")
        super().__init__(module, client)

    @property
    def _waiter_model_data(self):
        data = super()._waiter_model_data
        ddb_data = dict(
            table_exists=dict(
                operation="DescribeTable",
                delay=20,
                maxAttempts=25,
                acceptors=[
                    dict(expected="ACTIVE", matcher="path", state="success", argument="Table.TableStatus"),
                    dict(expected="ResourceNotFoundException", matcher="error", state="retry"),
                ],
            ),
            table_not_exists=dict(
                operation="DescribeTable",
                delay=20,
                maxAttempts=25,
                acceptors=[
                    dict(expected="ResourceNotFoundException", matcher="error", state="success"),
                ],
            ),
            global_indexes_active=dict(
                operation="DescribeTable",
                delay=20,
                maxAttempts=25,
                acceptors=[
                    dict(expected="ResourceNotFoundException", matcher="error", state="failure"),
                    # If there are no secondary indexes, simply return
                    dict(
                        expected=False,
                        matcher="path",
                        state="success",
                        argument="contains(keys(Table), `GlobalSecondaryIndexes`)",
                    ),
                    dict(
                        expected="ACTIVE",
                        matcher="pathAll",
                        state="success",
                        argument="Table.GlobalSecondaryIndexes[].IndexStatus",
                    ),
                    dict(
                        expected="CREATING",
                        matcher="pathAny",
                        state="retry",
                        argument="Table.GlobalSecondaryIndexes[].IndexStatus",
                    ),
                    dict(
                        expected="UPDATING",
                        matcher="pathAny",
                        state="retry",
                        argument="Table.GlobalSecondaryIndexes[].IndexStatus",
                    ),
                    dict(
                        expected="DELETING",
                        matcher="pathAny",
                        state="retry",
                        argument="Table.GlobalSecondaryIndexes[].IndexStatus",
                    ),
                    dict(
                        expected=True,
                        matcher="path",
                        state="success",
                        argument="length(Table.GlobalSecondaryIndexes) == `0`",
                    ),
                ],
            ),
        )
        data.update(ddb_data)
        return data


def _do_wait(module, waiter_name, action_description, wait_timeout, table_name):
    delay = min(wait_timeout, 5)
    max_attempts = wait_timeout // delay

    try:
        waiter = DynamodbWaiterFactory(module).get_waiter(waiter_name)
        waiter.wait(
            WaiterConfig={"Delay": delay, "MaxAttempts": max_attempts},
            TableName=table_name,
        )
    except botocore.exceptions.WaiterError as e:
        module.fail_json_aws(e, msg=f"Timeout while waiting for {action_description}")
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.BotoCoreError,
    ) as e:  # pylint: disable=duplicate-except
        module.fail_json_aws(e, msg=f"Failed while waiting for {action_description}")


def wait_table_exists(module, wait_timeout, table_name):
    _do_wait(module, "table_exists", "table creation", wait_timeout, table_name)


def wait_table_not_exists(module, wait_timeout, table_name):
    _do_wait(module, "table_not_exists", "table deletion", wait_timeout, table_name)


def wait_indexes_active(module, wait_timeout, table_name):
    _do_wait(module, "global_indexes_active", "secondary index updates", wait_timeout, table_name)
