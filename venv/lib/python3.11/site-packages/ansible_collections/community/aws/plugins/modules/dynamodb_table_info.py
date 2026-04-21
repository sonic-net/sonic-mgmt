#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: dynamodb_table_info
version_added: 7.2.0
short_description: Returns information about a Dynamo DB table
description:
  - Returns information about the Dynamo DB table, including the current status of the table,
    when it was created, the primary key schema, and any indexes on the table.
author:
  - Aubin Bikouo (@abikouo)
options:
  name:
    description:
      - The name of the table to describe.
    required: true
    type: str
extends_documentation_fragment:
  - amazon.aws.common.modules
  - amazon.aws.region.modules
  - amazon.aws.boto3
"""

EXAMPLES = r"""
- name: Return information about the DynamoDB table named 'my-table'
  community.aws.dynamodb_table_info:
    name: my-table
"""

RETURN = r"""
table:
    description: The returned table params from the describe API call.
    returned: success
    type: complex
    contains:
        table_name:
            description: The name of the table.
            returned: always
            type: str
        table_status:
            description: The current state of the table.
            returned: always
            type: str
            sample: 'ACTIVE'
        creation_date_time:
            description: The date and time when the table was created, in UNIX epoch time format.
            returned: always
            type: str
        table_size_bytes:
            description: The total size of the specified table, in bytes.
            returned: always
            type: int
        item_count:
            description: The number of items in the specified table.
            returned: always
            type: int
        table_arn:
            description: The Amazon Resource Name (ARN) that uniquely identifies the table.
            returned: always
            type: str
        table_id:
            description: Unique identifier for the table for which the backup was created.
            returned: always
            type: str
        attribute_definitions:
            description: A list of attributes for describing the key schema for the table and indexes.
            returned: always
            type: complex
            contains:
                attribute_name:
                    description: A name for the attribute.
                    type: str
                    returned: always
                attribute_type:
                    description: The data type for the attribute, S (String), N (Number) and B (Binary).
                    type: str
                    returned: always
        key_schema:
            description: A list of key schemas that specify the attributes that make up the primary key of a table, or the key attributes of an index.
            returned: always
            type: complex
            contains:
                attribute_name:
                    description: The name of a key attribute.
                    type: str
                    returned: always
                key_type:
                    description: The role that this key attribute will assume, 'HASH' for partition key, 'RANGE' for sort key
                    type: str
                    returned: always
        billing_mode:
            description: Controls how you are charged for read and write throughput and how you manage capacity.
            returned: always
            type: str
        local_secondary_indexes:
            description: Represents one or more local secondary indexes on the table.
            returned: if any, on the table
            type: list
            elements: dict
        global_secondary_indexes:
            description: The global secondary indexes of table.
            returned: if any, on the table
            type: list
            elements: dict
        stream_specification:
            description:  The current DynamoDB Streams configuration for the table.
            returned: if any, on the table
            type: complex
            contains:
                stream_enabled:
                    description: Indicates whether DynamoDB Streams is enabled (true) or disabled (false) on the table.
                    type: bool
                    returned: always
                    sample: true
                stream_view_type:
                    description: When an item in the table is modified, stream_view_type determines what information is written to the stream for this table.
                    type: str
                    returned: always
                    sample: KEYS_ONLY
        latest_stream_label:
            description: A timestamp, in ISO 8601 format, for this stream.
            type: str
            returned: if any on the table
        latest_stream_arn:
            description: The Amazon Resource Name (ARN) that uniquely identifies the latest stream for this table.
            returned: if any on the table
            type: str
        global_table_version:
            description: Represents the version of global tables in use, if the table is replicated across AWS Regions.
            type: str
            returned: if the table is replicated
        replicas:
            description: Represents replicas of the table.
            type: list
            elements: dict
            returned: if any on the table
        source_backup_arn:
            description: The Amazon Resource Name (ARN) of the backup from which the table was restored.
            type: str
            returned: if any, on the table
        source_table_arn:
            description: The ARN of the source table of the backup that is being restored.
            type: str
            returned: if any, on the table
        restore_date_time:
            description: Point in time or source backup time.
            type: str
            returned: if any, on table
        restore_in_progress:
            description: Indicates if a restore is in progress or not.
            type: bool
            returned: if any, on table
        sse_description:
            description: The description of the server-side encryption status on the specified table.
            type: dict
            returned: if any, on table
            sample: {}
        archival_summary:
            description: Contains information about the table archive.
            type: complex
            returned: if any, on table
            contains:
                archival_date_time:
                    description:  The date and time when table archival was initiated by DynamoDB, in UNIX epoch time format.
                    type: str
                    returned: always
                archival_reason:
                    description: The reason DynamoDB archived the table.
                    type: str
                    returned: always
                    sample: INACCESSIBLE_ENCRYPTION_CREDENTIALS
                archival_backup_arn:
                    description: The Amazon Resource Name (ARN) of the backup the table was archived to, when applicable in the archival reason.
                    type: str
                    returned: always
        table_class:
            description: The table class of the specified table.
            type: str
            returned: if any on the table
            sample: STANDARD_INFREQUENT_ACCESS
        deletion_protection_enabled:
            description: Indicates whether deletion protection is enabled (true) or disabled (false) on the table.
            type: bool
            returned: always
            sample: true
        provisioned_throughput:
            description: The provisioned throughput settings for the table.
            type: dict
            returned: always
            sample: '{"number_of_decreases_today": 0, "read_capacity_units": 1, "write_capacity_units": 1}'
        tags:
            description: A dict of tags associated with the DynamoDB table.
            returned: always
            type: dict
"""

try:
    import botocore
except ImportError:
    pass  # Handled by AnsibleAWSModule

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict

from ansible_collections.amazon.aws.plugins.module_utils.botocore import is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.retries import AWSRetry
from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_list_to_ansible_dict

from ansible_collections.community.aws.plugins.module_utils.modules import AnsibleCommunityAWSModule as AnsibleAWSModule


# ResourceNotFoundException is expected here if the table doesn't exist
@AWSRetry.jittered_backoff(catch_extra_error_codes=["LimitExceededException", "ResourceInUseException"])
def _describe_table(client, **params):
    return client.describe_table(**params)


def describe_dynamodb_table(module):
    table_name = module.params.get("name")
    retry_decorator = AWSRetry.jittered_backoff(
        catch_extra_error_codes=["LimitExceededException", "ResourceInUseException", "ResourceNotFoundException"],
    )
    client = module.client("dynamodb", retry_decorator=retry_decorator)
    try:
        table = _describe_table(client, TableName=table_name)
    except is_boto3_error_code("ResourceNotFoundException"):
        module.exit_json(table={})
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.BotoCoreError,
    ) as e:  # pylint: disable=duplicate-except
        module.fail_json_aws(e, msg="Failed to describe table")

    table = table["Table"]
    try:
        tags = client.list_tags_of_resource(aws_retry=True, ResourceArn=table["TableArn"])["Tags"]
    except is_boto3_error_code("AccessDeniedException"):
        module.warn("Permission denied when listing tags")
        tags = []
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.BotoCoreError,
    ) as e:  # pylint: disable=duplicate-except
        module.fail_json_aws(e, msg="Failed to list table tags")

    table = camel_dict_to_snake_dict(table)
    table["tags"] = boto3_tag_list_to_ansible_dict(tags)

    if "table_class_summary" in table:
        table["table_class"] = table["table_class_summary"]["table_class"]
        del table["table_class_summary"]

    # billing_mode_summary doesn't always seem to be set but is always set for PAY_PER_REQUEST
    # and when updating the billing_mode
    if "billing_mode_summary" in table:
        table["billing_mode"] = table["billing_mode_summary"]["billing_mode"]
        del table["billing_mode_summary"]
    else:
        table["billing_mode"] = "PROVISIONED"

    # Restore summary
    if "restore_summary" in table:
        table["source_backup_arn"] = table["restore_summary"].get("source_backup_arn", "")
        table["source_table_arn"] = table["restore_summary"].get("source_table_arn", "")
        table["restore_date_time"] = table["restore_summary"].get("restore_date_time", "")
        table["restore_in_progress"] = table["restore_summary"].get("restore_in_progress")
        del table["restore_summary"]

    module.exit_json(table=table)


def main():
    argument_spec = dict(
        name=dict(
            required=True,
        ),
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    describe_dynamodb_table(module)


if __name__ == "__main__":
    main()
