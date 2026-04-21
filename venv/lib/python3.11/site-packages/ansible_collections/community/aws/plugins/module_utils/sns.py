# -*- coding: utf-8 -*-

# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import copy
import re

try:
    import botocore
except ImportError:
    pass  # handled by AnsibleAWSModule

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict

from ansible_collections.amazon.aws.plugins.module_utils.botocore import is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.retries import AWSRetry
from ansible_collections.amazon.aws.plugins.module_utils.tagging import ansible_dict_to_boto3_tag_list
from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_list_to_ansible_dict
from ansible_collections.amazon.aws.plugins.module_utils.tagging import compare_aws_tags


@AWSRetry.jittered_backoff()
def _list_topics_with_backoff(client):
    paginator = client.get_paginator("list_topics")
    return paginator.paginate().build_full_result()["Topics"]


@AWSRetry.jittered_backoff(catch_extra_error_codes=["NotFound"])
def _list_topic_subscriptions_with_backoff(client, topic_arn):
    paginator = client.get_paginator("list_subscriptions_by_topic")
    return paginator.paginate(TopicArn=topic_arn).build_full_result()["Subscriptions"]


@AWSRetry.jittered_backoff(catch_extra_error_codes=["NotFound"])
def _list_subscriptions_with_backoff(client):
    paginator = client.get_paginator("list_subscriptions")
    return paginator.paginate().build_full_result()["Subscriptions"]


def list_topic_subscriptions(client, module, topic_arn):
    try:
        return _list_topic_subscriptions_with_backoff(client, topic_arn)
    except is_boto3_error_code("AuthorizationError"):
        try:
            # potentially AuthorizationError when listing subscriptions for third party topic
            return [sub for sub in _list_subscriptions_with_backoff(client) if sub["TopicArn"] == topic_arn]
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg=f"Couldn't get subscriptions list for topic {topic_arn}")
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.BotoCoreError,
    ) as e:  # pylint: disable=duplicate-except
        module.fail_json_aws(e, msg=f"Couldn't get subscriptions list for topic {topic_arn}")


def list_topics(client, module):
    try:
        topics = _list_topics_with_backoff(client)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg="Couldn't get topic list")
    return [t["TopicArn"] for t in topics]


def topic_arn_lookup(client, module, name):
    # topic names cannot have colons, so this captures the full topic name
    all_topics = list_topics(client, module)
    lookup_topic = f":{name}"
    for topic in all_topics:
        if topic.endswith(lookup_topic):
            return topic


def compare_delivery_policies(policy_a, policy_b):
    _policy_a = copy.deepcopy(policy_a)
    _policy_b = copy.deepcopy(policy_b)
    # AWS automatically injects disableSubscriptionOverrides if you set an
    # http policy
    if "http" in policy_a:
        if "disableSubscriptionOverrides" not in policy_a["http"]:
            _policy_a["http"]["disableSubscriptionOverrides"] = False
    if "http" in policy_b:
        if "disableSubscriptionOverrides" not in policy_b["http"]:
            _policy_b["http"]["disableSubscriptionOverrides"] = False
    comparison = _policy_a != _policy_b
    return comparison


def canonicalize_endpoint(protocol, endpoint):
    # AWS SNS expects phone numbers in
    # and canonicalizes to E.164 format
    # See <https://docs.aws.amazon.com/sns/latest/dg/sms_publish-to-phone.html>
    if protocol == "sms":
        return re.sub("[^0-9+]*", "", endpoint)
    return endpoint


def get_tags(client, module, topic_arn):
    try:
        return boto3_tag_list_to_ansible_dict(client.list_tags_for_resource(ResourceArn=topic_arn)["Tags"])
    except is_boto3_error_code("AuthorizationError"):
        module.warn("Permission denied accessing tags")
        return {}
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg="Couldn't obtain topic tags")


def get_info(connection, module, topic_arn):
    name = module.params.get("name")
    topic_type = module.params.get("topic_type")
    state = module.params.get("state")
    subscriptions = module.params.get("subscriptions")
    purge_subscriptions = module.params.get("purge_subscriptions")
    content_based_deduplication = module.params.get("content_based_deduplication")
    subscriptions_existing = module.params.get("subscriptions_existing", [])
    subscriptions_deleted = module.params.get("subscriptions_deleted", [])
    subscriptions_added = module.params.get("subscriptions_added", [])
    subscriptions_added = module.params.get("subscriptions_added", [])
    topic_created = module.params.get("topic_created", False)
    topic_deleted = module.params.get("topic_deleted", False)
    attributes_set = module.params.get("attributes_set", [])
    check_mode = module.check_mode

    info = {
        "name": name,
        "topic_type": topic_type,
        "state": state,
        "subscriptions_new": subscriptions,
        "subscriptions_existing": subscriptions_existing,
        "subscriptions_deleted": subscriptions_deleted,
        "subscriptions_added": subscriptions_added,
        "subscriptions_purge": purge_subscriptions,
        "content_based_deduplication": content_based_deduplication,
        "check_mode": check_mode,
        "topic_created": topic_created,
        "topic_deleted": topic_deleted,
        "attributes_set": attributes_set,
    }
    if state != "absent":
        if topic_arn in list_topics(connection, module):
            info.update(camel_dict_to_snake_dict(connection.get_topic_attributes(TopicArn=topic_arn)["Attributes"]))
            info["delivery_policy"] = info.pop("effective_delivery_policy")
        info["subscriptions"] = [
            camel_dict_to_snake_dict(sub) for sub in list_topic_subscriptions(connection, module, topic_arn)
        ]
        info["tags"] = get_tags(connection, module, topic_arn)
    return info


def update_tags(client, module, topic_arn):
    if module.params.get("tags") is None:
        return False

    existing_tags = get_tags(client, module, topic_arn)
    to_update, to_delete = compare_aws_tags(existing_tags, module.params["tags"], module.params["purge_tags"])

    if not bool(to_delete or to_update):
        return False

    if module.check_mode:
        return True

    if to_update:
        try:
            client.tag_resource(ResourceArn=topic_arn, Tags=ansible_dict_to_boto3_tag_list(to_update))
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg="Couldn't add tags to topic")
    if to_delete:
        try:
            client.untag_resource(ResourceArn=topic_arn, TagKeys=to_delete)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, msg="Couldn't remove tags from topic")

    return True
