# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import time
from copy import deepcopy

from ansible.module_utils._text import to_text
from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict
from ansible.module_utils.six import string_types

from ansible_collections.amazon.aws.plugins.module_utils.arn import parse_aws_arn
from ansible_collections.amazon.aws.plugins.module_utils.botocore import is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.retries import AWSRetry
from ansible_collections.amazon.aws.plugins.module_utils.tagging import ansible_dict_to_boto3_tag_list
from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_list_to_ansible_dict
from ansible_collections.amazon.aws.plugins.module_utils.tagging import compare_aws_tags

from ansible_collections.community.aws.plugins.module_utils.base import BaseResourceManager
from ansible_collections.community.aws.plugins.module_utils.base import BaseWaiterFactory
from ansible_collections.community.aws.plugins.module_utils.base import Boto3Mixin
from ansible_collections.community.aws.plugins.module_utils.ec2 import BaseEc2Manager


def _merge_set(current, new, purge):
    _current = set(current)
    _new = set(new)
    if purge:
        final = _new
    else:
        final = _new | _current

    return final


def _merge_dict(current, new, purge):
    _current = deepcopy(current)
    if purge:
        final = dict()
    else:
        final = _current
    final.update(new)

    return final


def _string_list(value):
    if isinstance(value, string_types):
        value = [value]
    elif isinstance(value, bool):
        value = [to_text(value).lower()]
    elif isinstance(value, list):
        value = [to_text(v) for v in value]
    else:
        value = [to_text(value)]
    return value


class NetworkFirewallWaiterFactory(BaseWaiterFactory):
    def __init__(self, module):
        # the AWSRetry wrapper doesn't support the wait functions (there's no
        # public call we can cleanly wrap)
        client = module.client("network-firewall")
        super(NetworkFirewallWaiterFactory, self).__init__(module, client)

    @property
    def _waiter_model_data(self):
        data = super(NetworkFirewallWaiterFactory, self)._waiter_model_data
        nw_data = dict(
            rule_group_active=dict(
                operation="DescribeRuleGroup",
                delay=5,
                maxAttempts=120,
                acceptors=[
                    dict(
                        state="failure",
                        matcher="path",
                        expected="DELETING",
                        argument="RuleGroupResponse.RuleGroupStatus",
                    ),
                    dict(
                        state="success", matcher="path", expected="ACTIVE", argument="RuleGroupResponse.RuleGroupStatus"
                    ),
                ],
            ),
            rule_group_deleted=dict(
                operation="DescribeRuleGroup",
                delay=5,
                maxAttempts=120,
                acceptors=[
                    dict(
                        state="retry", matcher="path", expected="DELETING", argument="RuleGroupResponse.RuleGroupStatus"
                    ),
                    dict(state="success", matcher="error", expected="ResourceNotFoundException"),
                ],
            ),
            policy_active=dict(
                operation="DescribeFirewallPolicy",
                delay=5,
                maxAttempts=120,
                acceptors=[
                    dict(
                        state="failure",
                        matcher="path",
                        expected="DELETING",
                        argument="FirewallPolicyResponse.FirewallPolicyStatus",
                    ),
                    dict(
                        state="success",
                        matcher="path",
                        expected="ACTIVE",
                        argument="FirewallPolicyResponse.FirewallPolicyStatus",
                    ),
                ],
            ),
            policy_deleted=dict(
                operation="DescribeFirewallPolicy",
                delay=5,
                maxAttempts=120,
                acceptors=[
                    dict(
                        state="retry",
                        matcher="path",
                        expected="DELETING",
                        argument="FirewallPolicyResponse.FirewallPolicyStatus",
                    ),
                    dict(state="success", matcher="error", expected="ResourceNotFoundException"),
                ],
            ),
            firewall_active=dict(
                operation="DescribeFirewall",
                delay=5,
                maxAttempts=120,
                acceptors=[
                    dict(state="failure", matcher="path", expected="DELETING", argument="FirewallStatus.Status"),
                    dict(state="retry", matcher="path", expected="PROVISIONING", argument="FirewallStatus.Status"),
                    dict(state="success", matcher="path", expected="READY", argument="FirewallStatus.Status"),
                ],
            ),
            firewall_updated=dict(
                operation="DescribeFirewall",
                delay=5,
                maxAttempts=240,
                acceptors=[
                    dict(state="failure", matcher="path", expected="DELETING", argument="FirewallStatus.Status"),
                    dict(state="retry", matcher="path", expected="PROVISIONING", argument="FirewallStatus.Status"),
                    dict(
                        state="retry",
                        matcher="path",
                        expected="PENDING",
                        argument="FirewallStatus.ConfigurationSyncStateSummary",
                    ),
                    dict(
                        state="success",
                        matcher="path",
                        expected="IN_SYNC",
                        argument="FirewallStatus.ConfigurationSyncStateSummary",
                    ),
                ],
            ),
            firewall_deleted=dict(
                operation="DescribeFirewall",
                delay=5,
                maxAttempts=240,
                acceptors=[
                    dict(state="retry", matcher="path", expected="DELETING", argument="FirewallStatus.Status"),
                    dict(state="success", matcher="error", expected="ResourceNotFoundException"),
                ],
            ),
        )
        data.update(nw_data)
        return data


class NetworkFirewallBoto3Mixin(Boto3Mixin):
    def __init__(self, module):
        r"""
        Parameters:
            module (AnsibleAWSModule): An Ansible module.
        """
        self.nf_waiter_factory = NetworkFirewallWaiterFactory(module)
        super(NetworkFirewallBoto3Mixin, self).__init__(module)
        self._update_token = None


class NFRuleGroupBoto3Mixin(NetworkFirewallBoto3Mixin):
    # Paginators can't be (easily) wrapped, so we wrap this method with the
    # retry - retries the full fetch, but better than simply giving up.
    @AWSRetry.jittered_backoff()
    def _paginated_list_rule_groups(self, **params):
        paginator = self.client.get_paginator("list_rule_groups")
        result = paginator.paginate(**params).build_full_result()
        return result.get("RuleGroups", None)

    @Boto3Mixin.aws_error_handler("list all rule groups")
    def _list_rule_groups(self, **params):
        return self._paginated_list_rule_groups(**params)

    @Boto3Mixin.aws_error_handler("describe rule group")
    def _describe_rule_group(self, **params):
        try:
            result = self.client.describe_rule_group(aws_retry=True, **params)
        except is_boto3_error_code("ResourceNotFoundException"):
            return None

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        rule_group = result.get("RuleGroup", None)
        metadata = result.get("RuleGroupResponse", None)
        return dict(RuleGroup=rule_group, RuleGroupMetadata=metadata)

    @Boto3Mixin.aws_error_handler("create rule group")
    def _create_rule_group(self, **params):
        result = self.client.create_rule_group(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("RuleGroupResponse", None)

    @Boto3Mixin.aws_error_handler("update rule group")
    def _update_rule_group(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.update_rule_group(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("RuleGroupResponse", None)

    @Boto3Mixin.aws_error_handler("delete rule group")
    def _delete_rule_group(self, **params):
        try:
            result = self.client.delete_rule_group(aws_retry=True, **params)
        except is_boto3_error_code("ResourceNotFoundException"):
            return None

        return result.get("RuleGroupResponse", None)

    @Boto3Mixin.aws_error_handler("firewall rule to finish deleting")
    def _wait_rule_group_deleted(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("rule_group_deleted")
        waiter.wait(**params)

    @Boto3Mixin.aws_error_handler("firewall rule to become active")
    def _wait_rule_group_active(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("rule_group_active")
        waiter.wait(**params)


class NFPolicyBoto3Mixin(NetworkFirewallBoto3Mixin):
    # Paginators can't be (easily) wrapped, so we wrap this method with the
    # retry - retries the full fetch, but better than simply giving up.
    @AWSRetry.jittered_backoff()
    def _paginated_list_policies(self, **params):
        paginator = self.client.get_paginator("list_firewall_policies")
        result = paginator.paginate(**params).build_full_result()
        return result.get("FirewallPolicies", None)

    @Boto3Mixin.aws_error_handler("list all firewall policies")
    def _list_policies(self, **params):
        return self._paginated_list_policies(**params)

    @Boto3Mixin.aws_error_handler("describe firewall policy")
    def _describe_policy(self, **params):
        try:
            result = self.client.describe_firewall_policy(aws_retry=True, **params)
        except is_boto3_error_code("ResourceNotFoundException"):
            return None

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        policy = result.get("FirewallPolicy", None)
        metadata = result.get("FirewallPolicyResponse", None)
        return dict(FirewallPolicy=policy, FirewallPolicyMetadata=metadata)

    @Boto3Mixin.aws_error_handler("create firewall policy")
    def _create_policy(self, **params):
        result = self.client.create_firewall_policy(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallPolicyResponse", None)

    @Boto3Mixin.aws_error_handler("update firewall policy")
    def _update_policy(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.update_firewall_policy(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallPolicyResponse", None)

    @Boto3Mixin.aws_error_handler("delete firewall policy")
    def _delete_policy(self, **params):
        try:
            result = self.client.delete_firewall_policy(aws_retry=True, **params)
        except is_boto3_error_code("ResourceNotFoundException"):
            return None

        return result.get("FirewallPolicyResponse", None)

    @Boto3Mixin.aws_error_handler("firewall policy to finish deleting")
    def _wait_policy_deleted(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("policy_deleted")
        waiter.wait(**params)

    @Boto3Mixin.aws_error_handler("firewall policy to become active")
    def _wait_policy_active(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("policy_active")
        waiter.wait(**params)


class NFFirewallBoto3Mixin(NetworkFirewallBoto3Mixin):
    # Paginators can't be (easily) wrapped, so we wrap this method with the
    # retry - retries the full fetch, but better than simply giving up.
    @AWSRetry.jittered_backoff()
    def _paginated_list_firewalls(self, **params):
        paginator = self.client.get_paginator("list_firewalls")
        result = paginator.paginate(**params).build_full_result()
        return result.get("Firewalls", None)

    @Boto3Mixin.aws_error_handler("list all firewalls")
    def _list_firewalls(self, **params):
        return self._paginated_list_firewalls(**params)

    @Boto3Mixin.aws_error_handler("describe firewall")
    def _describe_firewall(self, **params):
        try:
            result = self.client.describe_firewall(aws_retry=True, **params)
        except is_boto3_error_code("ResourceNotFoundException"):
            return None

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        firewall = result.get("Firewall", None)
        metadata = result.get("FirewallStatus", None)
        return dict(Firewall=firewall, FirewallMetadata=metadata)

    @Boto3Mixin.aws_error_handler("create firewall")
    def _create_firewall(self, **params):
        result = self.client.create_firewall(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallStatus", None)

    @Boto3Mixin.aws_error_handler("update firewall description")
    def _update_firewall_description(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.update_firewall_description(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("update firewall subnet change protection")
    def _update_subnet_change_protection(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.update_subnet_change_protection(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("update firewall policy change protection")
    def _update_firewall_policy_change_protection(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.update_firewall_policy_change_protection(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("update firewall deletion protection")
    def _update_firewall_delete_protection(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.update_firewall_delete_protection(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("associate policy with firewall")
    def _associate_firewall_policy(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.associate_firewall_policy(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("associate subnets with firewall")
    def _associate_subnets(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.associate_subnets(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("disassociate subnets from firewall")
    def _disassociate_subnets(self, **params):
        if self._update_token and "UpdateToken" not in params:
            params["UpdateToken"] = self._update_token
        result = self.client.disassociate_subnets(aws_retry=True, **params)

        update_token = result.get("UpdateToken", None)
        if update_token:
            self._update_token = update_token
        return result.get("FirewallName", None)

    @Boto3Mixin.aws_error_handler("delete firewall")
    def _delete_firewall(self, **params):
        try:
            result = self.client.delete_firewall(aws_retry=True, **params)
        except is_boto3_error_code("ResourceNotFoundException"):
            return None

        return result.get("FirewallStatus", None)

    @Boto3Mixin.aws_error_handler("firewall to finish deleting")
    def _wait_firewall_deleted(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("firewall_deleted")
        waiter.wait(**params)

    @Boto3Mixin.aws_error_handler("firewall to finish updating")
    def _wait_firewall_updated(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("firewall_updated")
        waiter.wait(**params)

    @Boto3Mixin.aws_error_handler("firewall to become active")
    def _wait_firewall_active(self, **params):
        waiter = self.nf_waiter_factory.get_waiter("firewall_active")
        waiter.wait(**params)


class BaseNetworkFirewallManager(BaseResourceManager):
    def __init__(self, module):
        r"""
        Parameters:
            module (AnsibleAWSModule): An Ansible module.
        """
        super().__init__(module)

        self.client = self._create_client()

        # Network Firewall returns a token when you perform create/get/update
        # actions
        self._preupdate_metadata = dict()
        self._metadata_updates = dict()
        self._tagging_updates = dict()

    @Boto3Mixin.aws_error_handler("connect to AWS")
    def _create_client(self, client_name="network-firewall"):
        client = self.module.client(client_name, retry_decorator=AWSRetry.jittered_backoff())
        return client

    def _get_id_params(self):
        return dict()

    def _check_updates_pending(self):
        if self._metadata_updates:
            return True
        return super(BaseNetworkFirewallManager, self)._check_updates_pending()

    def _merge_metadata_changes(self, filter_immutable=True):
        """
        Merges the contents of the 'pre_update' metadata variables
        with the pending updates
        """
        metadata = deepcopy(self._preupdate_metadata)
        metadata.update(self._metadata_updates)

        if filter_immutable:
            metadata = self._filter_immutable_metadata_attributes(metadata)

        return metadata

    def _merge_changes(self, filter_metadata=True):
        """
        Merges the contents of the 'pre_update' resource and metadata variables
        with the pending updates
        """
        metadata = self._merge_metadata_changes(filter_metadata)
        resource = self._merge_resource_changes()
        return metadata, resource

    def _filter_immutable_metadata_attributes(self, metadata):
        """
        Removes information from the metadata which can't be updated.
        Returns a *copy* of the metadata dictionary.
        """
        meta = deepcopy(metadata)
        meta.pop("LastModifiedTime", None)
        return meta

    def _flush_create(self):
        changed = super(BaseNetworkFirewallManager, self)._flush_create()
        self._metadata_updates = dict()
        return changed

    def _flush_update(self):
        changed = super(BaseNetworkFirewallManager, self)._flush_update()
        self._metadata_updates = dict()
        return changed

    @BaseResourceManager.aws_error_handler("set tags on resource")
    def _add_tags(self, **params):
        self.client.tag_resource(aws_retry=True, **params)
        return True

    @BaseResourceManager.aws_error_handler("unset tags on resource")
    def _remove_tags(self, **params):
        self.client.untag_resource(aws_retry=True, **params)
        return True

    def _get_preupdate_arn(self):
        return self._preupdate_metadata.get("Arn")

    def _set_metadata_value(self, key, value, description=None, immutable=False):
        if value is None:
            return False
        if value == self._get_metadata_value(key):
            return False
        if immutable and self.original_resource:
            if description is None:
                description = key
            self.module.fail_json(msg=f"{description} can not be updated after creation")
        self._metadata_updates[key] = value
        self.changed = True
        return True

    def _get_metadata_value(self, key, default=None):
        return self._metadata_updates.get(key, self._preupdate_metadata.get(key, default))

    def _set_tag_values(self, desired_tags):
        return self._set_metadata_value("Tags", ansible_dict_to_boto3_tag_list(desired_tags))

    def _get_tag_values(self):
        return self._get_metadata_value("Tags", [])

    def _flush_tagging(self):
        changed = False
        tags_to_add = self._tagging_updates.get("add")
        tags_to_remove = self._tagging_updates.get("remove")

        resource_arn = self._get_preupdate_arn()
        if not resource_arn:
            return False

        if tags_to_add:
            changed = True
            tags = ansible_dict_to_boto3_tag_list(tags_to_add)
            if not self.module.check_mode:
                self._add_tags(ResourceArn=resource_arn, Tags=tags)
        if tags_to_remove:
            changed = True
            if not self.module.check_mode:
                self._remove_tags(ResourceArn=resource_arn, TagKeys=tags_to_remove)

        return changed

    def set_tags(self, tags, purge_tags):
        if tags is None:
            return False
        changed = False

        # Tags are returned as a part of the metadata, but have to be updated
        # via dedicated tagging methods
        current_tags = boto3_tag_list_to_ansible_dict(self._get_tag_values())

        # So that diff works in check mode we need to know the full target state
        if purge_tags:
            desired_tags = deepcopy(tags)
        else:
            desired_tags = deepcopy(current_tags)
            desired_tags.update(tags)

        tags_to_add, tags_to_remove = compare_aws_tags(current_tags, tags, purge_tags)

        if tags_to_add:
            self._tagging_updates["add"] = tags_to_add
            changed = True
        if tags_to_remove:
            self._tagging_updates["remove"] = tags_to_remove
            changed = True

        if changed:
            # Tags are a stored as a list, but treated like a list, the
            # simplisic '==' in _set_metadata_value doesn't do the comparison
            # properly
            return self._set_tag_values(desired_tags)

        return False


class NetworkFirewallRuleManager(NFRuleGroupBoto3Mixin, BaseNetworkFirewallManager):
    RULE_TYPES = frozenset(["StatelessRulesAndCustomActions", "StatefulRules", "RulesSourceList", "RulesString"])

    name = None
    rule_type = None
    arn = None

    def __init__(self, module, name=None, rule_type=None, arn=None):
        super().__init__(module)
        # Name parameter is unique (by region) and can not be modified.
        self.name = name
        self.rule_type = rule_type
        self.arn = arn
        if self.name or self.arn:
            rule_group = deepcopy(self.get_rule_group())
            self.original_resource = rule_group

    def _extra_error_output(self):
        output = super(NetworkFirewallRuleManager, self)._extra_error_output()
        if self.name:
            output["RuleGroupName"] = self.name
        if self.rule_type:
            output["Type"] = self.rule_type
        if self.arn:
            output["RuleGroupArn"] = self.arn
        return output

    def _filter_immutable_metadata_attributes(self, metadata):
        metadata = super(NetworkFirewallRuleManager, self)._filter_immutable_metadata_attributes(metadata)
        metadata.pop("RuleGroupArn", None)
        metadata.pop("RuleGroupName", None)
        metadata.pop("RuleGroupId", None)
        metadata.pop("Type", None)
        metadata.pop("Capacity", None)
        metadata.pop("RuleGroupStatus", None)
        metadata.pop("Tags", None)
        metadata.pop("ConsumedCapacity", None)
        metadata.pop("NumberOfAssociations", None)
        return metadata

    def _get_preupdate_arn(self):
        return self._get_metadata_value("RuleGroupArn")

    def _get_id_params(self, name=None, rule_type=None, arn=None):
        if arn:
            return dict(RuleGroupArn=arn)
        if self.arn:
            return dict(RuleGroupArn=self.arn)
        if not name:
            name = self.name
        if not rule_type:
            rule_type = self.rule_type
        if rule_type:
            rule_type = rule_type.upper()
        if not rule_type or not name:
            # Users should never see this, but let's cover ourself
            self.module.fail_json(msg="Rule identifier parameters missing")
        return dict(RuleGroupName=name, Type=rule_type)

    @staticmethod
    def _empty_rule_variables():
        return dict(IPSets=dict(), PortSets=dict())

    @staticmethod
    def _transform_rule_variables(variables):
        return {k: dict(Definition=_string_list(v)) for (k, v) in variables.items()}

    def delete(self, name=None, rule_type=None, arn=None):
        id_params = self._get_id_params(name=name, rule_type=rule_type, arn=arn)
        result = self._get_rule_group(**id_params)

        if not result:
            return False

        self.updated_resource = dict()

        # Rule Group is already in the process of being deleted (takes time)
        rule_status = self._get_metadata_value("RuleGroupStatus", "").upper()
        if rule_status == "DELETING":
            self._wait_for_deletion()
            return False

        if self.module.check_mode:
            self.changed = True
            return True

        result = self._delete_rule_group(**id_params)
        self._wait_for_deletion()
        self.changed |= bool(result)
        return bool(result)

    def list(self, scope=None):
        params = dict()
        if scope:
            scope = scope.upper()
            params["Scope"] = scope
        rule_groups = self._list_rule_groups(**params)
        if not rule_groups:
            return list()

        return [r.get("Arn", None) for r in rule_groups]

    def _normalize_rule_variable(self, variable):
        if variable is None:
            return None
        return {k: variable.get(k, dict()).get("Definition", []) for k in variable.keys()}

    def _normalize_rule_variables(self, variables):
        if variables is None:
            return None
        result = dict()
        ip_sets = self._normalize_rule_variable(variables.get("IPSets", None))
        if ip_sets:
            result["ip_sets"] = ip_sets
        port_sets = self._normalize_rule_variable(variables.get("PortSets", None))
        if port_sets:
            result["port_sets"] = port_sets
        return result

    def _normalize_rule_group(self, rule_group):
        if rule_group is None:
            return None
        rule_variables = self._normalize_rule_variables(rule_group.get("RuleVariables", None))
        rule_group = self._normalize_boto3_resource(rule_group)
        if rule_variables is not None:
            rule_group["rule_variables"] = rule_variables
        return rule_group

    def _normalize_rule_group_metadata(self, rule_group_metadata):
        return self._normalize_boto3_resource(rule_group_metadata, add_tags=True)

    def _normalize_rule_group_result(self, result):
        if result is None:
            return None
        rule_group = self._normalize_rule_group(result.get("RuleGroup", None))
        rule_group_metadata = self._normalize_rule_group_metadata(result.get("RuleGroupMetadata", None))
        result = camel_dict_to_snake_dict(result)
        if rule_group:
            result["rule_group"] = rule_group
        if rule_group_metadata:
            result["rule_group_metadata"] = rule_group_metadata
        return result

    def _normalize_resource(self, resource):
        return self._normalize_rule_group_result(resource)

    def get_rule_group(self, name=None, rule_type=None, arn=None):
        id_params = self._get_id_params(name=name, rule_type=rule_type, arn=arn)
        result = self._get_rule_group(**id_params)

        if not result:
            return None

        rule_group = self._normalize_rule_group_result(result)
        return rule_group

    def set_description(self, description):
        return self._set_metadata_value("Description", description)

    def set_capacity(self, capacity):
        return self._set_metadata_value("Capacity", capacity, description="Reserved Capacity", immutable=True)

    def _set_rule_option(self, option_name, description, value, immutable=False, default_value=None):
        if value is None:
            return False

        rule_options = deepcopy(self._get_resource_value("StatefulRuleOptions", dict()))
        if value == rule_options.get(option_name, default_value):
            return False
        if immutable and self.original_resource:
            self.module.fail_json(msg=f"{description} can not be updated after creation")

        rule_options[option_name] = value

        return self._set_resource_value("StatefulRuleOptions", rule_options)

    def set_rule_order(self, order):
        RULE_ORDER_MAP = {
            "default": "DEFAULT_ACTION_ORDER",
            "strict": "STRICT_ORDER",
        }
        value = RULE_ORDER_MAP.get(order)
        changed = self._set_rule_option("RuleOrder", "Rule order", value, True, "DEFAULT_ACTION_ORDER")
        self.changed |= changed
        return changed

    def _set_rule_variables(self, set_name, variables, purge):
        if variables is None:
            return False

        variables = self._transform_rule_variables(variables)

        all_variables = deepcopy(self._get_resource_value("RuleVariables", self._empty_rule_variables()))

        current_variables = all_variables.get(set_name, dict())
        updated_variables = _merge_dict(current_variables, variables, purge)

        if current_variables == updated_variables:
            return False

        all_variables[set_name] = updated_variables

        return self._set_resource_value("RuleVariables", all_variables)

    def set_ip_variables(self, variables, purge):
        return self._set_rule_variables("IPSets", variables, purge)

    def set_port_variables(self, variables, purge):
        return self._set_rule_variables("PortSets", variables, purge)

    def _set_rule_source(self, rule_type, rules):
        if not rules:
            return False
        conflicting_types = self.RULE_TYPES.difference({rule_type})
        rules_source = deepcopy(self._get_resource_value("RulesSource", dict()))
        current_keys = set(rules_source.keys())
        conflicting_rule_type = conflicting_types.intersection(current_keys)
        if conflicting_rule_type:
            self.module.fail_json(
                f"Unable to add {rule_type} rules, {' and '.join(conflicting_rule_type)} rules already set"
            )

        original_rules = rules_source.get(rule_type, None)
        if rules == original_rules:
            return False
        rules_source[rule_type] = rules
        return self._set_resource_value("RulesSource", rules_source)

    def set_rule_string(self, rule):
        if rule is None:
            return False
        if not rule:
            self.module.fail_json("Rule string must include at least one rule")

        rule = "\n".join(_string_list(rule))
        return self._set_rule_source("RulesString", rule)

    def set_domain_list(self, options):
        if not options:
            return False
        changed = False
        domain_names = options.get("domain_names")
        home_net = options.get("source_ips", None)
        action = options.get("action")
        filter_http = options.get("filter_http", False)
        filter_https = options.get("filter_https", False)

        if home_net:
            # Seems a little kludgy but the HOME_NET ip variable is how you
            # configure which source CIDRs the traffic should be filtered for.
            changed |= self.set_ip_variables(dict(HOME_NET=home_net), purge=True)
        else:
            self.set_ip_variables(dict(), purge=True)

        # Perform some transformations
        target_types = []
        if filter_http:
            target_types.append("HTTP_HOST")
        if filter_https:
            target_types.append("TLS_SNI")

        if action == "allow":
            action = "ALLOWLIST"
        else:
            action = "DENYLIST"

        # Finally build the 'rule'
        rule = dict(
            Targets=domain_names,
            TargetTypes=target_types,
            GeneratedRulesType=action,
        )
        changed |= self._set_rule_source("RulesSourceList", rule)
        return changed

    def _format_rule_options(self, options, sid):
        formatted_options = []
        opt = dict(Keyword=f"sid:{sid}")
        formatted_options.append(opt)
        if options:
            for option in sorted(options.keys()):
                opt = dict(Keyword=option)
                settings = options.get(option)
                if settings:
                    opt["Settings"] = _string_list(settings)
                formatted_options.append(opt)
        return formatted_options

    def _format_stateful_rule(self, rule):
        options = self._format_rule_options(
            rule.get("rule_options", dict()),
            rule.get("sid"),
        )
        formatted_rule = dict(
            Action=rule.get("action").upper(),
            RuleOptions=options,
            Header=dict(
                Protocol=rule.get("protocol").upper(),
                Source=rule.get("source"),
                SourcePort=rule.get("source_port"),
                Direction=rule.get("direction").upper(),
                Destination=rule.get("destination"),
                DestinationPort=rule.get("destination_port"),
            ),
        )
        return formatted_rule

    def set_rule_list(self, rules):
        if rules is None:
            return False
        if not rules:
            self.module.fail_json(msg="Rule list must include at least one rule")

        formatted_rules = [self._format_stateful_rule(r) for r in rules]
        return self._set_rule_source("StatefulRules", formatted_rules)

    def _do_create_resource(self):
        metadata, resource = self._merge_changes(filter_metadata=False)
        params = metadata
        params.update(self._get_id_params())
        params["RuleGroup"] = resource
        response = self._create_rule_group(**params)
        return bool(response)

    def _generate_updated_resource(self):
        metadata, resource = self._merge_changes(filter_metadata=False)
        metadata.update(self._get_id_params())
        updated_resource = dict(RuleGroup=resource, RuleGroupMetadata=metadata)
        return updated_resource

    def _flush_create(self):
        # Apply some pre-flight tests before trying to run the creation.
        if "Capacity" not in self._metadata_updates:
            self.module.fail_json("Capacity must be provided when creating a new Rule Group")

        rules_source = self._get_resource_value("RulesSource", dict())
        rule_type = self.RULE_TYPES.intersection(set(rules_source.keys()))
        if len(rule_type) != 1:
            self.module.fail_json(
                "Exactly one of rule strings, domain list or rule list must be provided when creating a new rule group",
                rule_type=rule_type,
                keys=self._resource_updates.keys(),
                types=self.RULE_TYPES,
            )

        return super(NetworkFirewallRuleManager, self)._flush_create()

    def _do_update_resource(self):
        filtered_metadata_updates = self._filter_immutable_metadata_attributes(self._metadata_updates)
        filtered_resource_updates = self._resource_updates

        if not filtered_resource_updates and not filtered_metadata_updates:
            return False

        metadata, resource = self._merge_changes()

        params = metadata
        params.update(self._get_id_params())
        params["RuleGroup"] = resource

        if not self.module.check_mode:
            self._update_rule_group(**params)

        return True

    def _flush_update(self):
        changed = False
        changed |= self._flush_tagging()
        changed |= super(NetworkFirewallRuleManager, self)._flush_update()
        return changed

    def _get_rule_group(self, **params):
        result = self._describe_rule_group(**params)
        if not result:
            return None

        rule_group = result.get("RuleGroup", None)
        metadata = result.get("RuleGroupMetadata", None)
        self._preupdate_resource = deepcopy(rule_group)
        self._preupdate_metadata = deepcopy(metadata)
        return dict(RuleGroup=rule_group, RuleGroupMetadata=metadata)

    def get_resource(self):
        return self.get_rule_group()

    def _do_creation_wait(self, **params):
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_rule_group_active(**all_params)

    def _do_deletion_wait(self, **params):
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_rule_group_deleted(**all_params)


class NetworkFirewallPolicyManager(NFPolicyBoto3Mixin, NFRuleGroupBoto3Mixin, BaseNetworkFirewallManager):
    name = None
    arn = None
    _group_name_cache = None

    def __init__(self, module, name=None, arn=None):
        super().__init__(module)
        # Name parameter is unique (by region) and can not be modified.
        self.name = name
        self.arn = arn
        if self.name or self.arn:
            policy = deepcopy(self.get_policy())
            self.original_resource = policy

    def _extra_error_output(self):
        output = super(NetworkFirewallPolicyManager, self)._extra_error_output()
        if self.name:
            output["FirewallPolicyName"] = self.name
        if self.arn:
            output["FirewallPolicyArn"] = self.arn
        return output

    def _filter_immutable_metadata_attributes(self, metadata):
        metadata = super(NetworkFirewallPolicyManager, self)._filter_immutable_metadata_attributes(metadata)
        metadata.pop("FirewallPolicyArn", None)
        metadata.pop("FirewallPolicyName", None)
        metadata.pop("FirewallPolicyId", None)
        metadata.pop("FirewallPolicyStatus", None)
        metadata.pop("ConsumedStatelessRuleCapacity", None)
        metadata.pop("ConsumedStatefulRuleCapacity", None)
        metadata.pop("Tags", None)
        metadata.pop("NumberOfAssociations", None)
        return metadata

    def _get_preupdate_arn(self):
        return self._get_metadata_value("FirewallPolicyArn")

    def _get_id_params(self, name=None, arn=None):
        if arn:
            return dict(FirewallPolicyArn=arn)
        if self.arn:
            return dict(FirewallPolicyArn=self.arn)
        if not name:
            name = self.name
        return dict(FirewallPolicyName=name)

    def delete(self, name=None, arn=None):
        id_params = self._get_id_params(name=name, arn=arn)
        result = self._get_policy(**id_params)

        if not result:
            return False

        self.updated_resource = dict()

        # Policy is already in the process of being deleted (takes time)
        rule_status = self._get_metadata_value("FirewallPolicyStatus", "").upper()
        if rule_status == "DELETING":
            self._wait_for_deletion()
            return False

        if self.module.check_mode:
            self.changed = True
            return True

        result = self._delete_policy(**id_params)
        self._wait_for_deletion()
        self.changed |= bool(result)
        return bool(result)

    def list(self):
        params = dict()
        policies = self._list_policies(**params)
        if not policies:
            return list()

        return [p.get("Arn", None) for p in policies]

    @property
    def _rule_group_name_cache(self):
        if self._group_name_cache:
            return self._group_name_cache
        results = self._list_rule_groups()
        if not results:
            return dict()

        group_cache = {r.get("Name", None): r.get("Arn", None) for r in results}
        self._group_name_cache = group_cache
        return group_cache

    @property
    def _stateful_rule_order(self):
        engine_options = self._get_resource_value("StatefulEngineOptions", None)
        if not engine_options:
            return "DEFAULT_ACTION_ORDER"
        return engine_options.get("RuleOrder", "DEFAULT_ACTION_ORDER")

    def _canonicalize_rule_group(self, name, group_type):
        """Iterates through a mixed list of ARNs and Names converting them to
        ARNs.  Also checks that the group type matches the provided group_type.
        """
        arn = None
        # : is only valid in ARNs
        if ":" in name:
            arn = name
        else:
            arn = self._rule_group_name_cache.get(name, None)
            if not arn:
                self.module.fail_json(
                    "Unable to fetch ARN for rule group", name=name, group_name_cache=self._rule_group_name_cache
                )
        arn_info = parse_aws_arn(arn)
        if not arn_info:
            self.module.fail_json("Unable to parse ARN for rule group", arn=arn, arn_info=arn_info)
        arn_type = arn_info["resource"].split("/")[0]
        if arn_type != group_type:
            self.module.fail_json(
                "Rule group not of expected type", name=name, arn=arn, expected_type=group_type, found_type=arn_type
            )

        return arn

    def _format_rulegroup_references(self, groups, strict_order):
        formated_groups = list()
        for idx, arn in enumerate(groups):
            entry = dict(ResourceArn=arn)
            if strict_order:
                entry["Priority"] = idx + 1
            formated_groups.append(entry)
        return formated_groups

    def _rulegroup_references_list(self, groups):
        return [g.get("ResourceArn") for g in groups]

    def _sorted_rulegroup_references_list(self, groups):
        sorted_list = sorted(groups, key=lambda g: g.get("Priority", None))
        return self._rulegroup_references_list(sorted_list)

    def _compare_rulegroup_references(self, current_groups, desired_groups, strict_order):
        if current_groups is None:
            return False
        if strict_order:
            current_groups = self._sorted_rulegroup_references_list(current_groups)
            return current_groups == desired_groups
        else:
            current_groups = self._rulegroup_references_list(current_groups)
            return set(current_groups) == set(desired_groups)

    def _set_engine_option(self, option_name, description, value, immutable=False, default_value=None):
        if value is None:
            return False

        engine_options = deepcopy(self._get_resource_value("StatefulEngineOptions", dict()))
        if value == engine_options.get(option_name, default_value):
            return False
        if immutable and self.original_resource:
            self.module.fail_json(msg=f"{description} can not be updated after creation")

        engine_options[option_name] = value
        return self._set_resource_value("StatefulEngineOptions", engine_options)

    def set_stateful_rule_order(self, order):
        RULE_ORDER_MAP = {
            "default": "DEFAULT_ACTION_ORDER",
            "strict": "STRICT_ORDER",
        }
        value = RULE_ORDER_MAP.get(order)
        changed = self._set_engine_option("RuleOrder", "Rule order", value, True, "DEFAULT_ACTION_ORDER")
        self.changed |= changed
        return changed

    def _set_rule_groups(self, groups, group_type, parameter_name, strict_order):
        if groups is None:
            return False
        group_arns = [self._canonicalize_rule_group(g, group_type) for g in groups]
        current_groups = self._get_resource_value(parameter_name)
        if self._compare_rulegroup_references(current_groups, group_arns, strict_order):
            return False
        formated_groups = self._format_rulegroup_references(group_arns, strict_order)
        return self._set_resource_value(parameter_name, formated_groups)

    def set_stateful_rule_groups(self, groups):
        strict_order = self._stateful_rule_order == "STRICT_ORDER"
        return self._set_rule_groups(groups, "stateful-rulegroup", "StatefulRuleGroupReferences", strict_order)

    def set_stateless_rule_groups(self, groups):
        return self._set_rule_groups(groups, "stateless-rulegroup", "StatelessRuleGroupReferences", True)

    def set_default_actions(self, key, actions, valid_actions=None):
        if actions is None:
            return False

        invalid_actions = list(set(actions) - set(valid_actions or []))
        if valid_actions and invalid_actions:
            self.module.fail_json(
                msg=f"{key} contains invalid actions",
                valid_actions=valid_actions,
                invalid_actions=invalid_actions,
                actions=actions,
            )

        return self._set_resource_value(key, actions)

    def set_stateful_default_actions(self, actions):
        if actions is None:
            return False
        if self._stateful_rule_order != "STRICT_ORDER":
            self.module.fail_json(msg="Stateful default actions can only be set when using strict rule order")

        valid_actions = ["aws:drop_strict", "aws:drop_established", "aws:alert_strict", "aws:alert_established"]
        return self.set_default_actions("StatefulDefaultActions", actions, valid_actions)

    def _set_stateless_default_actions(self, key, actions):
        valid_actions = ["aws:pass", "aws:drop", "aws:forward_to_sfe"]
        custom_actions = self._get_resource_value("StatelessCustomActions", dict())
        custom_action_names = [a["ActionName"] for a in custom_actions]
        valid_actions.extend(custom_action_names)
        return self.set_default_actions(key, actions, valid_actions)

    def set_stateless_default_actions(self, actions):
        return self._set_stateless_default_actions("StatelessDefaultActions", actions)

    def set_stateless_fragment_default_actions(self, actions):
        return self._set_stateless_default_actions("StatelessFragmentDefaultActions", actions)

    def _normalize_policy(self, policy):
        if policy is None:
            return None
        policy = self._normalize_boto3_resource(policy)
        return policy

    def _normalize_policy_metadata(self, policy_metadata):
        if policy_metadata is None:
            return None
        return self._normalize_boto3_resource(policy_metadata, add_tags=True)

    def _normalize_policy_result(self, result):
        if result is None:
            return None
        policy = self._normalize_policy(result.get("FirewallPolicy", None))
        policy_metadata = self._normalize_policy_metadata(result.get("FirewallPolicyMetadata", None))
        result = dict()
        if policy:
            result["policy"] = policy
        if policy_metadata:
            result["policy_metadata"] = policy_metadata
        return result

    def _normalize_resource(self, resource):
        return self._normalize_policy_result(resource)

    def get_policy(self, name=None, arn=None):
        id_params = self._get_id_params(name=name, arn=arn)
        result = self._get_policy(**id_params)

        if not result:
            return None

        policy = self._normalize_policy_result(result)
        return policy

    def _format_custom_action(self, action):
        formatted_action = dict(
            ActionName=action["name"],
        )
        action_definition = dict()
        if "publish_metric_dimension_value" in action:
            values = _string_list(action["publish_metric_dimension_value"])
            dimensions = [dict(Value=v) for v in values]
            action_definition["PublishMetricAction"] = dict(
                Dimensions=dimensions,
            )
        if action_definition:
            formatted_action["ActionDefinition"] = action_definition
        return formatted_action

    def _custom_action_map(self, actions):
        return {a["ActionName"]: a["ActionDefinition"] for a in actions}

    def set_custom_stateless_actions(self, actions, purge_actions):
        if actions is None:
            return False
        new_action_list = [self._format_custom_action(a) for a in actions]
        new_action_map = self._custom_action_map(new_action_list)

        existing_action_map = self._custom_action_map(self._get_resource_value("StatelessCustomActions", []))
        if purge_actions:
            desired_action_map = dict()
        else:
            desired_action_map = deepcopy(existing_action_map)
        desired_action_map.update(new_action_map)

        if desired_action_map == existing_action_map:
            return False

        action_list = [dict(ActionName=k, ActionDefinition=v) for k, v in desired_action_map.items()]
        self._set_resource_value("StatelessCustomActions", action_list)

    def set_description(self, description):
        return self._set_metadata_value("Description", description)

    def _do_create_resource(self):
        metadata, resource = self._merge_changes(filter_metadata=False)
        params = metadata
        params.update(self._get_id_params())
        params["FirewallPolicy"] = resource
        response = self._create_policy(**params)
        return bool(response)

    def _generate_updated_resource(self):
        metadata, resource = self._merge_changes(filter_metadata=False)
        metadata.update(self._get_id_params())
        updated_resource = dict(FirewallPolicy=resource, FirewallPolicyMetadata=metadata)
        return updated_resource

    def _flush_create(self):
        # Set some defaults
        if self._get_resource_value("StatelessDefaultActions", None) is None:
            self._set_resource_value("StatelessDefaultActions", ["aws:forward_to_sfe"])
        if self._get_resource_value("StatelessFragmentDefaultActions", None) is None:
            self._set_resource_value("StatelessFragmentDefaultActions", ["aws:forward_to_sfe"])
        return super(NetworkFirewallPolicyManager, self)._flush_create()

    def _do_update_resource(self):
        filtered_metadata_updates = self._filter_immutable_metadata_attributes(self._metadata_updates)
        filtered_resource_updates = self._resource_updates

        if not filtered_resource_updates and not filtered_metadata_updates:
            return False

        metadata, resource = self._merge_changes()

        params = metadata
        params.update(self._get_id_params())
        params["FirewallPolicy"] = resource

        if not self.module.check_mode:
            self._update_policy(**params)

        return True

    def _flush_update(self):
        changed = False
        changed |= self._flush_tagging()
        changed |= super(NetworkFirewallPolicyManager, self)._flush_update()
        return changed

    def _get_policy(self, **params):
        result = self._describe_policy(**params)
        if not result:
            return None

        policy = result.get("FirewallPolicy", None)
        # During deletion, there's a phase where this will return Metadata but
        # no policy
        if policy is None:
            policy = dict()

        metadata = result.get("FirewallPolicyMetadata", None)
        self._preupdate_resource = deepcopy(policy)
        self._preupdate_metadata = deepcopy(metadata)
        return dict(FirewallPolicy=policy, FirewallPolicyMetadata=metadata)

    def get_resource(self):
        return self.get_policy()

    def _do_creation_wait(self, **params):
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_policy_active(**all_params)

    def _do_deletion_wait(self, **params):
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_policy_deleted(**all_params)


class NetworkFirewallManager(NFFirewallBoto3Mixin, NFPolicyBoto3Mixin, BaseNetworkFirewallManager):
    name = None
    arn = None
    ec2_manager = None
    _subnet_updates = None
    _policy_list_cache = None
    _slow_start_change = False

    def __init__(self, module, name=None, arn=None):
        super().__init__(module)
        # Name parameter is unique (by region) and can not be modified.
        self.name = name
        self.arn = arn
        self.ec2_manager = BaseEc2Manager(module=module)
        self._subnet_updates = dict()
        if self.name or self.arn:
            firewall = deepcopy(self.get_firewall())
            self.original_resource = firewall

    def _extra_error_output(self):
        output = super(NetworkFirewallManager, self)._extra_error_output()
        if self.name:
            output["FirewallName"] = self.name
        if self.arn:
            output["FirewallArn"] = self.arn
        return output

    def _get_preupdate_arn(self):
        return self._get_resource_value("FirewallArn")

    def _get_id_params(self, name=None, arn=None):
        if arn:
            return dict(FirewallArn=arn)
        if self.arn:
            return dict(FirewallArn=self.arn)
        if not name:
            name = self.name
        if not name:
            # Users should never see this, but let's cover ourself
            self.module.fail_json(msg="Firewall identifier parameters missing")
        return dict(FirewallName=name)

    def delete(self, name=None, arn=None):
        id_params = self._get_id_params(name=name, arn=arn)
        result = self._get_firewall(**id_params)

        if not result:
            return False

        self.updated_resource = dict()

        # Firewall is already in the process of being deleted (takes time)
        firewall_status = self._get_metadata_value("Status", "").upper()
        if firewall_status == "DELETING":
            self._wait_for_deletion()
            return False

        if self.module.check_mode:
            self.changed = True
            return True

        if "DeleteProtection" in self._resource_updates:
            self._update_firewall_delete_protection(
                DeleteProtection=self._resource_updates["DeleteProtection"],
                **id_params,
            )

        result = self._delete_firewall(**id_params)
        self._wait_for_deletion()
        self.changed |= bool(result)
        return bool(result)

    def list(self, vpc_ids=None):
        params = dict()
        if vpc_ids:
            params["VpcIds"] = vpc_ids
        firewalls = self._list_firewalls(**params)
        if not firewalls:
            return list()

        return [f.get("FirewallArn", None) for f in firewalls]

    def _normalize_firewall(self, firewall):
        if firewall is None:
            return None
        subnets = [s.get("SubnetId") for s in firewall.get("SubnetMappings", [])]
        firewall = self._normalize_boto3_resource(firewall, add_tags=True)
        firewall["subnets"] = subnets
        return firewall

    def _normalize_sync_state_config(self, policy):
        return self._normalize_boto3_resource(policy)

    def _normalize_sync_state(self, state):
        config = {k: self._normalize_sync_state_config(v) for k, v in state.pop("Config", {}).items()}
        state = self._normalize_boto3_resource(state)
        state["config"] = config or {}
        return state

    def _normalize_firewall_metadata(self, firewall_metadata):
        if firewall_metadata is None:
            return None
        states = {k: self._normalize_sync_state(v) for k, v in firewall_metadata.pop("SyncStates", {}).items()}
        metadata = self._normalize_boto3_resource(firewall_metadata, add_tags=False)
        metadata["sync_states"] = states or {}
        return metadata

    def _normalize_firewall_result(self, result):
        if result is None:
            return None
        firewall = self._normalize_firewall(result.get("Firewall", None))
        firewall_metadata = self._normalize_firewall_metadata(result.get("FirewallMetadata", None))
        result = camel_dict_to_snake_dict(result)
        if firewall:
            result["firewall"] = firewall
        if firewall_metadata:
            result["firewall_metadata"] = firewall_metadata
        return result

    def _normalize_resource(self, resource):
        return self._normalize_firewall_result(resource)

    def get_firewall(self, name=None, arn=None):
        id_params = self._get_id_params(name=name, arn=arn)
        result = self._get_firewall(**id_params)

        if not result:
            return None

        firewall = self._normalize_firewall_result(result)
        return firewall

    @property
    def _subnets(self):
        subnet_mappings = self._get_resource_value("SubnetMappings", [])
        subnets = [s.get("SubnetId") for s in subnet_mappings]
        return subnets

    def _subnets_to_vpc(self, subnets, subnet_details=None):
        if not subnets:
            return None
        if not subnet_details:
            subnet_details = self.ec2_manager._describe_subnets(SubnetIds=list(subnets))
        vpcs = [s.get("VpcId") for s in subnet_details]
        if len(set(vpcs)) > 1:
            self.module.fail_json(
                msg="Firewall subnets may only be in one VPC, multiple VPCs found",
                vpcs=list(set(vpcs)),
                subnets=subnet_details,
            )
        return vpcs[0]

    def _format_subnet_mapping(self, subnets):
        if not subnets:
            return []
        return [dict(SubnetId=s) for s in subnets]

    @property
    def _policy_name_cache(self):
        if self._policy_list_cache:
            return self._policy_list_cache
        results = self._list_policies()
        if not results:
            return dict()

        policy_cache = {p.get("Name", None): p.get("Arn", None) for p in results}
        self._policy_list_cache = policy_cache
        return policy_cache

    def _canonicalize_policy(self, name):
        """Iterates through a mixed list of ARNs and Names converting them to
        ARNs.
        """
        arn = None
        # : is only valid in ARNs
        if ":" in name:
            arn = name
        else:
            arn = self._policy_name_cache.get(name, None)
            if not arn:
                self.module.fail_json(
                    "Unable to fetch ARN for policy", name=name, policy_name_cache=self._policy_name_cache
                )
        arn_info = parse_aws_arn(arn)
        if not arn_info:
            self.module.fail_json("Unable to parse ARN for policy", arn=arn, arn_info=arn_info)
        arn_type = arn_info["resource"].split("/")[0]
        if arn_type != "firewall-policy":
            self.module.fail_json(
                "Policy ARN not of expected resource type",
                name=name,
                arn=arn,
                expected_type="firewall-policy",
                found_type=arn_type,
            )

        return arn

    def set_policy(self, policy):
        if policy is None:
            return False

        # Because the canonicalization of a non-ARN policy name will require an API call,
        # try comparing the current name to the policy name we've been passed.
        # If they match we don't need to perform the lookup.
        current_policy = self._get_resource_value("FirewallPolicyArn", None)
        if current_policy:
            arn_info = parse_aws_arn(current_policy)
            current_name = arn_info["resource"].split("/")[-1]
            if current_name == policy:
                return False

        policy = self._canonicalize_policy(policy)
        return self._set_resource_value("FirewallPolicyArn", policy)

    def set_subnets(self, subnets, purge=True):
        if subnets is None:
            return False
        current_subnets = set(self._subnets)
        desired_subnets = set(subnets)
        if not purge:
            desired_subnets = desired_subnets.union(current_subnets)

        # We don't need to perform EC2 lookups if we're not changing anything.
        if current_subnets == desired_subnets:
            return False

        subnet_details = self.ec2_manager._describe_subnets(SubnetIds=list(desired_subnets))
        vpc = self._subnets_to_vpc(desired_subnets, subnet_details)
        self._set_resource_value("VpcId", vpc, description="firewall VPC", immutable=True)

        azs = [s.get("AvailabilityZoneId") for s in subnet_details]
        if len(azs) != len(set(azs)):
            self.module.fail_json(
                msg="Only one subnet per availability zone may set.", availability_zones=azs, subnets=subnet_details
            )

        subnets_to_add = list(desired_subnets.difference(current_subnets))
        subnets_to_remove = list(current_subnets.difference(desired_subnets))
        self._subnet_updates = dict(add=subnets_to_add, remove=subnets_to_remove)
        self._set_resource_value("SubnetMappings", self._format_subnet_mapping(desired_subnets))
        return True

    def set_policy_change_protection(self, protection):
        return self._set_resource_value("FirewallPolicyChangeProtection", protection)

    def set_subnet_change_protection(self, protection):
        return self._set_resource_value("SubnetChangeProtection", protection)

    def set_delete_protection(self, protection):
        return self._set_resource_value("DeleteProtection", protection)

    def set_description(self, description):
        return self._set_resource_value("Description", description)

    def _do_create_resource(self):
        metadata, resource = self._merge_changes(filter_metadata=False)
        params = metadata
        params.update(self._get_id_params())
        params.update(resource)
        response = self._create_firewall(**params)
        return bool(response)

    def _generate_updated_resource(self):
        metadata, resource = self._merge_changes(filter_metadata=False)
        resource.update(self._get_id_params())
        updated_resource = dict(Firewall=resource, FirewallMetadata=metadata)
        return updated_resource

    def _flush_create(self):
        # # Apply some pre-flight tests before trying to run the creation.
        # if 'Capacity' not in self._metadata_updates:
        #     self.module.fail_json('Capacity must be provided when creating a new Rule Group')

        return super(NetworkFirewallManager, self)._flush_create()

    def _do_update_resource(self):
        # There are no 'metadata' components of a Firewall to update
        resource_updates = self._resource_updates
        if not resource_updates:
            return False
        if self.module.check_mode:
            return True

        id_params = self._get_id_params()

        # There's no tool for 'bulk' updates, we need to iterate through these
        # one at a time...
        if "Description" in resource_updates:
            self._update_firewall_description(
                Description=resource_updates["Description"],
                **id_params,
            )
        if "DeleteProtection" in resource_updates:
            self._update_firewall_delete_protection(
                DeleteProtection=resource_updates["DeleteProtection"],
                **id_params,
            )

        # Disable Change Protection...
        # When disabling change protection, do so *before* making changes
        if "FirewallPolicyChangeProtection" in resource_updates:
            if not self._get_resource_value("FirewallPolicyChangeProtection"):
                self._update_firewall_policy_change_protection(
                    FirewallPolicyChangeProtection=resource_updates["FirewallPolicyChangeProtection"],
                    **id_params,
                )
        if "SubnetChangeProtection" in resource_updates:
            if not self._get_resource_value("SubnetChangeProtection"):
                self._update_subnet_change_protection(
                    SubnetChangeProtection=resource_updates["SubnetChangeProtection"],
                    **id_params,
                )

        # General Changes
        if "SubnetMappings" in resource_updates:
            self._slow_start_change = True
            subnets_to_add = self._subnet_updates.get("add", None)
            subnets_to_remove = self._subnet_updates.get("remove", None)
            if subnets_to_remove:
                self._disassociate_subnets(SubnetIds=subnets_to_remove, **id_params)
            if subnets_to_add:
                subnets_to_add = self._format_subnet_mapping(subnets_to_add)
                self._associate_subnets(SubnetMappings=subnets_to_add, **id_params)

        if "FirewallPolicyArn" in resource_updates:
            self._slow_start_change = True
            self._associate_firewall_policy(FirewallPolicyArn=resource_updates["FirewallPolicyArn"], **id_params)

        # Enable Change Protection.
        # When enabling change protection, do so *after* making changes
        if "FirewallPolicyChangeProtection" in resource_updates:
            if self._get_resource_value("FirewallPolicyChangeProtection"):
                self._update_firewall_policy_change_protection(
                    FirewallPolicyChangeProtection=resource_updates["FirewallPolicyChangeProtection"],
                    **id_params,
                )
        if "SubnetChangeProtection" in resource_updates:
            if self._get_resource_value("SubnetChangeProtection"):
                self._update_subnet_change_protection(
                    SubnetChangeProtection=resource_updates["SubnetChangeProtection"],
                    **id_params,
                )
        return True

    def _flush_update(self):
        changed = False
        changed |= self._flush_tagging()
        changed |= super(NetworkFirewallManager, self)._flush_update()
        self._subnet_updates = dict()
        self._slow_start_change = False
        return changed

    def _get_firewall(self, **params):
        result = self._describe_firewall(**params)
        if not result:
            return None

        firewall = result.get("Firewall", None)
        metadata = result.get("FirewallMetadata", None)
        self._preupdate_resource = deepcopy(firewall)
        self._preupdate_metadata = deepcopy(metadata)
        return dict(Firewall=firewall, FirewallMetadata=metadata)

    def get_resource(self):
        return self.get_firewall()

    def _do_creation_wait(self, **params):
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_firewall_active(**all_params)

    def _do_deletion_wait(self, **params):
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_firewall_deleted(**all_params)

    def _do_update_wait(self, **params):
        # It takes a couple of seconds before the firewall starts to update
        # the subnets and policies, pause if we know we've changed them.  We'll
        # be waiting subtantially more than this...
        if self._slow_start_change:
            time.sleep(4)
        all_params = self._get_id_params()
        all_params.update(params)
        return self._wait_firewall_updated(**all_params)

    # Unlike RuleGroups and Policies for some reason Firewalls have the tags set
    # directly on the resource.
    def _set_tag_values(self, desired_tags):
        return self._set_resource_value("Tags", ansible_dict_to_boto3_tag_list(desired_tags))

    def _get_tag_values(self):
        return self._get_resource_value("Tags", [])
