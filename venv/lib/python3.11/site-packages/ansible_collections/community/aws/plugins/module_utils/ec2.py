# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from copy import deepcopy

from ansible_collections.amazon.aws.plugins.module_utils.botocore import is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.retries import AWSRetry
from ansible_collections.amazon.aws.plugins.module_utils.tagging import ansible_dict_to_boto3_tag_list
from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_list_to_ansible_dict
from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_specifications
from ansible_collections.amazon.aws.plugins.module_utils.tagging import compare_aws_tags
from ansible_collections.amazon.aws.plugins.module_utils.transformation import ansible_dict_to_boto3_filter_list

from ansible_collections.community.aws.plugins.module_utils.base import BaseResourceManager
from ansible_collections.community.aws.plugins.module_utils.base import BaseWaiterFactory
from ansible_collections.community.aws.plugins.module_utils.base import Boto3Mixin


class Ec2WaiterFactory(BaseWaiterFactory):
    def __init__(self, module):
        # the AWSRetry wrapper doesn't support the wait functions (there's no
        # public call we can cleanly wrap)
        client = module.client("ec2")
        super(Ec2WaiterFactory, self).__init__(module, client)

    @property
    def _waiter_model_data(self):
        data = super(Ec2WaiterFactory, self)._waiter_model_data
        return data


class Ec2Boto3Mixin(Boto3Mixin):
    @AWSRetry.jittered_backoff()
    def _paginated_describe_subnets(self, **params):
        paginator = self.client.get_paginator("describe_subnets")
        return paginator.paginate(**params).build_full_result()

    @Boto3Mixin.aws_error_handler("describe subnets")
    def _describe_subnets(self, **params):
        try:
            result = self._paginated_describe_subnets(**params)
        except is_boto3_error_code("SubnetID.NotFound"):
            return None
        return result.get("Subnets", None)


class BaseEc2Manager(Ec2Boto3Mixin, BaseResourceManager):
    resource_id = None
    TAG_RESOURCE_TYPE = None
    # This can be overridden by a subclass *if* 'Tags' isn't returned as a part of
    # the standard Resource description
    TAGS_ON_RESOURCE = True
    # If the resource supports using "TagSpecifications" on creation we can
    TAGS_ON_CREATE = "TagSpecifications"

    def __init__(self, module, resource_id=None):
        r"""
        Parameters:
            module (AnsibleAWSModule): An Ansible module.
        """
        super(BaseEc2Manager, self).__init__(module)
        self.client = self._create_client()
        self._tagging_updates = dict()
        self.resource_id = resource_id

        # Name parameter is unique (by region) and can not be modified.
        if self.resource_id:
            resource = deepcopy(self.get_resource())
            self.original_resource = resource

    def _flush_update(self):
        changed = False
        changed |= self._do_tagging()
        changed |= super(BaseEc2Manager, self)._flush_update()
        return changed

    @Boto3Mixin.aws_error_handler("connect to AWS")
    def _create_client(self, client_name="ec2"):
        client = self.module.client(client_name, retry_decorator=AWSRetry.jittered_backoff())
        return client

    @Boto3Mixin.aws_error_handler("set tags on resource")
    def _add_tags(self, **params):
        self.client.create_tags(aws_retry=True, **params)
        return True

    @Boto3Mixin.aws_error_handler("unset tags on resource")
    def _remove_tags(self, **params):
        self.client.delete_tags(aws_retry=True, **params)
        return True

    @AWSRetry.jittered_backoff()
    def _paginated_describe_tags(self, **params):
        paginator = self.client.get_paginator("describe_tags")
        return paginator.paginate(**params).build_full_result()

    @Boto3Mixin.aws_error_handler("list tags on resource")
    def _describe_tags(self, resource_id=None):
        if not resource_id:
            resource_id = self.resource_id
        filters = ansible_dict_to_boto3_filter_list({"resource-id": resource_id})
        tags = self._paginated_describe_tags(Filters=filters)
        return tags

    def _get_tags(self, resource_id=None):
        if resource_id is None:
            resource_id = self.resource_id
        # If the Tags are available from the resource, then use them
        if self.TAGS_ON_RESOURCE:
            tags = self._preupdate_resource.get("Tags", [])
        # Otherwise we'll have to look them up
        else:
            tags = self._describe_tags(resource_id=resource_id)
        return boto3_tag_list_to_ansible_dict(tags)

    def _do_tagging(self):
        changed = False
        tags_to_add = self._tagging_updates.get("add")
        tags_to_remove = self._tagging_updates.get("remove")

        if tags_to_add:
            changed = True
            tags = ansible_dict_to_boto3_tag_list(tags_to_add)
            if not self.module.check_mode:
                self._add_tags(Resources=[self.resource_id], Tags=tags)
        if tags_to_remove:
            changed = True
            if not self.module.check_mode:
                tag_list = [dict(Key=tagkey) for tagkey in tags_to_remove]
                self._remove_tags(Resources=[self.resource_id], Tags=tag_list)

        return changed

    def _merge_resource_changes(self, filter_immutable=True, creation=False):
        resource = super(BaseEc2Manager, self)._merge_resource_changes(
            filter_immutable=filter_immutable, creation=creation
        )

        if creation:
            if not self.TAGS_ON_CREATE:
                resource.pop("Tags", None)
            elif self.TAGS_ON_CREATE == "TagSpecifications":
                tags = boto3_tag_list_to_ansible_dict(resource.pop("Tags", []))
                tag_specs = boto3_tag_specifications(tags, types=[self.TAG_RESOURCE_TYPE])
                if tag_specs:
                    resource["TagSpecifications"] = tag_specs

        return resource

    def set_tags(self, tags, purge_tags):
        if tags is None:
            return False
        changed = False

        # Tags are returned as a part of the resource, but have to be updated
        # via dedicated tagging methods
        current_tags = self._get_tags()

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
            # simplisic '==' in _set_resource_value doesn't do the comparison
            # properly
            return self._set_resource_value("Tags", ansible_dict_to_boto3_tag_list(desired_tags))

        return False
