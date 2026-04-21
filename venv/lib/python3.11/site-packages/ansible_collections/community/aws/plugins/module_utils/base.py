# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#
# Note: This code should probably live in amazon.aws rather than community.aws.
# However, for the sake of getting something into a useful shape first, it makes
# sense for it to start life in community.aws.
#

from copy import deepcopy
from functools import wraps

try:
    import botocore
except ImportError:
    pass  # Handled by AnsibleAWSModule

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict

from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_list_to_ansible_dict


class BaseWaiterFactory:
    """
    A helper class used for creating additional waiters.
    Unlike the waiters available directly from botocore these waiters will
    automatically retry on common (temporary) AWS failures.

    This class should be treated as an abstract class and subclassed before use.
    A subclass should:
    - create the necessary client to pass to BaseWaiterFactory.__init__
    - override _BaseWaiterFactory._waiter_model_data to return the data defining
      the waiter

    Usage:
    waiter_factory = BaseWaiterFactory(module, client)
    waiter = waiters.get_waiter('my_waiter_name')
    waiter.wait(**params)
    """

    module = None
    client = None

    def __init__(self, module, client):
        self.module = module
        self.client = client
        # While it would be nice to supliment this with the upstream data,
        # unfortunately client doesn't have a public method for getting the
        # waiter configs.
        data = self._inject_ratelimit_retries(self._waiter_model_data)
        self._model = botocore.waiter.WaiterModel(
            waiter_config=dict(version=2, waiters=data),
        )

    @property
    def _waiter_model_data(self):
        r"""
        Subclasses should override this method to return a dictionary mapping
        waiter names to the waiter definition.

        This data is similar to the data found in botocore's waiters-2.json
        files (for example: botocore/botocore/data/ec2/2016-11-15/waiters-2.json)
        with two differences:
        1) Waiter names do not have transformations applied during lookup
        2) Only the 'waiters' data is required, the data is assumed to be
           version 2

        for example:

        @property
        def _waiter_model_data(self):
            return dict(
                tgw_attachment_deleted=dict(
                    operation='DescribeTransitGatewayAttachments',
                    delay=5, maxAttempts=120,
                    acceptors=[
                        dict(state='retry', matcher='pathAll', expected='deleting', argument='TransitGatewayAttachments[].State'),
                        dict(state='success', matcher='pathAll', expected='deleted', argument='TransitGatewayAttachments[].State'),
                        dict(state='success', matcher='path', expected=True, argument='length(TransitGatewayAttachments[]) == `0`'),
                        dict(state='success', matcher='error', expected='InvalidRouteTableID.NotFound'),
                    ]
                ),
            )

        or

        @property
        def _waiter_model_data(self):
            return {
                "instance_exists": {
                    "delay": 5,
                    "maxAttempts": 40,
                    "operation": "DescribeInstances",
                    "acceptors": [
                        {
                            "matcher": "path",
                            "expected": true,
                            "argument": "length(Reservations[]) > `0`",
                            "state": "success"
                        },
                        {
                            "matcher": "error",
                            "expected": "InvalidInstanceID.NotFound",
                            "state": "retry"
                        }
                    ]
                },
            }
        """

        return dict()

    def _inject_ratelimit_retries(self, model):
        extra_retries = [
            "RequestLimitExceeded",
            "Unavailable",
            "ServiceUnavailable",
            "InternalFailure",
            "InternalError",
            "TooManyRequestsException",
            "Throttling",
        ]

        acceptors = []
        for error in extra_retries:
            acceptors.append(dict(state="retry", matcher="error", expected=error))

        _model = deepcopy(model)
        for waiter in _model:
            _model[waiter]["acceptors"].extend(acceptors)

        return _model

    def get_waiter(self, waiter_name):
        waiters = self._model.waiter_names
        if waiter_name not in waiters:
            self.module.fail_json(f"Unable to find waiter {waiter_name}.  Available_waiters: {waiters}")
        return botocore.waiter.create_waiter_with_client(
            waiter_name,
            self._model,
            self.client,
        )


class Boto3Mixin:
    @staticmethod
    def aws_error_handler(description):
        r"""
        A simple wrapper that handles the usual botocore exceptions and exits
        with module.fail_json_aws.  Designed to be used with BaseResourceManager.
        Assumptions:
          1) First argument (usually `self` of method being wrapped will have a
             'module' attribute which is an AnsibleAWSModule
          2) First argument of method being wrapped will have an
            _extra_error_output() method which takes no arguments and returns a
            dictionary of extra parameters to be returned in the event of a
            botocore exception.
        Parameters:
          description (string): In the event of a botocore exception the error
                                message will be 'Failed to {DESCRIPTION}'.

        Example Usage:
            class ExampleClass(Boto3Mixin):
                def __init__(self, module)
                    self.module = module
                    self._get_client()

                @Boto3Mixin.aws_error_handler("connect to AWS")
                def _get_client(self):
                    self.client = self.module.client('ec2')

                @Boto3Mixin.aws_error_handler("describe EC2 instances")
                def _do_something(**params):
                    return self.client.describe_instances(**params)
        """

        def wrapper(func):
            @wraps(func)
            def handler(_self, *args, **kwargs):
                extra_ouput = _self._extra_error_output()
                try:
                    return func(_self, *args, **kwargs)
                except botocore.exceptions.WaiterError as e:
                    _self.module.fail_json_aws(e, msg=f"Failed waiting for {description}", **extra_ouput)
                except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                    _self.module.fail_json_aws(e, msg=f"Failed to {description}", **extra_ouput)

            return handler

        return wrapper

    def _normalize_boto3_resource(self, resource, add_tags=False):
        r"""
        Performs common boto3 resource to Ansible resource conversion.
        `resource['Tags']` will by default be converted from the boto3 tag list
        format to a simple dictionary.
        Parameters:
          resource (dict): The boto3 style resource to convert to the normal Ansible
                           format (snake_case).
          add_tags (bool): When `true`, if a resource does not have 'Tags' property
                           the returned resource will have tags set to an empty
                           dictionary.
        """
        if resource is None:
            return None

        tags = resource.get("Tags", None)
        if tags:
            tags = boto3_tag_list_to_ansible_dict(tags)
        elif add_tags or tags is not None:
            tags = {}

        normalized_resource = camel_dict_to_snake_dict(resource)
        if tags is not None:
            normalized_resource["tags"] = tags
        return normalized_resource

    def _extra_error_output(self):
        # In the event of an error it can be helpful to ouput things like the
        # 'name'/'arn' of a resource.
        return dict()


class BaseResourceManager(Boto3Mixin):
    def __init__(self, module):
        r"""
        Parameters:
            module (AnsibleAWSModule): An Ansible module.
        """
        self.module = module
        self.changed = False
        self.original_resource = dict()
        self.updated_resource = dict()
        self._resource_updates = dict()
        self._preupdate_resource = dict()
        self._wait = True
        self._wait_timeout = None
        super(BaseResourceManager, self).__init__()

    def _merge_resource_changes(self, filter_immutable=True, creation=False):
        """
        Merges the contents of the 'pre_update' resource and metadata variables
        with the pending updates
        """
        resource = deepcopy(self._preupdate_resource)
        resource.update(self._resource_updates)

        if filter_immutable:
            resource = self._filter_immutable_resource_attributes(resource)

        return resource

    def _filter_immutable_resource_attributes(self, resource):
        return deepcopy(resource)

    def _do_creation_wait(self, **params):
        pass

    def _do_deletion_wait(self, **params):
        pass

    def _do_update_wait(self, **params):
        pass

    @property
    def _waiter_config(self):
        params = dict()
        if self._wait_timeout:
            delay = min(5, self._wait_timeout)
            max_attempts = self._wait_timeout // delay
            config = dict(Delay=delay, MaxAttempts=max_attempts)
            params["WaiterConfig"] = config
        return params

    def _wait_for_deletion(self):
        if not self._wait:
            return
        params = self._waiter_config
        self._do_deletion_wait(**params)

    def _wait_for_creation(self):
        if not self._wait:
            return
        params = self._waiter_config
        self._do_creation_wait(**params)

    def _wait_for_update(self):
        if not self._wait:
            return
        params = self._waiter_config
        self._do_update_wait(**params)

    def _generate_updated_resource(self):
        """
        Merges all pending changes into self.updated_resource
        Used during check mode where it's not possible to get and
        refresh the resource
        """
        return self._merge_resource_changes(filter_immutable=False)

    # If you override _flush_update you're responsible for handling check_mode
    # If you override _do_update_resource you'll only be called if check_mode == False
    def _flush_create(self):
        changed = True

        if not self.module.check_mode:
            changed = self._do_create_resource()
            self._wait_for_creation()
            self._do_creation_wait()
            self.updated_resource = self.get_resource()
        else:  # (CHECK MODE)
            self.updated_resource = self._normalize_resource(self._generate_updated_resource())

        self._resource_updates = dict()
        self.changed = changed
        return True

    def _check_updates_pending(self):
        if self._resource_updates:
            return True
        return False

    # If you override _flush_update you're responsible for handling check_mode
    # If you override _do_update_resource you'll only be called if there are
    # updated pending and check_mode == False
    def _flush_update(self):
        if not self._check_updates_pending():
            self.updated_resource = self.original_resource
            return False

        if not self.module.check_mode:
            self._do_update_resource()
            self._wait_for_update()
            self.updated_resource = self.get_resource()
        else:  # (CHECK_MODE)
            self.updated_resource = self._normalize_resource(self._generate_updated_resource())

        self._resource_updates = dict()
        return True

    def flush_changes(self):
        if self.original_resource:
            return self._flush_update()
        else:
            return self._flush_create()

    def _set_resource_value(self, key, value, description=None, immutable=False):
        if value is None:
            return False
        if value == self._get_resource_value(key):
            return False
        if immutable and self.original_resource:
            if description is None:
                description = key
            self.module.fail_json(msg=f"{description} can not be updated after creation")
        self._resource_updates[key] = value
        self.changed = True
        return True

    def _get_resource_value(self, key, default=None):
        default_value = self._preupdate_resource.get(key, default)
        return self._resource_updates.get(key, default_value)

    def set_wait(self, wait):
        if wait is None:
            return False
        if wait == self._wait:
            return False

        self._wait = wait
        return True

    def set_wait_timeout(self, timeout):
        if timeout is None:
            return False
        if timeout == self._wait_timeout:
            return False

        self._wait_timeout = timeout
        return True
