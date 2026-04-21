# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>

# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)


from __future__ import annotations

import traceback
from typing import Any, NoReturn

from ansible.module_utils.basic import AnsibleModule as AnsibleModuleBase, env_fallback
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.validation import (
    check_missing_parameters,
    check_required_one_of,
)

from .client import ClientException, client_check_required_lib, client_get_by_name_or_id
from .vendor.hcloud import (
    APIException,
    Client,
    HCloudException,
    exponential_backoff_function,
)
from .vendor.hcloud.actions import ActionException
from .version import version


# Provide typing definitions to the AnsibleModule class
class AnsibleModule(AnsibleModuleBase):
    params: dict


class AnsibleHCloud:
    represent: str

    module: AnsibleModule

    def __init__(self, module: AnsibleModule):
        if not self.represent:
            raise NotImplementedError(f"represent property is not defined for {self.__class__.__name__}")

        self.module = module
        self.result = {"changed": False, self.represent: None}

        try:
            client_check_required_lib()
        except ClientException as exception:
            module.fail_json(msg=to_native(exception))

        self._build_client()

    def fail_json_hcloud(
        self,
        exception: HCloudException,
        msg: str | None = None,
        params: Any = None,
        **kwargs,
    ) -> NoReturn:
        last_traceback = traceback.format_exc()

        failure = {}

        if params is not None:
            failure["params"] = params

        if isinstance(exception, APIException):
            failure["message"] = exception.message
            failure["code"] = exception.code
            failure["details"] = exception.details

        elif isinstance(exception, ActionException):
            failure["action"] = {k: getattr(exception.action, k) for k in exception.action.__slots__}

        exception_message = to_native(exception)
        if msg is not None:
            msg = f"{exception_message}: {msg}"
        else:
            msg = exception_message

        self.module.fail_json(msg=msg, exception=last_traceback, failure=failure, **kwargs)

    def _build_client(self) -> None:
        self.client = Client(
            token=self.module.params["api_token"],
            api_endpoint=self.module.params["api_endpoint"],
            application_name="ansible-module",
            application_version=version,
            # Total waiting time before timeout is > 117.0
            poll_interval=exponential_backoff_function(base=1.0, multiplier=2, cap=5.0),
            poll_max_retries=25,
        )

    def _client_get_by_name_or_id(self, resource: str, param: str | int):
        """
        Get a resource by name, and if not found by its ID.

        :param resource: Name of the resource client that implements both `get_by_name` and `get_by_id` methods
        :param param: Name or ID of the resource to query
        """
        try:
            return client_get_by_name_or_id(self.client, resource, param)
        except ClientException as exception:
            self.module.fail_json(msg=to_native(exception))

    def _mark_as_changed(self) -> None:
        self.result["changed"] = True

    def fail_on_invalid_params(
        self,
        *,
        required: list[str] | None = None,
        required_one_of: list[list[str]] | None = None,
    ) -> None:
        """
        Run additional validation that cannot be done in the argument spec validation.

        :param required_params: Check that terms exists in the module params.
        :param required_one_of: Check each list of terms to ensure at least one exists in the module parameters.
        """
        try:
            if required:
                check_missing_parameters(self.module.params, required)

            if required_one_of:
                params_without_nones = {k: v for k, v in self.module.params.items() if v is not None}
                check_required_one_of(required_one_of, params_without_nones)

        except TypeError as e:
            self.module.fail_json(msg=to_native(e))

    @classmethod
    def base_module_arguments(cls):
        return {
            "api_token": {
                "type": "str",
                "required": True,
                "fallback": (env_fallback, ["HCLOUD_TOKEN"]),
                "no_log": True,
            },
            "api_endpoint": {
                "type": "str",
                "fallback": (env_fallback, ["HCLOUD_ENDPOINT"]),
                "default": "https://api.hetzner.cloud/v1",
                "aliases": ["endpoint"],
            },
        }

    def _prepare_result(self) -> dict[str, Any]:
        """Prepare the result for every module"""
        return {}

    def get_result(self) -> dict[str, Any]:
        if getattr(self, self.represent) is not None:
            self.result[self.represent] = self._prepare_result()
        return self.result
