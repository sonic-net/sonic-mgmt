# -*- coding: utf-8 -*-
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import random
import time

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.urls import fetch_url

VULTR_USER_AGENT = "Ansible Vultr v2"


def vultr_argument_spec():
    return dict(
        api_endpoint=dict(
            type="str",
            fallback=(env_fallback, ["VULTR_API_ENDPOINT"]),
            default="https://api.vultr.com/v2",
        ),
        api_key=dict(
            type="str",
            fallback=(env_fallback, ["VULTR_API_KEY"]),
            no_log=True,
            required=True,
        ),
        api_timeout=dict(
            type="int",
            fallback=(env_fallback, ["VULTR_API_TIMEOUT"]),
            default=180,
        ),
        api_retries=dict(
            type="int",
            fallback=(env_fallback, ["VULTR_API_RETRIES"]),
            default=5,
        ),
        api_retry_max_delay=dict(
            type="int",
            fallback=(env_fallback, ["VULTR_API_RETRY_MAX_DELAY"]),
            default=12,
        ),
        validate_certs=dict(
            type="bool",
            default=True,
        ),
    )


def backoff(retry, retry_max_delay=12):
    randomness = random.randint(0, 1000) / 1000.0
    delay = 2**retry + randomness
    if delay > retry_max_delay:
        delay = retry_max_delay + randomness
    time.sleep(delay)


class AnsibleVultr:
    def __init__(
        self,
        module,
        namespace,
        resource_path,
        ressource_result_key_singular,
        ressource_result_key_plural=None,
        resource_key_name=None,
        resource_key_id="id",
        resource_get_details=False,
        resource_create_param_keys=None,
        resource_update_param_keys=None,
        resource_update_method="PATCH",
    ):
        self.module = module
        self.namespace = namespace

        # The API resource path e.g ssh_key
        self.ressource_result_key_singular = ressource_result_key_singular

        # The API result data key e.g ssh_keys
        self.ressource_result_key_plural = ressource_result_key_plural or "%ss" % ressource_result_key_singular

        # The API resource path e.g /ssh-keys
        self.resource_path = resource_path

        # The name key of the resource, usually 'name'
        self.resource_key_name = resource_key_name

        # The name key of the resource, usually 'id'
        self.resource_key_id = resource_key_id

        # Some resources need an additional GET request to get all attributes
        self.resource_get_details = resource_get_details

        # List of params used to create the resource
        self.resource_create_param_keys = resource_create_param_keys or []

        # List of params used to update the resource
        self.resource_update_param_keys = resource_update_param_keys or []

        # Some resources have PUT, many have PATCH
        self.resource_update_method = resource_update_method

        self.result = {
            "changed": False,
            namespace: dict(),
            "diff": dict(before=dict(), after=dict()),
            "vultr_api": {
                "api_timeout": module.params["api_timeout"],
                "api_retries": module.params["api_retries"],
                "api_retry_max_delay": module.params["api_retry_max_delay"],
                "api_endpoint": module.params["api_endpoint"],
            },
        }

        self.headers = {
            "Authorization": "Bearer %s" % self.module.params["api_key"],
            "User-Agent": VULTR_USER_AGENT,
            "Accept": "application/json",
        }

        # Hook custom configurations
        self.configure()

    def configure(self):
        pass

    def transform_resource(self, resource):
        """
        Transforms (optional) the resource dict queried from the API
        """
        return resource

    def api_query(self, path, method="GET", data=None, query_params=None):
        if query_params:
            query = "?"
            for k, v in query_params.items():
                query += "&%s=%s" % (to_text(k), quote(to_text(v)))
            path += query

        if data:
            data = self.module.jsonify(data)

        retry_max_delay = self.module.params["api_retry_max_delay"]

        info = dict()
        resp_body = None
        for retry in range(0, self.module.params["api_retries"]):
            resp, info = fetch_url(
                self.module,
                self.module.params["api_endpoint"] + path,
                method=method,
                data=data,
                headers=self.headers,
                timeout=self.module.params["api_timeout"],
            )

            resp_body = resp.read() if resp is not None else ""

            # Check for:
            # 429 Too Many Requests
            # 500 Internal Server Error
            # 504 Gateway Time-out
            if info["status"] not in (429, 500, 504):
                break

            # Vultr has a rate limiting requests per second, try to be polite
            # Use exponential backoff plus a little bit of randomness
            backoff(retry=retry, retry_max_delay=retry_max_delay)
        else:
            self.module.fail_json(
                msg='Failure while calling the Vultr API v2 with %s for "%s" with %s retries' % (method, path, retry + 1),
                fetch_url_info=info,
            )

        # Success with content
        if info["status"] in (200, 201, 202):
            return self.module.from_json(to_text(resp_body, errors="surrogate_or_strict"))

        # Success without content
        if info["status"] in (404, 204):
            return dict()

        self.module.fail_json(
            msg='Failure while calling the Vultr API v2 with %s for "%s".' % (method, path),
            fetch_url_info=info,
        )

    def query_filter_list_by_name(
        self,
        path,
        key_name,
        result_key,
        param_key=None,
        key_id=None,
        query_params=None,
        get_details=False,
        fail_not_found=False,
        skip_transform=True,
    ):
        param_value = self.module.params.get(param_key or key_name)

        found = dict()
        for resource in self.query_list(path=path, result_key=result_key, query_params=query_params):
            if resource.get(key_name) == param_value:
                # In case the resource has a region, distinguish between the region
                # This allows to have identical identifiers (e.g. names) per region
                region_param = self.module.params.get("region")
                region_resource = resource.get("region")
                if region_resource and region_param and (region_param != region_resource):
                    continue

                if found:
                    if region_resource and not region_param:
                        msg = "More than one record with name=%s found. Use region to distinguish." % param_value
                    else:
                        msg = "More than one record with name=%s found. Use multiple=true if module supports it." % param_value

                    self.module.fail_json(msg=msg)

                found = resource

        if found:
            if get_details:
                return self.query_by_id(resource_id=found[key_id], skip_transform=skip_transform)
            else:
                if skip_transform:
                    return found
                else:
                    return self.transform_resource(found)

        elif fail_not_found:
            self.module.fail_json(msg="No Resource %s with %s found: %s" % (path, key_name, param_value))

        return dict()

    def query_filter_list(self):
        # Returns a single dict representing the resource queryied by name
        return self.query_filter_list_by_name(
            key_name=self.resource_key_name,
            key_id=self.resource_key_id,
            get_details=self.resource_get_details,
            path=self.resource_path,
            result_key=self.ressource_result_key_plural,
            skip_transform=False,
        )

    def query_by_id(self, resource_id=None, path=None, result_key=None, skip_transform=True):
        # Defaults
        path = path or self.resource_path
        result_key = result_key or self.ressource_result_key_singular

        resource = self.api_query(path="%s%s" % (path, "/" + resource_id if resource_id else resource_id))
        if resource:
            if skip_transform:
                return resource[result_key]
            else:
                return self.transform_resource(resource[result_key])

        return dict()

    def query(self):
        # Returns a single dict representing the resource
        return self.query_filter_list()

    def query_list(self, path=None, result_key=None, query_params=None):
        # Defaults
        path = path or self.resource_path
        result_key = result_key or self.ressource_result_key_plural

        resources = self.api_query(path=path, query_params=query_params)
        return resources[result_key] if resources else []

    def wait_for_state(self, resource, key, states, cmp="=", retries=60, skip_wait=False):
        if skip_wait:
            return resource

        resource_id = resource[self.resource_key_id]
        for retry in range(0, retries):
            resource = self.query_by_id(resource_id=resource_id, skip_transform=False)
            if resource and key in resource:
                if cmp == "=":
                    if resource[key] in states:
                        break
                else:
                    if resource[key] not in states:
                        break
            backoff(retry=retry)
        else:
            if cmp == "=":
                msg = "Wait for %s to become one in %s timed out" % (key, states)
            else:
                msg = "Wait for %s to not be in %s timed out" % (key, states)
            self.module.fail_json(msg=msg)

        return resource

    def create_or_update(self):
        resource = self.query()
        if not resource:
            resource = self.create()
        else:
            resource = self.update(resource)
        return resource

    def present(self):
        self.get_result(self.create_or_update())

    def create(self):
        data = dict()
        for param in self.resource_create_param_keys:
            data[param] = self.module.params.get(param)

        self.result["changed"] = True
        resource = dict()

        self.result["diff"]["before"] = dict()
        self.result["diff"]["after"] = data

        if not self.module.check_mode:
            resource = self.api_query(
                path=self.resource_path,
                method="POST",
                data=data,
            )
        return resource.get(self.ressource_result_key_singular) if resource else dict()

    def is_diff(self, param, resource):
        value = self.module.params.get(param)
        if value is None:
            return False

        if param not in resource:
            self.module.fail_json(msg="Can not diff, key %s not found in resource" % param)

        if isinstance(value, list):
            for v in value:
                if v not in resource[param]:
                    return True
        elif resource[param] != value:
            return True

        return False

    def update(self, resource):
        data = dict()

        for param in self.resource_update_param_keys:
            if self.is_diff(param, resource):
                self.result["changed"] = True
                data[param] = self.module.params.get(param)

        if self.result["changed"]:
            self.result["diff"]["before"] = dict(**resource)
            self.result["diff"]["after"] = dict(**resource)
            self.result["diff"]["after"].update(data)

            if not self.module.check_mode:
                self.api_query(
                    path="%s/%s" % (self.resource_path, resource[self.resource_key_id]),
                    method=self.resource_update_method,
                    data=data,
                )
                resource = self.query_by_id(resource_id=resource[self.resource_key_id])
        return resource

    def absent(self, resource=None):
        if resource is None:
            resource = self.query()

        if resource:
            self.result["changed"] = True

            self.result["diff"]["before"] = dict(**resource)
            self.result["diff"]["after"] = dict()

            if not self.module.check_mode:
                self.api_query(
                    path="%s/%s" % (self.resource_path, resource[self.resource_key_id]),
                    method="DELETE",
                )
        self.get_result(resource)

    def transform_result(self, resource):
        return resource

    def get_result(self, resource):
        self.result[self.namespace] = self.transform_result(resource)
        self.module.exit_json(**self.result)
