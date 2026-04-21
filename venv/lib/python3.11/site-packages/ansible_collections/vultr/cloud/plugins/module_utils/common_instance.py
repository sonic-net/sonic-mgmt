# -*- coding: utf-8 -*-
#
# Copyright (c) 2023, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64

from .vultr_v2 import AnsibleVultr


class AnsibleVultrCommonInstance(AnsibleVultr):
    VPC_CONFIGS = {
        "v1": {
            "param": "vpcs",
            "path": "/vpcs",
            "suffix": "",
        },
        "v2": {
            "param": "vpc2s",
            "path": "/vpc2",
            "suffix": "2",
        },
    }

    def get_ssh_key_ids(self):
        ssh_key_names = list(self.module.params["ssh_keys"])
        ssh_keys = self.query_list(path="/ssh-keys", result_key="ssh_keys")

        ssh_key_ids = list()
        for ssh_key in ssh_keys:
            if ssh_key["name"] in ssh_key_names:
                ssh_key_ids.append(ssh_key["id"])
                ssh_key_names.remove(ssh_key["name"])

        if ssh_key_names:
            self.module.fail_json(msg="SSH key names not found: %s" % ", ".join(ssh_key_names))

        return ssh_key_ids

    def get_resource_vpcs(self, resource, api_version="v1"):
        path = "%s/%s" % (self.resource_path, resource["id"] + self.VPC_CONFIGS[api_version]["path"])
        vpcs = self.query_list(path=path, result_key="vpcs")

        # TODO: Workaround to get the description field into the list if missing
        result = list()
        for vpc in vpcs:
            if "description" in vpc:
                return vpcs

            vpc_detail = self.query_by_id(resource_id=vpc["id"], path=self.VPC_CONFIGS[api_version]["path"], result_key="vpc")
            vpc["description"] = vpc_detail["description"]
            result.append(vpc)
        return result

    def get_vpc_ids(self, api_version="v1"):
        vpc_names = list(self.module.params[self.VPC_CONFIGS[api_version]["param"]])
        vpcs = self.query_list(self.VPC_CONFIGS[api_version]["path"], result_key="vpcs")

        vpc_ids = list()
        for vpc in vpcs:
            if self.module.params["region"] != vpc["region"]:
                continue

            if vpc["description"] in vpc_names:
                vpc_ids.append(vpc["id"])
                vpc_names.remove(vpc["description"])

        if vpc_names:
            self.module.fail_json(msg="VPCs (%s) not found: %s" % (api_version, ", ".join(vpc_names)))

        return vpc_ids

    def get_firewall_group(self):
        return self.query_filter_list_by_name(
            key_name="description",
            param_key="firewall_group",
            path="/firewalls",
            result_key="firewall_groups",
            fail_not_found=True,
        )

    def get_snapshot(self):
        return self.query_filter_list_by_name(
            key_name="description",
            param_key="snapshot",
            path="/snapshots",
            result_key="snapshots",
            fail_not_found=True,
        )

    def get_startup_script(self):
        return self.query_filter_list_by_name(
            key_name="name",
            param_key="startup_script",
            path="/startup-scripts",
            result_key="startup_scripts",
            fail_not_found=True,
        )

    def get_os(self):
        return self.query_filter_list_by_name(
            key_name="name",
            param_key="os",
            path="/os",
            result_key="os",
            fail_not_found=True,
        )

    def get_app(self):
        return self.query_filter_list_by_name(
            key_name="deploy_name",
            param_key="app",
            path="/applications",
            result_key="applications",
            fail_not_found=True,
            query_params={"type": "one-click"},
        )

    def get_image(self):
        return self.query_filter_list_by_name(
            key_name="deploy_name",
            param_key="image",
            path="/applications",
            result_key="applications",
            fail_not_found=True,
            query_params={"type": "marketplace"},
        )

    def get_user_data(self, resource):
        res = self.api_query(
            path="%s/%s/%s" % (self.resource_path, resource[self.resource_key_id], "user-data"),
        )
        if res:
            return str(res.get("user_data", dict()).get("data"))
        return ""

    def transform_resource(self, resource):
        if not resource:
            return resource

        features = resource.get("features", list())
        # Cloud instance features
        if "backups" in self.module.params:
            resource["backups"] = "enabled" if "auto_backups" in features else "disabled"
        if "ddos_protection" in self.module.params:
            resource["ddos_protection"] = "ddos_protection" in features

        # Bare metal features
        if "persistent_pxe" in self.module.params:
            resource["persistent_pxe"] = "persistent_pxe" in features

        # Common features
        resource["enable_ipv6"] = "ipv6" in features

        # VPCs
        if "vpcs" in self.module.params:
            resource["vpcs"] = self.get_resource_vpcs(resource=resource)
        if "vpc2s" in self.module.params:
            resource["vpc2s"] = self.get_resource_vpcs(resource=resource, api_version="v2")

        return resource

    def get_detach_vpcs_ids(self, resource, api_version="v1"):
        detach_vpc_ids = []
        for vpc in resource.get(self.VPC_CONFIGS[api_version]["param"], list()):
            param = "attach_vpc%s" % self.VPC_CONFIGS[api_version]["suffix"]
            if vpc["id"] not in list(self.module.params[param]):
                detach_vpc_ids.append(vpc["id"])
        return detach_vpc_ids

    def configure(self):
        if self.module.params["state"] != "absent":
            if self.module.params.get("startup_script") is not None:
                self.module.params["script_id"] = self.get_startup_script()["id"]

            if self.module.params.get("snapshot") is not None:
                self.module.params["snapshot_id"] = self.get_snapshot()["id"]

            if self.module.params.get("os") is not None:
                self.module.params["os_id"] = self.get_os()["id"]

            if self.module.params.get("app") is not None:
                self.module.params["app_id"] = self.get_app()["id"]

            if self.module.params.get("image") is not None:
                self.module.params["image_id"] = self.get_image()["image_id"]

            if self.module.params.get("user_data") is not None:
                self.module.params["user_data"] = base64.b64encode(self.module.params["user_data"].encode())

            if self.module.params.get("ssh_keys") is not None:
                # sshkey_id ist a list of ids
                self.module.params["sshkey_id"] = self.get_ssh_key_ids()

            if self.module.params.get("vpcs") is not None:
                # attach_vpc is a list of ids used while creating
                self.module.params["attach_vpc"] = self.get_vpc_ids()

            if self.module.params.get("vpc2s") is not None:
                # attach_vpc2 is a list of ids used while creating
                self.module.params["attach_vpc2"] = self.get_vpc_ids(api_version="v2")

    def create(self):
        param_keys = ("os", "image", "app", "snapshot")
        if not any(self.module.params.get(x) is not None for x in param_keys):
            self.module.fail_json(msg="missing required arguements, one of the following required: %s" % ", ".join(param_keys))
        return super(AnsibleVultrCommonInstance, self).create()

    def update(self, resource):
        user_data = self.get_user_data(resource=resource)
        resource["user_data"] = user_data.encode()

        # VPC1
        if self.module.params.get("vpcs") is not None:
            resource["attach_vpc"] = list()
            for vpc in list(resource["vpcs"]):
                resource["attach_vpc"].append(vpc["id"])

            # detach_vpc is a list of ids to be detached
            resource["detach_vpc"] = list()
            self.module.params["detach_vpc"] = self.get_detach_vpcs_ids(resource=resource)

        # VPC2
        if self.module.params.get("vpc2s") is not None:
            resource["attach_vpc2"] = list()
            for vpc in list(resource["vpc2s"]):
                resource["attach_vpc2"].append(vpc["id"])

            # detach_vpc2 is a list of ids to be detached
            resource["detach_vpc2"] = list()
            self.module.params["detach_vpc2"] = self.get_detach_vpcs_ids(resource=resource, api_version="v2")

        return super(AnsibleVultrCommonInstance, self).update(resource=resource)

    def create_or_update(self):
        resource = super(AnsibleVultrCommonInstance, self).create_or_update()
        if resource:
            resource = self.wait_for_state(resource=resource, key="status", states=["active"], retries=300)
        return resource

    def transform_result(self, resource):
        if resource:
            resource["user_data"] = self.get_user_data(resource=resource)
        return resource
