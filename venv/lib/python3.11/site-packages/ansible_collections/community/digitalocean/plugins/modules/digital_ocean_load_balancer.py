#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2021, Mark Mercado <mamercad@gmail.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_load_balancer
version_added: 1.10.0
short_description: Manage DigitalOcean Load Balancers
description:
  - Manage DigitalOcean Load Balancers
author: "Mark Mercado (@mamercad)"
options:
  state:
    description:
      - The usual, C(present) to create, C(absent) to destroy
    type: str
    choices: ["present", "absent"]
    default: present
  name:
    description:
      - A human-readable name for a load balancer instance.
      - Required and must be unique (current API documentation is not up-to-date for this parameter).
    type: str
    required: true
  size:
    description:
      - The size of the load balancer.
      - The available sizes are C(lb-small), C(lb-medium), or C(lb-large).
      - You can resize load balancers after creation up to once per hour.
      - You cannot resize a load balancer within the first hour of its creation.
      - This field has been replaced by the C(size_unit) field for all regions except in C(ams2), C(nyc2), and C(sfo1).
      - Each available load balancer size now equates to the load balancer having a set number of nodes.
      - The formula is C(lb-small) = 1 node, C(lb-medium) = 3 nodes, C(lb-large) = 6 nodes.
    required: false
    type: str
    choices: ["lb-small", "lb-medium", "lb-large"]
    default: lb-small
  size_unit:
    description:
      - How many nodes the load balancer contains.
      - Each additional node increases the load balancer's ability to manage more connections.
      - Load balancers can be scaled up or down, and you can change the number of nodes after creation up to once per hour.
      - This field is currently not available in the C(ams2), C(nyc2), or C(sfo1) regions.
      - Use the C(size) field to scale load balancers that reside in these regions.
      - The value must be in the range 1-100.
    required: false
    type: int
    default: 1
  droplet_ids:
    description:
      - An array containing the IDs of the Droplets assigned to the load balancer.
      - Required when creating load balancers.
      - Mutually exclusive with tag, you can either define tag or droplet_ids but not both.
    required: false
    type: list
    elements: int
  tag:
    description:
      - A tag associated with the droplets that you want to dynamically assign to the load balancer.
      - Required when creating load balancers.
      - Mutually exclusive with droplet_ids, you can either define tag or droplet_ids but not both.
    required: false
    type: str
  region:
    description:
      - The slug identifier for the region where the resource will initially be available.
    required: false
    type: str
    aliases: ["region_id"]
  forwarding_rules:
    description:
      - An array of objects specifying the forwarding rules for a load balancer.
      - Required when creating load balancers.
    required: false
    type: list
    elements: dict
    suboptions:
      entry_protocol:
        type: str
        description: Entry protocol
        default: http
      entry_port:
        type: int
        description: Entry port
        default: 8080
      target_protocol:
        type: str
        description: Target protocol
        default: http
      target_port:
        type: int
        description: Target port
        default: 8080
      certificate_id:
        type: str
        description: Certificate ID
        default: ""
      tls_passthrough:
        type: bool
        description: TLS passthrough
        default: false
    default:
      - entry_protocol: http
        entry_port: 8080
        target_protocol: http
        target_port: 8080
        certificate_id: ""
        tls_passthrough: false
  health_check:
    description:
      - An object specifying health check settings for the load balancer.
    required: false
    type: dict
    suboptions:
      protocol:
        description: Protocol
        type: str
        required: false
        default: http
      port:
        description: Port
        type: int
        required: false
        default: 80
      path:
        description: Path
        type: str
        required: false
        default: /
      check_interval_seconds:
        description: Check interval seconds
        type: int
        required: false
        default: 10
      response_timeout_seconds:
        description: Response timeout seconds
        type: int
        required: false
        default: 5
      healthy_threshold:
        description: Healthy threshold
        type: int
        required: false
        default: 5
      unhealthy_threshold:
        description: Unhealthy threshold
        type: int
        required: false
        default: 3
    default:
      protocol: http
      port: 80
      path: /
      check_interval_seconds: 10
      response_timeout_seconds: 5
      healthy_threshold: 5
      unhealthy_threshold: 3
  sticky_sessions:
    description:
      - An object specifying sticky sessions settings for the load balancer.
    required: false
    type: dict
    suboptions:
      type:
        description: Type
        type: str
        required: false
        default: none
    default:
      type: none
  redirect_http_to_https:
    description:
      - A boolean value indicating whether HTTP requests to the load balancer on port 80 will be redirected to HTTPS on port 443.
    type: bool
    required: false
    default: false
  enable_proxy_protocol:
    description:
      - A boolean value indicating whether PROXY Protocol is in use.
    type: bool
    required: false
    default: false
  enable_backend_keepalive:
    description:
      - A boolean value indicating whether HTTP keepalive connections are maintained to target Droplets.
    type: bool
    required: false
    default: false
  vpc_uuid:
    description:
      - A string specifying the UUID of the VPC to which the load balancer is assigned.
      - If unspecified, uses the default VPC in the region.
    type: str
    required: false
  wait:
    description:
      - Wait for the Load Balancer to be running before returning.
    type: bool
    required: false
    default: true
  wait_timeout:
    description:
      - How long before wait gives up, in seconds, when creating a Load Balancer.
    type: int
    default: 600
  project_name:
    aliases: ["project"]
    description:
    - Project to assign the resource to (project name, not UUID).
    - Defaults to the default project of the account (empty string).
    - Currently only supported when creating.
    type: str
    required: false
    default: ""
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Create a Load Balancer
  community.digitalocean.digital_ocean_load_balancer:
    state: present
    name: test-loadbalancer-1
    droplet_ids:
      - 12345678
    region: nyc1
    forwarding_rules:
      - entry_protocol: http
        entry_port: 8080
        target_protocol: http
        target_port: 8080
        certificate_id: ""
        tls_passthrough: false

- name: Create a Load Balancer (and assign to Project "test")
  community.digitalocean.digital_ocean_load_balancer:
    state: present
    name: test-loadbalancer-1
    droplet_ids:
      - 12345678
    region: nyc1
    forwarding_rules:
      - entry_protocol: http
        entry_port: 8080
        target_protocol: http
        target_port: 8080
        certificate_id: ""
        tls_passthrough: false
    project: test

- name: Create a Load Balancer and associate it with a tag
  community.digitalocean.digital_ocean_load_balancer:
    state: present
    name: test-loadbalancer-1
    tag: test-tag
    region: tor1
"""


RETURN = r"""
data:
  description: A DigitalOcean Load Balancer
  returned: changed
  type: dict
  sample:
    load_balancer:
      algorithm: round_robin
      created_at: '2021-08-22T14:23:41Z'
      droplet_ids:
      - 261172461
      enable_backend_keepalive: false
      enable_proxy_protocol: false
      forwarding_rules:
      - certificate_id: ''
        entry_port: 8080
        entry_protocol: http
        target_port: 8080
        target_protocol: http
        tls_passthrough: false
      health_check:
        check_interval_seconds: 10
        healthy_threshold: 5
        path: /
        port: 80
        protocol: http
        response_timeout_seconds: 5
        unhealthy_threshold: 3
      id: b4fdb507-70e8-4325-a89e-d02271b93618
      ip: 159.203.150.113
      name: test-loadbalancer-1
      redirect_http_to_https: false
      region:
        available: true
        features:
        - backups
        - ipv6
        - metadata
        - install_agent
        - storage
        - image_transfer
        name: New York 3
        sizes:
        - s-1vcpu-1gb
        - s-1vcpu-1gb-amd
        - s-1vcpu-1gb-intel
        - s-1vcpu-2gb
        - s-1vcpu-2gb-amd
        - s-1vcpu-2gb-intel
        - s-2vcpu-2gb
        - s-2vcpu-2gb-amd
        - s-2vcpu-2gb-intel
        - s-2vcpu-4gb
        - s-2vcpu-4gb-amd
        - s-2vcpu-4gb-intel
        - s-4vcpu-8gb
        - c-2
        - c2-2vcpu-4gb
        - s-4vcpu-8gb-amd
        - s-4vcpu-8gb-intel
        - g-2vcpu-8gb
        - gd-2vcpu-8gb
        - s-8vcpu-16gb
        - m-2vcpu-16gb
        - c-4
        - c2-4vcpu-8gb
        - s-8vcpu-16gb-amd
        - s-8vcpu-16gb-intel
        - m3-2vcpu-16gb
        - g-4vcpu-16gb
        - so-2vcpu-16gb
        - m6-2vcpu-16gb
        - gd-4vcpu-16gb
        - so1_5-2vcpu-16gb
        - m-4vcpu-32gb
        - c-8
        - c2-8vcpu-16gb
        - m3-4vcpu-32gb
        - g-8vcpu-32gb
        - so-4vcpu-32gb
        - m6-4vcpu-32gb
        - gd-8vcpu-32gb
        - so1_5-4vcpu-32gb
        - m-8vcpu-64gb
        - c-16
        - c2-16vcpu-32gb
        - m3-8vcpu-64gb
        - g-16vcpu-64gb
        - so-8vcpu-64gb
        - m6-8vcpu-64gb
        - gd-16vcpu-64gb
        - so1_5-8vcpu-64gb
        - m-16vcpu-128gb
        - c-32
        - c2-32vcpu-64gb
        - m3-16vcpu-128gb
        - m-24vcpu-192gb
        - g-32vcpu-128gb
        - so-16vcpu-128gb
        - m6-16vcpu-128gb
        - gd-32vcpu-128gb
        - m3-24vcpu-192gb
        - g-40vcpu-160gb
        - so1_5-16vcpu-128gb
        - m-32vcpu-256gb
        - gd-40vcpu-160gb
        - so-24vcpu-192gb
        - m6-24vcpu-192gb
        - m3-32vcpu-256gb
        - so1_5-24vcpu-192gb
        - m6-32vcpu-256gb
        slug: nyc3
      size: lb-small
      status: active
      sticky_sessions:
        type: none
      tag: ''
      vpc_uuid: b8fd9a58-d93d-4329-b54a-78a397d64855
msg:
    description: Informational or error message encountered during execution
    returned: changed
    type: str
    sample: No project named test2 found
assign_status:
    description: Assignment status (ok, not_found, assigned, already_assigned, service_down)
    returned: changed
    type: str
    sample: assigned
resources:
    description: Resource assignment involved in project assignment
    returned: changed
    type: dict
    sample:
        assigned_at: '2021-10-25T17:39:38Z'
        links:
            self: https://api.digitalocean.com/v2/load_balancers/17d171d0-8a8b-4251-9c18-c96cc515d36d
        status: assigned
        urn: do:loadbalancer:17d171d0-8a8b-4251-9c18-c96cc515d36d
"""


import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)


class DOLoadBalancer(object):
    # Regions which use 'size' versus 'size_unit'
    size_regions = {"ams2", "nyc2", "sfo1"}
    all_sizes = {"lb-small", "lb-medium", "lb-large"}
    default_size = "lb-small"
    min_size_unit = 1
    max_size_unit = 100
    default_size_unit = 1

    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        self.id = None
        self.name = self.module.params.get("name")
        self.region = self.module.params.get("region")

        # Handle size versus size_unit
        if self.region in DOLoadBalancer.size_regions:
            self.module.params.pop("size_unit")
            # Ensure that we have size
            size = self.module.params.get("size", None)
            if not size:
                self.module.fail_json(msg="Missing required 'size' parameter")
            elif size not in DOLoadBalancer.all_sizes:
                self.module.fail_json(
                    msg="Invalid 'size' parameter '{0}', must be one of: {1}".format(
                        size, ", ".join(DOLoadBalancer.all_sizes)
                    )
                )
        else:
            self.module.params.pop("size")
            # Ensure that we have size_unit
            size_unit = self.module.params.get("size_unit", None)
            if not size_unit:
                self.module.fail_json(msg="Missing required 'size_unit' parameter")
            elif (
                size_unit < DOLoadBalancer.min_size_unit
                or size_unit > DOLoadBalancer.max_size_unit
            ):
                self.module.fail_json(
                    msg="Invalid 'size_unit' parameter '{0}', must be in range: {1}-{2}".format(
                        size_unit,
                        DOLoadBalancer.min_size_unit,
                        DOLoadBalancer.max_size_unit,
                    )
                )

        self.updates = []

        # Pop these values so we don't include them in the POST data
        self.module.params.pop("oauth_token")
        self.wait = self.module.params.pop("wait", True)
        self.wait_timeout = self.module.params.pop("wait_timeout", 600)
        if self.module.params.get("project_name"):
            # only load for non-default project assignments
            self.projects = DigitalOceanProjects(module, self.rest)

    def get_by_id(self):
        """Fetch an existing DigitalOcean Load Balancer (by id)
        API reference: https://docs.digitalocean.com/reference/api/api-reference/#operation/get_load_balancer
        """
        response = self.rest.get("load_balancers/{0}".format(self.id))
        json_data = response.json
        if response.status_code == 200:
            # Found one with the given id:
            lb = json_data.get("load_balancer", None)
            if lb is not None:
                self.lb = lb
                return lb
            else:
                self.module.fail_json(
                    msg="Unexpected error; please file a bug: get_by_id"
                )
        return None

    def get_by_name(self):
        """Fetch all existing DigitalOcean Load Balancers
        API reference: https://docs.digitalocean.com/reference/api/api-reference/#operation/list_all_load_balancers
        """
        page = 1
        while page is not None:
            response = self.rest.get("load_balancers?page={0}".format(page))
            json_data = response.json
            if json_data is None:
                self.module.fail_json(
                    msg="Empty response from the DigitalOcean API; please try again or open a bug if it never succeeds."
                )
            if response.status_code == 200:
                lbs = json_data.get("load_balancers", [])
                for lb in lbs:
                    # Found one with the same name:
                    name = lb.get("name", None)
                    if name == self.name:
                        # Make sure the region is the same!
                        region = lb.get("region", None)
                        if region is not None:
                            region_slug = region.get("slug", None)
                            if region_slug is not None:
                                if region_slug == self.region:
                                    self.lb = lb
                                    return lb
                                else:
                                    self.module.fail_json(
                                        msg="Cannot change load balancer region -- delete and re-create"
                                    )
                            else:
                                self.module.fail_json(
                                    msg="Unexpected error; please file a bug: get_by_name"
                                )
                        else:
                            self.module.fail_json(
                                msg="Unexpected error; please file a bug: get_by_name"
                            )
                if (
                    "links" in json_data
                    and "pages" in json_data["links"]
                    and "next" in json_data["links"]["pages"]
                ):
                    page += 1
                else:
                    page = None
            else:
                self.module.fail_json(
                    msg="Unexpected error; please file a bug: get_by_name"
                )
        return None

    def ensure_active(self):
        """Wait for the existing Load Balancer to be active"""
        end_time = time.monotonic() + self.wait_timeout
        while time.monotonic() < end_time:
            if self.get_by_id():
                status = self.lb.get("status", None)
                if status is not None:
                    if status == "active":
                        return True
                else:
                    self.module.fail_json(
                        msg="Unexpected error; please file a bug: ensure_active"
                    )
            else:
                self.module.fail_json(
                    msg="Load Balancer {0} in {1} not found".format(
                        self.id, self.region
                    )
                )
            time.sleep(10)
        self.module.fail_json(
            msg="Timed out waiting for Load Balancer {0} in {1} to be active".format(
                self.id, self.region
            )
        )

    def is_same(self, found_lb):
        """Checks if exising Load Balancer is the same as requested"""

        check_attributes = [
            "droplet_ids",
            "size",
            "size_unit",
            "forwarding_rules",
            "health_check",
            "sticky_sessions",
            "redirect_http_to_https",
            "enable_proxy_protocol",
            "enable_backend_keepalive",
        ]

        lb_region = found_lb.get("region", None)
        if not lb_region:
            self.module.fail_json(
                msg="Unexpected error; please file a bug should this persist: empty load balancer region"
            )

        lb_region_slug = lb_region.get("slug", None)
        if not lb_region_slug:
            self.module.fail_json(
                msg="Unexpected error; please file a bug should this persist: empty load balancer region slug"
            )

        for attribute in check_attributes:
            if (
                attribute == "size"
                and lb_region_slug not in DOLoadBalancer.size_regions
            ):
                continue
            if (
                attribute == "size_unit"
                and lb_region_slug in DOLoadBalancer.size_regions
            ):
                continue
            if self.module.params.get(attribute, None) != found_lb.get(attribute, None):
                self.updates.append(attribute)

        # Check if the VPC needs changing.
        vpc_uuid = self.lb.get("vpc_uuid", None)
        if vpc_uuid is not None:
            if vpc_uuid != found_lb.get("vpc_uuid", None):
                self.updates.append("vpc_uuid")

        if len(self.updates):
            return False
        else:
            return True

    def update(self):
        """Updates a DigitalOcean Load Balancer
        API reference: https://docs.digitalocean.com/reference/api/api-reference/#operation/update_load_balancer
        """
        request_params = dict(self.module.params)
        self.id = self.lb.get("id", None)
        self.name = self.lb.get("name", None)
        self.vpc_uuid = self.lb.get("vpc_uuid", None)
        if self.id is not None and self.name is not None and self.vpc_uuid is not None:
            request_params["vpc_uuid"] = self.vpc_uuid
            response = self.rest.put(
                "load_balancers/{0}".format(self.id), data=request_params
            )
            json_data = response.json
            if response.status_code == 200:
                self.module.exit_json(
                    changed=True,
                    msg="Load Balancer {0} ({1}) in {2} updated: {3}".format(
                        self.name, self.id, self.region, ", ".join(self.updates)
                    ),
                )
            else:
                self.module.fail_json(
                    changed=False,
                    msg="Error updating Load Balancer {0} ({1}) in {2}: {3}".format(
                        self.name, self.id, self.region, json_data["message"]
                    ),
                )
        else:
            self.module.fail_json(msg="Unexpected error; please file a bug: update")

    def create(self):
        """Creates a DigitalOcean Load Balancer
        API reference: https://docs.digitalocean.com/reference/api/api-reference/#operation/create_load_balancer
        """

        # Check if it exists already (the API docs aren't up-to-date right now,
        # "name" is required and must be unique across the account.
        found_lb = self.get_by_name()
        if found_lb is not None:
            # Do we need to update it?
            if not self.is_same(found_lb):
                if self.module.check_mode:
                    self.module.exit_json(
                        changed=False,
                        msg="Load Balancer {0} already exists in {1} (and needs changes)".format(
                            self.name, self.region
                        ),
                        data={"load_balancer": found_lb},
                    )
                else:
                    self.update()
            else:
                self.module.exit_json(
                    changed=False,
                    msg="Load Balancer {0} already exists in {1} (and needs no changes)".format(
                        self.name, self.region
                    ),
                    data={"load_balancer": found_lb},
                )

        # Check mode.
        if self.module.check_mode:
            self.module.exit_json(
                changed=False,
                msg="Would create Load Balancer {0} in {1}".format(
                    self.name, self.region
                ),
            )

        # Create it.
        request_params = dict(self.module.params)
        response = self.rest.post("load_balancers", data=request_params)
        json_data = response.json
        if response.status_code != 202:
            self.module.fail_json(
                msg="Failed creating Load Balancer {0} in {1}: {2}".format(
                    self.name, self.region, json_data["message"]
                )
            )

        # Store it.
        lb = json_data.get("load_balancer", None)
        if lb is None:
            self.module.fail_json(
                msg="Unexpected error; please file a bug: create empty lb"
            )

        self.id = lb.get("id", None)
        if self.id is None:
            self.module.fail_json(
                msg="Unexpected error; please file a bug: create missing id"
            )

        if self.wait:
            self.ensure_active()

        project_name = self.module.params.get("project_name")
        if project_name:  # empty string is the default project, skip project assignment
            urn = "do:loadbalancer:{0}".format(self.id)
            (
                assign_status,
                error_message,
                resources,
            ) = self.projects.assign_to_project(project_name, urn)
            self.module.exit_json(
                changed=True,
                data=json_data,
                msg=error_message,
                assign_status=assign_status,
                resources=resources,
            )
        else:
            self.module.exit_json(changed=True, data=json_data)

    def delete(self):
        """Deletes a DigitalOcean Load Balancer
        API reference: https://docs.digitalocean.com/reference/api/api-reference/#operation/delete_load_balancer
        """

        lb = self.get_by_name()
        if lb is not None:
            id = lb.get("id", None)
            name = lb.get("name", None)
            lb_region = lb.get("region", None)
            if not lb_region:
                self.module.fail_json(
                    msg="Unexpected error; please file a bug: delete missing region"
                )
            lb_region_slug = lb_region.get("slug", None)
            if id is None or name is None or lb_region_slug is None:
                self.module.fail_json(
                    msg="Unexpected error; please file a bug: delete missing id, name, or region slug"
                )
            else:
                response = self.rest.delete("load_balancers/{0}".format(id))
                json_data = response.json
                if response.status_code == 204:
                    # Response body should be empty
                    self.module.exit_json(
                        changed=True,
                        msg="Load Balancer {0} ({1}) in {2} deleted".format(
                            name, id, lb_region_slug
                        ),
                    )
                else:
                    message = json_data.get(
                        "message", "Empty failure message from the DigitalOcean API!"
                    )
                    self.module.fail_json(
                        changed=False,
                        msg="Failed to delete Load Balancer {0} ({1}) in {2}: {3}".format(
                            name, id, lb_region_slug, message
                        ),
                    )
        else:
            self.module.fail_json(
                changed=False,
                msg="Load Balancer {0} not found in {1}".format(self.name, self.region),
            )


def run(module):
    state = module.params.pop("state")
    lb = DOLoadBalancer(module)
    if state == "present":
        lb.create()
    elif state == "absent":
        lb.delete()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        name=dict(type="str", required=True),
        size=dict(
            type="str",
            choices=list(DOLoadBalancer.all_sizes),
            required=False,
            default=DOLoadBalancer.default_size,
        ),
        size_unit=dict(
            type="int",
            required=False,
            default=DOLoadBalancer.default_size_unit,
        ),
        droplet_ids=dict(type="list", elements="int", required=False),
        tag=dict(type="str", required=False),
        region=dict(
            aliases=["region_id"],
            required=False,
        ),
        forwarding_rules=dict(
            type="list",
            elements="dict",
            required=False,
            default=[
                {
                    "entry_protocol": "http",
                    "entry_port": 8080,
                    "target_protocol": "http",
                    "target_port": 8080,
                    "certificate_id": "",
                    "tls_passthrough": False,
                }
            ],
        ),
        health_check=dict(
            type="dict",
            required=False,
            default=dict(
                {
                    "protocol": "http",
                    "port": 80,
                    "path": "/",
                    "check_interval_seconds": 10,
                    "response_timeout_seconds": 5,
                    "healthy_threshold": 5,
                    "unhealthy_threshold": 3,
                }
            ),
        ),
        sticky_sessions=dict(
            type="dict", required=False, default=dict({"type": "none"})
        ),
        redirect_http_to_https=dict(type="bool", required=False, default=False),
        enable_proxy_protocol=dict(type="bool", required=False, default=False),
        enable_backend_keepalive=dict(type="bool", required=False, default=False),
        vpc_uuid=dict(type="str", required=False),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=600),
        project_name=dict(type="str", aliases=["project"], required=False, default=""),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(
            [
                ("state", "present", ["forwarding_rules"]),
                ("state", "present", ["tag", "droplet_ids"], True),
            ]
        ),
        # Droplet ID and tag are mutually exclusive, check that both have not been defined
        mutually_exclusive=(
            [
                ("tag", "droplet_ids"),
                ("size", "size_unit"),
            ]
        ),
        supports_check_mode=True,
    )

    run(module)


if __name__ == "__main__":
    main()
