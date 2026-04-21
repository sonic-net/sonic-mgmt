#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_droplet
short_description: Create and delete a DigitalOcean droplet
description:
  - Create and delete a droplet in DigitalOcean and optionally wait for it to be active.
author:
  - Gurchet Rai (@gurch101)
  - Mark Mercado (@mamercad)
options:
  state:
    description:
      - Indicate desired state of the target.
      - C(present) will create the named droplet; be mindful of the C(unique_name) parameter.
      - C(absent) will delete the named droplet, if it exists.
      - C(active) will create the named droplet (unless it exists) and ensure that it is powered on.
      - C(inactive) will create the named droplet (unless it exists) and ensure that it is powered off.
    default: present
    choices: ["present", "absent", "active", "inactive"]
    type: str
  id:
    description:
      - The Droplet ID you want to operate on.
    aliases: ["droplet_id"]
    type: int
  name:
    description:
      - This is the name of the Droplet.
      - Must be formatted by hostname rules.
    type: str
  unique_name:
    description:
      - Require unique hostnames.
      - By default, DigitalOcean allows multiple hosts with the same name.
      - Setting this to C(true) allows only one host per name.
      - Useful for idempotence.
    default: false
    type: bool
  size:
    description:
      - This is the slug of the size you would like the Droplet created with.
      - Please see U(https://slugs.do-api.dev/) for current slugs.
    aliases: ["size_id"]
    type: str
  image:
    description:
      - This is the slug of the image you would like the Droplet created with.
    aliases: ["image_id"]
    type: str
  region:
    description:
      - This is the slug of the region you would like your Droplet to be created in.
    aliases: ["region_id"]
    type: str
  ssh_keys:
    description:
      - Array of SSH key fingerprints that you would like to be added to the Droplet.
    required: false
    type: list
    elements: str
  firewall:
    description:
      - Array of firewall names to apply to the Droplet.
      - Omitting a firewall name that is currently applied to a droplet will remove it.
    required: false
    type: list
    elements: str
  private_networking:
    description:
      - Add an additional, private network interface to the Droplet (for inter-Droplet communication).
    default: false
    type: bool
  vpc_uuid:
    description:
      - A string specifying the UUID of the VPC to which the Droplet will be assigned.
      - If excluded, the Droplet will be assigned to the account's default VPC for the region.
    type: str
    version_added: 0.1.0
  user_data:
    description:
      - Opaque blob of data which is made available to the Droplet.
    required: False
    type: str
  ipv6:
    description:
      - Enable IPv6 for the Droplet.
    required: false
    default: false
    type: bool
  wait:
    description:
      - Wait for the Droplet to be active before returning.
      - If wait is C(false) an IP address may not be returned.
    required: false
    default: true
    type: bool
  wait_timeout:
    description:
      - How long before C(wait) gives up, in seconds, when creating a Droplet.
    default: 120
    type: int
  backups:
    description:
      - Indicates whether automated backups should be enabled.
    required: false
    default: false
    type: bool
  monitoring:
    description:
      - Indicates whether to install the DigitalOcean agent for monitoring.
    required: false
    default: false
    type: bool
  tags:
    description:
      - A list of tag names as strings to apply to the Droplet after it is created.
      - Tag names can either be existing or new tags.
    required: false
    type: list
    elements: str
  volumes:
    description:
      - A list including the unique string identifier for each Block Storage volume to be attached to the Droplet.
    required: False
    type: list
    elements: str
  resize_disk:
    description:
      - Whether to increase disk size on resize.
      - Only consulted if the C(unique_name) is C(true).
      - Droplet C(size) must dictate an increase.
    required: false
    default: false
    type: bool
  project_name:
    aliases: ["project"]
    description:
    - Project to assign the resource to (project name, not UUID).
    - Defaults to the default project of the account (empty string).
    - Currently only supported when creating.
    type: str
    required: false
    default: ""
  sleep_interval:
    description:
      - How long to C(sleep) in between action and status checks.
      - Default is 10 seconds; this should be less than C(wait_timeout) and nonzero.
    default: 10
    type: int
extends_documentation_fragment:
- community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Create a new Droplet
  community.digitalocean.digital_ocean_droplet:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    name: mydroplet
    size: s-1vcpu-1gb
    region: sfo3
    image: ubuntu-20-04-x64
    wait_timeout: 500
    ssh_keys: [ .... ]
  register: my_droplet

- name: Show Droplet info
  ansible.builtin.debug:
    msg: |
      Droplet ID is {{ my_droplet.data.droplet.id }}
      First Public IPv4 is {{ (my_droplet.data.droplet.networks.v4 | selectattr('type', 'equalto', 'public')).0.ip_address | default('<none>', true) }}
      First Private IPv4 is {{ (my_droplet.data.droplet.networks.v4 | selectattr('type', 'equalto', 'private')).0.ip_address | default('<none>', true) }}

- name: Create a new Droplet (and assign to Project "test")
  community.digitalocean.digital_ocean_droplet:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    name: mydroplet
    size: s-1vcpu-1gb
    region: sfo3
    image: ubuntu-20-04-x64
    wait_timeout: 500
    ssh_keys: [ .... ]
    project: test
  register: my_droplet

- name: Ensure a Droplet is present
  community.digitalocean.digital_ocean_droplet:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    id: 123
    name: mydroplet
    size: s-1vcpu-1gb
    region: sfo3
    image: ubuntu-20-04-x64
    wait_timeout: 500

- name: Ensure a Droplet is present and has firewall rules applied
  community.digitalocean.digital_ocean_droplet:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    id: 123
    name: mydroplet
    size: s-1vcpu-1gb
    region: sfo3
    image: ubuntu-20-04-x64
    firewall: ['myfirewall', 'anotherfirewall']
    wait_timeout: 500

- name: Ensure a Droplet is present with SSH keys installed
  community.digitalocean.digital_ocean_droplet:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    id: 123
    name: mydroplet
    size: s-1vcpu-1gb
    region: sfo3
    ssh_keys: ['1534404', '1784768']
    image: ubuntu-20-04-x64
    wait_timeout: 500
"""

RETURN = r"""
# Digital Ocean API info https://docs.digitalocean.com/reference/api/api-reference/#tag/Droplets
data:
    description: a DigitalOcean Droplet
    returned: changed
    type: dict
    sample:
        ip_address: 104.248.118.172
        ipv6_address: 2604:a880:400:d1::90a:6001
        private_ipv4_address: 10.136.122.141
        droplet:
            id: 3164494
            name: example.com
            memory: 512
            vcpus: 1
            disk: 20
            locked: true
            status: new
            kernel:
                id: 2233
                name: Ubuntu 14.04 x64 vmlinuz-3.13.0-37-generic
                version: 3.13.0-37-generic
            created_at: "2014-11-14T16:36:31Z"
            features: ["virtio"]
            backup_ids: []
            snapshot_ids: []
            image: {}
            volume_ids: []
            size: {}
            size_slug: 512mb
            networks: {}
            region: {}
            tags: ["web"]
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
            self: https://api.digitalocean.com/v2/droplets/3164494
        status: assigned
        urn: do:droplet:3164494
"""

import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)


class DODroplet(object):
    failure_message = {
        "empty_response": "Empty response from the DigitalOcean API; please try again or open a bug if it never "
        "succeeds.",
        "resizing_off": "Droplet must be off prior to resizing: "
        "https://docs.digitalocean.com/reference/api/api-reference/#operation/post_droplet_action",
        "unexpected": "Unexpected error [{0}]; please file a bug: "
        "https://github.com/ansible-collections/community.digitalocean/issues",
        "support_action": "Error status on Droplet action [{0}], please try again or contact DigitalOcean support: "
        "https://docs.digitalocean.com/support/",
        "failed_to": "Failed to {0} {1} [HTTP {2}: {3}]",
    }

    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        self.wait = self.module.params.pop("wait", True)
        self.wait_timeout = self.module.params.pop("wait_timeout", 120)
        self.unique_name = self.module.params.pop("unique_name", False)
        # pop the oauth token so we don't include it in the POST data
        self.module.params.pop("oauth_token")
        self.id = None
        self.name = None
        self.size = None
        self.status = None
        if self.module.params.get("project_name"):
            # only load for non-default project assignments
            self.projects = DigitalOceanProjects(module, self.rest)
        self.firewalls = self.get_firewalls()
        self.sleep_interval = self.module.params.pop("sleep_interval", 10)
        if self.wait:
            if self.sleep_interval > self.wait_timeout:
                self.module.fail_json(
                    msg="Sleep interval {0} should be less than {1}".format(
                        self.sleep_interval, self.wait_timeout
                    )
                )
            if self.sleep_interval <= 0:
                self.module.fail_json(
                    msg="Sleep interval {0} should be greater than zero".format(
                        self.sleep_interval
                    )
                )

    def get_firewalls(self):
        response = self.rest.get("firewalls")
        status_code = response.status_code
        json_data = response.json
        if status_code != 200:
            self.module.fail_json(msg="Failed to get firewalls", data=json_data)

        return self.rest.get_paginated_data(
            base_url="firewalls?", data_key_name="firewalls"
        )

    def get_firewall_by_name(self):
        rule = {}
        item = 0
        for firewall in self.firewalls:
            for firewall_name in self.module.params["firewall"]:
                if firewall_name in firewall["name"]:
                    rule[item] = {}
                    rule[item].update(firewall)
                    item += 1
        if len(rule) > 0:
            return rule
        return None

    def add_droplet_to_firewalls(self):
        changed = False
        rule = self.get_firewall_by_name()
        if rule is None:
            err = "Failed to find firewalls: {0}".format(self.module.params["firewall"])
            return err
        json_data = self.get_droplet()
        if json_data is not None:
            request_params = {}
            droplet = json_data.get("droplet", None)
            droplet_id = droplet.get("id", None)
            request_params["droplet_ids"] = [droplet_id]
            for firewall in rule:
                if droplet_id not in rule[firewall]["droplet_ids"]:
                    response = self.rest.post(
                        "firewalls/{0}/droplets".format(rule[firewall]["id"]),
                        data=request_params,
                    )
                    json_data = response.json
                    status_code = response.status_code
                    if status_code != 204:
                        err = "Failed to add droplet {0} to firewall {1}".format(
                            droplet_id, rule[firewall]["id"]
                        )
                        return err, changed
                    changed = True
        return None, changed

    def remove_droplet_from_firewalls(self):
        changed = False
        json_data = self.get_droplet()
        if json_data is not None:
            request_params = {}
            droplet = json_data.get("droplet", None)
            droplet_id = droplet.get("id", None)
            request_params["droplet_ids"] = [droplet_id]
            for firewall in self.firewalls:
                if (
                    firewall["name"] not in self.module.params["firewall"]
                    and droplet_id in firewall["droplet_ids"]
                ):
                    response = self.rest.delete(
                        "firewalls/{0}/droplets".format(firewall["id"]),
                        data=request_params,
                    )
                    json_data = response.json
                    status_code = response.status_code
                    if status_code != 204:
                        err = "Failed to remove droplet {0} from firewall {1}".format(
                            droplet_id, firewall["id"]
                        )
                        return err, changed
                    changed = True
        return None, changed

    def get_by_id(self, droplet_id):
        if not droplet_id:
            return None
        response = self.rest.get("droplets/{0}".format(droplet_id))
        status_code = response.status_code
        json_data = response.json
        if json_data is None:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["empty_response"],
            )
        else:
            if status_code == 200:
                droplet = json_data.get("droplet", None)
                if droplet is not None:
                    self.id = droplet.get("id", None)
                    self.name = droplet.get("name", None)
                    self.size = droplet.get("size_slug", None)
                    self.status = droplet.get("status", None)
                return json_data
            return None

    def get_by_name(self, droplet_name):
        if not droplet_name:
            return None
        page = 1
        while page is not None:
            response = self.rest.get("droplets?page={0}".format(page))
            json_data = response.json
            status_code = response.status_code
            if json_data is None:
                self.module.fail_json(
                    changed=False,
                    msg=DODroplet.failure_message["empty_response"],
                )
            else:
                if status_code == 200:
                    droplets = json_data.get("droplets", [])
                    for droplet in droplets:
                        if droplet.get("name", None) == droplet_name:
                            self.id = droplet.get("id", None)
                            self.name = droplet.get("name", None)
                            self.size = droplet.get("size_slug", None)
                            self.status = droplet.get("status", None)
                            return {"droplet": droplet}
                    if (
                        "links" in json_data
                        and "pages" in json_data["links"]
                        and "next" in json_data["links"]["pages"]
                    ):
                        page += 1
                    else:
                        page = None
        return None

    def get_addresses(self, data):
        """Expose IP addresses as their own property allowing users extend to additional tasks"""
        _data = data
        for k, v in data.items():
            setattr(self, k, v)
        networks = _data["droplet"]["networks"]
        for network in networks.get("v4", []):
            if network["type"] == "public":
                _data["ip_address"] = network["ip_address"]
            else:
                _data["private_ipv4_address"] = network["ip_address"]
        for network in networks.get("v6", []):
            if network["type"] == "public":
                _data["ipv6_address"] = network["ip_address"]
            else:
                _data["private_ipv6_address"] = network["ip_address"]
        return _data

    def get_droplet(self):
        json_data = self.get_by_id(self.module.params["id"])
        if not json_data and self.unique_name:
            json_data = self.get_by_name(self.module.params["name"])
        return json_data

    def resize_droplet(self, state, droplet_id):
        if self.status != "off":
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["resizing_off"],
            )

        self.wait_action(
            droplet_id,
            {
                "type": "resize",
                "disk": self.module.params["resize_disk"],
                "size": self.module.params["size"],
            },
        )

        if state == "active":
            self.ensure_power_on(droplet_id)

        # Get updated Droplet data
        json_data = self.get_droplet()
        droplet = json_data.get("droplet", None)
        if droplet is None:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["unexpected"].format("no Droplet"),
            )

        self.module.exit_json(
            changed=True,
            msg="Resized Droplet {0} ({1}) from {2} to {3}".format(
                self.name, self.id, self.size, self.module.params["size"]
            ),
            data={"droplet": droplet},
        )

    def wait_status(self, droplet_id, desired_statuses):
        # Make sure Droplet is active first
        end_time = time.monotonic() + self.wait_timeout
        while time.monotonic() < end_time:
            response = self.rest.get("droplets/{0}".format(droplet_id))
            json_data = response.json
            status_code = response.status_code
            message = json_data.get("message", "no error message")
            droplet = json_data.get("droplet", None)
            droplet_status = droplet.get("status", None) if droplet else None

            if droplet is None or droplet_status is None:
                self.module.fail_json(
                    changed=False,
                    msg=DODroplet.failure_message["unexpected"].format(
                        "no Droplet or status"
                    ),
                )

            if status_code >= 400:
                self.module.fail_json(
                    changed=False,
                    msg=DODroplet.failure_message["failed_to"].format(
                        "get", "Droplet", status_code, message
                    ),
                )

            if droplet_status in desired_statuses:
                return

            time.sleep(self.sleep_interval)

        self.module.fail_json(
            msg="Wait for Droplet [{0}] status timeout".format(
                ",".join(desired_statuses)
            )
        )

    def wait_check_action(self, droplet_id, action_id):
        end_time = time.monotonic() + self.wait_timeout
        while time.monotonic() < end_time:
            response = self.rest.get(
                "droplets/{0}/actions/{1}".format(droplet_id, action_id)
            )
            json_data = response.json
            status_code = response.status_code
            message = json_data.get("message", "no error message")
            action = json_data.get("action", None)
            action_id = action.get("id", None)
            action_status = action.get("status", None)

            if action is None or action_id is None or action_status is None:
                self.module.fail_json(
                    changed=False,
                    msg=DODroplet.failure_message["unexpected"].format(
                        "no action, ID, or status"
                    ),
                )

            if status_code >= 400:
                self.module.fail_json(
                    changed=False,
                    msg=DODroplet.failure_message["failed_to"].format(
                        "get", "action", status_code, message
                    ),
                )

            if action_status == "errored":
                self.module.fail_json(
                    changed=True,
                    msg=DODroplet.failure_message["support_action"].format(action_id),
                )

            if action_status == "completed":
                return

            time.sleep(self.sleep_interval)

        self.module.fail_json(msg="Wait for Droplet action timeout")

    def wait_action(self, droplet_id, desired_action_data):
        action_type = desired_action_data.get("type", "undefined")

        response = self.rest.post(
            "droplets/{0}/actions".format(droplet_id), data=desired_action_data
        )
        json_data = response.json
        status_code = response.status_code
        message = json_data.get("message", "no error message")

        # action and other fields may not be available in case of error, check first
        # will catch Not Authorized due to restrictive Scopes
        if status_code >= 400:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["failed_to"].format(
                    "post", "action", status_code, message
                ),
            )

        action = json_data.get("action", None)
        action_id = action.get("id", None)
        action_status = action.get("status", None)

        if action is None or action_id is None or action_status is None:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["unexpected"].format(
                    "no action, ID, or status"
                ),
            )

        # Keep checking till it is done or times out
        self.wait_check_action(droplet_id, action_id)

    def ensure_power_on(self, droplet_id):
        # Make sure Droplet is active or off first
        self.wait_status(droplet_id, ["active", "off"])
        # Trigger power-on
        self.wait_action(droplet_id, {"type": "power_on"})

    def ensure_power_off(self, droplet_id):
        # Make sure Droplet is active first
        self.wait_status(droplet_id, ["active"])
        # Trigger power-off
        self.wait_action(droplet_id, {"type": "power_off"})

    def create(self, state):
        json_data = self.get_droplet()
        # We have the Droplet
        if json_data is not None:
            droplet = json_data.get("droplet", None)
            droplet_id = droplet.get("id", None)
            droplet_size = droplet.get("size_slug", None)

            if droplet_id is None or droplet_size is None:
                self.module.fail_json(
                    changed=False,
                    msg=DODroplet.failure_message["unexpected"].format(
                        "no Droplet ID or size"
                    ),
                )

            # Add droplet to a firewall if specified
            if self.module.params["firewall"] is not None:
                firewall_changed = False
                if len(self.module.params["firewall"]) > 0:
                    firewall_add, add_changed = self.add_droplet_to_firewalls()
                    if firewall_add is not None:
                        self.module.fail_json(
                            changed=False,
                            msg=firewall_add,
                            data={"droplet": droplet, "firewall": firewall_add},
                        )
                    firewall_changed = firewall_changed or add_changed
                firewall_remove, remove_changed = self.remove_droplet_from_firewalls()
                if firewall_remove is not None:
                    self.module.fail_json(
                        changed=False,
                        msg=firewall_remove,
                        data={"droplet": droplet, "firewall": firewall_remove},
                    )
                firewall_changed = firewall_changed or remove_changed
                self.module.exit_json(
                    changed=firewall_changed,
                    data={"droplet": droplet},
                )

            # Check mode
            if self.module.check_mode:
                self.module.exit_json(changed=False)

            # Ensure Droplet size
            if droplet_size != self.module.params.get("size", None):
                self.resize_droplet(state, droplet_id)

            # Ensure Droplet power state
            droplet_data = self.get_addresses(json_data)
            droplet_id = droplet.get("id", None)
            droplet_status = droplet.get("status", None)
            if droplet_id is not None and droplet_status is not None:
                if state == "active" and droplet_status != "active":
                    self.ensure_power_on(droplet_id)
                    # Get updated Droplet data (fallback to current data)
                    json_data = self.get_droplet()
                    droplet = json_data.get("droplet", droplet)
                    self.module.exit_json(changed=True, data={"droplet": droplet})
                elif state == "inactive" and droplet_status != "off":
                    self.ensure_power_off(droplet_id)
                    # Get updated Droplet data (fallback to current data)
                    json_data = self.get_droplet()
                    droplet = json_data.get("droplet", droplet)
                    self.module.exit_json(changed=True, data={"droplet": droplet})
                else:
                    self.module.exit_json(changed=False, data={"droplet": droplet})

        # We don't have the Droplet, create it

        # Check mode
        if self.module.check_mode:
            self.module.exit_json(changed=True)

        request_params = dict(self.module.params)
        del request_params["id"]

        response = self.rest.post("droplets", data=request_params)
        json_data = response.json
        status_code = response.status_code
        message = json_data.get("message", "no error message")
        droplet = json_data.get("droplet", None)

        # Ensure that the Droplet is created
        if status_code != 202:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["failed_to"].format(
                    "create", "Droplet", status_code, message
                ),
            )

        droplet_id = droplet.get("id", None)
        if droplet is None or droplet_id is None:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["unexpected"].format("no Droplet or ID"),
            )

        if status_code >= 400:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["failed_to"].format(
                    "create", "Droplet", status_code, message
                ),
            )

        if self.wait:
            if state == "present" or state == "active":
                self.ensure_power_on(droplet_id)
            if state == "inactive":
                self.ensure_power_off(droplet_id)
        else:
            if state == "inactive":
                self.ensure_power_off(droplet_id)

        # Get updated Droplet data (fallback to current data)
        if self.wait:
            json_data = self.get_by_id(droplet_id)
            if json_data:
                droplet = json_data.get("droplet", droplet)

        project_name = self.module.params.get("project_name")
        if project_name:  # empty string is the default project, skip project assignment
            urn = "do:droplet:{0}".format(droplet_id)
            assign_status, error_message, resources = self.projects.assign_to_project(
                project_name, urn
            )
            self.module.exit_json(
                changed=True,
                data={"droplet": droplet},
                msg=error_message,
                assign_status=assign_status,
                resources=resources,
            )
        # Add droplet to firewall if specified
        if self.module.params["firewall"] is not None:
            # raise Exception(self.module.params["firewall"])
            firewall_add = self.add_droplet_to_firewalls()
            if firewall_add is not None:
                self.module.fail_json(
                    changed=False,
                    msg=firewall_add,
                    data={"droplet": droplet, "firewall": firewall_add},
                )
            firewall_remove = self.remove_droplet_from_firewalls()
            if firewall_remove is not None:
                self.module.fail_json(
                    changed=False,
                    msg=firewall_remove,
                    data={"droplet": droplet, "firewall": firewall_remove},
                )
            self.module.exit_json(changed=True, data={"droplet": droplet})

        self.module.exit_json(changed=True, data={"droplet": droplet})

    def delete(self):
        # to delete a droplet we need to know the droplet id or unique name, ie
        # name is not None and unique_name is True, but as "id or name" is
        # enforced elsewhere, we only need to enforce "id or unique_name" here
        if not self.module.params["id"] and not self.unique_name:
            self.module.fail_json(
                changed=False,
                msg="id must be set or unique_name must be true for deletes",
            )
        json_data = self.get_droplet()
        if json_data is None:
            self.module.exit_json(changed=False, msg="Droplet not found")

        # Check mode
        if self.module.check_mode:
            self.module.exit_json(changed=True)

        # Delete it
        droplet = json_data.get("droplet", None)
        droplet_id = droplet.get("id", None)
        droplet_name = droplet.get("name", None)

        if droplet is None or droplet_id is None:
            self.module.fail_json(
                changed=False,
                msg=DODroplet.failure_message["unexpected"].format(
                    "no Droplet, name, or ID"
                ),
            )

        response = self.rest.delete("droplets/{0}".format(droplet_id))
        json_data = response.json
        status_code = response.status_code
        if status_code == 204:
            self.module.exit_json(
                changed=True,
                msg="Droplet {0} ({1}) deleted".format(droplet_name, droplet_id),
            )
        else:
            self.module.fail_json(
                changed=False,
                msg="Failed to delete Droplet {0} ({1})".format(
                    droplet_name, droplet_id
                ),
            )


def core(module):
    state = module.params.pop("state")
    droplet = DODroplet(module)
    if state in ["present", "active", "inactive"]:
        droplet.create(state)
    elif state == "absent":
        droplet.delete()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(
            choices=["present", "absent", "active", "inactive"], default="present"
        ),
        name=dict(type="str"),
        size=dict(aliases=["size_id"]),
        image=dict(aliases=["image_id"]),
        region=dict(aliases=["region_id"]),
        ssh_keys=dict(type="list", elements="str", no_log=False),
        private_networking=dict(type="bool", default=False),
        vpc_uuid=dict(type="str"),
        backups=dict(type="bool", default=False),
        monitoring=dict(type="bool", default=False),
        id=dict(aliases=["droplet_id"], type="int"),
        user_data=dict(default=None),
        ipv6=dict(type="bool", default=False),
        volumes=dict(type="list", elements="str"),
        tags=dict(type="list", elements="str"),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(default=120, type="int"),
        unique_name=dict(type="bool", default=False),
        resize_disk=dict(type="bool", default=False),
        project_name=dict(type="str", aliases=["project"], required=False, default=""),
        firewall=dict(type="list", elements="str", default=None),
        sleep_interval=dict(default=10, type="int"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(["id", "name"],),
        required_if=(
            [
                ("state", "present", ["name", "size", "image", "region"]),
                ("state", "active", ["name", "size", "image", "region"]),
                ("state", "inactive", ["name", "size", "image", "region"]),
            ]
        ),
        supports_check_mode=True,
    )

    core(module)


if __name__ == "__main__":
    main()
