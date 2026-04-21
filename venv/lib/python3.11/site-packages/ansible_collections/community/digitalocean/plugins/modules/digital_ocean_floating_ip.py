#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, Patrick F. Marques <patrickfmarques@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_floating_ip
short_description: Manage DigitalOcean Floating IPs
description:
     - Create/delete/assign a floating IP.
author:
    - "Patrick Marques (@pmarques)"
    - "Daniel George (@danxg87)"
options:
  state:
    description:
     - Indicate desired state of the target.
     - If C(state=present) Create (and optionally attach) floating IP
     - If C(state=absent) Delete floating IP
     - If C(state=attached) attach floating IP to a droplet
     - If C(state=detached) detach floating IP from a droplet
    default: present
    choices: ['present', 'absent', 'attached', 'detached']
    type: str
  ip:
    description:
     - Public IP address of the Floating IP. Used to remove an IP
    type: str
    aliases: ['id']
  region:
    description:
     - The region that the Floating IP is reserved to.
    type: str
  droplet_id:
    description:
     - The Droplet that the Floating IP has been assigned to.
    type: str
  oauth_token:
    description:
     - DigitalOcean OAuth token.
    required: true
    type: str
  timeout:
    description:
      - Floating IP creation timeout.
    type: int
    default: 30
  validate_certs:
    description:
      - If set to C(no), the SSL certificates will not be validated.
      - This should only set to C(no) used on personally controlled sites using self-signed certificates.
    type: bool
    default: true
  project_name:
    aliases: ["project"]
    description:
    - Project to assign the resource to (project name, not UUID).
    - Defaults to the default project of the account (empty string).
    - Currently only supported when creating.
    type: str
    required: false
    default: ""
notes:
  - Version 2 of DigitalOcean API is used.
requirements:
  - "python >= 2.6"
"""


EXAMPLES = r"""
- name: "Create a Floating IP in region lon1"
  community.digitalocean.digital_ocean_floating_ip:
    state: present
    region: lon1

- name: Create a Floating IP in region lon1 (and assign to Project "test")
  community.digitalocean.digital_ocean_floating_ip:
    state: present
    region: lon1
    project: test

- name: "Create a Floating IP assigned to Droplet ID 123456"
  community.digitalocean.digital_ocean_floating_ip:
    state: present
    droplet_id: 123456

- name: "Attach an existing Floating IP of 1.2.3.4 to Droplet ID 123456"
  community.digitalocean.digital_ocean_floating_ip:
    state: attached
    ip: "1.2.3.4"
    droplet_id: 123456

- name: "Detach an existing Floating IP of 1.2.3.4 from its Droplet"
  community.digitalocean.digital_ocean_floating_ip:
    state: detached
    ip: "1.2.3.4"

- name: "Delete a Floating IP with ip 1.2.3.4"
  community.digitalocean.digital_ocean_floating_ip:
    state: absent
    ip: "1.2.3.4"

"""


RETURN = r"""
# Digital Ocean API info https://docs.digitalocean.com/reference/api/api-reference/#tag/Floating-IPs
data:
    description: a DigitalOcean Floating IP resource
    returned: success and no resource constraint
    type: dict
    sample:
      action:
        id: 68212728
        status: in-progress
        type: assign_ip
        started_at: '2015-10-15T17:45:44Z'
        completed_at: null
        resource_id: 758603823
        resource_type: floating_ip
        region:
          name: New York 3
          slug: nyc3
          sizes:
            - 512mb,
            - 1gb,
            - 2gb,
            - 4gb,
            - 8gb,
            - 16gb,
            - 32gb,
            - 48gb,
            - 64gb
          features:
            - private_networking
            - backups
            - ipv6
            - metadata
          available: true
        region_slug: nyc3
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
            self: https://api.digitalocean.com/v2/floating_ips/157.230.64.107
        status: assigned
        urn: do:floatingip:157.230.64.107
"""

import json
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.urls import fetch_url

from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)


class Response(object):
    def __init__(self, resp, info):
        self.body = None
        if resp:
            self.body = resp.read()
        self.info = info

    @property
    def json(self):
        if not self.body:
            if "body" in self.info:
                return json.loads(self.info["body"])
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    @property
    def status_code(self):
        return self.info["status"]


class Rest(object):
    def __init__(self, module, headers):
        self.module = module
        self.headers = headers
        self.baseurl = "https://api.digitalocean.com/v2"

    def _url_builder(self, path):
        if path[0] == "/":
            path = path[1:]
        return "%s/%s" % (self.baseurl, path)

    def send(self, method, path, data=None, headers=None):
        url = self._url_builder(path)
        data = self.module.jsonify(data)
        timeout = self.module.params["timeout"]

        resp, info = fetch_url(
            self.module,
            url,
            data=data,
            headers=self.headers,
            method=method,
            timeout=timeout,
        )

        # Exceptions in fetch_url may result in a status -1, the ensures a
        if info["status"] == -1:
            self.module.fail_json(msg=info["msg"])

        return Response(resp, info)

    def get(self, path, data=None, headers=None):
        return self.send("GET", path, data, headers)

    def put(self, path, data=None, headers=None):
        return self.send("PUT", path, data, headers)

    def post(self, path, data=None, headers=None):
        return self.send("POST", path, data, headers)

    def delete(self, path, data=None, headers=None):
        return self.send("DELETE", path, data, headers)


def wait_action(module, rest, ip, action_id, timeout=60):
    end_time = time.monotonic() + timeout
    while time.monotonic() < end_time:
        response = rest.get("floating_ips/{0}/actions/{1}".format(ip, action_id))
        json_data = response.json
        status_code = response.status_code
        status = response.json["action"]["status"]
        if status_code == 200:
            if status == "completed":
                return json_data
            elif status == "errored":
                module.fail_json(
                    msg="Floating ip action error [ip: {0}: action: {1}]".format(
                        ip, action_id
                    ),
                    data=json,
                )
        time.sleep(10)
    module.fail_json(
        msg="Floating ip action timeout [ip: {0}: action: {1}]".format(ip, action_id),
        data=json,
    )


def core(module):
    api_token = module.params["oauth_token"]
    state = module.params["state"]
    ip = module.params["ip"]
    droplet_id = module.params["droplet_id"]

    rest = Rest(
        module,
        {
            "Authorization": "Bearer {0}".format(api_token),
            "Content-type": "application/json",
        },
    )

    if state in ("present"):
        if droplet_id is not None and module.params["ip"] is not None:
            # Lets try to associate the ip to the specified droplet
            associate_floating_ips(module, rest)
        else:
            create_floating_ips(module, rest)

    elif state in ("attached"):
        if droplet_id is not None and module.params["ip"] is not None:
            associate_floating_ips(module, rest)

    elif state in ("detached"):
        if module.params["ip"] is not None:
            detach_floating_ips(module, rest, module.params["ip"])

    elif state in ("absent"):
        response = rest.delete("floating_ips/{0}".format(ip))
        status_code = response.status_code
        json_data = response.json
        if status_code == 204:
            module.exit_json(changed=True)
        elif status_code == 404:
            module.exit_json(changed=False)
        else:
            module.exit_json(changed=False, data=json_data)


def get_floating_ip_details(module, rest):
    ip = module.params["ip"]

    response = rest.get("floating_ips/{0}".format(ip))
    status_code = response.status_code
    json_data = response.json
    if status_code == 200:
        return json_data["floating_ip"]
    else:
        module.fail_json(
            msg="Error assigning floating ip [{0}: {1}]".format(
                status_code, json_data["message"]
            ),
            region=module.params["region"],
        )


def assign_floating_id_to_droplet(module, rest):
    ip = module.params["ip"]

    payload = {
        "type": "assign",
        "droplet_id": module.params["droplet_id"],
    }

    response = rest.post("floating_ips/{0}/actions".format(ip), data=payload)
    status_code = response.status_code
    json_data = response.json
    if status_code == 201:
        json_data = wait_action(module, rest, ip, json_data["action"]["id"])

        module.exit_json(changed=True, data=json_data)
    else:
        module.fail_json(
            msg="Error creating floating ip [{0}: {1}]".format(
                status_code, json_data["message"]
            ),
            region=module.params["region"],
        )


def detach_floating_ips(module, rest, ip):
    payload = {"type": "unassign"}
    response = rest.post("floating_ips/{0}/actions".format(ip), data=payload)
    status_code = response.status_code
    json_data = response.json

    if status_code == 201:
        json_data = wait_action(module, rest, ip, json_data["action"]["id"])
        module.exit_json(
            changed=True, msg="Detached floating ip {0}".format(ip), data=json_data
        )
        action = json_data.get("action", None)
        action_id = action.get("id", None)
        if action is None:
            module.fail_json(
                changed=False,
                msg="Error retrieving detach action. Got: {0}".format(action),
            )
        if action_id is None:
            module.fail_json(
                changed=False,
                msg="Error retrieving detach action ID. Got: {0}".format(action_id),
            )
    else:
        module.fail_json(
            changed=False,
            msg="Error detaching floating ip [{0}: {1}]".format(
                status_code, json_data["message"]
            ),
        )


def associate_floating_ips(module, rest):
    floating_ip = get_floating_ip_details(module, rest)
    droplet = floating_ip["droplet"]

    # TODO: If already assigned to a droplet verify if is one of the specified as valid
    if droplet is not None and str(droplet["id"]) in [module.params["droplet_id"]]:
        module.exit_json(changed=False)
    else:
        assign_floating_id_to_droplet(module, rest)


def create_floating_ips(module, rest):
    payload = {}

    if module.params["region"] is not None:
        payload["region"] = module.params["region"]
    if module.params["droplet_id"] is not None:
        payload["droplet_id"] = module.params["droplet_id"]

    # Get existing floating IPs
    response = rest.get("floating_ips/")
    status_code = response.status_code
    json_data = response.json

    # Exit unchanged if any of them are assigned to this Droplet already
    if status_code == 200:
        floating_ips = json_data.get("floating_ips", [])
        if len(floating_ips) != 0:
            for floating_ip in floating_ips:
                droplet = floating_ip.get("droplet", None)
                if droplet is not None:
                    droplet_id = droplet.get("id", None)
                    if droplet_id is not None:
                        if str(droplet_id) == module.params["droplet_id"]:
                            ip = floating_ip.get("ip", None)
                            if ip is not None:
                                module.exit_json(
                                    changed=False, data={"floating_ip": floating_ip}
                                )
                            else:
                                module.fail_json(
                                    changed=False,
                                    msg="Unexpected error querying floating ip",
                                )

    response = rest.post("floating_ips", data=payload)
    status_code = response.status_code
    json_data = response.json
    if status_code == 202:
        if module.params.get(
            "project_name"
        ):  # only load for non-default project assignments
            rest = DigitalOceanHelper(module)
            projects = DigitalOceanProjects(module, rest)
            project_name = module.params.get("project_name")
            if (
                project_name
            ):  # empty string is the default project, skip project assignment
                floating_ip = json_data.get("floating_ip")
                ip = floating_ip.get("ip")
                if ip:
                    urn = "do:floatingip:{0}".format(ip)
                    (
                        assign_status,
                        error_message,
                        resources,
                    ) = projects.assign_to_project(project_name, urn)
                    module.exit_json(
                        changed=True,
                        data=json_data,
                        msg=error_message,
                        assign_status=assign_status,
                        resources=resources,
                    )
                else:
                    module.exit_json(
                        changed=True,
                        msg="Floating IP created but not assigned to the {0} Project (missing information from the API response)".format(
                            project_name
                        ),
                        data=json_data,
                    )
            else:
                module.exit_json(changed=True, data=json_data)
        else:
            module.exit_json(changed=True, data=json_data)
    else:
        module.fail_json(
            msg="Error creating floating ip [{0}: {1}]".format(
                status_code, json_data["message"]
            ),
            region=module.params["region"],
        )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(
                choices=["present", "absent", "attached", "detached"], default="present"
            ),
            ip=dict(aliases=["id"], required=False),
            region=dict(required=False),
            droplet_id=dict(required=False),
            oauth_token=dict(
                no_log=True,
                # Support environment variable for DigitalOcean OAuth Token
                fallback=(
                    env_fallback,
                    ["DO_API_TOKEN", "DO_API_KEY", "DO_OAUTH_TOKEN"],
                ),
                required=True,
            ),
            validate_certs=dict(type="bool", default=True),
            timeout=dict(type="int", default=30),
            project_name=dict(
                type="str", aliases=["project"], required=False, default=""
            ),
        ),
        required_if=[
            ("state", "delete", ["ip"]),
            ("state", "attached", ["ip", "droplet_id"]),
            ("state", "detached", ["ip"]),
        ],
        mutually_exclusive=[["region", "droplet_id"]],
    )

    core(module)


if __name__ == "__main__":
    main()
