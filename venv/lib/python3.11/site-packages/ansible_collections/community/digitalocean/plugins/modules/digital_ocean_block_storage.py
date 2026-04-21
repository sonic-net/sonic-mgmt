#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_block_storage
short_description: Create/destroy or attach/detach Block Storage volumes in DigitalOcean
description:
     - Create/destroy Block Storage volume in DigitalOcean, or attach/detach Block Storage volume to a droplet.
options:
  command:
    description:
     - Which operation do you want to perform.
    choices: ['create', 'attach']
    required: true
    type: str
  state:
    description:
     - Indicate desired state of the target.
    choices: ['present', 'absent']
    required: true
    type: str
  block_size:
    description:
    - The size of the Block Storage volume in gigabytes.
    - Required when I(command=create) and I(state=present).
    - If snapshot_id is included, this will be ignored.
    - If block_size > current size of the volume, the volume is resized.
    type: int
  volume_name:
    description:
    - The name of the Block Storage volume.
    type: str
    required: true
  description:
    description:
    - Description of the Block Storage volume.
    type: str
  region:
    description:
    - The slug of the region where your Block Storage volume should be located in.
    - If I(snapshot_id) is included, this will be ignored.
    type: str
  snapshot_id:
    description:
    - The snapshot id you would like the Block Storage volume created with.
    - If included, I(region) and I(block_size) will be ignored and changed to C(null).
    type: str
  droplet_id:
    description:
    - The droplet id you want to operate on.
    - Required when I(command=attach).
    type: int
  project_name:
    aliases: ["project"]
    description:
    - Project to assign the resource to (project name, not UUID).
    - Defaults to the default project of the account (empty string).
    - Currently only supported when C(command=create).
    type: str
    required: false
    default: ""
extends_documentation_fragment:
- community.digitalocean.digital_ocean.documentation

notes:
  - Two environment variables can be used, DO_API_KEY and DO_API_TOKEN.
    They both refer to the v2 token.
  - If snapshot_id is used, region and block_size will be ignored and changed to null.

author:
    - "Harnek Sidhu (@harneksidhu)"
"""

EXAMPLES = r"""
- name: Create new Block Storage
  community.digitalocean.digital_ocean_block_storage:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    command: create
    region: nyc1
    block_size: 10
    volume_name: nyc1-block-storage

- name: Create new Block Storage (and assign to Project "test")
  community.digitalocean.digital_ocean_block_storage:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    command: create
    region: nyc1
    block_size: 10
    volume_name: nyc1-block-storage
    project_name: test

- name: Resize an existing Block Storage
  community.digitalocean.digital_ocean_block_storage:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    command: create
    region: nyc1
    block_size: 20
    volume_name: nyc1-block-storage

- name: Delete Block Storage
  community.digitalocean.digital_ocean_block_storage:
    state: absent
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    command: create
    region: nyc1
    volume_name: nyc1-block-storage

- name: Attach Block Storage to a Droplet
  community.digitalocean.digital_ocean_block_storage:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    command: attach
    volume_name: nyc1-block-storage
    region: nyc1
    droplet_id: <ID>

- name: Detach Block Storage from a Droplet
  community.digitalocean.digital_ocean_block_storage:
    state: absent
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    command: attach
    volume_name: nyc1-block-storage
    region: nyc1
    droplet_id: <ID>
"""

RETURN = r"""
id:
    description: Unique identifier of a Block Storage volume returned during creation.
    returned: changed
    type: str
    sample: "69b25d9a-494c-12e6-a5af-001f53126b44"
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
            self: https://api.digitalocean.com/v2/volumes/8691c49e-35ba-11ec-9406-0a58ac1472b9
        status: assigned
        urn: do:volume:8691c49e-35ba-11ec-9406-0a58ac1472b9
"""

import time
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)


class DOBlockStorageException(Exception):
    pass


class DOBlockStorage(object):
    def __init__(self, module):
        self.module = module
        self.rest = DigitalOceanHelper(module)
        if self.module.params.get("project_name"):
            # only load for non-default project assignments
            self.projects = DigitalOceanProjects(module, self.rest)

    def get_key_or_fail(self, k):
        v = self.module.params[k]
        if v is None:
            self.module.fail_json(msg="Unable to load %s" % k)
        return v

    def poll_action_for_complete_status(self, action_id):
        url = "actions/{0}".format(action_id)
        end_time = time.monotonic() + self.module.params["timeout"]
        while time.monotonic() < end_time:
            time.sleep(10)
            response = self.rest.get(url)
            status = response.status_code
            json = response.json
            if status == 200:
                if json["action"]["status"] == "completed":
                    return True
                elif json["action"]["status"] == "errored":
                    raise DOBlockStorageException(json["message"])
        raise DOBlockStorageException(
            "Unable to reach the DigitalOcean API at %s"
            % self.module.params.get("baseurl")
        )

    def get_block_storage_by_name(self, volume_name, region):
        url = "volumes?name={0}&region={1}".format(volume_name, region)
        resp = self.rest.get(url)
        if resp.status_code != 200:
            raise DOBlockStorageException(resp.json["message"])

        volumes = resp.json["volumes"]
        if not volumes:
            return None

        return volumes[0]

    def get_attached_droplet_ID(self, volume_name, region):
        volume = self.get_block_storage_by_name(volume_name, region)
        if not volume or not volume["droplet_ids"]:
            return None

        return volume["droplet_ids"][0]

    def attach_detach_block_storage(self, method, volume_name, region, droplet_id):
        data = {
            "type": method,
            "volume_name": volume_name,
            "region": region,
            "droplet_id": droplet_id,
        }
        response = self.rest.post("volumes/actions", data=data)
        status = response.status_code
        json = response.json
        if status == 202:
            return self.poll_action_for_complete_status(json["action"]["id"])
        elif status == 200:
            return True
        elif status == 404 and method == "detach":
            return False  # Already detached
        elif status == 422:
            return False
        else:
            raise DOBlockStorageException(json["message"])

    def resize_block_storage(self, volume_name, region, desired_size):
        if not desired_size:
            return False

        volume = self.get_block_storage_by_name(volume_name, region)
        if volume["size_gigabytes"] == desired_size:
            return False

        data = {
            "type": "resize",
            "size_gigabytes": desired_size,
        }
        resp = self.rest.post(
            "volumes/{0}/actions".format(volume["id"]),
            data=data,
        )
        if resp.status_code == 202:
            return self.poll_action_for_complete_status(resp.json["action"]["id"])
        else:
            # we'd get status 422 if desired_size <= current volume size
            raise DOBlockStorageException(resp.json["message"])

    def create_block_storage(self):
        volume_name = self.get_key_or_fail("volume_name")
        snapshot_id = self.module.params["snapshot_id"]
        if snapshot_id:
            self.module.params["block_size"] = None
            self.module.params["region"] = None
            block_size = None
            region = None
        else:
            block_size = self.get_key_or_fail("block_size")
            region = self.get_key_or_fail("region")
        description = self.module.params["description"]
        data = {
            "size_gigabytes": block_size,
            "name": volume_name,
            "description": description,
            "region": region,
            "snapshot_id": snapshot_id,
        }
        response = self.rest.post("volumes", data=data)
        status = response.status_code
        json = response.json
        if status == 201:
            project_name = self.module.params.get("project_name")
            if (
                project_name
            ):  # empty string is the default project, skip project assignment
                urn = "do:volume:{0}".format(json["volume"]["id"])
                (
                    assign_status,
                    error_message,
                    resources,
                ) = self.projects.assign_to_project(project_name, urn)
                self.module.exit_json(
                    changed=True,
                    id=json["volume"]["id"],
                    msg=error_message,
                    assign_status=assign_status,
                    resources=resources,
                )
            else:
                self.module.exit_json(changed=True, id=json["volume"]["id"])
        elif status == 409 and json["id"] == "conflict":
            # The volume exists already, but it might not have the desired size
            resized = self.resize_block_storage(volume_name, region, block_size)
            self.module.exit_json(changed=resized)
        else:
            raise DOBlockStorageException(json["message"])

    def delete_block_storage(self):
        volume_name = self.get_key_or_fail("volume_name")
        region = self.get_key_or_fail("region")
        url = "volumes?name={0}&region={1}".format(volume_name, region)
        attached_droplet_id = self.get_attached_droplet_ID(volume_name, region)
        if attached_droplet_id is not None:
            self.attach_detach_block_storage(
                "detach", volume_name, region, attached_droplet_id
            )
        response = self.rest.delete(url)
        status = response.status_code
        json = response.json
        if status == 204:
            self.module.exit_json(changed=True)
        elif status == 404:
            self.module.exit_json(changed=False)
        else:
            raise DOBlockStorageException(json["message"])

    def attach_block_storage(self):
        volume_name = self.get_key_or_fail("volume_name")
        region = self.get_key_or_fail("region")
        droplet_id = self.get_key_or_fail("droplet_id")
        attached_droplet_id = self.get_attached_droplet_ID(volume_name, region)
        if attached_droplet_id is not None:
            if attached_droplet_id == droplet_id:
                self.module.exit_json(changed=False)
            else:
                self.attach_detach_block_storage(
                    "detach", volume_name, region, attached_droplet_id
                )
        changed_status = self.attach_detach_block_storage(
            "attach", volume_name, region, droplet_id
        )
        self.module.exit_json(changed=changed_status)

    def detach_block_storage(self):
        volume_name = self.get_key_or_fail("volume_name")
        region = self.get_key_or_fail("region")
        droplet_id = self.get_key_or_fail("droplet_id")
        changed_status = self.attach_detach_block_storage(
            "detach", volume_name, region, droplet_id
        )
        self.module.exit_json(changed=changed_status)


def handle_request(module):
    block_storage = DOBlockStorage(module)
    command = module.params["command"]
    state = module.params["state"]
    if command == "create":
        if state == "present":
            block_storage.create_block_storage()
        elif state == "absent":
            block_storage.delete_block_storage()
    elif command == "attach":
        if state == "present":
            block_storage.attach_block_storage()
        elif state == "absent":
            block_storage.detach_block_storage()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(choices=["present", "absent"], required=True),
        command=dict(choices=["create", "attach"], required=True),
        block_size=dict(type="int", required=False),
        volume_name=dict(type="str", required=True),
        description=dict(type="str"),
        region=dict(type="str", required=False),
        snapshot_id=dict(type="str", required=False),
        droplet_id=dict(type="int"),
        project_name=dict(type="str", aliases=["project"], required=False, default=""),
    )

    module = AnsibleModule(argument_spec=argument_spec)

    try:
        handle_request(module)
    except DOBlockStorageException as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    except KeyError as e:
        module.fail_json(msg="Unable to load %s" % e, exception=traceback.format_exc())


if __name__ == "__main__":
    main()
