#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 Catalyst Cloud Limited
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: object_containers_info
short_description: Fetch container info from the OpenStack Swift service.
author: OpenStack Ansible SIG
description:
  - Fetch container info from the OpenStack Swift service.
options:
  name:
    description:
      - Name of the container
    type: str
    aliases: ["container"]
  prefix:
    description:
      - Filter containers by prefix
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
"""

EXAMPLES = r"""
- name: List all containers existing on the project
  openstack.cloud.object_containers_info:

- name: Retrive a single container by name
  openstack.cloud.object_containers_info:
    name: test-container

- name: Retrieve and filter containers by prefix
  openstack.cloud.object_containers_info:
    prefix: test-
"""

RETURN = r"""
containers:
  description: List of dictionaries describing matching containers.
  returned: always
  type: list
  elements: dict
  contains:
    bytes:
      description: The total number of bytes that are stored in Object Storage
                   for the container.
      type: int
      sample: 5449
    bytes_used:
      description: The count of bytes used in total.
      type: int
      sample: 5449
    content_type:
      description: The MIME type of the list of names.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    count:
      description: The number of objects in the container.
      type: int
      sample: 1
    history_location:
      description: Enables versioning on the container.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    id:
      description: The ID of the container. Equals I(name).
      type: str
      sample: "otc"
    if_none_match:
      description: "In combination with C(Expect: 100-Continue), specify an
                    C(If-None-Match: *) header to query whether the server
                    already has a copy of the object before any data is sent.
                    Only set when searching for a container by name."
      type: str
      sample: null
    is_content_type_detected:
      description: If set to C(true), Object Storage guesses the content type
                   based on the file extension and ignores the value sent in
                   the Content-Type header, if present.
                   Only fetched when searching for a container by name.
      type: bool
      sample: null
    is_newest:
      description: If set to True, Object Storage queries all replicas to
                   return the most recent one. If you omit this header, Object
                   Storage responds faster after it finds one valid replica.
                   Because setting this header to True is more expensive for
                   the back end, use it only when it is absolutely needed.
                   Only fetched when searching for a container by name.
      type: bool
      sample: null
    meta_temp_url_key:
      description: The secret key value for temporary URLs. If not set,
                   this header is not returned by this operation.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    meta_temp_url_key_2:
      description: A second secret key value for temporary URLs. If not set,
                   this header is not returned by this operation.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    name:
      description: The name of the container.
      type: str
      sample: "otc"
    object_count:
      description: The number of objects.
      type: int
      sample: 1
    read_ACL:
      description: The ACL that grants read access. If not set, this header is
                   not returned by this operation.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    storage_policy:
      description: Storage policy used by the container. It is not possible to
                   change policy of an existing container.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    sync_key:
      description: The secret key for container synchronization. If not set,
                   this header is not returned by this operation.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    sync_to:
      description: The destination for container synchronization. If not set,
                   this header is not returned by this operation.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    timestamp:
      description: The timestamp of the transaction.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    versions_location:
      description: Enables versioning on this container. The value is the name
                   of another container. You must UTF-8-encode and then
                   URL-encode the name before you include it in the header. To
                   disable versioning, set the header to an empty string.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
    write_ACL:
      description: The ACL that grants write access. If not set, this header is
                   not returned by this operation.
                   Only fetched when searching for a container by name.
      type: str
      sample: null
"""

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ObjectContainersInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(aliases=["container"]),
        prefix=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    def run(self):
        if self.params["name"]:
            containers = [
                (
                    self.conn.object_store.get_container_metadata(
                        self.params["name"],
                    ).to_dict(computed=False)
                ),
            ]
        else:
            query = {}
            if self.params["prefix"]:
                query["prefix"] = self.params["prefix"]
            containers = [
                c.to_dict(computed=False)
                for c in self.conn.object_store.containers(**query)
            ]
        self.exit(changed=False, containers=containers)


def main():
    module = ObjectContainersInfoModule()
    module()


if __name__ == "__main__":
    main()
