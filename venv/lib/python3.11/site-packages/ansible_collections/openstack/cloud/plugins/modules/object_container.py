#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 by Open Telekom Cloud, operated by T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: object_container
short_description: Manage a Swift container.
author: OpenStack Ansible SIG
description:
  - Create, update and delete a Swift container.
options:
  delete_with_all_objects:
    description:
        - Whether the container should be deleted recursively,
          i.e. including all of its objects.
        - If I(delete_with_all_objects) is set to C(false), an attempt to
          delete a container which contains objects will fail.
    type: bool
    default: False
  delete_metadata_keys:
    description:
      - Keys from I(metadata) to be deleted.
      - "I(metadata) has precedence over I(delete_metadata_keys): If any
         key is present in both options, then it will be created or updated,
         not deleted."
      - Metadata keys are case-insensitive.
    type: list
    elements: str
    aliases: ['keys']
  metadata:
    description:
      - Key value pairs to be set as metadata on the container.
      - Both custom and system metadata can be set.
      - Custom metadata are keys and values defined by the user.
      - I(metadata) is the same as setting properties in openstackclient with
        C(openstack container set --property ...).
      - Metadata keys are case-insensitive.
    type: dict
  name:
    description:
      - Name (and ID) of a Swift container.
    type: str
    required: true
    aliases: ['container']
  read_ACL:
    description:
      - The ACL that grants read access.
      - For example, use C(.r:*,.rlistings) for public access
        and C('') for private access.
    type: str
  write_ACL:
    description:
      - The ACL that grants write access.
    type: str
  state:
    description:
      - Whether the object should be C(present) or C(absent).
    default: 'present'
    choices: ['present', 'absent']
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
container:
  description: Dictionary describing the Swift container.
  returned: On success when I(state) is C(present).
  type: dict
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
      type: str
      sample: null
    count:
      description: The number of objects in the container.
      type: int
      sample: 1
    history_location:
      description: Enables versioning on the container.
      type: str
      sample: null
    id:
      description: The ID of the container. Equals I(name).
      type: str
      sample: "otc"
    if_none_match:
      description: "In combination with C(Expect: 100-Continue), specify an
                    C(If-None-Match: *) header to query whether the server
                    already has a copy of the object before any data is sent."
      type: str
      sample: null
    is_content_type_detected:
      description: If set to C(true), Object Storage guesses the content type
                   based on the file extension and ignores the value sent in
                   the Content-Type header, if present.
      type: bool
      sample: null
    is_newest:
      description: If set to True, Object Storage queries all replicas to
                   return the most recent one. If you omit this header, Object
                   Storage responds faster after it finds one valid replica.
                   Because setting this header to True is more expensive for
                   the back end, use it only when it is absolutely needed.
      type: bool
      sample: null
    meta_temp_url_key:
      description: The secret key value for temporary URLs. If not set,
                   this header is not returned by this operation.
      type: str
      sample: null
    meta_temp_url_key_2:
      description: A second secret key value for temporary URLs. If not set,
                   this header is not returned by this operation.
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
      type: str
      sample: null
    storage_policy:
      description: Storage policy used by the container. It is not possible to
                   change policy of an existing container.
      type: str
      sample: null
    sync_key:
      description: The secret key for container synchronization. If not set,
                   this header is not returned by this operation.
      type: str
      sample: null
    sync_to:
      description: The destination for container synchronization. If not set,
                   this header is not returned by this operation.
      type: str
      sample: null
    timestamp:
      description: The timestamp of the transaction.
      type: str
      sample: null
    versions_location:
      description: Enables versioning on this container. The value is the name
                   of another container. You must UTF-8-encode and then
                   URL-encode the name before you include it in the header. To
                   disable versioning, set the header to an empty string.
      type: str
      sample: null
    write_ACL:
      description: The ACL that grants write access. If not set, this header is
                   not returned by this operation.
      type: str
      sample: null
'''

EXAMPLES = r'''
- name: Create empty container with public access
  openstack.cloud.object_container:
    name: "new-container"
    state: present
    read_ACL: ".r:*,.rlistings"

- name: Set metadata for container
  openstack.cloud.object_container:
    name: "new-container"
    metadata:
      'Cache-Control': 'no-cache'
      'foo': 'bar'

- name: Delete metadata keys of a container
  openstack.cloud.object_container:
    name: "new-container"
    delete_metadata_keys:
      - foo

- name: Delete container
  openstack.cloud.object_container:
    name: "new-container"
    state: absent

- name: Delete container and all its objects
  openstack.cloud.object_container:
    name: "new-container"
    delete_with_all_objects: true
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ContainerModule(OpenStackModule):

    argument_spec = dict(
        delete_metadata_keys=dict(type='list', elements='str',
                                  no_log=False,  # := noqa no-log-needed
                                  aliases=['keys']),
        delete_with_all_objects=dict(type='bool', default=False),
        metadata=dict(type='dict'),
        name=dict(required=True, aliases=['container']),
        read_ACL=dict(),
        state=dict(default='present', choices=['present', 'absent']),
        write_ACL=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        state = self.params['state']
        container = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, container))

        if state == 'present' and not container:
            # Create container
            container = self._create()
            self.exit_json(changed=True,
                           # metadata is not returned by
                           # to_dict(computed=False) so return it explicitly
                           container=dict(metadata=container.metadata,
                                          **container.to_dict(computed=False)))

        elif state == 'present' and container:
            # Update container
            update = self._build_update(container)
            if update:
                container = self._update(container, update)

            self.exit_json(changed=bool(update),
                           # metadata is not returned by
                           # to_dict(computed=False) so return it explicitly
                           container=dict(metadata=container.metadata,
                                          **container.to_dict(computed=False)))

        elif state == 'absent' and container:
            # Delete container
            self._delete(container)
            self.exit_json(changed=True)

        elif state == 'absent' and not container:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, container):
        update = {}

        metadata = self.params['metadata']
        if metadata is not None:
            # Swift metadata keys must be treated as case-insensitive
            old_metadata = dict((k.lower(), v)
                                for k, v in (container.metadata or {}).items())
            new_metadata = dict((k, v) for k, v in metadata.items()
                                if k.lower() not in old_metadata
                                or v != old_metadata[k.lower()])
            if new_metadata:
                update['metadata'] = new_metadata

        delete_metadata_keys = self.params['delete_metadata_keys']
        if delete_metadata_keys is not None:
            for key in delete_metadata_keys:
                if (container.metadata is not None
                    and key.lower() in [k.lower()
                                        for k in container.metadata.keys()]):
                    update['delete_metadata_keys'] = delete_metadata_keys
                    break

        attributes = dict((k, self.params[k])
                          for k in ['read_ACL', 'write_ACL']
                          if self.params[k] is not None
                          and self.params[k] != container[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['metadata', 'name', 'read_ACL', 'write_ACL']
                      if self.params[k] is not None)

        return self.conn.object_store.create_container(**kwargs)

    def _delete(self, container):
        if self.params['delete_with_all_objects']:
            for object in self.conn.object_store.objects(container.name):
                self.conn.object_store.delete_object(obj=object.name,
                                                     container=container.name)

        self.conn.object_store.delete_container(container=container.name)

    def _find(self):
        name_or_id = self.params['name']
        # openstacksdk has no container_store.find_container() function
        try:
            return self.conn.object_store.get_container_metadata(name_or_id)
        except self.sdk.exceptions.ResourceNotFound:
            return None

    def _update(self, container, update):
        delete_metadata_keys = update.get('delete_metadata_keys')
        if delete_metadata_keys:
            self.conn.object_store.delete_container_metadata(
                container=container.name, keys=delete_metadata_keys)
            # object_store.delete_container_metadata() does not delete keys
            # from metadata dictionary so reload container
            container = \
                self.conn.object_store.get_container_metadata(container.name)

        # metadata has higher precedence than delete_metadata_keys
        # and thus is updated after later
        metadata = update.get('metadata')
        if metadata:
            container = self.conn.object_store.set_container_metadata(
                container.name, refresh=True, **metadata)

        attributes = update.get('attributes')
        if attributes:
            container = self.conn.object_store.set_container_metadata(
                container.name, refresh=True, **attributes)

        return container

    def _will_change(self, state, container):
        if state == 'present' and not container:
            return True
        elif state == 'present' and container:
            return bool(self._build_update(container))
        elif state == 'absent' and container:
            return True
        else:
            # state == 'absent' and not container:
            return False


def main():
    module = ContainerModule()
    module()


if __name__ == "__main__":
    main()
