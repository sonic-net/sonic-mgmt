#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: tag_associations
short_description: Manage the tags associated with a vSphere object.
description:
    - This module allows you to attach and detach tags to a vSphere object.
    - For better performance, use object IDs instead of names when possible.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    state:
        description:
            - Whether ensure the tags are present or absent on the object.
        type: str
        default: present
        choices: [present, absent]

    remove_extra_tags:
        description:
            - Whether to remove tags that are not in the list of tags to manage.
            - If O(state) is set to C(absent), all tags will be removed.
        type: bool
        default: false

    tags:
        description:
            - A list of tags to manage.
        type: list
        required: true
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the tag. Either O(tags[].name) or O(tags[].id) is required.
                type: str
                required: false
            id:
                description:
                    - The id of the tag to manage. Either O(tags[].name) or O(tags[].id) is required.
                type: str
                required: false
            category_name:
                description:
                    - The name of the category of the tag.
                    - Either category_name or category_id is required when looking up a tag by name.
                    - The category must already exist.
                type: str
                required: false
            category_id:
                description:
                    - The id of the category of the tag.
                    - Either category_name or category_id is required when looking up a tag by name.
                    - The category must already exist.
                type: str
                required: false

    object_moid:
        description:
            - The managed object ID (MOID) of the object to manage.
            - One of O(object_moid) or O(object_name) is required.
        type: str
        required: false

    object_name:
        description:
            - The name of the object to manage.
            - One of O(object_moid) or O(object_name) is required.
        type: str
        required: false

    object_type:
        description:
            - The type of the object to manage.
        type: str
        required: true
        choices:
            - VirtualMachine
            - Datacenter
            - ClusterComputeResource
            - HostSystem
            - DistributedVirtualSwitch
            - DistributedVirtualPortgroup
            - Datastore
            - DatastoreCluster
            - ResourcePool
            - Folder

    validate_tags_before_attaching:
        description:
            - Whether to validate the tags before attaching them to the object.
            - If true, additional API calls will be made to validate the tags exist and can be applied to the type of object specified.
            - If a tag fails validation, an error will be raised.
            - If false, the tags will be attached to the object without validation. This is faster, but may result in the module reporting
              changes every time. This is due to the module attempting to attach the tag, and vSphere simply ignoring the invalid request.
        type: bool
        default: false

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

seealso:
    - module: vmware.vmware.tags
    - module: vmware.vmware.tag_categories
"""

EXAMPLES = r"""
- name: Attach tags to a VM
  vmware.vmware.tag_associations:
    state: present
    object_moid: "{{ lookup('vmware.vmware.moid_from_path', '/Datacenter/vm/test-vm') }}"
    object_type: VirtualMachine
    tags:
      - name: my-test-tag-1
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
      - id: urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
      - name: my-test-tag-3
        category_name: my-test-category

- name: Make sure only these two tags are attached to the VM
  vmware.vmware.tag_associations:
    state: present
    object_moid: "{{ lookup('vmware.vmware.moid_from_path', '/Datacenter/vm/test-vm') }}"
    object_type: VirtualMachine
    remove_extra_tags: true
    tags:
      - name: my-test-tag-1
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
      - id: urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL

- name: Remove all tags from the VM
  vmware.vmware.tag_associations:
    state: absent
    object_moid: "{{ lookup('vmware.vmware.moid_from_path', '/Datacenter/vm/test-vm') }}"
    object_type: VirtualMachine
    remove_extra_tags: true
    tags: []

- name: Remove a tag from the VM
  vmware.vmware.tag_associations:
    state: present
    object_moid: "{{ lookup('vmware.vmware.moid_from_path', '/Datacenter/vm/test-vm') }}"
    object_type: VirtualMachine
    tags:
      - name: my-test-tag-1
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
"""

RETURN = r"""
added_tags:
    description:
        - A list of tag IDs that were added to the object.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
    ]

removed_tags:
    description:
        - A list of tag IDs that were removed from the object.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
    ]

object:
    description:
        - A dictionary containing details about the object that was managed.
    returned: always
    type: dict
    sample: {
        "id": "vm-1234567890",
        "tags": ["urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL"]
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import (
    ModuleRestBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec,
)

try:
    from com.vmware.vapi.std_client import DynamicID
    from com.vmware.vapi.std.errors_client import NotFound
    from pyVmomi import vim
    from com.vmware.vapi.std.errors_client import Unauthorized
except ImportError:
    pass


class VmwareTagAssociationsModule(ModuleRestBase):

    def __init__(self, module):
        super().__init__(module)
        self._attachable_tags = None
        self.category_cache = dict()
        self.object_tag_cache = dict()
        self._only_using_tag_ids = all(
            tag_param.get("id") is not None for tag_param in self.params["tags"]
        )
        self.dynamic_object = None

    def validate_object_params(self):
        object_moid = self.params.get("object_moid")
        if object_moid is None:
            object_moid = self._lookup_object_moid()

        self.dynamic_object = DynamicID(
            type=self.params.get("object_type"), id=object_moid
        )

        try:
            self.object_tag_ids = self.tag_association_service.list_attached_tags(
                self.dynamic_object
            )
        except Unauthorized as e:
            self.module.fail_json(
                msg="Unauthorized to get tags attached on object MOID %s. If the MOID looks correct, check the user has the correct permissions."
                % self.dynamic_object.id
            )

    def _lookup_object_moid(self):
        pyv = ModulePyvmomiBase(self.module)
        if self.params.get("object_search_folder_path") is not None:
            folder_object = pyv.get_folder_by_absolute_path(
                self.params.get("object_search_folder_path"), fail_on_missing=True
            )
        else:
            folder_object = pyv.content.rootFolder

        object_result = pyv.get_objs_by_name_or_moid(
            vim[self.params.get("object_type")],
            self.params.get("object_name"),
            return_all=True,
            search_root_folder=folder_object,
        )
        if len(object_result) > 1:
            self.module.fail_json(
                msg="Multiple vSphere objects found with the name %s and type %s. Consider using the object_moid or object_search_folder_path parameters."
                % (self.params.get("object_name"), self.params.get("object_type"))
            )
        elif len(object_result) == 0:
            self.module.fail_json(
                msg="No vSphere object found with the name %s and type %s"
                % (self.params.get("object_name"), self.params.get("object_type"))
            )

        return object_result[0]._GetMoId()

    def _get_category_id(self, category_name):
        if category_name not in self.category_cache:
            for category_id in self.tag_category_service.list():
                category = self.tag_category_service.get(category_id)
                self.category_cache[category.name] = category_id
                if category.name == category_name:
                    break
            else:
                self.module.fail_json(
                    msg="Could not find category with name %s" % category_name
                )

        return self.category_cache[category_name]

    def get_tag_changes_for_absent_state(self):
        if self.params["remove_extra_tags"]:
            return self.object_tag_ids

        tags_to_remove = []
        for tag_param in self.params["tags"]:
            if tag_param.get("id") is not None:
                if tag_param["id"] in self.object_tag_ids:
                    tags_to_remove.append(tag_param["id"])
                continue

            if tag_param.get("category_name") is not None:
                category_id = self._get_category_id(tag_param["category_name"])
            else:
                category_id = tag_param.get("category_id")

            for object_tag_id in self.object_tag_ids:
                if object_tag_id not in self.object_tag_cache:
                    tag = self.tag_service.get(object_tag_id)
                    self.object_tag_cache[object_tag_id] = tag

                if (
                    self.object_tag_cache[object_tag_id].name == tag_param["name"]
                    and self.object_tag_cache[object_tag_id].category_id == category_id
                ):
                    tags_to_remove.append(object_tag_id)

        return tags_to_remove

    def get_tag_changes_for_present_state(self):
        tags_to_add = []
        tags_managed_and_already_present = []
        for tag_param in self.params["tags"]:
            # User provided the tag ID, so we can just see if that is already associated with the object
            if tag_param.get("id") is not None:
                if tag_param["id"] not in self.object_tag_ids:
                    # Tag is not associated with the object, so we need to add it
                    tags_to_add.append(tag_param["id"])
                else:
                    # Tag is already associated with the object, we dont want to remove it as an "extra"
                    tags_managed_and_already_present.append(tag_param["id"])
                continue

            # User provided the tag name, so we need to look up the tag by name and category
            self._get_tag_change_for_present_state_by_name(
                tag_param, tags_to_add, tags_managed_and_already_present
            )

        if self.params["remove_extra_tags"]:
            tags_to_remove = list(
                set(self.object_tag_ids) - (set(tags_managed_and_already_present))
            )
        else:
            tags_to_remove = []

        return tags_to_add, tags_to_remove

    def _get_tag_change_for_present_state_by_name(
        self, tag_param, tags_to_add, tags_managed_and_already_present
    ):
        if tag_param.get("category_name") is not None:
            category_id = self._get_category_id(tag_param["category_name"])
        else:
            category_id = tag_param.get("category_id")

        # Check if the tag is already managed and present on the object
        is_tag_managed_and_already_present, object_tag_id = (
            self._is_tag_managed_and_already_present(tag_param["name"], category_id)
        )
        if is_tag_managed_and_already_present:
            tags_managed_and_already_present.append(object_tag_id)
            return

        # If the tag is not managed and present on the object, we need to look it up and then add it
        remote_tag = self.get_tag_by_category_id(
            tag_name=tag_param["name"], category_id=category_id
        )
        if remote_tag is None:
            self.module.fail_json(
                msg="Could not find tag with name %s and category %s"
                % (tag_param["name"], category_id)
            )
        tags_to_add.append(remote_tag.id)

    def _is_tag_managed_and_already_present(self, tag_name, category_id):
        for object_tag_id in self.object_tag_ids:
            # We cache the object tags lookups to avoid making duplicate API calls
            if object_tag_id not in self.object_tag_cache:
                tag = self.tag_service.get(object_tag_id)
                self.object_tag_cache[object_tag_id] = tag

            # If a tag on the object has the same name and category as the one from the user,
            # we dont want to remove it as an "extra"
            if (
                self.object_tag_cache[object_tag_id].name == tag_name
                and self.object_tag_cache[object_tag_id].category_id == category_id
            ):
                return True, object_tag_id

        return False, None

    def apply_tag_changes(self, tags_to_add, tags_to_remove):
        if tags_to_add:
            self.tag_association_service.attach_multiple_tags_to_object(
                self.dynamic_object, tags_to_add
            )
        if tags_to_remove:
            self.tag_association_service.detach_multiple_tags_from_object(
                self.dynamic_object, tags_to_remove
            )

    def validate_tags_before_attaching(self, tags_to_add):
        if not self.params["validate_tags_before_attaching"]:
            return

        if self._attachable_tags is None:
            self._attachable_tags = self.tag_association_service.list_attachable_tags(
                self.dynamic_object
            )

        for tag_id in tags_to_add:
            try:
                _ = self.tag_service.get(tag_id)  # pylint: disable=disallowed-name
            except NotFound:
                self.module.fail_json(msg=f"Tag {tag_id} does not exist.")

            if tag_id not in self._attachable_tags:
                self.module.fail_json(
                    msg=f"Tag {tag_id} is not attachable to the object type {self.params['object_type']}."
                )


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", choices=["present", "absent"], default="present"),
            remove_extra_tags=dict(type="bool", default=False),
            tags=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    name=dict(type="str", required=False),
                    id=dict(type="str", required=False),
                    category_name=dict(type="str", required=False),
                    category_id=dict(type="str", required=False),
                ),
                required_one_of=[["name", "id"]],
                mutually_exclusive=[["category_name", "category_id"]],
            ),
            object_moid=dict(type="str", required=False),
            object_name=dict(type="str", required=False),
            object_type=dict(
                type="str",
                choices=[
                    "VirtualMachine",
                    "Datacenter",
                    "ClusterComputeResource",
                    "HostSystem",
                    "DistributedVirtualSwitch",
                    "DistributedVirtualPortgroup",
                    "Datastore",
                    "DatastoreCluster",
                    "ResourcePool",
                    "Folder",
                ],
                required=True,
            ),
            validate_tags_before_attaching=dict(type="bool", default=False),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[["object_moid", "object_name"]],
        mutually_exclusive=[["object_moid", "object_name"]],
    )

    result = dict(
        changed=False,
        added_tags=[],
        removed_tags=[],
        object=dict(
            id="",
            tags=[],
        ),
    )

    vmware_tag_assoc = VmwareTagAssociationsModule(module)
    vmware_tag_assoc.validate_object_params()

    tags_to_add, tags_to_remove = [], []
    if module.params["state"] == "present":
        tags_to_add, tags_to_remove = (
            vmware_tag_assoc.get_tag_changes_for_present_state()
        )
        vmware_tag_assoc.validate_tags_before_attaching(tags_to_add)
    else:
        tags_to_remove = vmware_tag_assoc.get_tag_changes_for_absent_state()

    result["added_tags"] = tags_to_add
    result["removed_tags"] = tags_to_remove
    result["object"]["id"] = vmware_tag_assoc.dynamic_object.id
    result["object"]["tags"] = list(
        set(vmware_tag_assoc.object_tag_ids)
        .difference(tags_to_remove)
        .union(tags_to_add)
    )
    result["changed"] = bool(tags_to_add or tags_to_remove)

    if module.check_mode or not result["changed"]:
        module.exit_json(**result)

    vmware_tag_assoc.apply_tag_changes(tags_to_add, tags_to_remove)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
