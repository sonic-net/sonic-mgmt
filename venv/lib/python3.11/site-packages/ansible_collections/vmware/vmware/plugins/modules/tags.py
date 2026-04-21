#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: tags
short_description: Manage one or more VMware tags.
description:
    - This module allows you to create, update, and delete VMware tags.
    - For better performance, use object IDs instead of names when possible.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    state:
        description:
            - Whether ensure the tags are present or absent.
        type: str
        default: present
        choices: [present, absent]

    tags:
        description:
            - A list of tags to manage.
        type: list
        required: true
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the tag.
                    - The name is required when creating a new tag.
                    - If both name and ID are provided, the ID will be used to search for the tag. If
                      a tag cannot be found and O(state) is present, an error will be raised.
                    - If both name and ID are provided and a tag is found, the name will be updated if
                      needed.
                type: str
                required: false
            id:
                description:
                    - The id of the tag to manage.
                    - Only applicable if the tag already exists.
                    - If both name and ID are provided, the ID will be used to search for the tag. If
                      a tag cannot be found and O(state) is present, an error will be raised.
                    - If both name and ID are provided and a tag is found, the name will be updated if
                      needed.
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
            description:
                description:
                    - The description of the tag.
                type: str
                required: false

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

seealso:
    - module: vmware.vmware.tag_categories
"""

EXAMPLES = r"""
- name: Create or update tags
  vmware.vmware.tags:
    state: present
    tags:
      - name: my-test-tag-1
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
      - id: urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
        description: "This is a test tag"
      - name: my-test-tag-3
        category_name: my-test-category
        description: "This is another test tag"

- name: Delete tags
  vmware.vmware.tags:
    state: absent
    tags:
      - name: my-test-tag-1
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
      - id: urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL
        category_id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL
"""

RETURN = r"""
vsphere_tags:
    description:
        - Dictionary of tags that were managed by this module. This includes any tags that the user specified, even
          if nothing was changed.
        - The key is the tag ID, the value is a dictionary with tag information.
    returned: always
    type: dict
    sample: {
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL": {
            "category_id": "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
            "name": "tag1",
            "description": "Description of tag1",
            "id": "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL"
        },
    }

created_tags:
    description:
        - List of tag IDs that were created by this module.
        - The list is empty if no tags were created.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
    ]

updated_tags:
    description:
        - List of tag IDs that were updated by this module.
        - The list is empty if no tags were updated.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
    ]

removed_tags:
    description:
        - List of tag IDs that were removed by this module.
        - The list is empty if no tags were removed.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceTag:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL",
    ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import (
    ModuleRestBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec,
)

try:
    from com.vmware.vapi.std.errors_client import NotFound
except ImportError:
    pass


class TagDiff:
    """
    A data class representing a change to a tag.

    This class encapsulates the before and after state of a tag change,
    providing methods to convert the change to module output format.

    Attributes:
        remote_def (object): Tag model before the change (None for new tags)
        param_def (dict): Tag parameters after the change (None for deletions)
    """

    def __init__(self, remote_def: object = None, param_def: dict = None):
        if param_def is None:
            param_def = dict()
        self.remote_def = remote_def
        self.param_def = param_def
        self._is_update = None

    def get_tag_id(self):
        if self.remote_def is not None:
            # Tag already exists and is being updated or removed, so we can use the remote def ID
            return self.remote_def.id

        if self.param_def.get("id") is not None:
            # Tag didn't exist and we created it, so we have the new ID available
            return self.param_def.get("id")

        return None

    def is_creation(self):
        return self.param_def != dict() and self.remote_def is None

    def is_update(self):
        if self._is_update is None:
            if self.param_def == dict() or self.remote_def is None:
                self._is_update = False
            elif self.param_def.get("description") is not None and self.param_def.get("description") != self.remote_def.description:
                self._is_update = True
            elif self.param_def.get("name") is not None and self.param_def.get("name") != self.remote_def.name:
                self._is_update = True
            else:
                self._is_update = False

        return self._is_update

    def is_removal(self):
        return self.param_def == dict() and self.remote_def is not None

    def new_tag_state_to_module_output(self):
        """
        Convert the future/new state of a tag to a dictionary format suitable for Ansible module output.

        Returns:
            dict: Dictionary with 'id', 'name', 'category_id', and 'description' keys containing tag information
        """
        if self.is_removal():
            return dict()

        return dict(
            id=self.get_tag_id(),
            name=self.param_def.get("name") or self.remote_def.name,
            category_id=self.param_def.get("category_id") or self.remote_def.category_id,
            description=self.param_def.get("description") or self.remote_def.description,
        )


class VmwareTagModule(ModuleRestBase):
    """
    A specialized Ansible module for managing VMware tags using the vSphere REST API.

    This class extends ModuleRestBase to provide comprehensive tag management capabilities
    including creation, updates, and deletion of VMware tags. It uses caching mechanisms
    for optimal performance and supports both check mode and normal operation.

    Attributes:
        _category_names_to_ids_cache (dict): Maps category names to their IDs
        _tag_ids_in_category_cache (dict): Maps category IDs to lists of tag IDs
        _tag_names_to_tags_cache (dict): Maps tag names to tag model objects

    Example:
        vmware_tag = VmwareTagModule(module)
        tag_changes = vmware_tag.determine_tag_changes()
        vmware_tag.apply_tag_changes(tag_changes)
    """

    def __init__(self, module):
        super().__init__(module)
        self._category_names_to_ids_cache = self._resolve_category_ids()
        if not all(self._category_names_to_ids_cache.values()):
            missing_categories = [
                category_name
                for category_name, category_id in self._category_names_to_ids_cache.items()
                if category_id is None
            ]
            self.module.fail_json(
                msg="One or more categories specified in the parameters were not found: %s"
                % missing_categories
            )

        # Caches to help speed up the crawl through the remote tags
        self._tag_ids_in_category_cache = (
            dict()
        )  # Maps category IDs to a list of tag IDs
        self._tag_names_to_tags_cache = dict()  # Maps tag names to tag models

    def _resolve_category_ids(self):
        """
        Resolve category names to their corresponding IDs by querying the remote VMware environment.

        This method optimizes performance by stopping once all required categories are found
        and validates that all specified categories exist.

        Returns:
            dict: Mapping of category names to their IDs

        Raises:
            AnsibleModule.fail_json: If any categories specified in parameters are not found
        """
        param_category_names_to_ids_map = {
            tag["category_name"]: None
            for tag in self.params["tags"]
            if tag.get("category_name")
        }
        param_category_ids = tuple(
            [
                tag["category_id"]
                for tag in self.params["tags"]
                if tag.get("category_id")
            ]
        )
        processed_category_count = 0

        for category_id in param_category_ids:
            try:
                remote_category = self.tag_category_service.get(category_id)
            except NotFound:
                self.module.fail_json(
                    msg="Unable to find a category with the ID %s" % category_id
                )

        for remote_category_id in self.tag_category_service.list():
            if processed_category_count >= len(param_category_names_to_ids_map.keys()):
                # we found all of the categories in the parameters, no need to keep looking
                break

            remote_category = self.tag_category_service.get(remote_category_id)
            if remote_category.name in param_category_names_to_ids_map.keys():
                # user specified the category name in the parameters and we found it
                param_category_names_to_ids_map[remote_category.name] = (
                    remote_category_id
                )
                processed_category_count += 1
                continue

        return param_category_names_to_ids_map

    def _lookup_tag(self, category_id=None, tag_id=None, tag_name=None):
        """
        Efficiently look up tags using caching to minimize API calls.

        Args:
            category_id (str, optional): ID of the category to search in
            tag_id (str, optional): Direct tag ID for lookup
            tag_name (str, optional): Tag name for lookup

        Returns:
            object: Tag model object if found, None otherwise

        Raises:
            Exception: If neither tag_id nor tag_name is provided
        """
        if tag_id is not None:
            try:
                return self.tag_service.get(tag_id)
            except NotFound:
                if self.module.params["state"] == "present":
                    self.module.fail_json(
                        msg="Unable to find a tag with the ID %s, and this module does not support creating tags when the ID is provided."
                        % tag_id
                    )
                return None

        if tag_name is None:
            raise Exception("Either tag_id or tag_name must be provided")

        if category_id is None:
            raise Exception("Either category_id or category_name must be provided when looking up a tag by name")

        if tag_name in self._tag_names_to_tags_cache:
            return self._tag_names_to_tags_cache[tag_name]

        # Weve never looked this tag up, so we crawl through the category tags until we find it or we run out of tags
        if category_id not in self._tag_ids_in_category_cache:
            # Weve also never looked up the tags in this category, so we need to initialize the cache
            self._tag_ids_in_category_cache[category_id] = (
                self.tag_service.list_tags_for_category(category_id)
            )

        for remote_tag_id in self._tag_ids_in_category_cache[category_id]:
            remote_tag = self.tag_service.get(remote_tag_id)

            if remote_tag.name.lower() == tag_name.lower():
                return remote_tag

            # Cache tag for future lookups
            self._tag_names_to_tags_cache[remote_tag.name] = remote_tag

        return None

    def determine_tag_diffs(self):
        """
        Analyze the current state of tags and create diff objects for each tag,
        indicating what needs to be created, updated, or deleted.

        Returns:
            list[TagDiff]: List of tag diffs to be applied
        """
        tag_diffs = []
        for tag_param in self.module.params["tags"]:
            try:
                tag_category_id = (
                    tag_param.get("category_id")
                    or self._category_names_to_ids_cache[tag_param.get("category_name")]
                )
            except KeyError:
                tag_category_id = None

            remote_tag = self._lookup_tag(
                category_id=tag_category_id,
                tag_name=tag_param.get("name"),
                tag_id=tag_param.get("id"),
            )

            if self.module.params["state"] == "present":
                param_def = tag_param.copy()
                param_def["category_id"] = tag_category_id
                if remote_tag is None:
                    if param_def.get("name") is None:
                        self.module.fail_json(
                            msg="A tag name is required when creating a new tag",
                            violating_tag_param=tag_param,
                        )
                    tag_diffs.append(TagDiff(remote_def=None, param_def=param_def))
                else:
                    tag_diffs.append(TagDiff(remote_def=remote_tag, param_def=param_def))

            else:
                if remote_tag is not None:
                    tag_diffs.append(TagDiff(remote_def=remote_tag, param_def=None))
        return tag_diffs

    def apply_tag_changes(self, tag_diffs):
        """
        Apply the determined tag changes to the VMware environment.

        Args:
            tag_diffs (list[TagDiff]): List of tag diffs to process

        Operations performed:
            - Create: Creates new tags with specified name, category, and description
            - Update: Updates existing tag descriptions
            - Delete: Removes tags from the system
        """
        for tag_diff in tag_diffs:
            if tag_diff.is_creation():
                new_tag_id = self._create_tag(
                    name=tag_diff.param_def["name"],
                    category_id=tag_diff.param_def["category_id"],
                    description=tag_diff.param_def.get("description"),
                )
                tag_diff.param_def["id"] = new_tag_id
            elif tag_diff.is_removal():
                try:
                    self.tag_service.delete(tag_diff.remote_def.id)
                except NotFound:
                    raise Exception("Tag %s not found" % tag_diff.remote_def.id)
            elif tag_diff.is_update():
                update_spec = self.tag_service.UpdateSpec(
                    name=tag_diff.param_def.get("name"),
                    description=tag_diff.param_def.get("description"),
                )
                self.tag_service.update(tag_diff.remote_def.id, update_spec)

    def _create_tag(self, name, category_id, description=None):
        """
        Create a new tag in the VMware environment.

        Args:
            name (str): Name of the tag to create
            category_id (str): ID of the category to assign the tag to
            description (str, optional): Description for the tag

        Returns:
            str: ID of the newly created tag
        """
        create_spec = self.tag_service.CreateSpec()
        create_spec.name = name
        create_spec.description = description or ""
        create_spec.category_id = category_id
        return self.tag_service.create(create_spec)


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", choices=["present", "absent"], default="present"),
            tags=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    name=dict(type="str", required=False),
                    id=dict(type="str", required=False),
                    category_name=dict(type="str", required=False),
                    category_id=dict(type="str", required=False),
                    description=dict(type="str", required=False),
                ),
                required_one_of=[["name", "id"]],
                mutually_exclusive=[["category_name", "category_id"]],
            ),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    result = dict(
        changed=False,
        vsphere_tags=dict(),
        removed_tags=[],
        created_tags=[],
        updated_tags=[],
    )

    vmware_tag = VmwareTagModule(module)
    tag_diffs = vmware_tag.determine_tag_diffs()
    result["vsphere_tags"] = {
        tag_diff.get_tag_id(): tag_diff.new_tag_state_to_module_output()
        for tag_diff in tag_diffs
        if tag_diff.get_tag_id() is not None and not tag_diff.is_removal()
    }
    if not tag_diffs:
        module.exit_json(**result)

    if not module.check_mode:
        vmware_tag.apply_tag_changes(tag_diffs)

    for tag_diff in tag_diffs:
        if tag_diff.is_creation():
            result["created_tags"].append(tag_diff.get_tag_id())
            result["changed"] = True
        elif tag_diff.is_update():
            result["updated_tags"].append(tag_diff.get_tag_id())
            result["changed"] = True
        elif tag_diff.is_removal():
            result["removed_tags"].append(tag_diff.get_tag_id())
            result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
