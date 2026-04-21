#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: tag_categories
short_description: Manage one or more VMware tag categories.
description:
    - This module allows you to create, update, and delete VMware tag categories.
    - For better performance, use object IDs instead of names when possible.
    - For better performance, manage many tag categories per module call (as opposed
      to using a loop). See the examples for more details.

author:
    - Ansible Cloud Team (@ansible-collections)

options:
    state:
        description:
            - Whether ensure the tag categories are present or absent.
        type: str
        choices: [present, absent]
        default: present

    tag_categories:
        description:
            - A list of tag categories to manage.
            - Providing the ID instead of the name will reduce the number of API calls, and
              potentially speed up the module execution.
        type: list
        required: true
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the tag category.
                    - At least one of O(tag_categories[].name) or O(tag_categories[].id) must be provided.
                    - If only the name is provided, it will be used to search for the tag category.
                      If a category cannot be found and O(state) is present, a new category will be created.
                    - If both name and ID are provided, the ID will be used to search for the category. If
                      If a category cannot be found and O(state) is present, an error will be raised.
                      If a category can be found and O(state) is present, the category will be updated to use O(tag_categories[].name).
                    - This value is required when creating a new tag category.
                type: str
                required: false
            id:
                description:
                    - The id of the tag category to manage.
                    - At least one of O(tag_categories[].name) or O(tag_categories[].id) must be provided.
                    - Only applicable if the tag category already exists.
                type: str
                required: false
            description:
                description:
                    - The description of the tag category.
                type: str
                required: false
            cardinality:
                description:
                    - Controls if an object can be assigned to multiple tags in the category.
                    - An example of a single cardinality category is "Operating System", with tags like "Windows", "Linux", "Mac OS".
                    - An example of a multiple cardinality category is "Server", with tags like "AppServer", "DatabaseServer".
                    - If this is not specified when creating a tag category, cardinality MULTIPLE will be used.
                    - You cannot change the cardinality of a tag category from MULTIPLE to SINGLE.
                type: str
                required: false
                choices: [SINGLE, MULTIPLE]
            associable_types:
                description:
                    - A list of types of vSphere objects that can be assigned to the tag category.
                    - When creating a category, at least one type must be specified. If this is parameter is not set or set
                      an empty list, the category will be created with all types.
                    - Due to a vSphere limitation, this list is additive. In other words, you cannot remove a type
                      once it has been added to the category. Any types specified in this parameter will be added if they are missing.
                type: list
                required: false
                elements: str
                default: []
                choices:
                    - Folder
                    - DistributedVirtualPortgroup
                    - VmwareDistributedVirtualSwitch
                    - Datacenter
                    - com.vmware.content.Library
                    - com.vmware.content.library.Item
                    - Datastore
                    - StoragePod
                    - HostNetwork
                    - Network
                    - HostSystem
                    - DistributedVirtualSwitch
                    - VirtualMachine
                    - VirtualApp
                    - ResourcePool
                    - ClusterComputeResource
                    - OpaqueNetwork

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

seealso:
    - module: vmware.vmware.tags
"""

EXAMPLES = r"""
- name: Create or update tag categories
  vmware.vmware.tag_categories:
    state: present
    tags:
      - name: my-test-category-1
      - id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL
        name: my-test-category-2
        description: "This is a test category"
        cardinality: SINGLE
        associable_types: [VirtualMachine]
      - name: my-test-category-3
        description: "This is a test category"
        cardinality: MULTIPLE

- name: Delete tag categories
  vmware.vmware.tag_categories:
    state: absent
    tag_categories:
      - name: my-test-category-1
      - id: urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-21b1f07e73cf:GLOBAL

# For better performance, manage many tag categories per module call
- name: Manage many categories
  vmware.vmware.tag_categories:
    state: present
    tag_categories:
      - name: my-test-category-1
      - name: my-test-category-2
      - name: my-test-category-3
      - name: my-test-category-4

# Do not use loops when possible
- name: This will be very slow
  vmware.vmware.tag_categories:
    state: present
    tag_categories: ["{{ item }}"]
  loop:
    - name: my-test-category-1
    - name: my-test-category-2
    - name: my-test-category-3
    - name: my-test-category-4
"""

RETURN = r"""
vsphere_tag_categories:
    description:
        - Dictionary of tag categories that were managed by this module. This includes any tag categories that the user specified, even
          if nothing was changed.
        - The key is the tag category ID, the value is a dictionary with tag category information.
    returned: always
    type: dict
    sample: {
        "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL": {
            "name": "cat1",
            "description": "Description of cat1",
            "cardinality": "MULTIPLE",
            "associable_types": ["VirtualMachine", "Datastore"],
            "id": "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL"
        },
    }

created_categories:
    description:
        - List of tag category IDs that were created by this module.
        - The list is empty if no tag categories were created.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
    ]

updated_categories:
    description:
        - List of tag category IDs that were updated by this module.
        - The list is empty if no tag categories were updated.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
    ]

removed_categories:
    description:
        - List of tag category IDs that were removed by this module.
        - The list is empty if no tag categories were removed.
    returned: always
    type: list
    sample: [
        "urn:vmomi:InventoryServiceCategory:00000000-0000-0000-0000-000000000000:GLOBAL",
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


ALL_ASSOCIABLE_TYPES = [
    "Folder",
    "DistributedVirtualPortgroup",
    "VmwareDistributedVirtualSwitch",
    "Datacenter",
    "com.vmware.content.Library",
    "com.vmware.content.library.Item",
    "Datastore",
    "StoragePod",
    "HostNetwork",
    "Network",
    "HostSystem",
    "DistributedVirtualSwitch",
    "VirtualMachine",
    "VirtualApp",
    "ResourcePool",
    "ClusterComputeResource",
    "OpaqueNetwork",
]


class TagCategoryDiff:
    """
    A data class representing a diff to a tag category.

    This class encapsulates the before and after state of a tag category diff,
    providing methods to convert the diff to module output format.

    Attributes:
        remote_def (object): Tag category model before the diff (None for new categories)
        param_def (dict): Tag category parameters after the diff (None for deletions)
    """

    def __init__(self, remote_def: object = None, param_def: dict = None):
        self._is_update = None
        if param_def is None:
            param_def = dict()
        # before is always a tag model, after is a dict of parameters
        self.remote_def = remote_def
        self.param_def = param_def
        if self.param_def.get("associable_types") is not None and self.remote_def is not None:
            self.param_def["associable_types"] = list(set(self.param_def.get("associable_types", [])) | self.remote_def.associable_types)

    def param_def_to_spec_args(self):
        out = {
            "name": self.param_def.get("name"),
            "description": self.param_def.get("description"),
            "cardinality": self.param_def.get("cardinality"),
            "associable_types": set(self.param_def["associable_types"]),
        }
        return out

    def get_category_id(self):
        if self.remote_def is not None:
            # Category already exists and is being updated or removed, so we can use the remote def ID
            return self.remote_def.id

        if self.param_def.get("id") is not None:
            # Category didn't exist and we created it, so we have the new ID available
            return self.param_def.get("id")

        return None

    def is_creation(self):
        return self.param_def != dict() and self.remote_def is None

    def is_update(self):
        if self._is_update is None:
            self._is_update = self._does_tag_category_need_update()

        return self._is_update

    def _does_tag_category_need_update(self):
        """
        Determine if a tag category requires an update based on parameter changes.

        Args:
            param_category (dict): Category parameters from user input
            remote_category (object, optional): Current category model from VMware

        Returns:
            bool: True if update is needed, False otherwise
        """
        if self.param_def == dict() or self.remote_def is None:
            return False

        for attr in ["name", "description", "cardinality"]:
            if self.param_def.get(attr) is None:
                continue
            elif self.param_def[attr] != getattr(self.remote_def, attr):
                return True

        if self.param_def.get("associable_types") is not None:
            if not self.remote_def.associable_types.issuperset(set(self.param_def["associable_types"])):
                return True

        return False

    def is_removal(self):
        return self.param_def == dict() and self.remote_def is not None

    def new_tag_category_state_to_module_output(self):
        """
        Convert the future/new state of a tag to a dictionary format suitable for Ansible module output.

        Returns:
            dict: Dictionary with 'id', 'name', 'category_id', and 'description' keys containing tag information
        """
        if self.is_removal():
            return dict()

        return dict(
            id=self.get_category_id(),
            name=self.param_def.get("name") or self.remote_def.name,
            description=self.param_def.get("description") or self.remote_def.description,
            cardinality=self.param_def.get("cardinality") or self.remote_def.cardinality,
            associable_types=list(set(self.param_def.get("associable_types") or []) | set(self.remote_def.associable_types)),
        )


class VmwareTagCategoryModule(ModuleRestBase):
    """
    A specialized Ansible module for managing VMware tag categories using the vSphere REST API.

    This class extends ModuleRestBase to provide comprehensive tag category management capabilities
    including creation, updates, and deletion of VMware tag categories. It optimizes performance by
    using different processing strategies based on whether parameters use IDs or names.

    Attributes:
        _params_only_use_ids (bool): True if all parameters use IDs, False otherwise

    Example:
        vmware_tag_category = VmwareTagCategoryModule(module)
        category_changes = vmware_tag_category.determine_tag_category_changes()
        vmware_tag_category.apply_tag_category_changes(category_changes)
    """

    def __init__(self, module):
        super().__init__(module)
        self._params_only_use_ids = all(
            c.get("id") is not None for c in module.params["tag_categories"]
        )

    def determine_tag_category_diffs(self):
        tag_category_diffs = []
        if self._params_only_use_ids:
            self._determine_tag_category_diffs_by_ids_only(tag_category_diffs)
        else:
            self._determine_tag_category_diffs_by_names_and_ids(tag_category_diffs)

        return tag_category_diffs

    def _determine_tag_category_diffs_by_ids_only(self, tag_category_diffs):
        """
        Process tag category changes when all parameters use IDs.

        This method is optimized for scenarios where all category parameters provide IDs,
        allowing for direct lookups without needing to iterate through all remote categories.

        Args:
            tag_category_diffs (list): List to append diffs to

        Raises:
            AnsibleModule.fail_json: If an ID is provided for a new category creation
        """
        for param_category in self.module.params["tag_categories"]:
            try:
                remote_category = self.tag_category_service.get(
                    param_category.get("id")
                )
            except NotFound:
                remote_category = None

            if remote_category is None and self.module.params["state"] == "present":
                self.module.fail_json(
                    msg="You cannot provide an ID when creating a new category.",
                    violating_tag_category_param=param_category,
                )

            category_change = self._create_category_change(
                param_category, remote_category
            )
            if category_change is not None:
                tag_category_diffs.append(category_change)

    def _determine_tag_category_diffs_by_names_and_ids(self, tag_category_diffs):
        """
        Process tag category changes when parameters use names or mixed names/IDs.

        This method iterates through all remote categories to find matches with parameters.
        Looping through all tags once is required when parameters use names or mixed names/IDs.

        Args:
            tag_category_changes (list): List to append changes to
        """
        category_params_left_to_process = dict(
            enumerate(self.module.params["tag_categories"])
        )

        # Cycle through all remote categories and find the ones that match the parameters. Determine
        # what changes need to be made with them.
        for remote_category_id in self.tag_category_service.list():
            remote_category = self.tag_category_service.get(remote_category_id)
            for index, param_category in category_params_left_to_process.copy().items():
                if param_category.get(
                    "id"
                ) is not None and remote_category.id != param_category.get("id"):
                    continue

                if param_category.get(
                    "id"
                ) is None and remote_category.name != param_category.get("name"):
                    continue

                del category_params_left_to_process[index]
                category_change = self._create_category_change(
                    param_category, remote_category
                )
                if category_change is not None:
                    tag_category_diffs.append(category_change)
                break

            if len(category_params_left_to_process) == 0:
                return

        # Determine what to do with the parameters that were not found in the remote categories
        for param_category in category_params_left_to_process.values():
            category_change = self._create_category_change(param_category, None)
            if category_change is not None:
                tag_category_diffs.append(category_change)

    def _create_category_change(
        self, param_category: dict, remote_category: object = None
    ):
        """
        Create a TagCategoryChange object based on parameters and remote category state.

        Args:
            param_category (dict): Category parameters from user input
            remote_category (object, optional): Current category model from VMware

        Returns:
            TagCategoryChange or None: Change object if action is needed, None otherwise
        """
        if self.module.params["state"] == "present":
            if remote_category is None:
                return TagCategoryDiff(remote_def=None, param_def=param_category)

            if param_category.get("cardinality") == "SINGLE" and remote_category.cardinality == "MULTIPLE":
                self.module.fail_json(
                    msg="You cannot change the cardinality of a tag category from MULTIPLE to SINGLE.",
                    violating_tag_category_param=param_category,
                )
            return TagCategoryDiff(remote_def=remote_category, param_def=param_category)

        else:
            if remote_category is not None:
                return TagCategoryDiff(remote_def=remote_category, param_def=None)

        return None

    def apply_tag_category_changes(self, tag_category_diffs):
        """
        Apply the determined tag category changes to the VMware environment.

        Args:
            tag_category_diffs (list[TagCategoryDiff]): List of diffs to apply

        Operations performed:
            - Create: Creates new tag categories with specified properties
            - Update: Updates existing tag category properties
            - Delete: Removes tag categories from the system
        """
        for tag_category_diff in tag_category_diffs:
            if tag_category_diff.is_creation():
                new_category_id = self._create_tag_category(
                    **tag_category_diff.param_def_to_spec_args()
                )
                tag_category_diff.param_def["id"] = new_category_id
            elif tag_category_diff.is_removal():
                self.tag_category_service.delete(tag_category_diff.remote_def.id)
            elif tag_category_diff.is_update():
                self._update_tag_category(
                    tag_category_id=tag_category_diff.remote_def.id,
                    **tag_category_diff.param_def_to_spec_args()
                )

    def _create_tag_category(self, name, description, cardinality, associable_types):
        create_spec = self.tag_category_service.CreateSpec()
        create_spec.name = name
        create_spec.description = description or ""
        create_spec.cardinality = cardinality or "MULTIPLE"
        create_spec.associable_types = set(associable_types) or set(ALL_ASSOCIABLE_TYPES)
        return self.tag_category_service.create(create_spec)

    def _update_tag_category(
        self, tag_category_id, name, description, cardinality, associable_types
    ):
        update_spec = self.tag_category_service.UpdateSpec(
            name=name,
            description=description,
            cardinality=cardinality,
            associable_types=associable_types,
        )
        return self.tag_category_service.update(tag_category_id, update_spec)


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", choices=["present", "absent"], default="present"),
            tag_categories=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    name=dict(type="str", required=False),
                    id=dict(type="str", required=False),
                    description=dict(type="str", required=False),
                    cardinality=dict(
                        type="str", required=False, choices=["SINGLE", "MULTIPLE"]
                    ),
                    associable_types=dict(
                        type="list",
                        elements="str",
                        default=[],
                        required=False,
                        choices=ALL_ASSOCIABLE_TYPES,
                    ),
                ),
                required_one_of=[["name", "id"]],
            ),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    result = dict(
        changed=False,
        created_categories=[],
        updated_categories=[],
        removed_categories=[],
        vsphere_tag_categories={},
    )

    vmware_tag_category = VmwareTagCategoryModule(module)
    tag_category_diffs = vmware_tag_category.determine_tag_category_diffs()
    result["vsphere_tag_categories"] = {
        cat_diff.get_category_id(): cat_diff.new_tag_category_state_to_module_output()
        for cat_diff in tag_category_diffs
        if cat_diff.get_category_id() is not None and not cat_diff.is_removal()
    }
    if not tag_category_diffs:
        module.exit_json(**result)

    if not module.check_mode:
        vmware_tag_category.apply_tag_category_changes(tag_category_diffs)

    for cat_diff in tag_category_diffs:
        if cat_diff.is_creation():
            result["created_categories"].append(cat_diff.get_category_id())
            result["changed"] = True
        elif cat_diff.is_update():
            result["updated_categories"].append(cat_diff.get_category_id())
            result["changed"] = True
        elif cat_diff.is_removal():
            result["removed_categories"].append(cat_diff.get_category_id())
            result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
