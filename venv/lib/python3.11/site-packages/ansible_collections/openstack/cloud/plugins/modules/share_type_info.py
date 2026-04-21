#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 VEXXHOST, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: share_type_info
short_description: Get OpenStack share type details
author: OpenStack Ansible SIG
description:
  - Get share type details in OpenStack Manila.
  - Get share type access details for private share types.
  - Uses Manila API microversion 2.50 to retrieve complete share type information including is_default field.
  - Safely falls back to basic information if microversion 2.50 is not supported by the backend.
  - Private share types can only be accessed by UUID.
options:
  name:
    description:
      - Share type name or id.
      - For private share types, the UUID must be used instead of name.
    required: true
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
"""

EXAMPLES = r"""
    - name: Get share type details
      openstack.cloud.share_type_info:
        name: manila-generic-share

    - name: Get share type details by id
      openstack.cloud.share_type_info:
        name: fbadfa6b-5f17-4c26-948e-73b94de57b42
"""

RETURN = """
share_type:
  description: Dictionary describing share type
  returned: On success
  type: dict
  contains:
    id:
      description: share type uuid
      returned: success
      type: str
      sample: 59575cfc-3582-4efc-8eee-f47fcb25ea6b
    name:
      description: share type name
      returned: success
      type: str
      sample: default
    description:
      description:
        - share type description
        - Available when Manila API microversion 2.50 is supported
        - Falls back to empty string if microversion is not available
      returned: success
      type: str
      sample: "Default Manila share type"
    is_default:
      description:
        - whether this is the default share type
        - Retrieved from the API response when microversion 2.50 is supported
        - Falls back to null if microversion is not available or field is not present
      returned: success
      type: bool
      sample: true
    is_public:
      description: whether the share type is public (true) or private (false)
      returned: success
      type: bool
      sample: true
    required_extra_specs:
      description: Required extra specifications for the share type
      returned: success
      type: dict
      sample: {"driver_handles_share_servers": "True"}
    optional_extra_specs:
      description: Optional extra specifications for the share type
      returned: success
      type: dict
      sample: {"snapshot_support": "True", "create_share_from_snapshot_support": "True"}
"""

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule,
)

# Manila API microversion 2.50 provides complete share type information
# including is_default field and description
# Reference: https://docs.openstack.org/api-ref/shared-file-system/#show-share-type-detail
MANILA_MICROVERSION = "2.50"


class ShareTypeInfoModule(OpenStackModule):
    argument_spec = dict(name=dict(type="str", required=True))
    module_kwargs = dict(
        supports_check_mode=True,
    )

    def __init__(self, **kwargs):
        super(ShareTypeInfoModule, self).__init__(**kwargs)

    def _find_share_type(self, name_or_id):
        """
        Find share type by name or ID with comprehensive information.
        """
        share_type = self._find_by_direct_access(name_or_id)
        if share_type:
            return share_type

        # If direct access fails, try searching in public listing
        # This handles cases where we have the name but need to find the ID
        try:
            response = self.conn.shared_file_system.get("/types")
            share_types = response.json().get("share_types", [])

            for share_type in share_types:
                if share_type["name"] == name_or_id or share_type["id"] == name_or_id:
                    # Found by name, now get complete info using the ID
                    result = self._find_by_direct_access(share_type["id"])
                    if result:
                        return result
        except Exception:
            pass

        return None

    def _find_by_direct_access(self, name_or_id):
        """
        Find share type by direct access (for private share types).
        """
        try:
            response = self.conn.shared_file_system.get(
                f"/types/{name_or_id}", microversion=MANILA_MICROVERSION
            )
            share_type_data = response.json().get("share_type", {})
            if share_type_data:
                return share_type_data
        except Exception:
            pass

        # Fallback: try without microversion for basic information
        try:
            response = self.conn.shared_file_system.get(f"/types/{name_or_id}")
            share_type_data = response.json().get("share_type", {})
            if share_type_data:
                return share_type_data
        except Exception:
            pass

        return None

    def _normalize_share_type_dict(self, share_type_dict):
        """
        Normalize share type dictionary to match CLI output format.
        """
        # Extract extra specs information
        extra_specs = share_type_dict.get("extra_specs", {})
        required_extra_specs = share_type_dict.get("required_extra_specs", {})

        # Optional extra specs are those in extra_specs but not in required_extra_specs
        optional_extra_specs = {
            key: value
            for key, value in extra_specs.items()
            if key not in required_extra_specs
        }

        # Determine if this is the default share type
        # Use the is_default field from API response (available with microversion 2.50)
        # If not available (older API versions), default to None
        is_default = share_type_dict.get("is_default", None)

        # Handle the description field - available through microversion 2.50
        # Convert None to empty string if API returns null
        description = share_type_dict.get("description") or ""

        # Determine visibility - check both new and legacy field names
        # Use the same logic as share_type.py for consistency
        is_public = share_type_dict.get(
            "os-share-type-access:is_public",
            share_type_dict.get("share_type_access:is_public"),
        )

        # Build the normalized dictionary matching CLI output
        normalized = {
            "id": share_type_dict.get("id"),
            "name": share_type_dict.get("name"),
            "is_public": is_public,
            "is_default": is_default,
            "required_extra_specs": required_extra_specs,
            "optional_extra_specs": optional_extra_specs,
            "description": description,
        }

        return normalized

    def run(self):
        """
        Main execution method following OpenStackModule pattern.

        Retrieves share type information using Manila API microversion for complete
        details including description and is_default fields. Falls back gracefully to
        basic API calls if microversion is not supported by the backend.
        """
        name_or_id = self.params["name"]

        share_type = self._find_share_type(name_or_id)
        if not share_type:
            self.fail_json(
                msg=f"Share type '{name_or_id}' not found. "
                f"If this is a private share type, use its UUID instead of name."
            )

        if hasattr(share_type, "to_dict"):
            share_type_dict = share_type.to_dict()
        elif isinstance(share_type, dict):
            share_type_dict = share_type
        else:
            share_type_dict = dict(share_type) if share_type else {}

        # Normalize the output to match CLI format
        normalized_share_type = self._normalize_share_type_dict(share_type_dict)

        # Return results in the standard format
        result = dict(changed=False, share_type=normalized_share_type)
        return result


def main():
    module = ShareTypeInfoModule()
    module()


if __name__ == "__main__":
    main()
