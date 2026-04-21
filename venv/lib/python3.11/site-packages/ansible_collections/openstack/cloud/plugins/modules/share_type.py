#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 VEXXHOST, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: share_type
short_description: Manage OpenStack share type
author: OpenStack Ansible SIG
description:
  - Add, remove or update share types in OpenStack Manila.
options:
  name:
    description:
      - Share type name or id.
      - For private share types, the UUID must be used instead of name.
    required: true
    type: str
  description:
    description:
      - Description of the share type.
    type: str
  extra_specs:
    description:
      - Dictionary of share type extra specifications
    type: dict
  is_public:
    description:
      - Make share type accessible to the public.
      - Can be updated after creation using Manila API direct updates.
    type: bool
    default: true
  driver_handles_share_servers:
    description:
      - Boolean flag indicating whether share servers are managed by the driver.
      - Required for share type creation.
      - This is automatically added to extra_specs as 'driver_handles_share_servers'.
    type: bool
    default: true
  state:
    description:
      - Indicate desired state of the resource.
    choices: ['present', 'absent']
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
"""

EXAMPLES = r"""
    - name: Delete share type by name
      openstack.cloud.share_type:
        name: test_share_type
        state: absent

    - name: Delete share type by id
      openstack.cloud.share_type:
        name: fbadfa6b-5f17-4c26-948e-73b94de57b42
        state: absent

    - name: Create share type
      openstack.cloud.share_type:
        name: manila-generic-share
        state: present
        driver_handles_share_servers: true
        extra_specs:
          share_backend_name: GENERIC_BACKEND
          snapshot_support: true
          create_share_from_snapshot_support: true
        description: Generic share type
        is_public: true
"""

RETURN = """
share_type:
  description: Dictionary describing share type
  returned: On success when I(state) is 'present'
  type: dict
  contains:
    name:
      description: share type name
      returned: success
      type: str
      sample: manila-generic-share
    extra_specs:
      description: share type extra specifications
      returned: success
      type: dict
      sample: {"share_backend_name": "GENERIC_BACKEND", "snapshot_support": "true"}
    is_public:
      description: whether the share type is public
      returned: success
      type: bool
      sample: True
    description:
      description: share type description
      returned: success
      type: str
      sample: Generic share type
    driver_handles_share_servers:
      description: whether driver handles share servers
      returned: success
      type: bool
      sample: true
    id:
      description: share type uuid
      returned: success
      type: str
      sample: b75d8c5c-a6d8-4a5d-8c86-ef4f1298525d
"""

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule,
)

# Manila API microversion 2.50 provides complete share type information
# including is_default field and description
# Reference: https://docs.openstack.org/api-ref/shared-file-system/#show-share-type-detail
MANILA_MICROVERSION = "2.50"


class ShareTypeModule(OpenStackModule):
    argument_spec = dict(
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        extra_specs=dict(type="dict", required=False),
        is_public=dict(type="bool", default=True),
        driver_handles_share_servers=dict(type="bool", default=True),
        state=dict(type="str", default="present", choices=["absent", "present"]),
    )
    module_kwargs = dict(
        required_if=[("state", "present", ["driver_handles_share_servers"])],
        supports_check_mode=True,
    )

    @staticmethod
    def _extract_result(details):
        if details is not None:
            if hasattr(details, "to_dict"):
                result = details.to_dict(computed=False)
            elif isinstance(details, dict):
                result = details.copy()
            else:
                result = dict(details) if details else {}

            # Normalize is_public field from API response
            if result and "os-share-type-access:is_public" in result:
                result["is_public"] = result["os-share-type-access:is_public"]
            elif result and "share_type_access:is_public" in result:
                result["is_public"] = result["share_type_access:is_public"]

            return result
        return {}

    def _find_share_type(self, name_or_id):
        """
        Find share type by name or ID with comprehensive information.

        Uses direct Manila API calls since SDK methods are not available.
        Handles both public and private share types.
        """
        # Try direct access first for complete information
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
        Find share type by direct access using Manila API.

        Uses microversion to get complete information including description and is_default.
        Falls back to basic API if microversion is not supported.
        """
        # Try with microversion first for complete information
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

    def run(self):
        state = self.params["state"]
        name_or_id = self.params["name"]

        # Find existing share type (similar to volume_type.py pattern)
        share_type = self._find_share_type(name_or_id)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, share_type))

        if state == "present" and not share_type:
            # Create type
            create_result = self._create()
            share_type = self._extract_result(create_result)
            self.exit_json(changed=True, share_type=share_type)

        elif state == "present" and share_type:
            # Update type
            update = self._build_update(share_type)
            update_result = self._update(share_type, update)
            share_type = self._extract_result(update_result)
            self.exit_json(changed=bool(update), share_type=share_type)

        elif state == "absent" and share_type:
            # Delete type
            self._delete(share_type)
            self.exit_json(changed=True)

        else:
            # state == 'absent' and not share_type
            self.exit_json(changed=False)

    def _build_update(self, share_type):
        return {
            **self._build_update_extra_specs(share_type),
            **self._build_update_share_type(share_type),
        }

    def _build_update_extra_specs(self, share_type):
        update = {}

        old_extra_specs = share_type.get("extra_specs", {})

        # Build the complete new extra specs including driver_handles_share_servers
        new_extra_specs = {}

        # Add driver_handles_share_servers (always required)
        if self.params.get("driver_handles_share_servers") is not None:
            new_extra_specs["driver_handles_share_servers"] = str(
                self.params["driver_handles_share_servers"]
            ).title()

        # Add user-defined extra specs
        if self.params.get("extra_specs"):
            new_extra_specs.update(
                {k: str(v) for k, v in self.params["extra_specs"].items()}
            )

        delete_extra_specs_keys = set(old_extra_specs.keys()) - set(
            new_extra_specs.keys()
        )

        if delete_extra_specs_keys:
            update["delete_extra_specs_keys"] = delete_extra_specs_keys

        if old_extra_specs != new_extra_specs:
            update["create_extra_specs"] = new_extra_specs

        return update

    def _build_update_share_type(self, share_type):
        update = {}
        # Only allow description updates - name is used for identification
        allowed_attributes = ["description"]

        # Handle is_public updates - CLI supports this, so we should too
        # Always check is_public since it has a default value of True
        current_is_public = share_type.get(
            "os-share-type-access:is_public",
            share_type.get("share_type_access:is_public"),
        )
        requested_is_public = self.params["is_public"]  # Will be True by default now
        if current_is_public != requested_is_public:
            # Mark this as needing a special access update
            update["update_access"] = {
                "is_public": requested_is_public,
                "share_type_id": share_type.get("id"),
            }

        type_attributes = {
            k: self.params[k]
            for k in allowed_attributes
            if k in self.params
            and self.params.get(k) is not None
            and self.params.get(k) != share_type.get(k)
        }

        if type_attributes:
            update["type_attributes"] = type_attributes

        return update

    def _create(self):
        share_type_attrs = {"name": self.params["name"]}

        if self.params.get("description") is not None:
            share_type_attrs["description"] = self.params["description"]

        # Handle driver_handles_share_servers - this is the key required parameter
        extra_specs = {}
        if self.params.get("driver_handles_share_servers") is not None:
            extra_specs["driver_handles_share_servers"] = str(
                self.params["driver_handles_share_servers"]
            ).title()

        # Add user-defined extra specs
        if self.params.get("extra_specs"):
            extra_specs.update(
                {k: str(v) for k, v in self.params["extra_specs"].items()}
            )

        if extra_specs:
            share_type_attrs["extra_specs"] = extra_specs

        # Handle is_public parameter - field name depends on API version
        if self.params.get("is_public") is not None:
            # For microversion (API 2.7+), use share_type_access:is_public
            # For older versions, use os-share-type-access:is_public
            share_type_attrs["share_type_access:is_public"] = self.params["is_public"]
            # Also include legacy field for compatibility
            share_type_attrs["os-share-type-access:is_public"] = self.params[
                "is_public"
            ]

        try:
            payload = {"share_type": share_type_attrs}

            # Try with microversion first (supports share_type_access:is_public)
            try:
                response = self.conn.shared_file_system.post(
                    "/types", json=payload, microversion=MANILA_MICROVERSION
                )
                share_type_data = response.json().get("share_type", {})
            except Exception:
                # Fallback: try without microversion (uses os-share-type-access:is_public)
                # Remove the newer field name for older API compatibility
                if "share_type_access:is_public" in share_type_attrs:
                    del share_type_attrs["share_type_access:is_public"]
                payload = {"share_type": share_type_attrs}
                response = self.conn.shared_file_system.post("/types", json=payload)
                share_type_data = response.json().get("share_type", {})

            return share_type_data

        except Exception as e:
            self.fail_json(msg=f"Failed to create share type: {str(e)}")

    def _delete(self, share_type):
        # Use direct API call since SDK method may not exist
        try:
            share_type_id = (
                share_type.get("id") if isinstance(share_type, dict) else share_type.id
            )
            # Try with microversion first, fallback if not supported
            try:
                self.conn.shared_file_system.delete(
                    f"/types/{share_type_id}", microversion=MANILA_MICROVERSION
                )
            except Exception:
                self.conn.shared_file_system.delete(f"/types/{share_type_id}")
        except Exception as e:
            self.fail_json(msg=f"Failed to delete share type: {str(e)}")

    def _update(self, share_type, update):
        if not update:
            return share_type
        share_type = self._update_share_type(share_type, update)
        share_type = self._update_extra_specs(share_type, update)
        share_type = self._update_access(share_type, update)
        return share_type

    def _update_extra_specs(self, share_type, update):
        share_type_id = (
            share_type.get("id") if isinstance(share_type, dict) else share_type.id
        )

        delete_extra_specs_keys = update.get("delete_extra_specs_keys")
        if delete_extra_specs_keys:
            for key in delete_extra_specs_keys:
                try:
                    # Try with microversion first, fallback if not supported
                    try:
                        self.conn.shared_file_system.delete(
                            f"/types/{share_type_id}/extra_specs/{key}",
                            microversion=MANILA_MICROVERSION,
                        )
                    except Exception:
                        self.conn.shared_file_system.delete(
                            f"/types/{share_type_id}/extra_specs/{key}"
                        )
                except Exception as e:
                    self.fail_json(msg=f"Failed to delete extra spec '{key}': {str(e)}")
            # refresh share_type information
            share_type = self._find_share_type(share_type_id)

        create_extra_specs = update.get("create_extra_specs")
        if create_extra_specs:
            # Convert values to strings as Manila API expects string values
            string_specs = {k: str(v) for k, v in create_extra_specs.items()}
            try:
                # Try with microversion first, fallback if not supported
                try:
                    self.conn.shared_file_system.post(
                        f"/types/{share_type_id}/extra_specs",
                        json={"extra_specs": string_specs},
                        microversion=MANILA_MICROVERSION,
                    )
                except Exception:
                    self.conn.shared_file_system.post(
                        f"/types/{share_type_id}/extra_specs",
                        json={"extra_specs": string_specs},
                    )
            except Exception as e:
                self.fail_json(msg=f"Failed to update extra specs: {str(e)}")
            # refresh share_type information
            share_type = self._find_share_type(share_type_id)

        return share_type

    def _update_access(self, share_type, update):
        """Update share type access (public/private) using direct API update"""
        access_update = update.get("update_access")
        if not access_update:
            return share_type

        share_type_id = access_update["share_type_id"]
        is_public = access_update["is_public"]

        try:
            # Use direct update with share_type_access:is_public (works for both public and private)
            update_payload = {"share_type": {"share_type_access:is_public": is_public}}

            try:
                self.conn.shared_file_system.put(
                    f"/types/{share_type_id}",
                    json=update_payload,
                    microversion=MANILA_MICROVERSION,
                )
            except Exception:
                # Fallback: try with legacy field name for older API versions
                update_payload = {
                    "share_type": {"os-share-type-access:is_public": is_public}
                }
                self.conn.shared_file_system.put(
                    f"/types/{share_type_id}", json=update_payload
                )

            # Refresh share type information after access change
            share_type = self._find_share_type(share_type_id)

        except Exception as e:
            self.fail_json(msg=f"Failed to update share type access: {str(e)}")

        return share_type

    def _update_share_type(self, share_type, update):
        type_attributes = update.get("type_attributes")
        if type_attributes:
            share_type_id = (
                share_type.get("id") if isinstance(share_type, dict) else share_type.id
            )
            try:
                # Try with microversion first, fallback if not supported
                try:
                    response = self.conn.shared_file_system.put(
                        f"/types/{share_type_id}",
                        json={"share_type": type_attributes},
                        microversion=MANILA_MICROVERSION,
                    )
                except Exception:
                    response = self.conn.shared_file_system.put(
                        f"/types/{share_type_id}", json={"share_type": type_attributes}
                    )
                updated_type = response.json().get("share_type", {})
                return updated_type
            except Exception as e:
                self.fail_json(msg=f"Failed to update share type: {str(e)}")
        return share_type

    def _will_change(self, state, share_type):
        if state == "present" and not share_type:
            return True
        if state == "present" and share_type:
            return bool(self._build_update(share_type))
        if state == "absent" and share_type:
            return True
        return False


def main():
    module = ShareTypeModule()
    module()


if __name__ == "__main__":
    main()
