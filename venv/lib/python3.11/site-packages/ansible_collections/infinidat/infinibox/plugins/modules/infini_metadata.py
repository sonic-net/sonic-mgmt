#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,too-many-branches,too-many-locals,line-too-long,wrong-import-position

"""This module creates, deletes or modifies metadata on Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_metadata
version_added: 2.13.0
short_description:  Create, Delete or Modify metadata on Infinibox
description:
    - This module creates, deletes or modifies metadata on Infinibox. It can
    also search for objects by metadata key and object type.
    - Deleting metadata by object, without specifying a key, is not implemented for any object_type (e.g. DELETE api/rest/metadata/system).
    - This would delete all metadata belonging to the object. Instead delete each key explicitely using its key name.
author: David Ohlemacher (@ohlemacher)
options:
  object_type:
    description:
      - Type of object
    type: str
    required: true
    choices: ["cluster", "fs", "fs-snap", "host", "pool", "system", "vol", "vol-snap"]
  object_name:
    description:
      - Name of the object. Not used if object_type is system
    type: str
    required: false
  key:
    description:
      - Name of the metadata key
    type: str
    required: true
  value:
    description:
      - Value of the metadata key
    type: str
    required: false
  state:
    description:
      - Creates, modifies, removes or searches for metadata.
    type: str
    required: false
    default: present
    choices: [ "stat", "present", "absent", "search" ]

extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Create new metadata key foo with value bar
  infini_metadata:
    object_name: test-vol
    object_type: vol
    key: foo
    value: bar
    state: present
    user: admin
    password: secret
    system: ibox001
- name: Stat metadata key named foo
  infini_metadata:
    object_name: test-vol
    state: stat
    user: admin
    password: secret
    system: ibox001
- name: Remove metadata key named foo
  infini_metadata:
    object_name: test-vol
    object_type: vol,
    key: foo
    state: absent
    user: admin
    password: secret
    system: ibox001
- name: Search for objects that have a metadata key named foo with value bar
  infini_metadata:
    key: foo
    value: bar
    state: search
    user: admin
    password: secret
    system: ibox001

"""

# RETURN = r''' # '''

import json

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    append_key_to_api_path,
    get_cluster,
    get_filesystem,
    get_host,
    get_pool,
    get_system,
    get_volume,
    infinibox_api_get,
    infinibox_argument_spec,
)

HAS_INFINISDK = True
try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    HAS_INFINISDK = False

HAS_CAPACITY = False


@api_wrapper
def get_metadata_vol(module, disable_fail):
    """Get metadata about a volume"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    vol = get_volume(module, system)
    if vol:
        path = f"metadata/{vol.id}/{key}"
        try:
            metadata = infinibox_api_get(module, path=path, disable_fail=disable_fail)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"Volume {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = f"Volume with object name {object_name} not found. Cannot stat its metadata."
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata_fs(module, disable_fail):
    """Get metadata about a fs"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    fs = get_filesystem(module, system)
    if fs:
        path = f"metadata/{fs.id}/{key}"
        try:
            metadata = system.api.get(path=path)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"File system {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = f"File system named {object_name} not found. Cannot stat its metadata."
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata_host(module, disable_fail):
    """Get metadata about a host"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    host = get_host(module, system)
    if host:
        path = f"metadata/{host.id}/{key}"
        try:
            metadata = system.api.get(path=path)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"Host {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = f"Host named {object_name} not found. Cannot stat its metadata."
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata_cluster(module, disable_fail):
    """Get metadata about a cluster"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    cluster = get_cluster(module, system)
    if cluster:
        path = f"metadata/{cluster.id}/{key}"
        try:
            metadata = system.api.get(path=path)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"Cluster {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = f"Cluster named {object_name} not found. Cannot stat its metadata."
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata_fssnap(module, disable_fail):
    """Get metadata about a fs snapshot"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    fssnap = get_filesystem(module, system)
    if fssnap:
        path = f"metadata/{fssnap.id}/{key}"
        try:
            metadata = system.api.get(path=path)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"File system snapshot {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = f"File system snapshot named {object_name} not found. Cannot stat its metadata."
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata_pool(module, disable_fail):
    """Get metadata about a pool"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    pool = get_pool(module, system)
    if pool:
        path = f"metadata/{pool.id}/{key}"
        try:
            metadata = system.api.get(path=path)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"Pool {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = f"Pool named {object_name} not found. Cannot stat its metadata."
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata_volsnap(module, disable_fail):
    """Get metadata for a volume snapshot"""
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    metadata = None

    volsnap = get_volume(module, system)
    if volsnap:
        path = f"metadata/{volsnap.id}/{key}"
        try:
            metadata = system.api.get(path=path)
        except APICommandFailed:
            if not disable_fail:
                module.fail_json(
                    f"Cannot find {object_type} metadata key. "
                    f"Volume snapshot {object_name} key {key} not found"
                )
    elif not disable_fail:
        msg = (
            f"Volume snapshot named {object_name} not found. Cannot stat its metadata."
        )
        module.fail_json(msg=msg)

    return metadata


@api_wrapper
def get_metadata(module, disable_fail=False):
    """
    Find and return metadata
    Use disable_fail when we are looking for metadata
    and it may or may not exist and neither case is an error.
    """
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]

    if object_type == "system":
        path = f"metadata/{object_type}?key={key}"
        metadata = system.api.get(path=path)
    elif object_type == "fs":
        metadata = get_metadata_fs(module, disable_fail)
    elif object_type == "vol":
        metadata = get_metadata_vol(module, disable_fail)
    elif object_type == "host":
        metadata = get_metadata_host(module, disable_fail)
    elif object_type == "cluster":
        metadata = get_metadata_cluster(module, disable_fail)
    elif object_type == "fs-snap":
        metadata = get_metadata_fs(module, disable_fail)
    elif object_type == "pool":
        metadata = get_metadata_pool(module, disable_fail)
    elif object_type == "vol-snap":
        metadata = get_metadata_volsnap(module, disable_fail)

    else:
        msg = f"Metadata for {object_type} not supported. Cannot stat."
        module.fail_json(msg=msg)

    if metadata:
        result = metadata.get_result()
        if not disable_fail and not result:
            msg = f"Metadata for {object_type} with key {key} not found. Cannot stat."
            module.fail_json(msg=msg)
        return result

    if disable_fail:
        return None

    msg = f"Metadata for {object_type} named {object_name} not found. Cannot stat."
    module.fail_json(msg=msg)
    return None  # Quiet pylint


@api_wrapper
def put_metadata(module):  # pylint: disable=too-many-statements
    """Create metadata key with a value.  The changed variable is found elsewhere."""
    system = get_system(module)

    object_type = module.params["object_type"]
    key = module.params["key"]
    value = module.params["value"]

    # Could check metadata value size < 32k

    if object_type == "system":
        path = "metadata/system"
    elif object_type == "vol":
        vol = get_volume(module, system)
        if not vol:
            object_name = module.params["object_name"]
            msg = f"Volume {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{vol.id}"
    elif object_type == "fs":
        fs = get_filesystem(module, system)
        if not fs:
            object_name = module.params["object_name"]
            msg = f"File system {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{fs.id}"
    elif object_type == "host":
        host = get_host(module, system)
        if not host:
            object_name = module.params["object_name"]
            msg = f"Cluster {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{host.id}"
    elif object_type == "cluster":
        cluster = get_cluster(module, system)
        if not cluster:
            object_name = module.params["object_name"]
            msg = f"Cluster {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{cluster.id}"
    elif object_type == "fs-snap":
        fssnap = get_filesystem(module, system)
        if not fssnap:
            object_name = module.params["object_name"]
            msg = f"File system snapshot {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{fssnap.id}"
    elif object_type == "pool":
        pool = get_pool(module, system)
        if not pool:
            object_name = module.params["object_name"]
            msg = f"Pool {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{pool.id}"
    elif object_type == "vol-snap":
        volsnap = get_volume(module, system)
        if not volsnap:
            object_name = module.params["object_name"]
            msg = f"Volume snapshot {object_name} not found. Cannot add metadata key {key}."
            module.fail_json(msg=msg)
        path = f"metadata/{volsnap.id}"

    # Create json data
    data = {key: value}

    # Put
    system.api.put(path=path, data=data)
    # Variable 'changed' not returned by design


@api_wrapper
def delete_metadata(module):  # pylint: disable=too-many-return-statements
    """
    Remove metadata key.
    Not implemented by design: Deleting all of the system's metadata
    using 'DELETE api/rest/metadata/system'.
    """
    system = get_system(module)
    changed = False
    object_type = module.params["object_type"]
    key = module.params["key"]
    if object_type == "system":
        path = f"metadata/system/{key}"
    elif object_type == "vol":
        vol = get_volume(module, system)
        if not vol:
            changed = False
            return changed  # No vol therefore no metadata to delete
        path = f"metadata/{vol.id}/{key}"
    elif object_type == "fs":
        fs = get_filesystem(module, system)
        if not fs:
            changed = False
            return changed  # No fs therefore no metadata to delete
        path = f"metadata/{fs.id}/{key}"
    elif object_type == "host":
        host = get_host(module, system)
        if not host:
            changed = False
            return changed  # No host therefore no metadata to delete
        path = f"metadata/{host.id}/{key}"
    elif object_type == "cluster":
        cluster = get_cluster(module, system)
        if not cluster:
            changed = False
            return changed  # No cluster therefore no metadata to delete
        path = f"metadata/{cluster.id}/{key}"
    elif object_type == "fs-snap":
        fssnap = get_filesystem(module, system)
        if not fssnap:
            changed = False
            return changed  # No fssnap therefore no metadata to delete
        path = f"metadata/{fssnap.id}/{key}"
    elif object_type == "pool":
        pool = get_pool(module, system)
        if not pool:
            changed = False
            return changed  # No pool therefore no metadata to delete
        path = f"metadata/{pool.id}/{key}"
    elif object_type == "vol-snap":
        volsnap = get_volume(module, system)
        if not volsnap:
            changed = False
            return changed  # No volsnap therefore no metadata to delete
        path = f"metadata/{volsnap.id}/{key}"
    else:
        module.fail_json(f"Object type {object_type} not supported")

    try:
        system.api.delete(path=path)
        changed = True
    except APICommandFailed as err:
        if err.status_code != 404:
            raise
    return changed


def object_type_to_api_type(module, object_type):
    api_types = {
        "cluster": "clusters",
        "fs": "filesystems",
        "fs-snap": "filesystems",
        "host": "hosts",
        "pool": "pools",
        "system": "system",
        "volume": "volumes",
        "vol-snap": "volumes",
    }
    try:
        return api_types[object_type]
    except TypeError:
        msg = f"Invalid object_type: {object_type}"
        module.fail_json(msg=msg)


def add_fields_to_metadata_result(module, metadata):
    """Add useful fields to metadata such as name.
    Return updated result.
    """
    system = get_system(module)
    result = metadata  #.get_result()

    for item in result:
        object_id = item['object_id']
        object_type = item['object_type']
        api_type = object_type_to_api_type(module, object_type)
        path = f"{api_type}?id={object_id}"
        data = infinibox_api_get(module, path=path)[0]
        item_name = data["name"]
        item['name'] = item_name  # Add object name to result
    return result


@api_wrapper
def search_metadata(module):
    """Get metadata by type, name, key and/or value."""
    # TODO - support pagination
    system = get_system(module)
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    value = module.params["value"]

    # Assemble rest path
    path = "metadata"
    if object_type:
        path = append_key_to_api_path(path, f"object_type={object_type}")
    if object_name:
        path = append_key_to_api_path(path, f"object_name={object_name}")
    if key:
        path = append_key_to_api_path(path, f"key={key}")
    if value:
        path = append_key_to_api_path(path, f"value={value}")

    fail_msg = f"Cannot search metadata for object_type '{object_type}', object_name '{object_name}', key '{key}', value '{value}'"
    metadata = infinibox_api_get(module, path=path, fail_msg=fail_msg)

    result = add_fields_to_metadata_result(module, metadata)
    return result


def handle_stat(module):
    """Return metadata stat"""
    object_type = module.params["object_type"]
    key = module.params["key"]
    metadata = get_metadata(module)
    if object_type == "system":
        metadata_id = metadata[0]["id"]
        object_id = metadata[0]["object_id"]
        value = metadata[0]["value"]
    else:
        metadata_id = metadata["id"]
        object_id = metadata["object_id"]
        value = metadata["value"]

    result = {
        "msg": "Metadata found",
        "changed": False,
        "object_type": object_type,
        "key": key,
        "id": metadata_id,
        "object_id": object_id,
        "value": value,
    }
    module.exit_json(**result)


def handle_present(module):
    """Make metadata present"""
    changed = False
    msg = "Metadata unchanged"
    if not module.check_mode:
        old_metadata = get_metadata(module, disable_fail=True)
        put_metadata(module)
        new_metadata = get_metadata(module)
        changed = False
        if not old_metadata:
            changed = True
            msg = "Metadata added"
        elif new_metadata != old_metadata:
            changed = True
            msg = "Metadata changed"
        else:
            msg = "Metadata unchanged since the value is the same as the existing metadata"
    module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """Make metadata absent"""
    msg = "Metadata unchanged"
    changed = False
    if not module.check_mode:
        changed = delete_metadata(module)
        if changed:
            msg = "Metadata removed"
        else:
            msg = "Metadata did not exist so no removal was necessary"
    module.exit_json(changed=changed, msg=msg)


def handle_search(module):
    """Make metadata search"""
    result = {}
    result["changed"] = False
    result["objects"] = search_metadata(module)
    msg = "No objects found"
    if len(result["objects"]):
        msg = "Objects found"
    result["msg"] = msg
    module.exit_json(**result)


def execute_state(module):
    """Determine which state function to execute and do so"""
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        elif state == "search":
            handle_search(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def fail_if_missing_required_param(module, param, is_inverting_logic=False):
    """Fail with bad params"""
    state = module.params["state"]
    if is_inverting_logic and module.params[param]:
        module.fail_json(f"Parameter '{param}' cannot be provided for state '{state}'")
    elif not module.params[param]:
        module.fail_json(f"Parameter '{param}' is required for state '{state}'")


def check_and_convert_system_keys_values(module):
    """object_type system key values may need type conversions"""
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]
    key = module.params["key"]
    value = module.params["value"]
    # Check system object_type
    if object_type == "system":

        # Check object_name is None
        if object_name:
            module.fail_json(
                "An object_name for object_type system must not be provided."
            )

        # Handle special system metadata keys
        if key == "ui-dataset-default-provisioning":
            values = ["THICK", "THIN"]
            if value not in values:
                module.fail_json(
                    f"Cannot create {object_type} metadata for key {key}. "
                    f"Value must be one of {values}. Invalid value: {value}."
                )

        # Convert bool string to bool
        if key in [
            "ui-dataset-base2-units",
            "ui-feedback-dialog",
            "ui-feedback-form",
        ]:
            try:
                module.params["value"] = json.loads(value.lower())
            except json.decoder.JSONDecodeError:
                module.fail_json(
                    f"Cannot create {object_type} metadata for key {key}. "
                    f"Value must be able to be decoded as a boolean. Invalid value: {value}."
                )

        # Convert integer string to int
        if key in ["ui-bulk-volume-zero-padding", "ui-table-export-limit"]:
            try:
                module.params["value"] = json.loads(value.lower())
            except json.decoder.JSONDecodeError:
                module.fail_json(
                    f"Cannot create {object_type} metadata for key {key}. "
                    f"Value must be of type integer. Invalid value: {value}."
                )


def check_options(module):
    """Verify module options are sane"""
    state = module.params["state"]
    key = module.params["key"]
    value = module.params["value"]
    object_type = module.params["object_type"]
    object_name = module.params["object_name"]

    if state == "present":
        req_params = ["object_name", "object_type", "key", "value"]
        for req_param in req_params:
            fail_if_missing_required_param(module, req_param)
        check_and_convert_system_keys_values(module)
    elif state in ["stat", "absent"]:
        req_params = ["object_name", "object_type", "key"]
        for req_param in req_params:
            fail_if_missing_required_param(module, req_param)
    elif state == "search":
        if not key and not value:
            module.fail_json(
                "The state 'search' requires either a key or value parameter to search for"
            )
        if object_type or object_name:
            module.fail_json(
                "The state 'search' cannot be used with object_type or object_name parameters"
            )
    else:
        module.fail_json(f"The state '{state}' is not supported")


def main():
    """Main"""
    argument_spec = infinibox_argument_spec()

    argument_spec.update(
        {
            "object_type": {
                "required": False,
                "default": None,
                "choices": [
                    "cluster",
                    "fs",
                    "fs-snap",
                    "host",
                    "pool",
                    "system",
                    "vol",
                    "vol-snap",
                    None,
                ],
            },
            "object_name": {"required": False, "default": None},
            "key": {"required": False, "default": None},
            "value": {"required": False, "default": None, "no_log": True},
            "state": {
                "required": True,
                "choices": ["stat", "present", "absent", "search"],
            },
        }
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    check_options(module)
    execute_state(module)


if __name__ == "__main__":
    main()
