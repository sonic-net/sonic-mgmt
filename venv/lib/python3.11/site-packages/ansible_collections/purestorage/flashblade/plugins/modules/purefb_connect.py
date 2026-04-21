#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_connect
version_added: '1.0.0'
short_description: Manage replication connections between two FlashBlades
description:
- Manage replication connections to specified remote FlashBlade system
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete replication connection
    default: present
    type: str
    choices: [ absent, present ]
  encrypted:
    description:
    - Define if replication connection is encrypted
    type: bool
    default: false
  target_url:
    description:
    - Management IP address of target FlashBlade system
    type: str
    required: true
  target_api:
    description:
    - API token for target FlashBlade system
    type: str
  target_repl:
    description:
    - Replication IP address of target FlashBlade system
    - If not set at time of connection creation, will default to
      all the replication addresses available on the target array
      at the time of connection creation.
    type: list
    elements: str
    version_added: "1.9.0"
  default_limit:
    description:
    - Default maximum bandwidth threshold for outbound traffic in bytes.
    - B, K, M, or G units. See examples.
    - Must be 0 or between 5MB and 28GB
    - Once exceeded, bandwidth throttling occurs
    type: str
    version_added: "1.9.0"
  window_limit:
    description:
    - Maximum bandwidth threshold for outbound traffic during the specified
      time range in bytes.
    - B, K, M, or G units. See examples.
    - Must be 0 or between 5MB and 28GB
    - Once exceeded, bandwidth throttling occurs
    type: str
    version_added: "1.9.0"
  window_start:
    description:
    - The window start time.
    - The time must be set to the hour.
    type: str
    version_added: "1.9.0"
  window_end:
    description:
    - The window end time.
    - The time must be set to the hour.
    type: str
    version_added: "1.9.0"
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: "1.22.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a connection to remote FlashBlade system
  purestorage.flashblade.purefb_connect:
    target_url: 10.10.10.20
    target_api: T-b3275b1c-8958-4190-9052-eb46b0bd09f8
    fb_url: 10.10.10.2
    api_token: T-91528421-fe42-47ee-bcb1-47eefb0a9220
- name: Create a connection to remote FlashBlade system with bandwidth limits
  purestorage.flashblade.purefb_connect:
    target_url: 10.10.10.20
    target_api: T-b3275b1c-8958-4190-9052-eb46b0bd09f8
    window_limit: 28G
    window_start: 1AM
    window_end: 7AM
    default_limit: 5M
    fb_url: 10.10.10.2
    api_token: T-91528421-fe42-47ee-bcb1-47eefb0a9220
- name: Delete connection to target FlashBlade system
  purestorage.flashblade.purefb_connect:
    state: absent
    target_url: 10.10.10.20
    target_api: T-b3275b1c-8958-4190-9052-eb46b0bd09f8
    fb_url: 10.10.10.2
    api_token: T-91528421-fe42-47ee-bcb1-47eefb0a9220
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        Client,
        ArrayConnectionPost,
        TimeWindow,
        Throttle,
    )
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule, human_to_bytes
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


CONTEXT_API_VERSION = "2.17"
FAN_IN_MAXIMUM = 5
FAN_OUT_MAXIMUM = 5


def _convert_to_millisecs(hour_str: str) -> int:
    """Convert a 12-hour formatted time string (e.g., '02AM', '12PM') to milliseconds since midnight."""
    time_part = int(hour_str[:-2])
    period = hour_str[-2:]

    if period == "AM":
        return 0 if time_part == 12 else time_part * 3600000
    # PM
    return 12 * 3600000 if time_part == 12 else (time_part + 12) * 3600000


def _check_connected(module, blade):
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        connected_blades = list(
            blade.get_array_connections(context_names=[module.params["context"]]).items
        )
    else:
        connected_blades = list(blade.get_array_connections().items)
    for target in range(len(connected_blades)):
        if connected_blades[target].management_address is None:
            remote_system = Client(
                target=module.params["target_url"],
                api_token=module.params["target_api"],
            )
            res = remote_system.get_arrays()
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to connect to remote array {0}.".format(
                        module.params["target_url"]
                    )
                )
            remote_array = list(res.items)[0].name
            if connected_blades[target].remote.name == remote_array:
                return connected_blades[target]
        if connected_blades[target].management_address == module.params[
            "target_url"
        ] and connected_blades[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_blades[target]
    return None


def break_connection(module, blade, target_blade):
    """Break connection between arrays"""
    api_version = list(blade.get_versions().items)
    changed = True
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            source_blade = (
                blade.get_arrays(context_names=[module.params["context"]]).items[0].name
            )
        else:
            source_blade = blade.get_arrays().items[0].name
        if target_blade.management_address is None:
            module.fail_json(
                msg="Disconnect can only happen from the array that formed the connection"
            )
        if CONTEXT_API_VERSION in api_version:
            res = blade.delete_array_connections(
                remote_names=[target_blade.remote.name],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.delete_array_connections(
                remote_names=[target_blade.remote.name]
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to disconnect {0} from {1}. Error: {2}".format(
                    target_blade.remote.name, source_blade, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_connection(module, blade):
    """Create connection between REST 2 capable arrays"""
    api_version = list(blade.get_versions().items)
    changed = True
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_array_connections(context_names=[module.params["context"]])
    else:
        res = blade.get_array_connections()
    if res.total_item_count >= FAN_OUT_MAXIMUM:
        module.fail_json(
            msg="FlashBlade fan-out maximum of {0} already reached".format(
                FAN_OUT_MAXIMUM
            )
        )
    try:
        remote_system = Client(
            target=module.params["target_url"], api_token=module.params["target_api"]
        )
    except Exception:
        module.fail_json(
            msg="Failed to connect to remote array {0}.".format(
                module.params["target_url"]
            )
        )
    remote_array = list(remote_system.get_arrays().items)[0].name
    remote_conn_cnt = remote_system.get_array_connections().total_item_count
    if remote_conn_cnt >= FAN_IN_MAXIMUM:
        module.fail_json(
            msg="Remote array {0} already connected to {1} other array. Fan-In not supported".format(
                remote_array, remote_conn_cnt
            )
        )
    connection_key = list(remote_system.post_array_connections_connection_key().items)[
        0
    ].connection_key

    if module.params["default_limit"] or module.params["window_limit"]:
        if module.params["window_limit"]:
            if not module.params["window_start"]:
                module.params["window_start"] = "12AM"
            if not module.params["window_end"]:
                module.params["window_end"] = "12AM"
            window = TimeWindow(
                start=_convert_to_millisecs(module.params["window_start"]),
                end=_convert_to_millisecs(module.params["window_end"]),
            )
        if module.params["window_limit"] and module.params["default_limit"]:
            throttle = Throttle(
                default_limit=human_to_bytes(module.params["default_limit"]),
                window_limit=human_to_bytes(module.params["window_limit"]),
                window=window,
            )
        elif module.params["window_limit"] and not module.params["default_limit"]:
            throttle = Throttle(
                window_limit=human_to_bytes(module.params["window_limit"]),
                window=window,
            )
        else:
            throttle = Throttle(
                default_limit=human_to_bytes(module.params["default_limit"]),
            )
        connection_info = ArrayConnectionPost(
            management_address=module.params["target_url"],
            replication_addresses=module.params["target_repl"],
            encrypted=module.params["encrypted"],
            connection_key=connection_key,
            throttle=throttle,
        )
    else:
        connection_info = ArrayConnectionPost(
            management_address=module.params["target_url"],
            replication_addresses=module.params["target_repl"],
            encrypted=module.params["encrypted"],
            connection_key=connection_key,
        )
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_array_connections(
                array_connection=connection_info,
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_array_connections(array_connection=connection_info)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to connect to remote array {0}. Error: {1}".format(
                    remote_array, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_connection(module, blade):
    """Update REST 2 based array connection"""
    changed = False
    api_version = list(blade.get_versions().items)
    remote_blade = Client(
        target=module.params["target_url"], api_token=module.params["target_api"]
    )
    remote_name = list(remote_blade.get_arrays().items)[0].name
    remote_connection = list(
        blade.get_array_connections(filter="remote.name='" + remote_name + "'").items
    )[0]
    if remote_connection.management_address is None:
        module.fail_json(
            msg="Update can only happen from the array that formed the connection"
        )
    if module.params["encrypted"] != remote_connection.encrypted:
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_file_system_replica_links(
                context_names=[module.params["context"]]
            )
        else:
            res = blade.get_file_system_replica_links()
        if module.params["encrypted"] and res.total_item_count != 0:
            module.fail_json(
                msg="Cannot turn array connection encryption on if file system replica links exist"
            )
    current_connection = {
        "encrypted": remote_connection.encrypted,
        "replication_addresses": sorted(remote_connection.replication_addresses),
        "throttle": [],
    }
    if (
        not remote_connection.throttle.default_limit
        and not remote_connection.throttle.window_limit
    ):
        if CONTEXT_API_VERSION in api_version:
            blade.get_bucket_replica_links(context_names=[module.params["context"]])
        else:
            blade.get_bucket_replica_links()
        if (
            module.params["default_limit"] or module.params["window_limit"]
        ) and res.total_item_count != 0:
            module.fail_json(
                msg="Cannot set throttle when bucket replica links already exist"
            )
    current_connection["throttle"] = {
        "default_limit": remote_connection.throttle.default_limit,
        "window_limit": remote_connection.throttle.window_limit,
        "start": remote_connection.throttle.window.start,
        "end": remote_connection.throttle.window.end,
    }
    if module.params["encrypted"]:
        encryption = module.params["encrypted"]
    else:
        encryption = remote_connection.encrypted
    if module.params["target_repl"]:
        target_repl = sorted(module.params["target_repl"])
    else:
        target_repl = remote_connection.replication_addresses
    if module.params["default_limit"]:
        default_limit = human_to_bytes(module.params["default_limit"])
        if default_limit == 0:
            default_limit = None
    else:
        default_limit = remote_connection.throttle.default_limit
    if module.params["window_limit"]:
        window_limit = human_to_bytes(module.params["window_limit"])
    else:
        window_limit = remote_connection.throttle.window_limit
    if module.params["window_start"]:
        start = _convert_to_millisecs(module.params["window_start"])
    else:
        start = remote_connection.throttle.window.start
    if module.params["window_end"]:
        end = _convert_to_millisecs(module.params["window_end"])
    else:
        end = remote_connection.throttle.window.end

    new_connection = {
        "encrypted": encryption,
        "replication_addresses": target_repl,
        "throttle": [],
    }
    new_connection["throttle"] = {
        "default_limit": default_limit,
        "window_limit": window_limit,
        "start": start,
        "end": end,
    }
    if new_connection != current_connection:
        changed = True
        if not module.check_mode:
            window = TimeWindow(
                start=new_connection["throttle"]["start"],
                end=new_connection["throttle"]["end"],
            )
            throttle = Throttle(
                default_limit=new_connection["throttle"]["default_limit"],
                window_limit=new_connection["throttle"]["window_limit"],
                window=window,
            )
            connection_info = ArrayConnectionPost(
                replication_addresses=new_connection["replication_addresses"],
                encrypted=new_connection["encrypted"],
                throttle=throttle,
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_array_connections(
                    remote_names=[remote_name],
                    array_connection=connection_info,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_array_connections(
                    remote_names=[remote_name], array_connection=connection_info
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update connection to remote array {0}. Error: {1}".format(
                        remote_name, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            encrypted=dict(type="bool", default=False),
            target_url=dict(type="str", required=True),
            target_api=dict(type="str", no_log=True),
            target_repl=dict(type="list", elements="str"),
            default_limit=dict(type="str"),
            window_limit=dict(type="str"),
            window_start=dict(type="str"),
            window_end=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    required_if = [("state", "present", ["target_api"])]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)

    if module.params["default_limit"]:
        if (
            human_to_bytes(module.params["default_limit"]) != 0
            and 5242880 >= human_to_bytes(module.params["default_limit"]) >= 30064771072
        ):
            module.fail_json(msg="Default Bandwidth must be between 5MB and 28GB")
    if module.params["window_limit"]:
        if (
            human_to_bytes(module.params["window_limit"]) != 0
            and 5242880 >= human_to_bytes(module.params["window_limit"]) >= 30064771072
        ):
            module.fail_json(msg="Window Bandwidth must be between 5MB and 28GB")

    target_blade = _check_connected(module, blade)
    if state == "present" and not target_blade:
        create_connection(module, blade)
    elif state == "present" and target_blade:
        update_connection(module, blade)
    elif state == "absent" and target_blade:
        break_connection(module, blade, target_blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
