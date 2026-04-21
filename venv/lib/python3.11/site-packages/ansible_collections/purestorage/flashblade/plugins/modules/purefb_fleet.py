#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025, Simon Dodsley (simon@purestorage.com)
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
module: purefb_fleet
version_added: '1.20.0'
short_description: Manage Fusion Fleet
description:
- Create/Modify/Delete Fusion fleet and members
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the fleet.
    - If not provided local array will be used.
    type: str
  state:
    description:
    - Define whether to add or remove member from a fleet.
    - Create a new fleet if one does not exist.
      This will use the current array as the first member.
    - Fleet deletion can only occiur when the current array
      is the only fleet member.
    default: present
    choices: [ absent, present, create ]
    type: str
  member_url:
    description:
    - Management IP address/FQDN of array to add to fleet.
    type: str
  member_api:
    description:
    - API token for target array
    type: str
  rename:
    description:
    - new name for fleet
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a new fleet
  purestorage.flashblade.purefb_fleet:
    name: foo
    state: create
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Add a member to fleet foo
  purestorage.flashblade.purefb_fleet:
    name: foo
    member_url: array2
    member_api: c6033033-fe69-2515-a9e8-966bb7fe4b40
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete a member from fleet foo
  purestorage.flashblade.purefb_fleet:
    name: foo
    member_url: array2
    member_api: c6033033-fe69-2515-a9e8-966bb7fe4b40
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete fleet foo
  purestorage.flashblade.purefb_fleet:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""

HAS_URLLIB3 = True
try:
    import urllib3
except ImportError:
    HAS_URLLIB3 = False

HAS_DISTRO = True
try:
    import distro
except ImportError:
    HAS_DISTRO = False

HAS_PURESTORAGE = True
try:
    from pypureclient import flashblade
    from pypureclient import flasharray
    from pypureclient.flashblade import (
        FleetMemberPost,
        FleetmemberpostMember,
        FleetmemberpostMembers,
        FleetPatch,
    )
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)
from ansible_collections.purestorage.flashblade.plugins.module_utils.version import (
    LooseVersion,
)
import platform

VERSION = 1.5
USER_AGENT_BASE = "Ansible"
MIN_REQUIRED_API_VERSION = "2.17"
MIN_FA_VERSION = "2.42"


def create_fleet(module, blade):
    """Create new fleet - only ever called once per fleet"""
    changed = True
    if not module.check_mode:
        res = blade.post_fleets(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create fleet {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_fleet(module, blade):
    """Delete the fleet.

    Only works when the current array is the only remaining
    memebr of the fleet'
    """
    changed = True
    res = blade.delete_fleets(names=[module.params["name"]])
    if res.status_code != 200:
        module.fail_json(
            msg="Fleet {0} deletion failed. Error: {1}".format(
                module.params["name"], res.errors[0].message
            )
        )
    module.exit_json(changed=changed)


def add_fleet_members(module, blade):
    """Add new member to the fleet"""
    changed = False
    existing = False
    if not module.params["member_url"] and not module.params["member_api"]:
        module.fail_json(msg="missing required arguments: member_api, member_url")
    res = blade.post_fleets_fleet_key()
    if res.status_code != 200:
        module.fail_json(
            msg="Fleet key generation failed. Error: {0}".format(res.errors[0].message)
        )
    fleet_key = list(res.items)[0].fleet_key
    if HAS_URLLIB3 and module.params["disable_warnings"]:
        urllib3.disable_warnings()
    if HAS_DISTRO:
        user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": distro.name(pretty=True),
        }
    else:
        user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": platform.platform(),
        }
    # FlashBlade API tokens start with "T-" so use that to differentiate
    # fleet member platform type
    if "T-" in module.params["member_api"]:
        remote_system = flashblade.Client(
            target=module.params["member_url"],
            api_token=module.params["member_api"],
            user_agent=user_agent,
        )
    else:
        remote_system = flasharray.Client(
            target=module.params["member_url"],
            api_token=module.params["member_api"],
            user_agent=user_agent,
        )
        remote_api = remote_system.get_rest_version()
        if LooseVersion(MIN_FA_VERSION) > LooseVersion(remote_api):
            module.fail_json(
                msg="FlashArray must be a minimum of Purity//FA 6.8.5"
                " to join a fleet containing FlashBlades"
            )
    local_name = list(remote_system.get_arrays().items)[0].name
    members = list(blade.get_fleets_members().items)
    for member in range(len(members)):
        if members[member].member.name == local_name:
            existing = True
    if not existing:
        changed = True
        if not module.check_mode:
            res = remote_system.post_fleets_members(
                fleet_names=[module.params["name"]],
                members=FleetMemberPost(
                    members=[
                        FleetmemberpostMembers(
                            key=fleet_key,
                            member=FleetmemberpostMember(
                                name=local_name, resource_type="remote-arrays"
                            ),
                        )
                    ]
                ),
            )
            if res.status_code != 200:
                module.fail_json(
                    "Array {0} failed to join fleet {1}. Error: {2}".format(
                        local_name, module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def delete_fleet_members(module, blade):
    """Delete member from a fleet"""
    changed = False
    if HAS_URLLIB3 and module.params["disable_warnings"]:
        urllib3.disable_warnings()
    if HAS_DISTRO:
        user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": distro.name(pretty=True),
        }
    else:
        user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": platform.platform(),
        }
    # FlashBlade API tokens start with "T-" so use that to differentiate
    # fleet member platform type
    if "T-" in module.params["member_api"]:
        remote_system = flashblade.Client(
            target=module.params["member_url"],
            api_token=module.params["member_api"],
            user_agent=user_agent,
        )
    else:
        remote_system = flasharray.Client(
            target=module.params["member_url"],
            api_token=module.params["member_api"],
            user_agent=user_agent,
        )
    local_name = list(remote_system.get_arrays().items)[0].name
    members = list(blade.get_fleets_members().items)
    for member in range(len(members)):
        if members[member].member.name == local_name:
            changed = True
            if not module.check_mode:
                if members[member].status not in [
                    "joined",
                    "connected",
                    "partially connected",
                ]:
                    res = blade.delete_fleets_members(
                        member_names=[local_name], unreachable=True
                    )
                else:
                    res = blade.delete_fleets_members(member_names=[local_name])
                if res.status_code != 200:
                    module.fail_json(
                        "Array {0} failed to be removed from fleet. Error: {1}".format(
                            module.params["member_url"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def rename_fleet(module, blade):
    """Rename the fleet"""
    changed = False
    fleet = list(blade.get_fleets().items)[0].name
    if module.params["rename"] != fleet:
        changed = True
        if not module.check_mode:
            res = blade.patch_fleets(
                names=[module.params["name"]],
                fleet=FleetPatch(name=module.params["rename"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Fleet rename failed. Error: {0}".format(res.errors[0].message)
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str"),
            state=dict(
                type="str", default="present", choices=["absent", "present", "create"]
            ),
            member_url=dict(type="str"),
            member_api=dict(type="str"),
            rename=dict(type="str"),
        )
    )

    required_together = [["member_url", "member_api"]]

    module = AnsibleModule(
        argument_spec, required_together=required_together, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashBlade REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]
    fleet = True
    fleet_res = blade.get_fleets()
    if fleet_res.status_code == 404:
        module.fail_json(
            msg="Fusion is not enabled on this system. "
            "Please speak to Pure Support to enable this feature"
        )
    else:
        if not list(fleet_res.items):
            fleet = False

    if state == "create" and not fleet:
        create_fleet(module, blade)
    elif state == "present" and module.params["rename"]:
        rename_fleet(module, blade)
    elif state == "present" and fleet:
        add_fleet_members(module, blade)
    elif state == "absent" and fleet and module.params["member_url"]:
        delete_fleet_members(module, blade)
    elif state == "absent" and fleet:
        delete_fleet(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
