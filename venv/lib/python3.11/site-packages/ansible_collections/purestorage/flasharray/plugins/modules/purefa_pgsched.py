#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefa_pgsched
short_description: Manage protection groups replication schedules on Pure Storage FlashArrays
version_added: '1.0.0'
description:
- Modify or delete protection groups replication schedules on Pure Storage FlashArrays.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the protection group.
    type: str
    required: true
  state:
    description:
    - Define whether to set or delete the protection group schedule.
    type: str
    default: present
    choices: [ absent, present ]
  schedule:
    description:
    - Which schedule to change.
    type: str
    choices: ['replication', 'snapshot']
    required: true
  enabled:
    description:
    - Enable the schedule being configured.
    type: bool
    default: true
  replicate_at:
    description:
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    - Only valid if I(replicate_frequency) is an exact multiple of 86400, ie 1 day.
    type: str
  blackout_start:
    description:
    - Specifies the time at which to suspend replication.
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    type: str
  blackout_end:
    description:
    - Specifies the time at which to restart replication.
    - Provide a time in 12-hour AM/PM format, eg. 5PM
    type: str
  replicate_frequency:
    description:
    - Specifies the replication frequency in seconds.
    - Range 900 - 34560000 (FA-405, //M10, //X10 and Cloud Block Store).
    - Range 300 - 34560000 (all other arrays).
    type: int
  snap_at:
    description:
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    - Only valid if I(snap_frequency) is an exact multiple of 86400, ie 1 day.
    type: str
  snap_frequency:
    description:
    - Specifies the snapshot frequency in seconds.
    - Range available 300 - 34560000.
    type: int
  days:
    description:
    - Specifies the number of days to keep the I(per_day) snapshots beyond the
      I(all_for) period before they are eradicated
    - Max retention period is 4000 days
    type: int
  all_for:
    description:
    - Specifies the length of time, in seconds, to keep the snapshots on the
      source array before they are eradicated.
    - Range available 1 - 34560000.
    type: int
  per_day:
    description:
    - Specifies the number of I(per_day) snapshots to keep beyond the I(all_for) period.
    - Maximum number is 1440
    type: int
  target_all_for:
    description:
    - Specifies the length of time, in seconds, to keep the replicated snapshots on the targets.
    - Range is 1 - 34560000 seconds.
    type: int
  target_per_day:
    description:
    - Specifies the number of I(per_day) replicated snapshots to keep beyond the I(target_all_for) period.
    - Maximum number is 1440
    type: int
  target_days:
    description:
    - Specifies the number of days to keep the I(target_per_day) replicated snapshots
      beyond the I(target_all_for) period before they are eradicated.
    - Max retention period is 4000 days
    type: int
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.33.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Update protection group snapshot schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: snapshot
    enabled: true
    snap_frequency: 86400
    snap_at: 3PM
    per_day: 5
    all_for: 5
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update protection group replication schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: replication
    enabled: true
    replicate_frequency: 86400
    replicate_at: 3PM
    target_per_day: 5
    target_all_for: 5
    blackout_start: 2AM
    blackout_end: 5AM
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete protection group snapshot schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: snapshot
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete protection group replication schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: replication
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)


HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        ProtectionGroup,
        ReplicationSchedule,
        SnapshotSchedule,
        RetentionPolicy,
        TimeWindow,
    )
except ImportError:
    HAS_PURESTORAGE = False


CONTEXT_API_VERSION = "2.38"


def get_pending_pgroup(module, array):
    """Get Protection Group"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[module.params["name"]],
            destroyed=True,
            context_names=[module.params["name"]],
        )
    else:
        res = array.get_protection_groups(names=[module.params["name"]], destroyed=True)
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_pgroup(module, array):
    """Get Protection Group"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_protection_groups(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def _convert_to_minutes(hour):
    period = hour[-2:].upper()
    hour_value = int(hour[:-2])

    if period == "AM" and hour_value == 12:
        return 0
    if period == "AM":
        return hour_value * 3600
    if period == "PM" and hour_value == 12:
        return 43200
    return (hour_value + 12) * 3600


def update_schedule(module, array, snap_time, repl_time):
    """Update Protection Group Schedule"""
    api_version = array.get_rest_version()
    changed = False
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        schedule = list(
            array.get_protection_groups(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        schedule = list(
            array.get_protection_groups(names=[module.params["name"]]).items
        )[0]
    if not hasattr(schedule.replication_schedule.blackout, "start"):
        schedule.replication_schedule.blackout = TimeWindow(start=0, end=0)
    current_repl = {
        "replicate_frequency": schedule.replication_schedule.frequency,
        "replicate_enabled": schedule.replication_schedule.enabled,
        "target_days": schedule.target_retention.days,
        "replicate_at": getattr(schedule.replication_schedule, "at", None),
        "target_per_day": schedule.target_retention.days,
        "target_all_for": schedule.target_retention.all_for_sec,
        "blackout_start": schedule.replication_schedule.blackout.start,
        "blackout_end": schedule.replication_schedule.blackout.end,
    }
    current_snap = {
        "days": schedule.source_retention.days,
        "snap_frequency": schedule.snapshot_schedule.frequency,
        "snap_enabled": schedule.snapshot_schedule.enabled,
        "snap_at": getattr(schedule.snapshot_schedule, "at", None),
        "per_day": schedule.source_retention.per_day,
        "all_for": schedule.source_retention.all_for_sec,
    }
    if module.params["schedule"] == "snapshot":
        if not module.params["snap_frequency"]:
            snap_frequency = current_snap["snap_frequency"]
        else:
            if not 300 <= module.params["snap_frequency"] <= 34560000:
                module.fail_json(
                    msg="Snap Frequency support is out of range (300 to 34560000)"
                )
            else:
                snap_frequency = module.params["snap_frequency"] * 1000

        if module.params["enabled"] is None:
            snap_enabled = current_snap["snap_enabled"]
        else:
            snap_enabled = module.params["enabled"]

        if not module.params["snap_at"]:
            snap_at = current_snap["snap_at"]
        else:
            snap_at = _convert_to_minutes(module.params["snap_at"].upper())

        if not module.params["days"]:
            if isinstance(module.params["days"], int):
                days = module.params["days"]
            else:
                days = current_snap["days"]
        else:
            if module.params["days"] > 4000:
                module.fail_json(msg="Maximum value for days is 4000")
            else:
                days = module.params["days"]

        if module.params["per_day"] is None:
            per_day = current_snap["per_day"]
        else:
            if module.params["per_day"] > 1440:
                module.fail_json(msg="Maximum value for per_day is 1440")
            else:
                per_day = module.params["per_day"]

        if not module.params["all_for"]:
            all_for = current_snap["all_for"]
        else:
            if module.params["all_for"] > 34560000:
                module.fail_json(msg="Maximum all_for value is 34560000")
            else:
                all_for = module.params["all_for"]
        new_snap = {
            "days": days,
            "snap_frequency": snap_frequency,
            "snap_enabled": snap_enabled,
            "snap_at": snap_at,
            "per_day": per_day,
            "all_for": all_for,
        }
        if current_snap != new_snap:
            changed = True
            if not module.check_mode:
                try:
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            protection_group=ProtectionGroup(
                                snapshot_schedule=SnapshotSchedule(
                                    enabled=new_snap["snap_enabled"],
                                )
                            ),
                        )
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            protection_group=ProtectionGroup(
                                snapshot_schedule=SnapshotSchedule(
                                    frequency=new_snap["snap_frequency"],
                                )
                            ),
                        )
                    else:
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            protection_group=ProtectionGroup(
                                snapshot_schedule=SnapshotSchedule(
                                    enabled=new_snap["snap_enabled"],
                                )
                            ),
                        )
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            protection_group=ProtectionGroup(
                                snapshot_schedule=SnapshotSchedule(
                                    frequency=new_snap["snap_frequency"],
                                )
                            ),
                        )
                    if snap_time:
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                protection_group=ProtectionGroup(
                                    snapshot_schedule=SnapshotSchedule(
                                        at=new_snap["snap_at"],
                                    )
                                ),
                            )
                        else:
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                protection_group=ProtectionGroup(
                                    snapshot_schedule=SnapshotSchedule(
                                        at=new_snap["snap_at"],
                                    )
                                ),
                            )
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            protection_group=ProtectionGroup(
                                source_retention=RetentionPolicy(
                                    all_for_sec=new_snap["all_for"],
                                    per_day=new_snap["per_day"],
                                    days=new_snap["days"],
                                )
                            ),
                        )
                    else:
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            protection_group=ProtectionGroup(
                                source_retention=RetentionPolicy(
                                    all_for_sec=new_snap["all_for"],
                                    per_day=new_snap["per_day"],
                                    days=new_snap["days"],
                                )
                            ),
                        )
                except Exception:
                    module.fail_json(
                        msg="Failed to change snapshot schedule for pgroup {0}.".format(
                            module.params["name"]
                        )
                    )
    else:
        if not module.params["replicate_frequency"]:
            replicate_frequency = current_repl["replicate_frequency"]
        else:
            replicate_frequency = module.params["replicate_frequency"] * 1000

        if module.params["enabled"] is None:
            replicate_enabled = current_repl["replicate_enabled"]
        else:
            replicate_enabled = module.params["enabled"]

        if not module.params["replicate_at"]:
            replicate_at = current_repl["replicate_at"]
        else:
            replicate_at = _convert_to_minutes(module.params["replicate_at"].upper())

        if not module.params["target_days"]:
            if isinstance(module.params["target_days"], int):
                target_days = module.params["target_days"]
            else:
                target_days = current_repl["target_days"]
        else:
            if module.params["target_days"] > 4000:
                module.fail_json(msg="Maximum value for target_days is 4000")
            else:
                target_days = module.params["target_days"]

        if not module.params["target_per_day"]:
            if isinstance(module.params["target_per_day"], int):
                target_per_day = module.params["target_per_day"]
            else:
                target_per_day = current_repl["target_per_day"]
        else:
            if module.params["target_per_day"] > 1440:
                module.fail_json(msg="Maximum value for target_per_day is 1440")
            else:
                target_per_day = module.params["target_per_day"]

        if not module.params["target_all_for"]:
            target_all_for = current_repl["target_all_for"]
        else:
            if module.params["target_all_for"] > 34560000:
                module.fail_json(msg="Maximum target_all_for value is 34560000")
            else:
                target_all_for = module.params["target_all_for"]
        if not module.params["blackout_end"]:
            blackout_end = current_repl["blackout_start"]
        else:
            blackout_end = _convert_to_minutes(module.params["blackout_end"].upper())
        if not module.params["blackout_start"]:
            blackout_start = current_repl["blackout_start"]
        else:
            blackout_start = _convert_to_minutes(
                module.params["blackout_start"].upper()
            )

        new_repl = {
            "replicate_frequency": replicate_frequency,
            "replicate_enabled": replicate_enabled,
            "target_days": target_days,
            "replicate_at": replicate_at,
            "target_per_day": target_per_day,
            "target_all_for": target_all_for,
            "blackout_start": blackout_start,
            "blackout_end": blackout_end,
        }
        if current_repl != new_repl:
            changed = True
            if not module.check_mode:
                try:
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            protection_group=ProtectionGroup(
                                replication_schedule=ReplicationSchedule(
                                    enabled=new_repl["replicate_enabled"],
                                )
                            ),
                        )
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            protection_group=ProtectionGroup(
                                replication_schedule=ReplicationSchedule(
                                    frequency=new_repl["replicate_frequency"],
                                )
                            ),
                        )
                    else:
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            protection_group=ProtectionGroup(
                                replication_schedule=ReplicationSchedule(
                                    enabled=new_repl["replicate_enabled"],
                                )
                            ),
                        )
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            protection_group=ProtectionGroup(
                                replication_schedule=ReplicationSchedule(
                                    frequency=new_repl["replicate_frequency"],
                                )
                            ),
                        )
                    if repl_time:
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                protection_group=ProtectionGroup(
                                    replication_schedule=ReplicationSchedule(
                                        at=new_repl["replicate_at"],
                                    )
                                ),
                            )
                        else:
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                protection_group=ProtectionGroup(
                                    replication_schedule=ReplicationSchedule(
                                        at=new_repl["replicate_at"],
                                    )
                                ),
                            )
                    if blackout_start == 0:
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                protection_group=ProtectionGroup(
                                    replication_schedule=ReplicationSchedule(
                                        blackout=TimeWindow(start=0, end=0)
                                    )
                                ),
                            )
                        else:
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                protection_group=ProtectionGroup(
                                    replication_schedule=ReplicationSchedule(
                                        blackout=TimeWindow(start=0, end=0)
                                    )
                                ),
                            )
                    else:
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                protection_group=ProtectionGroup(
                                    replication_schedule=ReplicationSchedule(
                                        blackout=TimeWindow(
                                            start=new_repl["blackout_start"],
                                            end=new_repl["blackout_end"],
                                        )
                                    )
                                ),
                            )
                        else:
                            array.patch_protection_groups(
                                names=[module.params["name"]],
                                protection_group=ProtectionGroup(
                                    replication_schedule=ReplicationSchedule(
                                        blackout=TimeWindow(
                                            start=new_repl["blackout_start"],
                                            end=new_repl["blackout_end"],
                                        )
                                    )
                                ),
                            )
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            protection_group=ProtectionGroup(
                                target_retention=RetentionPolicy(
                                    all_for_sec=new_repl["target_all_for"],
                                    per_day=new_repl["target_per_day"],
                                    days=new_repl["target_days"],
                                )
                            ),
                        )
                    else:
                        array.patch_protection_groups(
                            names=[module.params["name"]],
                            protection_group=ProtectionGroup(
                                target_retention=RetentionPolicy(
                                    all_for_sec=new_repl["target_all_for"],
                                    per_day=new_repl["target_per_day"],
                                    days=new_repl["target_days"],
                                )
                            ),
                        )
                except Exception:
                    module.fail_json(
                        msg="Failed to change replication schedule for pgroup {0}.".format(
                            module.params["name"]
                        )
                    )

    module.exit_json(changed=changed)


def delete_schedule(module, array):
    """Delete, ie. disable, Protection Group Schedules"""
    api_version = array.get_rest_version()
    changed = False
    res = {"status_code": 200}
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        schedule = list(
            array.get_protection_groups(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        schedule = list(
            array.get_protection_groups(names=[module.params["name"]]).items
        )[0]
    if module.params["schedule"] == "replication":
        if schedule.replication_schedule.enabled:
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                        protection_group=ProtectionGroup(
                            replication_schedule=ReplicationSchedule(
                                blackout=TimeWindow(start=0, end=0),
                                frequency=14400,
                                enabled=False,
                            ),
                        ),
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Resetting pgroup {0} {1} schedule failed. Error: {2}".format(
                                module.params["name"],
                                module.params["schedule"],
                                res.errors[0].message,
                            )
                        )
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                        protection_group=ProtectionGroup(
                            target_retention=RetentionPolicy(
                                all_for_sec=1,
                                per_day=0,
                                days=0,
                            ),
                        ),
                    )
                else:
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(
                            target_retention=RetentionPolicy(
                                all_for_sec=1,
                                per_day=0,
                                days=0,
                            ),
                        ),
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Resetting pgroup {0} {1} schedule failed. Error: {2}".format(
                                module.params["name"],
                                module.params["schedule"],
                                res.errors[0].message,
                            )
                        )
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(
                            replication_schedule=ReplicationSchedule(
                                blackout=TimeWindow(start=0, end=0),
                                frequency=14400,
                                enabled=False,
                            ),
                        ),
                    )
    else:
        if schedule.snapshot_schedule.enabled:
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                        protection_group=ProtectionGroup(
                            snapshot_schedule=SnapshotSchedule(
                                frequency=300, enabled=False
                            ),
                        ),
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Resetting pgroup {0} {1} schedule failed. Error: {2}".format(
                                module.params["name"],
                                module.params["schedule"],
                                res.errors[0].message,
                            )
                        )
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                        protection_group=ProtectionGroup(
                            source_retention=RetentionPolicy(
                                all_for_sec=1,
                                per_day=0,
                                days=0,
                            ),
                        ),
                    )
                else:
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(
                            snapshot_schedule=SnapshotSchedule(
                                frequency=300, enabled=False
                            ),
                        ),
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Resetting pgroup {0} {1} schedule failed. Error: {2}".format(
                                module.params["name"],
                                module.params["schedule"],
                                res.errors[0].message,
                            )
                        )
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(
                            source_retention=RetentionPolicy(
                                all_for_sec=1,
                                per_day=0,
                                days=0,
                            ),
                        ),
                    )
    if res.status_code != 200:
        module.fail_json(
            msg="Deleting pgroup {0} {1} schedule failed. Error: {2}".format(
                module.params["name"], module.params["schedule"], res.errors[0].message
            )
        )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            schedule=dict(
                type="str", required=True, choices=["replication", "snapshot"]
            ),
            blackout_start=dict(type="str"),
            blackout_end=dict(type="str"),
            snap_at=dict(type="str"),
            replicate_at=dict(type="str"),
            replicate_frequency=dict(type="int"),
            snap_frequency=dict(type="int"),
            all_for=dict(type="int"),
            days=dict(type="int"),
            per_day=dict(type="int"),
            target_all_for=dict(type="int"),
            target_per_day=dict(type="int"),
            target_days=dict(type="int"),
            enabled=dict(type="bool", default=True),
            context=dict(type="str", default=""),
        )
    )

    required_together = [["blackout_start", "blackout_end"]]

    module = AnsibleModule(
        argument_spec, required_together=required_together, supports_check_mode=True
    )

    state = module.params["state"]
    array = get_array(module)

    pgroup = get_pgroup(module, array)
    repl_time = False
    if module.params["replicate_at"] and module.params["replicate_frequency"]:
        if not module.params["replicate_frequency"] % 86400 == 0:
            module.fail_json(
                msg="replicate_at not valid unless replicate frequency is measured in days, ie. a multiple of 86400"
            )
        repl_time = True
    snap_time = False
    if module.params["snap_at"] and module.params["snap_frequency"]:
        if not module.params["snap_frequency"] % 86400 == 0:
            module.fail_json(
                msg="snap_at not valid unless snapshot frequency is measured in days, ie. a multiple of 86400"
            )
        snap_time = True
    if pgroup and state == "present":
        update_schedule(module, array, snap_time, repl_time)
    elif pgroup and state == "absent":
        delete_schedule(module, array)
    elif pgroup is None:
        module.fail_json(
            msg="Specified protection group {0} does not exist.".format(
                module.params["name"]
            )
        )


if __name__ == "__main__":
    main()
