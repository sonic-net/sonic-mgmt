#!/usr/bin/python
# Configure OCS cross-connects on an L1 (FanoutL1Sonic) switch using the OCS CLI,
# instead of building a JSON patch and reloading the config.
#
# All of the parsing and set math is implemented in Python here so the playbook task is
# a single, declarative module invocation.
#
# Algorithm (mirrors templates/config_patch/l1/ocs_xconnect.json.j2 for the desired set):
#   1. Read the current configured cross-connects ("show ocs cross-connect config")
#      and the live hardware status ("show ocs cross-connect status").
#   2. Compute the desired cross-connects from the cross_connects mapping. Each
#      (a, b) entry maps to two directed cross-connects: {a}A-{b}B and {b}A-{a}B.
#   3. Clear "stale" cross-connects that exist in hardware status but not in config
#      and that block a desired port. A status-only entry cannot be deleted directly,
#      so it is cleared by an add-then-delete sequence.
#   4. Remove current cross-connects that conflict (occupy an A or B side a still
#      missing desired cross-connect needs) so the new ones can be added.
#   5. Add the desired cross-connects that are not already present.
#   6. Optionally verify the operational status ("show ocs cross-connect status")
#      reports "tuned" on both sides for every desired cross-connect.
#
# The operation is idempotent: when every desired A-B connection already exists the
# add/remove/clear lists are all empty and nothing is changed.

import re
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: ocs_cross_connect
version_added: "1.0"
short_description: Configure OCS cross-connects on an L1 (FanoutL1Sonic) switch via live CLI.
description:
    - Configure the OCS cross-connects on an L1 switch to match a desired mapping using
      the "config ocs cross-connect" CLI, instead of building a JSON patch and reloading.
    - The OCS CLI persists changes automatically, so no "config save" is required.
    - The operation is idempotent. When every desired cross-connect already exists nothing
      is changed.
options:
    cross_connects:
        description:
            - Mapping of bare A-side port number to bare B-side port number for this device,
              e.g. device_l1_cross_connects[inventory_hostname].
                        - Each (a, b) entry expands to two directed cross-connects {a}A-{b}B and {b}A-{a}B.
        required: True
        type: dict
    clear_stale:
        description: Clear status-only entries that block a desired port via add-then-delete.
        required: False
        type: bool
        default: True
    verify:
        description: Verify status is "tuned" on both sides for every desired cross-connect.
        required: False
        type: bool
        default: True
    verify_retries:
        description: Number of times to poll the status table while verifying.
        required: False
        type: int
        default: 12
    verify_delay:
        description: Seconds to wait between status polls while verifying.
        required: False
        type: int
        default: 5
notes:
    - Run with become so the "config ocs cross-connect" commands have the required privileges.
    - Supports check mode, in which the planned changes are computed and returned but not applied.
'''

EXAMPLES = r'''
- name: deploy L1 OCS cross-connects via live CLI
  become: true
  ocs_cross_connect:
    cross_connects: "{{ device_l1_cross_connects[inventory_hostname] | default({}) }}"
    clear_stale: true
    verify: true
  register: ocs_reconcile
'''

RETURN = r'''
added:
    description: Ids of cross-connects that were (or would be, in check mode) added.
    returned: always
    type: list
removed:
    description: Ids of conflicting cross-connects that were (or would be) removed.
    returned: always
    type: list
cleared_stale:
    description: Ids of stale status-only cross-connects that were (or would be) cleared.
    returned: always
    type: list
desired:
    description: Ids of all desired cross-connects.
    returned: always
    type: list
'''

# A cross-connect id looks like "<num>A-<num>B", e.g. "29A-1B".
XCONN_ID_RE = re.compile(r'^[0-9]+[AB]-[0-9]+[AB]$')
NUMERIC_PORT_RE = re.compile(r'^[0-9]+$')
SHOW_CONFIG_CMD = 'show ocs cross-connect config'
SHOW_STATUS_CMD = 'show ocs cross-connect status'
ADD_CMD_TMPL = 'config ocs cross-connect add {id} update'
DEL_CMD_TMPL = 'config ocs cross-connect delete {id}'


def build_desired(cross_connects):
    """Expand the bare a->b mapping into the list of directed cross-connects.

    Each (a, b) entry yields {a}A-{b}B and {b}A-{a}B.
    """
    desired = []
    for a, b in cross_connects.items():
        a = str(a)
        b = str(b)
        desired.append({'id': '{}A-{}B'.format(a, b), 'a_side': '{}A'.format(a), 'b_side': '{}B'.format(b)})
        desired.append({'id': '{}A-{}B'.format(b, a), 'a_side': '{}A'.format(b), 'b_side': '{}B'.format(a)})
    return desired


def get_invalid_desired_ids(desired):
    """Return derived desired IDs that do not match the expected xconn format."""
    return [x['id'] for x in desired if not XCONN_ID_RE.match(x['id'])]


def get_invalid_cross_connect_pairs(cross_connects):
    """Return (a, b) entries whose ports are not bare numeric values."""
    invalid = []
    for a, b in cross_connects.items():
        sa = str(a)
        sb = str(b)
        if not NUMERIC_PORT_RE.match(sa) or not NUMERIC_PORT_RE.match(sb):
            invalid.append({'a': sa, 'b': sb})
    return invalid


def parse_config(stdout):
    """Parse "show ocs cross-connect config" output.

    Table format: "id  a_side  b_side". Skip the header ("a_side") and separator ("---") rows.
    """
    xconns = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if 'a_side' in line or '---' in line:
            continue
        cols = line.split()
        if len(cols) < 3 or not XCONN_ID_RE.match(cols[0]):
            continue
        xconns.append({'id': cols[0], 'a_side': cols[1], 'b_side': cols[2]})
    return xconns


def parse_status_ids(stdout):
    """Parse the cross-connect ids (first column) from "show ocs cross-connect status".

    Status table format: "id  a_side  b_side  a_side_status  b_side_status".
    """
    ids = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if 'a_side' in line or '---' in line:
            continue
        cols = line.split()
        if not cols or not XCONN_ID_RE.match(cols[0]):
            continue
        ids.append(cols[0])
    return ids


def parse_tuned_ids(stdout):
    """Return the ids whose status row reports "tuned" on both sides."""
    tuned = []
    for line in stdout.splitlines():
        norm = ' '.join(line.split())
        if norm.endswith('tuned tuned'):
            tuned.append(norm.split(' ', 1)[0])
    return tuned


def compute_changes(desired, current, status_ids):
    """Compute the stale-to-clear, conflicts-to-remove and to-add sets.

    Returns (stale_to_clear, to_remove, to_add).
    """
    def _port_num(side):
        return side[:-1] if side and side[-1] in ('A', 'B') else side

    desired_ids = [x['id'] for x in desired]
    current_ids = [x['id'] for x in current]
    desired_port_nums = set([_port_num(x['a_side']) for x in desired] + [_port_num(x['b_side']) for x in desired])

    # Add = desired cross-connects not already present in config. Computed up front so
    # that stale/conflict removals are computed independently from add operations.
    to_add = [x for x in desired if x['id'] not in current_ids]

    # Stale = id present in hardware status but absent from config. Keep only those whose
    # A or B port number blocks a port number a desired connect uses.
    stale_to_clear = []
    for sid in status_ids:
        if sid in current_ids or not XCONN_ID_RE.match(sid):
            continue
        parts = sid.split('-')
        if _port_num(parts[0]) in desired_port_nums or _port_num(parts[1]) in desired_port_nums:
            if sid not in stale_to_clear:
                stale_to_clear.append(sid)

    # Conflict = a currently configured cross-connect that is not a desired pairing but
    # occupies a port number (A side or B side) that a desired cross-connect uses.
    to_remove = []
    seen_remove = set()
    for x in current:
        if x['id'] in desired_ids:
            continue
        if _port_num(x['a_side']) in desired_port_nums or _port_num(x['b_side']) in desired_port_nums:
            if x['id'] not in seen_remove:
                seen_remove.add(x['id'])
                to_remove.append(x)

    return stale_to_clear, to_remove, to_add


def run_or_fail(module, cmd, failed_cmds):
    """Run a command, recording it on non-zero return code."""
    rc, out, err = module.run_command(cmd, use_unsafe_shell=True)
    if rc != 0:
        failed_cmds.append({'cmd': cmd, 'rc': rc, 'stderr': err.strip()})
    return rc, out, err


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cross_connects=dict(required=True, type='dict'),
            clear_stale=dict(required=False, type='bool', default=True),
            verify=dict(required=False, type='bool', default=True),
            verify_retries=dict(required=False, type='int', default=12),
            verify_delay=dict(required=False, type='int', default=5),
        ),
        supports_check_mode=True,
    )
    p = module.params

    invalid_pairs = get_invalid_cross_connect_pairs(p['cross_connects'])
    if invalid_pairs:
        module.fail_json(
            msg="Invalid cross_connects mapping; expected bare numeric ports for both sides.",
            invalid_pairs=invalid_pairs)

    desired = build_desired(p['cross_connects'])
    invalid = get_invalid_desired_ids(desired)
    if invalid:
        module.fail_json(
            msg="Invalid cross-connect mapping; expected bare numeric ports. Invalid id(s): {}".format(invalid),
            invalid=invalid)
    desired_ids = [x['id'] for x in desired]

    # Read current config and live status.
    rc, config_out, err = module.run_command(SHOW_CONFIG_CMD, use_unsafe_shell=True)
    if rc != 0:
        module.fail_json(msg="Failed to read OCS cross-connect config: {}".format(err.strip()))
    rc, status_out, err = module.run_command(SHOW_STATUS_CMD, use_unsafe_shell=True)
    if rc != 0:
        module.fail_json(msg="Failed to read OCS cross-connect status: {}".format(err.strip()))

    current = parse_config(config_out)
    status_ids = parse_status_ids(status_out)

    stale_to_clear, to_remove, to_add = compute_changes(desired, current, status_ids)
    remove_ids = [x['id'] for x in to_remove]
    add_ids = [x['id'] for x in to_add]

    result = dict(
        desired=desired_ids,
        cleared_stale=stale_to_clear,
        removed=remove_ids,
        added=add_ids,
    )

    changed = bool(stale_to_clear or to_remove or to_add)

    if module.check_mode:
        module.exit_json(changed=changed, **result)

    add_tmpl = ADD_CMD_TMPL
    del_tmpl = DEL_CMD_TMPL
    failed_cmds = []

    # A status-only ("stale") entry cannot be deleted directly; adding it to config first
    # lets the subsequent delete clear it from hardware status. Run before removing config
    # conflicts and adding the desired connects so the blocked ports are freed first.
    if p['clear_stale']:
        for xid in stale_to_clear:
            run_or_fail(module, add_tmpl.replace('{id}', xid), failed_cmds)
            run_or_fail(module, del_tmpl.replace('{id}', xid), failed_cmds)

    for xid in remove_ids:
        run_or_fail(module, del_tmpl.replace('{id}', xid), failed_cmds)

    for xid in add_ids:
        run_or_fail(module, add_tmpl.replace('{id}', xid), failed_cmds)

    if failed_cmds:
        module.fail_json(msg="One or more OCS cross-connect commands failed",
                         failed_cmds=failed_cmds, **result)

    # Operational status: a healthy cross-connect reports "tuned" for both status columns.
    # Poll until every desired cross-connect is tuned on both sides.
    if p['verify'] and desired_ids:
        pending = list(desired_ids)
        for attempt in range(p['verify_retries']):
            rc, status_out, err = module.run_command(SHOW_STATUS_CMD, use_unsafe_shell=True)
            tuned = parse_tuned_ids(status_out)
            pending = [d for d in desired_ids if d not in tuned]
            if not pending:
                break
            if attempt < p['verify_retries'] - 1:
                time.sleep(p['verify_delay'])
        if pending:
            module.fail_json(
                msg="OCS cross-connects not tuned after {} retries: {}".format(p['verify_retries'], pending),
                pending=pending, **result)

    module.exit_json(changed=changed, **result)


if __name__ == '__main__':
    main()
