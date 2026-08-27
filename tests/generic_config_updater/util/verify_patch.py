"""Helpers for checking that an applied GCU patch produced the intended configuration.

The add-cluster tests build a patch by diffing a "with neighbor" configuration
against a "without neighbor" configuration, then apply that patch to a device that
is currently in the "without" state.

The meaningful check afterwards is not that the touched entries merely exist, but
that they match the configuration the device had when the neighbor was present.
A patch that adds a neighbor with the wrong speed, wrong MTU, wrong BGP AS, or a
missing PORTCHANNEL_INTERFACE will happily satisfy an existence check.
"""

import logging

logger = logging.getLogger(__name__)


def patch_cable_length_ports(patch_data):
    """Extract the ports a patch sets a cable length for.

    CABLE_LENGTH is shaped differently from every other table: "CABLE_LENGTH|AZURE"
    is a single CONFIG_DB hash whose *fields* are port names, rather than one entry
    per port. So a patch can express the same change two ways:

        /CABLE_LENGTH/AZURE/Ethernet316   -> "500m"          (one port)
        /CABLE_LENGTH/AZURE               -> {"Ethernet316": "500m", ...}  (whole hash)

    patch_touched_entries() deliberately stops at the entry level and reports only
    "AZURE", which is the right CONFIG_DB key to verify but says nothing about which
    ports were covered. This walks the paths to recover that.

    Args:
        patch_data: List of RFC 6902 operations

    Returns:
        dict: {port_name: cable_length_value}. The value is None when the patch
            removes the port's cable length.
    """
    cable_lengths = {}

    for entry in patch_data:
        path = entry.get('path', '')
        parts = [p for p in path.split('/') if p]
        # Tolerate a leading single-ASIC 'localhost' wrapper, matching verify_patch.
        if parts and parts[0] == 'localhost':
            parts = parts[1:]
        if len(parts) < 2 or parts[0] != 'CABLE_LENGTH':
            continue

        if len(parts) >= 3:
            # Per-port field: /CABLE_LENGTH/<profile>/<port>
            port = unescape_json_pointer(parts[2])
            cable_lengths[port] = entry.get('value') if entry.get('op') != 'remove' else None
        elif isinstance(entry.get('value'), dict):
            # Whole hash: /CABLE_LENGTH/<profile>
            for port, length in entry['value'].items():
                cable_lengths[port] = length

    return cable_lengths


def unescape_json_pointer(token):
    """Decode a JSON pointer reference token (RFC 6901).

    '~1' decodes to '/' and '~0' to '~'. Order matters: decoding '~0' first would
    turn '~01' into '~1' and then into '/', instead of the correct '~1'.
    """
    return token.replace('~1', '/').replace('~0', '~')


def normalize_config(config):
    """Return the flat "table -> key -> fields" mapping for a config_db document.

    Single-ASIC dumps are already flat, but some dumps wrap the tables in a
    namespace key such as 'localhost' or ''. Unwrap those so callers see one shape.
    """
    if not isinstance(config, dict):
        return {}

    for namespace in ('localhost', ''):
        section = config.get(namespace)
        if isinstance(section, dict) and any(name.isupper() for name in section):
            return section

    return config


def patch_touched_entries(patch_data):
    """Map table name -> set of entry keys that the patch modifies.

    Only the first two path segments matter. Deeper segments address fields inside
    an entry, and the entry is compared as a whole regardless. That is deliberate:
    an append to /ACL_TABLE/EVERFLOW/ports/- should still be checked against the
    complete expected ACL_TABLE entry, so that a patch which clobbers 'type' or
    drops a pre-existing binding is caught.

    A leading 'localhost' namespace segment is skipped. 'localhost' is matched by
    name rather than guessed at, because guessing from capitalisation would
    misclassify any table that is not spelled in upper case.
    """
    touched = {}
    for operation in patch_data:
        segments = [s for s in operation.get('path', '').split('/') if s != '']
        if segments and segments[0] == 'localhost':
            segments = segments[1:]
        if len(segments) < 2:
            continue
        table = unescape_json_pointer(segments[0])
        key = unescape_json_pointer(segments[1])
        touched.setdefault(table, set()).add(key)

    return touched


def compare_touched_entries(baseline_config, actual_config, patch_data, ignore_fields=None):
    """Compare every entry the patch touched against the baseline configuration.

    Args:
        baseline_config: Known-good configuration, captured while the neighbor was present
        actual_config: Configuration read back after applying the patch
        patch_data: The applied patch, as a list of RFC 6902 operations
        ignore_fields: Field names to skip, for values that legitimately vary

    Returns:
        list: Human readable descriptions of each difference. Empty means the applied
            configuration matches the baseline for everything the patch claimed to change.
    """
    ignored = set(ignore_fields or ())
    baseline = normalize_config(baseline_config)
    actual = normalize_config(actual_config)

    differences = []
    for table, keys in sorted(patch_touched_entries(patch_data).items()):
        baseline_table = baseline.get(table, {})
        actual_table = actual.get(table, {})

        for key in sorted(keys):
            if key not in baseline_table:
                # The patch adds something the baseline never had. That points at patch
                # generation rather than at the applied result.
                differences.append(
                    "{}|{}: touched by the patch but absent from the baseline "
                    "configuration".format(table, key))
                continue

            if key not in actual_table:
                differences.append("{}|{}: missing after the patch was applied".format(table, key))
                continue

            expected = baseline_table[key]
            got = actual_table[key]

            if not isinstance(expected, dict) or not isinstance(got, dict):
                if expected != got:
                    differences.append("{}|{}: expected {!r}, got {!r}".format(table, key, expected, got))
                continue

            for field in sorted(set(expected) | set(got)):
                if field in ignored:
                    continue
                if expected.get(field) != got.get(field):
                    differences.append(
                        "{}|{} field '{}': expected {!r}, got {!r}".format(
                            table, key, field, expected.get(field), got.get(field)))

    return differences
