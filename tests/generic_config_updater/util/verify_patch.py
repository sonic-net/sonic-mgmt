"""Helpers for checking that an applied GCU patch produced the intended configuration.

The add-cluster tests build a patch by diffing a "with neighbor" configuration
against a "without neighbor" configuration, then apply that patch to a device that
is currently in the "without" state.

The meaningful check afterwards is not that the touched entries merely exist, but
that they match the configuration the device had when the neighbor was present.
A patch that adds a neighbor with the wrong speed, wrong MTU, wrong BGP AS, or a
missing PORTCHANNEL_INTERFACE will happily satisfy an existence check.
"""

import json
import logging

logger = logging.getLogger(__name__)


def _path_segments(path):
    """Split a JSON pointer into decoded segments, dropping a 'localhost' wrapper."""
    parts = [p for p in path.split('/') if p]
    if parts and parts[0] == 'localhost':
        parts = parts[1:]
    return [unescape_json_pointer(p) for p in parts]


def patch_added_ports(patch_data):
    """Return {port: fields} for the ports a patch adds to the PORT table.

    A patch can add ports three ways, and a check that only understands one of them
    fails open:

        /PORT                    -> {"Ethernet316": {...}, ...}   (whole table)
        /PORT/Ethernet316        -> {"speed": "100000", ...}      (whole entry)
        /PORT/Ethernet316/speed  -> "100000"                      (single field)

    Only 'add' operations count: a patch that merely edits an existing port is not
    introducing a port that needs cable length and neighbor data supplied alongside.
    """
    ports = {}

    for entry in patch_data:
        if entry.get('op') != 'add':
            continue

        parts = _path_segments(entry.get('path', ''))
        if not parts or parts[0] != 'PORT':
            continue

        value = entry.get('value')
        if len(parts) == 1 and isinstance(value, dict):
            for port, fields in value.items():
                ports.setdefault(port, {}).update(fields if isinstance(fields, dict) else {})
        elif len(parts) == 2 and isinstance(value, dict):
            ports.setdefault(parts[1], {}).update(value)
        elif len(parts) >= 3:
            ports.setdefault(parts[1], {})[parts[2]] = value

    return ports


def patch_pushed_lossless_pgs(patch_data, profile_prefix):
    """Return the paths of ops that push auto-generated lossless BUFFER_PG entries.

    Matches on the table segment rather than the substring '/BUFFER_PG/', so a
    whole-table op at '/BUFFER_PG' -- which has no trailing slash -- is still caught.
    """
    pushed = []

    for entry in patch_data:
        parts = _path_segments(entry.get('path', ''))
        if not parts or parts[0] != 'BUFFER_PG':
            continue
        if profile_prefix in json.dumps(entry.get('value', '')):
            pushed.append(entry.get('path'))

    return pushed


def patch_cable_length_ports(patch_data):
    """Extract the ports a patch sets a cable length for.

    CABLE_LENGTH is shaped differently from every other table: "CABLE_LENGTH|AZURE"
    is a single CONFIG_DB hash whose *fields* are port names, rather than one entry
    per port. So a patch can express the same change three ways:

        /CABLE_LENGTH/AZURE/Ethernet316   -> "500m"                       (one port)
        /CABLE_LENGTH/AZURE               -> {"Ethernet316": "500m", ...} (whole hash)
        /CABLE_LENGTH                     -> {"AZURE": {"Ethernet316": "500m"}}

    All three are handled. Recognising only some of them would report a valid patch as
    missing cable lengths, failing the run on a correct configuration.

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
        parts = _path_segments(entry.get('path', ''))
        if not parts or parts[0] != 'CABLE_LENGTH':
            continue

        value = entry.get('value')
        if len(parts) >= 3:
            # Per-port field: /CABLE_LENGTH/<profile>/<port>
            port = parts[2]
            cable_lengths[port] = value if entry.get('op') != 'remove' else None
        elif len(parts) == 2 and isinstance(value, dict):
            # Whole hash: /CABLE_LENGTH/<profile>
            for port, length in value.items():
                cable_lengths[port] = length
        elif len(parts) == 1 and isinstance(value, dict):
            # Whole table: /CABLE_LENGTH -> {<profile>: {<port>: <length>}}
            for ports in value.values():
                if isinstance(ports, dict):
                    for port, length in ports.items():
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


# --- Device readers -------------------------------------------------------------
# These take duthost as a parameter rather than reaching for a global, so the parsing
# they do can be exercised against a stub in the hardware-free tests. The parsing is
# where the risk lives: every one of them turns a shell result into a boolean or a
# lookup, and getting that wrong fails open rather than loudly.


def get_config_db_field(duthost, key, field):
    """Read a single CONFIG_DB field. Returns '' when the key or field is absent."""
    cmd = 'sonic-db-cli CONFIG_DB hget "{}" {}'.format(key, field)
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result['rc'] != 0:
        return ''
    return result['stdout'].strip()


def config_db_key_exists(duthost, key):
    """Check that a CONFIG_DB key exists, without matching on its rendered contents."""
    cmd = 'sonic-db-cli CONFIG_DB keys "{}"'.format(key)
    result = duthost.shell(cmd, module_ignore_errors=True)
    return result['rc'] == 0 and result['stdout'].strip() == key


def normalize_profile_reference(value):
    """Return the bare profile name from a CONFIG_DB buffer profile reference.

    SONiC writes this field two ways depending on version and on whether dynamic
    buffer management is in use:

        pg_lossless_100000_500m_profile
        [BUFFER_PROFILE|pg_lossless_100000_500m_profile]

    Comparing the raw field against a bare name silently fails on the second form,
    which would report a correctly-created lossless PG as missing.
    """
    value = (value or '').strip()
    if value.startswith('[') and value.endswith(']'):
        inner = value[1:-1]
        # Split rather than falling back to the bracketed text: a reference with an
        # empty name must normalise to empty, not to the table name it was qualified by.
        if '|' in inner:
            return inner.split('|', 1)[1]
        return inner
    return value


def expected_lossless_profile_name(speed, cable_length):
    """Build the profile name buffermgrd derives for a given speed and cable length.

    The name encodes both because PFC headroom scales with link speed and with the
    round-trip time of the cable, so 100G over 500m needs different headroom than
    100G over 20km. Mirrors the naming used by the port-speed-change test.
    """
    return 'pg_lossless_{}_{}_profile'.format(speed, cable_length)


def get_lossless_pg_entries(duthost, port, profile_prefix):
    """Return {buffer_pg_key: profile_name} for the port's lossless BUFFER_PG entries.

    These are created by buffermgrd once PORT speed and CABLE_LENGTH are set and the
    port comes up; they are never pushed by the config patch. Lossless PGs are
    identified by profile-name prefix rather than by priority number, so a platform
    that numbers its lossless PGs differently is still handled.
    """
    entries = {}

    keys_result = duthost.shell('sonic-db-cli CONFIG_DB keys "BUFFER_PG|{}|*"'.format(port),
                                module_ignore_errors=True)
    if keys_result['rc'] != 0:
        return entries

    for key in keys_result['stdout'].splitlines():
        key = key.strip()
        if not key:
            continue
        profile = normalize_profile_reference(get_config_db_field(duthost, key, 'profile'))
        if profile.startswith(profile_prefix):
            entries[key] = profile

    return entries


def buffer_profile_exists(duthost, profile_name):
    """Report whether a buffer profile is present in CONFIG_DB and in APPL_DB.

    Present in CONFIG_DB but absent from APPL_DB means buffermgrd wrote the config but
    the profile never reached the applied state -- config the dataplane never received.
    """
    in_config_db = config_db_key_exists(duthost, "BUFFER_PROFILE|{}".format(profile_name))

    expected_key = "BUFFER_PROFILE_TABLE:{}".format(profile_name)
    appl_result = duthost.shell(
        'sonic-db-cli APPL_DB keys "{}"'.format(expected_key), module_ignore_errors=True)
    in_appl_db = (appl_result['rc'] == 0
                  and expected_key in appl_result['stdout'].split())

    return in_config_db, in_appl_db
