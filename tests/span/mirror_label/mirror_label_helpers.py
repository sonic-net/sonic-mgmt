'''
Helpers for the SONiC mirror session label tests.

Test plan: docs/testplan/Mirror-session-label-test-plan.md
'''

import json
import logging
import re
import socket
import string
import threading
import time

import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.plugins.loganalyzer.loganalyzer import DisableLogrotateCronContext
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Label constants (HLD 2.10.2: length 1..31, charset [a-zA-Z0-9_-])
# ---------------------------------------------------------------------------
LABEL_MAX_LEN = 31
LABEL_CHARSET = string.ascii_letters + string.digits + "_-"

# Prefix of every session created by these tests; used for cleanup
SESSION_PREFIX = "lbl_"

# Redis database indexes
CONFIG_DB = 4
STATE_DB = 6
ASIC_DB = 1

SAI_LABEL_ATTR = "SAI_MIRROR_SESSION_ATTR_LABEL"
SAI_DST_IP_ATTR = "SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS"
ASIC_MIRROR_KEY_PATTERN = "ASIC_STATE:SAI_OBJECT_TYPE_MIRROR_SESSION:*"
CAPABILITY_KEY = "SWITCH_CAPABILITY|switch"
CAPABILITY_FIELD = "MIRROR_SESSION_LABEL_CAPABLE"
INGRESS_CAPABILITY_FIELD = "PORT_INGRESS_MIRROR_CAPABLE"
EGRESS_CAPABILITY_FIELD = "PORT_EGRESS_MIRROR_CAPABLE"

# One hardware mirror session slot is reserved when the SAI profile of syncd contains this key
SAI_PROFILE = "/tmp/sai.profile"
HW_ID_RESERVATION_KEY = "SAI_MIRROR_SESSION_HW_ID_RESERVATION"

SESSION_ACTIVE_TIMEOUT = 300
SESSION_POLL_INTERVAL = 5

# ---------------------------------------------------------------------------
# ERSPAN endpoint constants; one /24 route covers every destination used here
# ---------------------------------------------------------------------------
ERSPAN_SRC_IP = "10.1.0.32"
ERSPAN_DST_NET = "10.20.0.0/24"
ERSPAN_DST_BASE = 33
ERSPAN_DSCP = "8"
ERSPAN_TTL = "64"
ERSPAN_GRE_TYPE = "0x8949"
ERSPAN_QUEUE = "0"
SPAN_QUEUE = "0"


def erspan_dst_ip(index=0):
    '''Return a distinct ERSPAN destination address inside ERSPAN_DST_NET.'''
    return "10.20.0.{}".format(ERSPAN_DST_BASE + index)


# ---------------------------------------------------------------------------
# Label generators
# ---------------------------------------------------------------------------
def valid_labels():
    '''Return (id, label) pairs of labels that must be accepted.'''
    return [
        ("label-len1", "a"),
        ("label-len31", "L" * LABEL_MAX_LEN),
        ("label-charset", "A1_-z"),
        ("label-charset-len31", ("Az09_-" * 6)[:LABEL_MAX_LEN]),
    ]


def invalid_labels():
    '''Return (id, label) pairs of labels that must be rejected.'''
    return [
        ("label-empty", ""),
        ("label-len32", "L" * (LABEL_MAX_LEN + 1)),
        ("label-len65", "L" * 65),
        ("label-space", "bad label"),
        ("label-dot", "bad.label"),
        ("label-slash", "bad/label"),
        ("label-non-ascii", "labelé"),
    ]


# ---------------------------------------------------------------------------
# Database access
# ---------------------------------------------------------------------------
def redis_cmd(asic, db, cmd):
    '''Run one redis-cli command against a DB of the given ASIC; return stripped stdout.'''
    # Not asic.run_redis_cli_cmd(): it runs the command with verbose=False, which hides the command line from the log.
    cli = "/usr/bin/redis-cli -n {} {}".format(db, cmd)
    if asic.namespace != DEFAULT_NAMESPACE:
        cli = "sudo ip netns exec {} {}".format(asic.namespace, cli)
    result = asic.sonichost.command(cli)
    return result["stdout"].strip()


def unescape_sai(value):
    '''
    sairedis serializes chardata with \\xHH escapes (for example "_" is stored as \\x5F in ASIC_DB);
    return the plain string.
    '''
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), value)


def db_hget(asic, db, key, field):
    '''HGET a field; return None when the key or field does not exist. ASIC_DB values are unescaped.'''
    value = redis_cmd(asic, db, 'HGET "{}" {}'.format(key, field))
    if not value:
        return None
    return unescape_sai(value) if db == ASIC_DB else value


def db_keys(asic, db, pattern):
    '''Return the sorted list of keys matching pattern.'''
    out = redis_cmd(asic, db, 'KEYS "{}"'.format(pattern))
    return sorted(line.strip() for line in out.splitlines() if line.strip())


def config_label(asic, name):
    return db_hget(asic, CONFIG_DB, "MIRROR_SESSION|{}".format(name), "label")


def state_label(asic, name):
    return db_hget(asic, STATE_DB, "MIRROR_SESSION_TABLE|{}".format(name), "label")


def session_status(asic, name):
    return db_hget(asic, STATE_DB, "MIRROR_SESSION_TABLE|{}".format(name), "status")


def config_session_exists(asic, name):
    return bool(db_keys(asic, CONFIG_DB, "MIRROR_SESSION|{}".format(name)))


def asic_db_mirror_objects(asic):
    '''Return {asic_db_key: label or None} for every mirror session object in ASIC_DB.'''
    return {
        key: db_hget(asic, ASIC_DB, key, SAI_LABEL_ATTR)
        for key in db_keys(asic, ASIC_DB, ASIC_MIRROR_KEY_PATTERN)
    }


def asic_db_labels(asic):
    '''Return the sorted list of labels present on ASIC_DB mirror session objects.'''
    return sorted(label for label in asic_db_mirror_objects(asic).values() if label)


def hw_id_reservation_line(duthost, asic):
    '''
    Return the active (not commented out) SAI_MIRROR_SESSION_HW_ID_RESERVATION line from the
    SAI profile inside the syncd container of the ASIC, or None when the key is not set.
    '''
    container = asic.get_docker_name("syncd")
    result = duthost.shell("docker exec {} cat {}".format(container, SAI_PROFILE), module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, "Cannot read {} in container {}: {}".format(
        SAI_PROFILE, container, result.get("stderr")))
    for line in result["stdout"].splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.startswith(HW_ID_RESERVATION_KEY):
            return line
    return None


def snapshot_layers(asic):
    '''Capture CONFIG_DB sessions, STATE_DB sessions and ASIC_DB objects for before/after comparison.'''
    return {
        "config": db_keys(asic, CONFIG_DB, "MIRROR_SESSION|*"),
        "state": db_keys(asic, STATE_DB, "MIRROR_SESSION_TABLE|*"),
        "asic": asic_db_mirror_objects(asic),
    }


def direct_hset_session(asic, name, fields):
    '''
    Create a session straight in CONFIG_DB with ONE multi-field HSET (bypasses the CLI check).
    All fields, including label, must be written together: writing label afterwards would
    be seen by MirrorOrch as an in-place change of an existing session.
    '''
    args = " ".join('{} "{}"'.format(field, value) for field, value in fields.items())
    return redis_cmd(asic, CONFIG_DB, 'HSET "MIRROR_SESSION|{}" {}'.format(name, args))


def direct_hset_field(asic, name, field, value):
    '''Change one field of an existing CONFIG_DB session.'''
    return redis_cmd(asic, CONFIG_DB, 'HSET "MIRROR_SESSION|{}" {} "{}"'.format(name, field, value))


def direct_delete_session(asic, name):
    return redis_cmd(asic, CONFIG_DB, 'DEL "MIRROR_SESSION|{}"'.format(name))


# ---------------------------------------------------------------------------
# Session CLI
# ---------------------------------------------------------------------------
def _label_args(label, short):
    if label is None:
        return ""
    return ' {} "{}"'.format("-l" if short else "--label", label)


def create_span_session(duthost, name, dst_port, src_port, direction, label=None,
                        short=False, module_ignore_errors=False):
    '''config mirror_session span add <name> <dst_port> <src_port> <dir> <queue> [--label L]'''
    cmd = "config mirror_session span add {} {} {} {} {}{}".format(
        name, dst_port, src_port, direction, SPAN_QUEUE, _label_args(label, short))
    return duthost.command(cmd, module_ignore_errors=module_ignore_errors)


def span_direction_for(asic):
    '''
    Direction a SPAN session with a source port can use on the ASIC: "both" when ingress and egress port
    mirroring are supported, "rx" when only ingress is, None when ingress is not supported. Like the CLI,
    a capability that is absent from STATE_DB counts as supported; only a value other than "true" rejects it.
    '''
    ingress = db_hget(asic, STATE_DB, CAPABILITY_KEY, INGRESS_CAPABILITY_FIELD)
    egress = db_hget(asic, STATE_DB, CAPABILITY_KEY, EGRESS_CAPABILITY_FIELD)
    if ingress not in (None, "true"):
        return None
    return "both" if egress in (None, "true") else "rx"


def create_erspan_session(duthost, name, dst_ip, label=None, src_port=None, direction="rx",
                          legacy=False, short=False, module_ignore_errors=False):
    '''
    config mirror_session [erspan] add <name> <src_ip> <dst_ip> <dscp> <ttl> <gre> <queue>
    [<src_port> <direction>] [--label L]; legacy=True uses the old "add" command form, which
    takes no source port / direction (src_port is rejected for it).
    '''
    if legacy and src_port is not None:
        raise ValueError("config mirror_session add has no source port / direction arguments")
    verb = "add" if legacy else "erspan add"
    cmd = "config mirror_session {} {} {} {} {} {} {} {}".format(
        verb, name, ERSPAN_SRC_IP, dst_ip, ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE)
    if src_port is not None:
        cmd += " {} {}".format(src_port, direction)
    cmd += _label_args(label, short)
    return duthost.command(cmd, module_ignore_errors=module_ignore_errors)


def remove_session(duthost, name):
    return duthost.command("config mirror_session remove {}".format(name), module_ignore_errors=True)


def remove_all_label_sessions(duthost, asic):
    '''Remove every session created by these tests, including ones injected straight into CONFIG_DB.'''
    for key in db_keys(asic, CONFIG_DB, "MIRROR_SESSION|{}*".format(SESSION_PREFIX)):
        name = key.split("|", 1)[1]
        remove_session(duthost, name)
        direct_delete_session(asic, name)


def show_mirror_session(duthost):
    return duthost.command("show mirror_session")["stdout"]


def parse_show_mirror_session(output):
    '''
    Parse `show mirror_session` into {session_name: {column: value}}.
    Column extents are taken from the dashed separator line, so empty cells (for
    example the Label of an unlabeled session) stay empty instead of shifting columns.
    '''
    sessions = {}
    lines = output.splitlines()
    i = 0
    while i < len(lines) - 1:
        header, sep = lines[i], lines[i + 1]
        if header.strip().startswith("Name") and set(sep.strip()) <= set("- "):
            spans = []
            pos = 0
            for chunk in sep.split():
                start = sep.index(chunk, pos)
                spans.append((start, start + len(chunk)))
                pos = start + len(chunk)
            columns = [header[s:e].strip() for s, e in spans]
            i += 2
            while i < len(lines) and lines[i].strip():
                row = lines[i]
                values = [row[s:e].strip() for s, e in spans]
                sessions[values[0]] = dict(zip(columns, values))
                i += 1
        else:
            i += 1
    return sessions


def wait_sessions_active(asic, names, timeout=SESSION_ACTIVE_TIMEOUT):
    '''Wait until every named session reports status "active" in STATE_DB.'''
    def mirror_sessions_active():
        return all(session_status(asic, name) == "active" for name in names)

    # wait_until logs "Wait until <condition name> is True": make that line say which sessions are awaited
    mirror_sessions_active.__name__ = "mirror_sessions_{}_status_active".format("_".join(names))
    pytest_assert(wait_until(timeout, SESSION_POLL_INTERVAL, 0, mirror_sessions_active),
                  "Mirror sessions {} did not become active within {}s".format(names, timeout))


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
def assert_label_in_all_layers(duthost, asic, name, label):
    '''A labeled session carries the exact label in CONFIG_DB, STATE_DB, show and ASIC_DB.'''
    pytest_assert(config_label(asic, name) == label,
                  "CONFIG_DB label of {} is {!r}, expected {!r}".format(name, config_label(asic, name), label))
    pytest_assert(state_label(asic, name) == label,
                  "STATE_DB label of {} is {!r}, expected {!r}".format(name, state_label(asic, name), label))
    row = parse_show_mirror_session(show_mirror_session(duthost)).get(name)
    pytest_assert(row is not None, "Session {} is not listed by show mirror_session".format(name))
    pytest_assert(row.get("Label") == label,
                  "show mirror_session Label of {} is {!r}, expected {!r}".format(name, row.get("Label"), label))
    pytest_assert(label in asic_db_labels(asic),
                  "No ASIC_DB mirror object carries label {!r}: {}".format(label, asic_db_mirror_objects(asic)))


def assert_no_label(duthost, asic, name):
    '''An unlabeled session has no label in any layer and an empty Label column.'''
    pytest_assert(config_label(asic, name) is None, "Unexpected CONFIG_DB label on {}".format(name))
    pytest_assert(state_label(asic, name) is None, "Unexpected STATE_DB label on {}".format(name))
    row = parse_show_mirror_session(show_mirror_session(duthost)).get(name)
    pytest_assert(row is not None, "Session {} is not listed by show mirror_session".format(name))
    pytest_assert(row.get("Label", "") == "", "Label column of {} is not empty: {!r}".format(name, row.get("Label")))


def assert_layers_unchanged(asic, before):
    '''Rejection rows: CONFIG_DB, STATE_DB and ASIC_DB are exactly as before the failed operation.'''
    after = snapshot_layers(asic)
    pytest_assert(after == before, "Layers changed by a rejected operation.\nbefore: {}\nafter:  {}".format(
        before, after))


def assert_session_gone(asic, name):
    '''No CONFIG_DB or STATE_DB entry remains for the session.'''
    pytest_assert(not config_session_exists(asic, name), "CONFIG_DB still has session {}".format(name))
    pytest_assert(not db_keys(asic, STATE_DB, "MIRROR_SESSION_TABLE|{}".format(name)),
                  "STATE_DB still has session {}".format(name))


# ---------------------------------------------------------------------------
# PTF traffic
# ---------------------------------------------------------------------------
def collect_span_copies(ptfadapter, port, inner_ip_src, timeout=3):
    '''
    Return the raw frames seen on a PTF port during the timeout whose IPv4 source address is inner_ip_src.
    A port-mirror destination also receives copies of other traffic (background packets of the PTF host, and
    with direction both the packets that leave the source port), so only the frames that carry the test
    packet's source IP are counted.
    '''
    from scapy.all import IP
    from scapy.layers.l2 import Ether

    frames = []
    ignored = 0
    end = time.time() + timeout
    while time.time() < end:
        result = ptfadapter.dataplane.poll(device_number=0, port_number=port, timeout=0.1)
        raw = result[-2] if result is not None else None
        if raw is None:
            continue
        pkt = Ether(raw)
        if pkt.haslayer(IP) and pkt[IP].src == inner_ip_src:
            frames.append(raw)
        else:
            ignored += 1
    if ignored:
        logger.info("Ignored %d frame(s) on PTF port %s that do not carry source %s (background traffic)",
                    ignored, port, inner_ip_src)
    return frames


def collect_gre_by_dst(ptfadapter, port, timeout=3, details=None, inner_ip_src=None):
    '''
    Return {outer destination IP: number of ERSPAN frames} seen on a PTF port during the timeout.
    When a list is passed as details, one (seconds since start, outer dst, outer IP id) tuple is appended
    per frame, which tells a duplicated frame (same IP id) from two different frames.
    A port mirror copies everything that enters the port, including background packets of the PTF host.
    inner_ip_src keeps only the frames whose mirrored packet carries this IPv4 source address.
    '''
    from scapy.all import IP, GRE
    from scapy.layers.l2 import Ether

    counts = {}
    ignored = 0
    needle = socket.inet_aton(inner_ip_src) if inner_ip_src else None
    start = time.time()
    end = start + timeout
    while time.time() < end:
        result = ptfadapter.dataplane.poll(device_number=0, port_number=port, timeout=0.1)
        raw = result[-2] if result is not None else None
        if raw is None:
            continue
        pkt = Ether(raw)
        if pkt.haslayer(IP) and pkt.haslayer(GRE) and int(pkt[GRE].proto) == int(ERSPAN_GRE_TYPE, 16):
            if needle is not None and needle not in bytes(pkt[GRE].payload):
                ignored += 1
                continue
            counts[pkt[IP].dst] = counts.get(pkt[IP].dst, 0) + 1
            if details is not None:
                details.append((round(time.time() - start, 3), pkt[IP].dst, pkt[IP].id))
    if ignored:
        logger.info("Ignored %d ERSPAN frame(s) on PTF port %s that do not carry source %s (background traffic)",
                    ignored, port, inner_ip_src)
    return counts


# ---------------------------------------------------------------------------
# ACL mirror rule (ingress EVERFLOW table, same mechanism as tests/everflow)
# ---------------------------------------------------------------------------
ACL_TABLE = "EVERFLOW"
ACL_RULE_SRC_IP = "20.0.0.10"
ACL_RULE_FILE = "/tmp/label_acl_rule.json"
ACL_RULE_REMOVE_FILE = "/tmp/label_acl_rule_remove.json"


def acl_table_exists(asic, table=ACL_TABLE):
    return bool(db_keys(asic, CONFIG_DB, "ACL_TABLE|{}".format(table)))


def apply_mirror_acl_rule(duthost, session_name, table=ACL_TABLE):
    '''Create one rule that mirrors packets with source IP ACL_RULE_SRC_IP to the session (replaces the table rules).'''
    rule = {"acl": {"acl-sets": {"acl-set": {table: {"acl-entries": {"acl-entry": {"1": {
        "actions": {"config": {"forwarding-action": "ACCEPT"}},
        "config": {"sequence-id": 1},
        "ip": {"config": {"source-ip-address": "{}/32".format(ACL_RULE_SRC_IP)}},
    }}}}}}}}
    duthost.copy(content=json.dumps(rule, indent=4), dest=ACL_RULE_FILE)
    duthost.command("acl-loader update full {} --table_name {} --session_name {}".format(
        ACL_RULE_FILE, table, session_name))


def remove_mirror_acl_rules(duthost, table=ACL_TABLE):
    '''Remove every rule of the table (the EVERFLOW table has no rules on a clean DUT).'''
    empty = {"acl": {"acl-sets": {"acl-set": {}}}}
    duthost.copy(content=json.dumps(empty, indent=4), dest=ACL_RULE_REMOVE_FILE)
    return duthost.command("acl-loader update full {} --table_name {}".format(ACL_RULE_REMOVE_FILE, table),
                           module_ignore_errors=True)


def acl_rule_mirror_session(asic, table=ACL_TABLE):
    '''Return the mirror session the first rule of the table points to (None when there is no rule).'''
    for key in db_keys(asic, CONFIG_DB, "ACL_RULE|{}|*".format(table)):
        value = db_hget(asic, CONFIG_DB, key, "MIRROR_INGRESS_ACTION")
        if value:
            return value
    return None


def asic_db_attr_by_label(asic, label, attr):
    '''Return an attribute of the ASIC_DB mirror object that carries the label (None if absent).'''
    for key, obj_label in asic_db_mirror_objects(asic).items():
        if obj_label == label:
            return db_hget(asic, ASIC_DB, key, attr)
    return None


def asic_db_label_by_dst(asic):
    '''
    Return {ERSPAN destination IP: label or None} for every ERSPAN mirror object in ASIC_DB.
    This ties a label to the session it belongs to (each session has its own destination), which
    "some object carries the label" cannot show.
    '''
    result = {}
    for key in db_keys(asic, ASIC_DB, ASIC_MIRROR_KEY_PATTERN):
        dst = db_hget(asic, ASIC_DB, key, SAI_DST_IP_ATTR)
        if dst:
            result[dst] = db_hget(asic, ASIC_DB, key, SAI_LABEL_ATTR)
    return result


class ContinuousMirrorTraffic(threading.Thread):
    '''
    Send one packet every `interval` seconds on a PTF port and count, per outer destination, the ERSPAN frames
    that carry it on another PTF port. Runs in the background while the test reboots the DUT.
    The packets are sent and received by the same thread, so no packet-level locking is needed.
    '''

    def __init__(self, ptfadapter, src_index, pkt, route_index, inner_ip_src, interval=0.01):
        super(ContinuousMirrorTraffic, self).__init__(daemon=True)
        self.ptfadapter = ptfadapter
        self.src_index = src_index
        self.pkt = pkt
        self.route_index = route_index
        self.needle = socket.inet_aton(inner_ip_src)
        self.interval = interval
        self.stop_event = threading.Event()
        self.sent = 0
        self.send_errors = 0
        self.counts = {}
        self.last_seen = {}
        self.max_gap = {}

    def _poll(self, timeout):
        '''Poll the route port once and account one matching ERSPAN frame.'''
        from scapy.all import IP, GRE
        from scapy.layers.l2 import Ether

        result = self.ptfadapter.dataplane.poll(device_number=0, port_number=self.route_index, timeout=timeout)
        raw = result[-2] if result is not None else None
        if raw is None:
            return
        pkt = Ether(raw)
        if not (pkt.haslayer(IP) and pkt.haslayer(GRE) and int(pkt[GRE].proto) == int(ERSPAN_GRE_TYPE, 16)):
            return
        if self.needle not in bytes(pkt[GRE].payload):
            return
        dst, now = pkt[IP].dst, time.time()
        self.counts[dst] = self.counts.get(dst, 0) + 1
        if dst in self.last_seen:
            self.max_gap[dst] = max(self.max_gap.get(dst, 0), now - self.last_seen[dst])
        self.last_seen[dst] = now

    def run(self):
        while not self.stop_event.is_set():
            try:
                testutils.send(self.ptfadapter, self.src_index, self.pkt)
                self.sent += 1
            except Exception as err:    # the dataplane may hiccup while the DUT reboots
                self.send_errors += 1
                logger.warning("continuous traffic: send failed: %s", err)
            deadline = time.time() + self.interval
            while time.time() < deadline and not self.stop_event.is_set():
                self._poll(timeout=0.002)

    def finish(self, drain_timeout=3):
        '''Stop sending, wait for the frames still in flight and return the per-destination counts.'''
        self.stop_event.set()
        self.join()
        end = time.time() + drain_timeout
        while time.time() < end:
            self._poll(timeout=0.05)
        return self.counts


def label_unsupported_reason(duthost):
    '''Return why the mirror session label is not supported on the DUT, or None when it is.'''
    for asic in duthost.asics:
        value = db_hget(asic, STATE_DB, CAPABILITY_KEY, CAPABILITY_FIELD)
        if value != "true":
            return "{} is {!r} on {}: mirror session label is not supported".format(
                CAPABILITY_FIELD, value, asic.asic_index)
    help_out = duthost.command("config mirror_session span add --help", module_ignore_errors=True)["stdout"]
    if "--label" not in help_out:
        return "config mirror_session span add has no --label option"
    return None


# ---------------------------------------------------------------------------
# Waiting for a DUT log line
# ---------------------------------------------------------------------------
def run_and_wait_for_log(duthost, action, pattern, timeout=30, interval=2):
    '''
    Run action() and wait until a syslog line matching the regex appears after it.
    Return True when the line was seen, False on timeout.

    Same method as tests/crm/test_crm.py::wait_for_threshold_log: the starting point is the line number of
    /var/log/syslog (not a LogAnalyzer marker: the awk of find_log_msg.sh treats the brackets of a
    parametrized test name as a character class), and logrotate is stopped meanwhile (this DUT rotates
    syslog about once a minute, which would move the lines out of the file).
    '''
    with DisableLogrotateCronContext(duthost):
        result = duthost.shell("sudo wc -l < /var/log/syslog", module_ignore_errors=True)
        pytest_assert(result.get("rc", 1) == 0 and result.get("stdout", "").strip().isdigit(),
                      "Failed to determine the current syslog position")
        first_line = int(result["stdout"].strip()) + 1
        action()

        def seen():
            out = duthost.shell("sudo tail -n +{} /var/log/syslog".format(first_line), module_ignore_errors=True)
            return re.search(pattern, out.get("stdout", "")) is not None

        return wait_until(timeout, interval, 0, seen)
