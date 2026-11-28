'''
Tests for the optional mirror session label (SPAN / ERSPAN).

Test plan: docs/testplan/Mirror-session-label-test-plan.md
The readiness gate (label_capability) and the per-test session cleanup are autouse
fixtures of tests/span/mirror_label/conftest.py.
'''

import logging
import random

import pytest
import ptf.testutils as testutils

from tests.common.gu_utils import apply_patch, expect_op_failure, expect_op_success
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from mirror_label_helpers import (
    CAPABILITY_FIELD,
    CAPABILITY_KEY,
    CONFIG_DB,
    LABEL_MAX_LEN,
    SESSION_PREFIX,
    STATE_DB,
    assert_label_in_all_layers,
    assert_layers_unchanged,
    assert_no_label,
    assert_session_gone,
    asic_db_label_by_dst,
    asic_db_labels,
    asic_db_mirror_objects,
    collect_gre_by_dst,
    collect_span_copies,
    config_label,
    config_session_exists,
    create_erspan_session,
    create_span_session,
    direct_hset_field,
    direct_hset_session,
    erspan_dst_ip,
    hw_id_reservation_line,
    invalid_labels,
    parse_show_mirror_session,
    redis_cmd,
    remove_session,
    run_and_wait_for_log,
    session_status,
    show_mirror_session,
    snapshot_layers,
    state_label,
    valid_labels,
    wait_sessions_active,
    ERSPAN_DSCP,
    ERSPAN_GRE_TYPE,
    ERSPAN_QUEUE,
    ERSPAN_SRC_IP,
    ERSPAN_TTL,
)

logger = logging.getLogger(__name__)

TEST_PACKET_SRC_IP = "20.0.0.11"    # source IP of the packet that identifies the test copies among background traffic
TEST_PACKET_DST_IP = "30.0.0.10"

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_memory_utilization,
]

# How long to wait for the MirrorOrch log line that proves a CONFIG_DB write was processed
REJECT_LOG_TIMEOUT = 30

# What the CLI says when it rejects --label because the capability is not "true"
CAPABILITY_REJECTION = "Mirror session label is not supported"

# MirrorOrch log lines that prove a rejection (HLD 2.9 Table 5). A test registers the line it provokes as expected
# (LogAnalyzer checks it at teardown) and waits for it before asserting that nothing was created.
# A session written straight into CONFIG_DB with an invalid label is rejected
INVALID_LABEL_LOG_RE = r".*ERR swss#orchagent: :- createEntry: Invalid label for mirror session {name}.*"
# A second session with a label that is already used is rejected
DUPLICATE_LABEL_LOG_RE = (
    r".*ERR swss#orchagent: :- createEntry: Failed to create mirror session {name}: "
    r"label {label} is already used by session .*"
)
# A single-field HSET on a live session is not an update for MirrorOrch
SESSION_EXISTS_LOG_RE = r".*Failed to create session {name}: object already exists.*"
# YANG validation rejects a GCU patch with an over-long label
GCU_INVALID_LABEL_LOG_IGNORE = [
    r".*ERR sonic_yang: Data Loading Failed:failed to parse data tree: "
    r"Mirror session label must be 1\.\.31 characters.*"
]


# A session written straight into CONFIG_DB and rejected by MirrorOrch is never created; removing its
# CONFIG_DB key afterwards (cleanup) makes orchagent log this error, which is expected there.
REJECTED_SESSION_REMOVAL_LOG_IGNORE = [r".*Failed to remove non-existent mirror session.*"]


def _ignore_logs(loganalyzer, duthost, patterns):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(patterns)


def _expect_log(loganalyzer, duthost, pattern):
    if loganalyzer:
        loganalyzer[duthost.hostname].expect_regex.append(pattern)


def _run_and_wait_for_log(duthost, action, pattern):
    pytest_assert(run_and_wait_for_log(duthost, action, pattern, timeout=REJECT_LOG_TIMEOUT),
                  "MirrorOrch did not log the expected line within {} s: {}".format(REJECT_LOG_TIMEOUT, pattern))


def _ignore_rejected_session_removal_logs(loganalyzer, duthost):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(REJECTED_SESSION_REMOVAL_LOG_IGNORE)


def _erspan_fields(dst_ip, label=None):
    '''CONFIG_DB fields of an ERSPAN session.'''
    fields = {
        "type": "ERSPAN", "src_ip": ERSPAN_SRC_IP, "dst_ip": dst_ip, "dscp": ERSPAN_DSCP,
        "ttl": ERSPAN_TTL, "gre_type": ERSPAN_GRE_TYPE, "queue": ERSPAN_QUEUE,
    }
    if label is not None:
        fields["label"] = label
    return fields


def _span_fields(dst_port, src_port, direction, label=None):
    '''CONFIG_DB fields of a SPAN session.'''
    fields = {"type": "SPAN", "dst_port": dst_port, "src_port": src_port, "direction": direction.upper()}
    if label is not None:
        fields["label"] = label
    return fields


def _send_and_verify_span_copy(ptfadapter, src_index, dst_index):
    '''
    SPAN: exactly one identical copy of the test packet arrives on the monitor port. The monitor port also
    receives copies of other traffic, so only the frames that carry the test packet's source IP are counted.
    '''
    src_mac = ptfadapter.dataplane.get_mac(0, src_index)
    pkt = testutils.simple_ip_packet(eth_src=src_mac, eth_dst="ff:ff:ff:ff:ff:ff", ip_src=TEST_PACKET_SRC_IP,
                                     ip_dst=TEST_PACKET_DST_IP)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_index, pkt)
    frames = collect_span_copies(ptfadapter, dst_index, TEST_PACKET_SRC_IP)
    pytest_assert(len(frames) == 1,
                  "Expected exactly one SPAN copy of the test packet on the monitor port, got {}".format(len(frames)))
    pytest_assert(frames[0] == bytes(pkt), "The SPAN copy differs from the packet sent on the source port")


def _send_and_verify_erspan_copy(ptfadapter, src_index, routed_index, dst_ip):
    '''
    ERSPAN: exactly one GRE encapsulated copy of the test packet towards dst_ip arrives on the routed PTF
    port. The session mirrors everything that enters the source port, background packets of the PTF host
    included, so only the frames that carry the test packet (its source IP) are counted.
    '''
    src_mac = ptfadapter.dataplane.get_mac(0, src_index)
    pkt = testutils.simple_ip_packet(eth_src=src_mac, eth_dst="ff:ff:ff:ff:ff:ff", ip_src=TEST_PACKET_SRC_IP,
                                     ip_dst=TEST_PACKET_DST_IP)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_index, pkt)
    frames = []
    counts = collect_gre_by_dst(ptfadapter, routed_index, details=frames, inner_ip_src=TEST_PACKET_SRC_IP)
    logger.info("ERSPAN frames by outer destination: %s; frames (t, dst, ip id): %s", counts, frames)
    pytest_assert(counts.get(dst_ip, 0) == 1,
                  "Expected exactly one ERSPAN copy to {}, got {} (all destinations: {})".format(
                      dst_ip, counts.get(dst_ip, 0), counts))


@pytest.mark.parametrize("labeled", [True, False], ids=["labeled", "unlabeled"])
@pytest.mark.parametrize("form", ["erspan", "erspan_legacy", "span"])
def test_label_create(request, duthosts, rand_one_dut_hostname, label_asic, label_ports, ptfadapter, form, labeled):
    '''
    Create a session with / without a label: the label is visible in every layer only when
    set, and it does not change the mirrored packet.
    A SPAN session is never mixed with an ERSPAN one, so the SPAN form does not even set up the
    ERSPAN route.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    erspan_route = request.getfixturevalue("label_erspan_route") if form != "span" else None
    direction = request.getfixturevalue("span_direction") if form == "span" else None
    name = "{}create_{}".format(SESSION_PREFIX, form)
    label = "L_{}".format(form) if labeled else None
    baseline_objects = len(asic_db_mirror_objects(label_asic))
    src, dst = label_ports["src"], label_ports["dst"]

    if form == "span":
        create_span_session(duthost, name, dst["name"], src["name"], direction, label=label)
    else:
        legacy = form == "erspan_legacy"
        create_erspan_session(duthost, name, erspan_dst_ip(0), label=label,
                              src_port=None if legacy else src["name"], legacy=legacy, short=labeled)
    wait_sessions_active(label_asic, [name])

    if labeled:
        assert_label_in_all_layers(duthost, label_asic, name, label)
        if form != "span":
            # an unlabeled session coexists with the labeled one
            companion = name + "_c"
            create_erspan_session(duthost, companion, erspan_dst_ip(1))
            wait_sessions_active(label_asic, [companion])
            assert_no_label(duthost, label_asic, companion)
            remove_session(duthost, companion)
    else:
        assert_no_label(duthost, label_asic, name)
        pytest_assert(len(asic_db_mirror_objects(label_asic)) == baseline_objects + 1,
                      "Expected exactly one new ASIC_DB mirror object")
        pytest_assert(not asic_db_labels(label_asic), "Unlabeled session produced a LABEL attribute in ASIC_DB")

    # the mirrored packet is the same with and without a label
    if form == "span":
        _send_and_verify_span_copy(ptfadapter, src["index"], dst["index"])
    elif form == "erspan":
        _send_and_verify_erspan_copy(ptfadapter, src["index"], erspan_route["ptf_index"], erspan_dst_ip(0))

    remove_session(duthost, name)
    assert_session_gone(label_asic, name)
    pytest_assert(len(asic_db_mirror_objects(label_asic)) == baseline_objects,
                  "ASIC_DB mirror object of {} was not removed".format(name))


_SYNTAX_CASES = (
    [("valid", case_id, label) for case_id, label in valid_labels()]
    + [("valid-name32", "name-len32-label-len31", "a" * LABEL_MAX_LEN)]
    # one invalid label per run, chosen at random: all of them are covered by unit tests
    + [("invalid", "label-random", random.choice(invalid_labels())[1])]
)


@pytest.mark.parametrize("kind, label", [(kind, label) for kind, _, label in _SYNTAX_CASES],
                         ids=["{}-{}".format("valid" if kind.startswith("valid") else "invalid", case_id)
                              for kind, case_id, _ in _SYNTAX_CASES])
def test_label_validation_syntax(duthosts, rand_one_dut_hostname, label_asic, label_ports, span_direction,
                                 loganalyzer, kind, label):
    '''
    Label syntax: valid labels are accepted verbatim; invalid labels are rejected by the CLI
    without touching any layer and also by MirrorOrch when written straight into CONFIG_DB
    (no SAI object, no STATE_DB key, no truncated label).
    '''
    duthost = duthosts[rand_one_dut_hostname]
    src, dst = label_ports["src"], label_ports["dst"]
    if kind == "invalid":
        logger.info("Random invalid label for this run: %r", label)

    if kind.startswith("valid"):
        name = SESSION_PREFIX + ("n" * (32 - len(SESSION_PREFIX)) if kind == "valid-name32" else "v")
        create_span_session(duthost, name, dst["name"], src["name"], span_direction, label=label)
        wait_sessions_active(label_asic, [name])
        assert_label_in_all_layers(duthost, label_asic, name, label)
        return

    name = SESSION_PREFIX + "bad"
    before = snapshot_layers(label_asic)
    attempts = [
        lambda: create_span_session(duthost, name, dst["name"], src["name"], span_direction, label=label,
                                    module_ignore_errors=True),
        lambda: create_erspan_session(duthost, name, erspan_dst_ip(0), label=label, module_ignore_errors=True),
        lambda: create_erspan_session(duthost, name, erspan_dst_ip(0), label=label, legacy=True,
                                      module_ignore_errors=True),
    ]
    for attempt in attempts:
        result = attempt()
        pytest_assert(result["rc"] != 0, "CLI accepted invalid label {!r}".format(label))
        assert_layers_unchanged(label_asic, before)

    # MirrorOrch must not trust the CLI (HLD 4.5): inject the session directly. Every invalid row is injected,
    # so a later change that keeps only the length check cannot let a label with a bad character reach SAI.
    log_re = INVALID_LABEL_LOG_RE.format(name=name)
    _expect_log(loganalyzer, duthost, log_re)
    _ignore_rejected_session_removal_logs(loganalyzer, duthost)
    fields = _span_fields(dst["name"], src["name"], span_direction, label)
    _run_and_wait_for_log(duthost, lambda: direct_hset_session(label_asic, name, fields), log_re)
    pytest_assert(session_status(label_asic, name) is None,
                  "STATE_DB has MIRROR_SESSION_TABLE|{} for a rejected session".format(name))
    pytest_assert(len(asic_db_mirror_objects(label_asic)) == len(before["asic"]),
                  "MirrorOrch created a SAI object for invalid label {!r}".format(label))
    truncated = label[:LABEL_MAX_LEN]
    pytest_assert(not truncated or truncated not in asic_db_labels(label_asic),
                  "Invalid label {!r} reached ASIC_DB".format(label))


def test_label_validation_duplicate(duthosts, rand_one_dut_hostname, label_asic, label_erspan_route, loganalyzer):
    '''
    Uniqueness per ASIC: a second session with an already used label is rejected by the CLI
    and by MirrorOrch (direct HSET), including two same-label sessions written back to back.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    m1, m2, m3, m4 = ("{}m{}".format(SESSION_PREFIX, i) for i in range(1, 5))

    create_erspan_session(duthost, m1, erspan_dst_ip(0), label="DUP")
    wait_sessions_active(label_asic, [m1])
    pytest_assert(asic_db_labels(label_asic).count("DUP") == 1, "ASIC_DB must hold one object labeled DUP")

    result = create_erspan_session(duthost, m2, erspan_dst_ip(3), label="DUP", short=True,
                                   module_ignore_errors=True)
    pytest_assert(result["rc"] != 0, "CLI accepted a duplicate label")
    pytest_assert(not config_session_exists(label_asic, m2), "Rejected session {} is in CONFIG_DB".format(m2))

    m2_re = DUPLICATE_LABEL_LOG_RE.format(name=m2, label="DUP")
    _expect_log(loganalyzer, duthost, m2_re)
    _ignore_rejected_session_removal_logs(loganalyzer, duthost)
    _run_and_wait_for_log(duthost, lambda: direct_hset_session(label_asic, m2, _erspan_fields(erspan_dst_ip(3), "DUP")),
                          m2_re)
    pytest_assert(session_status(label_asic, m2) is None, "STATE_DB has a key for rejected session {}".format(m2))
    pytest_assert(asic_db_labels(label_asic).count("DUP") == 1, "MirrorOrch created a second object labeled DUP")
    redis_cmd(label_asic, CONFIG_DB, 'DEL "MIRROR_SESSION|{}"'.format(m2))

    # whichever of the two sessions loses logs the rejection, its name is not known in advance
    race_re = DUPLICATE_LABEL_LOG_RE.format(name="({}|{})".format(m3, m4), label="RACE")
    _expect_log(loganalyzer, duthost, race_re)

    def inject_race():
        direct_hset_session(label_asic, m3, _erspan_fields(erspan_dst_ip(1), "RACE"))
        direct_hset_session(label_asic, m4, _erspan_fields(erspan_dst_ip(2), "RACE"))

    _run_and_wait_for_log(duthost, inject_race, race_re)
    pytest_assert(asic_db_labels(label_asic).count("RACE") == 1,
                  "Exactly one ASIC_DB object must carry label RACE, got {}".format(asic_db_labels(label_asic)))
    pytest_assert(session_status(label_asic, m1) == "active", "{} is no longer active".format(m1))


@pytest.mark.parametrize("path", ["hset", "gcu"])
def test_label_change_on_live_session(duthosts, rand_one_dut_hostname, label_asic, label_erspan_route,
                                      loganalyzer, path):
    '''
    The label cannot be changed on a live session: a direct HSET never alters an existing ASIC_DB object
    (STATE_DB and ASIC_DB keep the old label, while CONFIG_DB and `show mirror_session`, which reads CONFIG_DB,
    show the new one). The supported way to change a label is remove + create. GCU has no way to change it
    either: it applies a replace of the label as delete + add, so the session comes back as a new SAI object.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    name = SESSION_PREFIX + "live"

    create_erspan_session(duthost, name, erspan_dst_ip(0), label="L1")
    wait_sessions_active(label_asic, [name])
    objects_before = {k: v for k, v in asic_db_mirror_objects(label_asic).items() if v == "L1"}
    pytest_assert(len(objects_before) == 1, "Expected one ASIC_DB object labeled L1")

    if path == "hset":
        exists_re = SESSION_EXISTS_LOG_RE.format(name=name)
        _expect_log(loganalyzer, duthost, exists_re)
        _run_and_wait_for_log(duthost, lambda: direct_hset_field(label_asic, name, "label", "L2"), exists_re)
    else:
        patch = [{"op": "replace", "path": "/MIRROR_SESSION/{}/label".format(name), "value": "L2"}]
        output = apply_patch(duthost, patch, "/tmp/label_live_change.json")
        expect_op_success(duthost, output)
        pytest_assert(wait_until(REJECT_LOG_TIMEOUT, 2, 0, lambda: session_status(label_asic, name) == "active"),
                      "Session {} is not active after the GCU patch".format(name))

    # An existing SAI object must never change its label. GCU turns the field replace into
    # delete + add, so the object may legitimately be replaced by a new one (new OID, new label).
    objects_after = asic_db_mirror_objects(label_asic)
    for key, old_label in objects_before.items():
        pytest_assert(objects_after.get(key, old_label) == old_label,
                      "ASIC_DB label of {} changed in place: {}".format(key, objects_after))
    recreated = not any(key in objects_after for key in objects_before)
    logger.info("path=%s: session %s; CONFIG_DB label %s, STATE_DB label %s, ASIC_DB %s", path,
                "recreated (new SAI object)" if recreated else "left untouched",
                config_label(label_asic, name), state_label(label_asic, name), objects_after)
    if path == "gcu":
        pytest_assert(recreated, "GCU replace must recreate the session as a new SAI object")
    if recreated:
        pytest_assert(path == "gcu", "Session was recreated by a plain CONFIG_DB field write")
        pytest_assert("L2" in objects_after.values(), "Recreated object does not carry the new label L2")
        pytest_assert(state_label(label_asic, name) == "L2", "STATE_DB label does not follow the recreated session")
    else:
        pytest_assert(state_label(label_asic, name) == "L1", "STATE_DB label changed in place")
        # CONFIG_DB and show mirror_session (it reads the label from CONFIG_DB) diverge from the runtime state
        pytest_assert(config_label(label_asic, name) == "L2", "CONFIG_DB label was not changed by the HSET")
        row = parse_show_mirror_session(show_mirror_session(duthost)).get(name)
        pytest_assert(row is not None and row.get("Label") == "L2",
                      "show mirror_session Label of {} is {!r}, expected L2 (CONFIG_DB) while STATE_DB and "
                      "ASIC_DB keep L1".format(name, row.get("Label") if row else None))

    # rollback, then the supported way to change a label: delete + recreate
    remove_session(duthost, name)
    redis_cmd(label_asic, CONFIG_DB, 'DEL "MIRROR_SESSION|{}"'.format(name))
    create_erspan_session(duthost, name, erspan_dst_ip(0), label="L1")
    wait_sessions_active(label_asic, [name])
    assert_label_in_all_layers(duthost, label_asic, name, "L1")

    remove_session(duthost, name)
    create_erspan_session(duthost, name, erspan_dst_ip(0), label="L2")
    wait_sessions_active(label_asic, [name])
    assert_label_in_all_layers(duthost, label_asic, name, "L2")


@pytest.mark.parametrize("mode", ["false", "missing"])
def test_label_capability_unsupported(duthosts, rand_one_dut_hostname, label_asic, label_ports, span_direction,
                                      loganalyzer, mode):
    '''
    The CLI rejects --label when MIRROR_SESSION_LABEL_CAPABLE is not "true"; unlabeled
    creation keeps working.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    src, dst = label_ports["src"], label_ports["dst"]
    name = SESSION_PREFIX + "cap"

    try:
        if mode == "false":
            redis_cmd(label_asic, STATE_DB, 'HSET "{}" {} false'.format(CAPABILITY_KEY, CAPABILITY_FIELD))
        else:
            redis_cmd(label_asic, STATE_DB, 'HDEL "{}" {}'.format(CAPABILITY_KEY, CAPABILITY_FIELD))
        before = snapshot_layers(label_asic)

        result = create_span_session(duthost, name, dst["name"], src["name"], span_direction, label="X",
                                     module_ignore_errors=True)
        pytest_assert(result["rc"] != 0, "CLI accepted --label while the capability is {}".format(mode))
        pytest_assert(CAPABILITY_REJECTION in result["stderr"],
                      "CLI rejected --label for another reason than the capability:\n{}".format(result["stderr"]))
        assert_layers_unchanged(label_asic, before)

        create_span_session(duthost, name, dst["name"], src["name"], span_direction)
        wait_sessions_active(label_asic, [name])
        assert_no_label(duthost, label_asic, name)
    finally:
        redis_cmd(label_asic, STATE_DB, 'HSET "{}" {} true'.format(CAPABILITY_KEY, CAPABILITY_FIELD))


def test_label_gcu(duthosts, rand_one_dut_hostname, label_asic, label_erspan_route, loganalyzer):
    '''GCU: a valid labeled create is applied; a patch with an invalid label is rejected and changes nothing.'''
    duthost = duthosts[rand_one_dut_hostname]
    name = SESSION_PREFIX + "gcu"
    path = "/MIRROR_SESSION/{}".format(name)

    good = [{"op": "add", "path": path, "value": _erspan_fields(erspan_dst_ip(0), "GCU1")}]
    expect_op_success(duthost, apply_patch(duthost, good, "/tmp/label_gcu_add.json"))
    wait_sessions_active(label_asic, [name])
    assert_label_in_all_layers(duthost, label_asic, name, "GCU1")

    redis_cmd(label_asic, CONFIG_DB, 'DEL "MIRROR_SESSION|{}"'.format(name))
    remove_session(duthost, name)
    before = snapshot_layers(label_asic)
    bad = [{"op": "add", "path": path, "value": _erspan_fields(erspan_dst_ip(0), "L" * (LABEL_MAX_LEN + 1))}]
    _ignore_logs(loganalyzer, duthost, GCU_INVALID_LABEL_LOG_IGNORE)
    expect_op_failure(apply_patch(duthost, bad, "/tmp/label_gcu_bad.json"))
    assert_layers_unchanged(label_asic, before)


def test_label_recreate(duthosts, rand_one_dut_hostname, label_asic, label_erspan_route):
    '''Ten create / remove cycles with the same label leave nothing behind and the label stays reusable.'''
    duthost = duthosts[rand_one_dut_hostname]
    name = SESSION_PREFIX + "rec"
    baseline = len(asic_db_mirror_objects(label_asic))

    for cycle in range(10):
        logger.info("create/remove cycle %d", cycle)
        create_erspan_session(duthost, name, erspan_dst_ip(0), label="REC")
        wait_sessions_active(label_asic, [name])
        remove_session(duthost, name)
        assert_session_gone(label_asic, name)

    pytest_assert(len(asic_db_mirror_objects(label_asic)) == baseline, "ASIC_DB mirror objects leaked")
    create_erspan_session(duthost, name, erspan_dst_ip(0), label="REC")
    wait_sessions_active(label_asic, [name])
    assert_label_in_all_layers(duthost, label_asic, name, "REC")


def test_label_scale(duthosts, rand_one_dut_hostname, label_asic, label_erspan_route, label_max_sessions):
    '''
    The platform maximum number of sessions, all with unique labels, are active with distinct
    ASIC_DB objects. The maximum comes from --label_max_sessions (no default; skipped without it).
    When the SAI profile of syncd reserves a mirror session slot (SAI_MIRROR_SESSION_HW_ID_RESERVATION
    in /tmp/sai.profile) one session less is created.
    Only ERSPAN sessions are used.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    reservation = hw_id_reservation_line(duthost, label_asic)
    session_count = label_max_sessions - 1 if reservation else label_max_sessions
    logger.info("--label_max_sessions=%d, SAI profile reservation line: %s -> creating %d sessions",
                label_max_sessions, reservation, session_count)
    pytest_assert(session_count >= 1, "No session slot left after the SAI profile reservation")
    names = []
    baseline = len(asic_db_mirror_objects(label_asic))

    for index in range(session_count):
        name = "{}scale{}".format(SESSION_PREFIX, index)
        create_erspan_session(duthost, name, erspan_dst_ip(index), label="S{}".format(index))
        names.append(name)

    wait_sessions_active(label_asic, names)
    objects = asic_db_mirror_objects(label_asic)
    pytest_assert(len(objects) == baseline + session_count,
                  "Expected {} ASIC_DB objects, got {}".format(baseline + session_count, len(objects)))
    for index, name in enumerate(names):
        assert_label_in_all_layers(duthost, label_asic, name, "S{}".format(index))
    # every label sits on the ASIC_DB object of its own session (each session has its own destination)
    expected = {erspan_dst_ip(i): "S{}".format(i) for i in range(session_count)}
    actual = {dst: label for dst, label in asic_db_label_by_dst(label_asic).items() if dst in expected}
    pytest_assert(actual == expected,
                  "ASIC_DB label does not belong to its session: expected {}, got {}".format(expected, actual))
    pytest_assert(len(set(asic_db_labels(label_asic))) == len(asic_db_labels(label_asic)),
                  "Duplicate labels in ASIC_DB")
