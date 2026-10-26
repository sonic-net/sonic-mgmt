"""
Shared fixtures for the mode-parameterized STP tests. The active protocol is
read from the test class's `STP_MODE` (set by `TestPvst` / `TestMstp`), so one
conftest drives both.
"""
import logging

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
# session-autouse fixture: copies ansible/.../ptftests to the PTF host so
# ptf_runner can find `ptftests/py3/*` (mstp_bpdu_test, mstp_lib, stp_bpdu_base).
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401
from tests.stp import stp_base
from tests.stp import stp_utils

logger = logging.getLogger(__name__)

# MST region used by the MST tests (name/revision are matched by the PTF so the
# config digest lines up; VLAN under test is mapped to instance 1).
MST_REGION_NAME = "sonic-test-region"
MST_REVISION = 1
MST_TEST_INSTANCE = 1

# Spare VLAN ids the config/enrolment tests (test_*_config.py) create as "VLAN B".
CANDIDATE_VLAN_B = [2000, 2100, 3000, 3100]

# Spare PortChannel names those tests create. High numbers, so they do not
# collide with the minigraph's PortChannel0001..000N.
CANDIDATE_PORTCHANNEL = ["PortChannel990", "PortChannel991", "PortChannel992"]


def _mode(request):
    mode = getattr(request.cls, "STP_MODE", None)
    py_assert(mode in (stp_base.PVST, stp_base.MST),
              "test class must set STP_MODE to 'pvst' or 'mst' (got {!r})".format(mode))
    return mode


@pytest.fixture(scope="module", autouse=True)
def check_stp_feature_status(duthost):
    """Ensure the STP feature is enabled. The image ships it `disabled` by
    default, so enable it (and wait for the container) rather than skipping;
    only skip when the feature is genuinely absent. Afterwards put every
    STP-owned CONFIG_DB row back as the module found it: a disable keeps the
    configuration, so the tests' own teardowns leave rows behind."""
    before = stp_base.snapshot_stp_config(duthost)
    feature_status = duthost.show_and_parse("show feature status")
    stp = next((f for f in feature_status if f["feature"] == "stp"), None)
    if not stp:
        pytest.skip("STP feature is not present in this image")
    if stp["state"] != "enabled" or not stp_base.stp_container_up(duthost):
        # `config reload` restores FEATURE|stp to the image default (disabled),
        # masks the stp container, and bounces featured; a plain enable during
        # that window is dropped. ensure_stp_feature_up() waits for featured,
        # enables, and force-starts the container if needed.
        py_assert(stp_base.ensure_stp_feature_up(duthost),
                  "stp container did not come up after enabling the feature")
    yield
    left = stp_base.restore_stp_config(duthost, before)
    if left:
        logger.warning("STP CONFIG_DB rows not restored: %s", left)


@pytest.fixture(scope="module", autouse=True)
def setup_stp_test_data(duthosts, rand_one_dut_hostname, tbinfo):
    """DUT/PTF port mapping, VLAN under test, MACs, and the MST region config."""
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    _vlan_name, vlan_info = list(mg_facts["minigraph_vlans"].items())[0]
    vlan_members = sorted((p for p in vlan_info["members"] if "Ethernet" in p),
                          key=lambda x: int(x.replace("Ethernet", "")))
    dut_port_1, dut_port_2 = vlan_members[0], vlan_members[1]

    ptf_indices = mg_facts["minigraph_ptf_indices"]
    vlan_id = int(vlan_info["vlanid"])

    host_facts = duthost.setup()["ansible_facts"]
    intf_mac_map = {
        k.replace("ansible_", ""): v["macaddress"]
        for k, v in host_facts.items()
        if k.startswith("ansible_") and isinstance(v, dict) and "macaddress" in v
    }

    return {
        "vlan": {"id": vlan_id},
        "dut_ports": {
            "dut_port_1": dut_port_1, "ptf_port_1": ptf_indices[dut_port_1],
            "dut_port_2": dut_port_2, "ptf_port_2": ptf_indices[dut_port_2],
            "mac": intf_mac_map.get(dut_port_1),
        },
        "mst": {
            "region_name": MST_REGION_NAME,
            "revision": MST_REVISION,
            "instance": MST_TEST_INSTANCE,
            # This build supports only the CIST (instance 0); MSTIs beyond the
            # CIST can't be created (no CLI path, and stpd ignores a direct
            # CONFIG_DB instance write). So we configure a region name/revision
            # but map no VLAN to an MSTI — the DUT's config digest stays the
            # empty-region digest, and the PTF must advertise the same (empty
            # vid_to_mstid) to be treated as in-region. All CIST tests use
            # instance 0. (MSTI mapping tracked as a product gap.)
            "instance_vlan_map": {},
            "vid_to_mstid": {},
        },
    }


@pytest.fixture(scope="class", autouse=True)
def enable_stp_and_verify(request, duthosts, rand_one_dut_hostname, setup_stp_test_data):
    """Enable the class's STP mode (+ MST region), verify it applied, and clean up."""
    mode = _mode(request)
    duthost = duthosts[rand_one_dut_hostname]

    # `config spanning-tree enable pvst` hard-fails when the box is already in
    # `mst` (and vice versa), so clear whatever mode a prior run left active
    # before enabling this class's mode -- otherwise the box silently stays in
    # the wrong mode and every table check fails.
    duthost.shell("config spanning-tree disable mst", module_ignore_errors=True)
    duthost.shell("config spanning-tree disable pvst", module_ignore_errors=True)
    stp_base.enable_stp(duthost, mode)
    if mode == stp_base.MST:
        mst = setup_stp_test_data["mst"]
        stp_base.setup_region(duthost, mode, mst["region_name"], mst["revision"],
                              mst["instance_vlan_map"])

    py_assert(
        wait_until(30, 2, 0, lambda: duthost.shell(
            "redis-cli -n 4 hget 'STP|GLOBAL' mode",
            module_ignore_errors=True).get("stdout", "").strip() == mode),
        "STP mode did not switch to {} (another mode still active?)".format(mode))

    # Port enrolment: sonic-stp creates a port's operational state on a
    # VLAN_MEMBER *add* event. VLAN members that pre-existed the STP-mode enable
    # are not re-enrolled by the enable (nor by an stp restart), so bounce the
    # test ports' membership to make the daemon materialise their port rows.
    # (Tracked separately as a product gap: enrolment should happen on enable.)
    #
    # Without this, a box whose STP feature has been up since an earlier session
    # keeps the stale `_STP_VLAN_PORT_TABLE` rows that session left behind: they
    # read FORWARDING forever and never follow the state machine, so
    # `test_*_validate_root_bridge` never observes LISTENING. Once the ports are
    # enrolled, a plain mode bounce does drive LISTENING -> LEARNING ->
    # FORWARDING correctly.
    vlan_id = setup_stp_test_data["vlan"]["id"]
    test_ports = [setup_stp_test_data["dut_ports"]["dut_port_1"],
                  setup_stp_test_data["dut_ports"]["dut_port_2"]]
    enrol_scope = 0 if mode == stp_base.MST else vlan_id  # CIST for MST
    for port in test_ports:
        duthost.shell("config vlan member del {} {}".format(vlan_id, port), module_ignore_errors=True)
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_id, port),
                      module_ignore_errors=True)
    # The re-add must be seen by orchagent before any test sends traffic. In the
    # window where CONFIG_DB has the member back but APPL_DB does not, hardware
    # still floods and learns, while fdborch drops the learn events for a port it
    # no longer considers a member: frames forward but `show mac` never learns,
    # which reads as a MAC-learning defect.
    for port in test_ports:
        stp_utils.assert_member_ready(
            duthost,
            wait_until(30, 2, 0, lambda p=port: duthost.shell(
                "redis-cli -n 0 exists 'VLAN_MEMBER_TABLE:Vlan{}:{}'".format(vlan_id, p),
                module_ignore_errors=True).get("stdout", "").strip() == "1"),
            "VLAN member {} did not reach APPL_DB after the membership bounce".format(port))
    for port in test_ports:
        if not wait_until(60, 2, 0,
                          lambda p=port: stp_utils.get_port_data(duthost, mode, enrol_scope, p) != {}):
            logger.warning(
                "STP did not enrol %s (%s scope %s) after the VLAN-membership bounce; "
                "continuing anyway -- tests needing port state will report it themselves ",
                port, mode, enrol_scope)

    yield

    if mode == stp_base.MST:
        stp_base.teardown_region(duthost, mode, setup_stp_test_data["mst"]["instance_vlan_map"])
    stp_base.disable_stp(duthost, mode)


def _run(duthost, cmd, tolerate=False):
    """Run a config command and fail loudly unless the caller says otherwise."""
    res = duthost.shell(cmd, module_ignore_errors=True)
    if res.get("rc", 0) != 0:
        msg = "command failed: {} (rc={}, stderr={!r})".format(
            cmd, res.get("rc"), (res.get("stderr") or "").strip())
        if tolerate:
            logger.warning("%s", msg)
        else:
            py_assert(False, msg)
    return res


def _vlan_ids_on_dut(duthost):
    """VLAN ids actually configured on the switch, from CONFIG_DB.

    The minigraph only describes how the testbed was built, so anything
    created outside it is invisible there.
    """
    out = duthost.shell("redis-cli -n 4 keys 'VLAN|Vlan*'",
                        module_ignore_errors=True).get("stdout", "")
    vids = set()
    for key in out.splitlines():
        name = key.strip().split("|")[-1]
        if name.startswith("Vlan") and name[4:].isdigit():
            vids.add(int(name[4:]))
    return vids


def _portchannels_on_dut(duthost):
    """PortChannel names actually configured on the switch, from CONFIG_DB."""
    out = duthost.shell("redis-cli -n 4 keys 'PORTCHANNEL|PortChannel*'",
                        module_ignore_errors=True).get("stdout", "")
    return {key.strip().split("|")[-1] for key in out.splitlines() if key.strip()}


def _port_memberships(duthost, ports):
    """{port: {vlan_id: tagging_mode}} for these ports, read from CONFIG_DB."""
    out = duthost.shell("redis-cli -n 4 keys 'VLAN_MEMBER|*'",
                        module_ignore_errors=True).get("stdout", "")
    wanted = set(ports)
    memberships = {p: {} for p in ports}
    for key in out.splitlines():
        key = key.strip()
        parts = key.split("|")
        if len(parts) != 3:
            continue
        _table, vlan_name, port = parts
        if port not in wanted or not vlan_name[4:].isdigit():
            continue
        mode = duthost.shell("redis-cli -n 4 hget '{}' tagging_mode".format(key),
                             module_ignore_errors=True).get("stdout", "").strip()
        memberships[port][int(vlan_name[4:])] = mode or "untagged"
    return memberships


def _restore_memberships(duthost, before, now):
    """Put each port back exactly as it was found, tagging included."""
    for port, wanted in before.items():
        current = now.get(port, {})
        for vlan, mode in sorted(current.items()):
            if wanted.get(vlan) != mode:
                _run(duthost, "config vlan member del {} {}".format(vlan, port), tolerate=True)
        for vlan, mode in sorted(wanted.items()):
            if current.get(vlan) != mode:
                flag = " --untagged" if mode == "untagged" else ""
                _run(duthost, "config vlan member add {} {}{}".format(vlan, port, flag))


def _delete_vlan(duthost, vlan_id):
    """Remove a VLAN this fixture created, members first."""
    out = duthost.shell("redis-cli -n 4 keys 'VLAN_MEMBER|Vlan{}|*'".format(vlan_id),
                        module_ignore_errors=True).get("stdout", "")
    for key in out.splitlines():
        parts = key.strip().split("|")
        if len(parts) == 3:
            _run(duthost, "config vlan member del {} {}".format(vlan_id, parts[2]), tolerate=True)
    _run(duthost, "config vlan del {}".format(vlan_id))


@pytest.fixture
def stp_config_env(request, duthosts, rand_one_dut_hostname, tbinfo):
    """Per-test topology for the config/enrolment tests (test_*_config.py): the
    minigraph default VLAN (VLAN A) with >=4 physical members, plus a spare VLAN
    id (VLAN B) these tests create. Establishes the baseline (STP feature enabled
    + the class's STP mode enabled). Mode-agnostic; the caller supplies the
    per-mode scope (CIST 0 for MST, VLAN id for PVST).

    Only ever removes what it created: VLAN B comes from ids unconfigured on
    the switch, and each port's real pre-state is restored. Teardown fails the
    module if the switch does not match what it found.
    """
    mode = _mode(request)
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    vlan_info = next(iter(mg_facts["minigraph_vlans"].values()))
    vlan_a = int(vlan_info["vlanid"])
    members = sorted((p for p in vlan_info["members"] if p.startswith("Ethernet")),
                     key=lambda p: int(p.replace("Ethernet", "")))
    if len(members) < 4:
        pytest.skip("need >=4 VLAN member ports for the STP config tests, have {}".format(len(members)))
    ports = members[:4]

    # Ask the switch, not just the minigraph: a VLAN configured outside the
    # minigraph is invisible there and must still count as taken.
    taken = _vlan_ids_on_dut(duthost) | {int(v["vlanid"]) for v in mg_facts["minigraph_vlans"].values()}
    vlan_b = next((v for v in CANDIDATE_VLAN_B if v != vlan_a and v not in taken), None)
    if vlan_b is None:
        pytest.skip(
            "no spare VLAN id available for VLAN B; candidates {} are all in use on {}".format(
                CANDIDATE_VLAN_B, duthost.hostname))

    # Whatever the tests do to these ports, this is what they go back to.
    before = _port_memberships(duthost, ports)
    logger.info("stp_config_env: VLAN A %s, VLAN B %s, ports %s, pre-state %s",
                vlan_a, vlan_b, ports, before)

    # The config tests assume the minigraph shape, every port a member of
    # VLAN A. Drift left by an earlier failed teardown is reported here, where
    # it is first seen, instead of as a product failure in the next test.
    drifted = [p for p in ports if vlan_a not in before[p]]
    if drifted:
        pytest.fail("{} are not members of VLAN {} on {}; the testbed has drifted from "
                    "its minigraph baseline".format(drifted, vlan_a, duthost.hostname),
                    pytrace=False)

    # baseline: feature up + the class's STP mode enabled. Clear whatever mode is
    # currently active first -- `config spanning-tree enable pvst` hard-fails when
    # the box is already in `mst` (and vice versa), so without this a box left in
    # the other mode by a prior run would silently stay there and every check
    # against this mode's tables would fail.
    py_assert(stp_base.ensure_stp_feature_up(duthost),
              "stp container did not come up after enabling the feature")
    duthost.shell("config spanning-tree disable mst", module_ignore_errors=True)
    duthost.shell("config spanning-tree disable pvst", module_ignore_errors=True)
    stp_base.enable_stp(duthost, mode)
    py_assert(
        wait_until(30, 2, 0, lambda: duthost.shell(
            "redis-cli -n 4 hget 'STP|GLOBAL' mode",
            module_ignore_errors=True).get("stdout", "").strip() == mode),
        "STP mode did not switch to {} (another mode still active?)".format(mode))

    yield {"vlan_a": vlan_a, "vlan_b": vlan_b, "ports": ports}

    # It did not exist at setup, so if it exists now the test made it. A
    # failed delete must not skip the membership restore or the check below.
    try:
        if vlan_b in _vlan_ids_on_dut(duthost):
            _delete_vlan(duthost, vlan_b)
    finally:
        _restore_memberships(duthost, before, _port_memberships(duthost, ports))

        after = _port_memberships(duthost, ports)
        py_assert(after == before,
                  "stp_config_env left the DUT changed.\n  before: {}\n  after:  {}".format(before, after))


@pytest.fixture
def spare_portchannel(duthosts, rand_one_dut_hostname):
    """A PortChannel name that does not exist on the switch, for tests that
    create and delete one.

    Teardown removes whatever the test left: VLAN membership first (a PortChannel
    with one cannot be deleted), then the interface. The STP row is dropped last
    and directly, because a row outliving its interface is the very thing under
    test here, and a failing test must not hand the next one a stale one.
    """
    duthost = duthosts[rand_one_dut_hostname]
    taken = _portchannels_on_dut(duthost)
    name = next((pc for pc in CANDIDATE_PORTCHANNEL if pc not in taken), None)
    if name is None:
        pytest.skip("no spare PortChannel name available; candidates {} are all in use on {}".format(
            CANDIDATE_PORTCHANNEL, duthost.hostname))
    logger.info("spare_portchannel: using %s on %s", name, duthost.hostname)

    yield name

    if name in _portchannels_on_dut(duthost):
        out = duthost.shell("redis-cli -n 4 keys 'VLAN_MEMBER|*|{}'".format(name),
                            module_ignore_errors=True).get("stdout", "")
        for key in out.splitlines():
            parts = key.strip().split("|")
            if len(parts) == 3 and parts[1][4:].isdigit():
                _run(duthost, "config vlan member del {} {}".format(parts[1][4:], name), tolerate=True)
        _run(duthost, "config portchannel del {}".format(name), tolerate=True)

    for table in ("STP_PORT", "STP_VLAN_PORT"):
        out = duthost.shell("redis-cli -n 4 keys '{}|*{}'".format(table, name),
                            module_ignore_errors=True).get("stdout", "")
        for key in out.splitlines():
            if key.strip().split("|")[-1] == name:
                _run(duthost, "redis-cli -n 4 del '{}'".format(key.strip()), tolerate=True)
