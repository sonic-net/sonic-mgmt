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


def _mode(request):
    mode = getattr(request.cls, "STP_MODE", None)
    py_assert(mode in (stp_base.PVST, stp_base.MST),
              "test class must set STP_MODE to 'pvst' or 'mst' (got {!r})".format(mode))
    return mode


@pytest.fixture(scope="module", autouse=True)
def check_stp_feature_status(duthost):
    """Ensure the STP feature is enabled. The image ships it `disabled` by
    default, so enable it (and wait for the container) rather than skipping;
    only skip when the feature is genuinely absent."""
    feature_status = duthost.show_and_parse("show feature status")
    stp = next((f for f in feature_status if f["feature"] == "stp"), None)
    if not stp:
        pytest.skip("STP feature is not present in this image")
    if stp["state"] != "enabled":
        duthost.shell("sudo config feature state stp enabled", module_ignore_errors=True)
        py_assert(
            wait_until(60, 3, 0, lambda: any(
                f["feature"] == "stp" and f["state"] == "enabled"
                for f in duthost.show_and_parse("show feature status"))),
            "STP feature did not reach 'enabled'")
        py_assert(
            wait_until(60, 3, 0, lambda: "stp" in duthost.shell(
                "docker ps --format '{{.Names}}'", module_ignore_errors=True).get("stdout", "")),
            "stp container did not come up after enabling the feature")


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


@pytest.fixture
def stp_config_env(request, duthosts, rand_one_dut_hostname, tbinfo):
    """Per-test topology for the config/enrolment tests (test_*_config.py): the
    minigraph default VLAN (VLAN A) with >=4 physical members, plus a spare VLAN
    id (VLAN B) these tests create. Establishes the baseline (STP feature enabled
    + the class's STP mode enabled) and clears any leftover VLAN B / stray
    membership on both setup and teardown. Mode-agnostic; the caller supplies the
    per-mode scope (CIST 0 for MST, VLAN id for PVST)."""
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

    existing_vids = {int(v["vlanid"]) for v in mg_facts["minigraph_vlans"].values()}
    vlan_b = next((v for v in CANDIDATE_VLAN_B if v != vlan_a and v not in existing_vids), None)
    py_assert(vlan_b is not None, "no spare VLAN id available for VLAN B")

    def _clean():
        # remove any residue from a prior/aborted run and put the 4 ports back
        # as untagged members of VLAN A
        for p in ports:
            duthost.shell("config vlan member del {} {}".format(vlan_b, p), module_ignore_errors=True)
        duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)
        for p in ports:
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p),
                          module_ignore_errors=True)

    _clean()
    # baseline: feature up + the class's STP mode enabled. Clear whatever mode is
    # currently active first -- `config spanning-tree enable pvst` hard-fails when
    # the box is already in `mst` (and vice versa), so without this a box left in
    # the other mode by a prior run would silently stay there and every check
    # against this mode's tables would fail.
    duthost.shell("config feature state stp enabled", module_ignore_errors=True)
    wait_until(90, 3, 0, lambda: "stp" in duthost.shell(
        "docker ps --format '{{.Names}}'", module_ignore_errors=True).get("stdout", ""))
    duthost.shell("config spanning-tree disable mst", module_ignore_errors=True)
    duthost.shell("config spanning-tree disable pvst", module_ignore_errors=True)
    stp_base.enable_stp(duthost, mode)
    py_assert(
        wait_until(30, 2, 0, lambda: duthost.shell(
            "redis-cli -n 4 hget 'STP|GLOBAL' mode",
            module_ignore_errors=True).get("stdout", "").strip() == mode),
        "STP mode did not switch to {} (another mode still active?)".format(mode))

    yield {"vlan_a": vlan_a, "vlan_b": vlan_b, "ports": ports}

    _clean()
