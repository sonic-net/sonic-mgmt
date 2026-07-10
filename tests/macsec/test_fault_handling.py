import time
import json
import re
from time import sleep
import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_helper import get_appl_db, getns_prefix, get_ipnetns_prefix
from tests.common.macsec.macsec_config_helper import disable_macsec_port, \
    enable_macsec_port, delete_macsec_profile, set_macsec_profile
from tests.common.macsec.macsec_platform_helper import get_eth_ifname, find_portchannel_from_member, \
    get_portchannel

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "lrh", "urh", "t0-sonic"),
]


def find_lag_member_key(duthost, port_name):
    """Return (ns, asic_db_key) for `port_name`'s SAI LAG member, or (ns, None) if it
    cannot be resolved. Scans ASIC_DB, so callers should cache the key and only re-resolve
    when it goes stale (see read_lag_member_disable).
    """
    ns = getns_prefix(duthost, port_name)
    port_oid = duthost.shell(
        "sonic-db-cli {} COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP {}".format(ns, port_name),
        module_ignore_errors=True)["stdout"].strip()
    if not port_oid:
        return ns, None
    member_keys = duthost.shell(
        "sonic-db-cli {} ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:*'".format(ns),
        module_ignore_errors=True)["stdout_lines"]
    for key in member_keys:
        pid = duthost.shell(
            "sonic-db-cli {} ASIC_DB HGET '{}' SAI_LAG_MEMBER_ATTR_PORT_ID".format(ns, key),
            module_ignore_errors=True)["stdout"].strip()
        if pid == port_oid:
            return ns, key
    return ns, None


def read_lag_member_disable(duthost, ns, key):
    """Return (egress_disabled, ingress_disabled) for a cached ASIC_DB LAG-member key, or
    None if the key no longer exists (member deleted/recreated -> caller re-resolves).

    This reflects what orchagent programmed into the hardware, independent of teamd's LACP
    view. teamd keeps a member deselected whenever MACsec is down (LACP PDUs are dropped),
    so teamd state cannot reveal whether orchagent wrongly re-enabled the member; ASIC_DB
    can. The PORT_ID read doubles as a staleness check, since an absent disable attribute
    and a deleted key both read as empty.
    """
    if not duthost.shell(
            "sonic-db-cli {} ASIC_DB HGET '{}' SAI_LAG_MEMBER_ATTR_PORT_ID".format(ns, key),
            module_ignore_errors=True)["stdout"].strip():
        return None
    egress = duthost.shell(
        "sonic-db-cli {} ASIC_DB HGET '{}' SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE".format(ns, key),
        module_ignore_errors=True)["stdout"].strip()
    ingress = duthost.shell(
        "sonic-db-cli {} ASIC_DB HGET '{}' SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE".format(ns, key),
        module_ignore_errors=True)["stdout"].strip()
    return (egress == "true", ingress == "true")


def push_lag_member_status(duthost, pc_name, port_name, status):
    """Inject a LAG_MEMBER_TABLE status update into APPL_DB via swssconfig, mimicking a
    teamsyncd refresh. Used to deterministically reproduce the teamsyncd re-enable race.
    """
    asic_idx = ""
    if duthost.is_multi_asic:
        asic_idx = duthost.get_port_asic_instance(port_name).asic_index
    cfg = [{"LAG_MEMBER_TABLE:{}:{}".format(pc_name, port_name): {"status": status}, "OP": "SET"}]
    tmp = duthost.shell("mktemp")["stdout"].strip()
    duthost.copy(content=json.dumps(cfg), dest=tmp, verbose=False)
    duthost.docker_exec_swssconfig("/dev/stdin < {}".format(tmp), "swss", asic_idx)


def lag_member_disabled(duthost, port_name):
    """(egress_disabled, ingress_disabled) for `port_name`'s SAI LAG member, or None if it
    cannot be resolved. Uncached convenience wrapper for coarse sampling."""
    ns, key = find_lag_member_key(duthost, port_name)
    if key is None:
        return None
    return read_lag_member_disable(duthost, ns, key)


def teamd_member_selected(duthost, pc_name, port_name):
    """teamd's view: is `port_name` currently a selected member of `pc_name`?"""
    try:
        state = duthost.get_port_channel_status(pc_name)
        return state["ports"][port_name]["runner"]["selected"]
    except Exception as e:
        logger.debug("teamdctl read for %s/%s failed: %s", pc_name, port_name, e)
        return False


def portchannel_status(duthost, port_name):
    """PortChannel oper status ('Up'/'Dw') for the LAG that owns `port_name`, or None."""
    pc = find_portchannel_from_member(port_name, get_portchannel(duthost))
    return pc["status"] if pc else None


def bgp_session_established(duthost, port_name, upstream_links):
    """Is the BGP session over `port_name`'s PortChannel Established? None if no BGP link.

    HGET the single `state` field so an absent NEIGH_STATE_TABLE entry reads as an empty
    string (not Established) without swallowing genuine sonic-db-cli/connection errors.
    """
    up_link = upstream_links.get(port_name)
    if not up_link:
        return None
    cmd = ("sonic-db-cli {} STATE_DB HGET 'NEIGH_STATE_TABLE|{}' state"
           .format(getns_prefix(duthost, port_name), up_link["local_ipv4_addr"]))
    return duthost.shell(cmd)["stdout"].strip() == "Established"


def macsec_lag_disable_log_count(duthost, port_name):
    """Count swss log lines where the fix disabled or flapped `port_name`'s LAG member
    because MACsec went down. A healthy rekey must not add any new such lines."""
    cmd = ("show logging | grep -E "
           "'MACsec disabled LAG member {p}|Flapping host interface {p} .*MACsec down' | wc -l"
           .format(p=port_name))
    return int(duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip() or 0)


def _valid_appl_db_entry(entry):
    """True for a populated sonic-db-cli HGETALL dict; empty/Null reads as absent."""
    return bool(entry) and entry != {'Null': 'Null'}


def macsec_crypto_plane_down(duthost, port_name, nbr):
    """Return True when the MKA crypto plane is torn down on `port_name`.

    STATE_MACSEC_PORT_TABLE can remain state=ok after SC/SA deletion on hardware;
    check APPL_DB as well as iface_macsec_ok.
    """
    if not duthost.iface_macsec_ok(port_name):
        return True
    try:
        _, egress_sc, ingress_sc, egress_sa, ingress_sa = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
    except Exception:
        return False
    sc_up = _valid_appl_db_entry(egress_sc) and _valid_appl_db_entry(ingress_sc)
    sa_up = bool(egress_sa) and bool(ingress_sa)
    return not (sc_up and sa_up)


def pick_ctrl_lag_port(ctrl_links, portchannels, want_single, duthost=None):
    """Pick a MACsec control-link port on a LAG with the requested member count.

    When duthost is given, prefer a port whose LAG is already Up and whose member is
    teamd-selected. Multi-member LAGs (e.g. PortChannel101 / VM01LT2) can lag MACsec
    session establishment after a profile module switch.
    """
    candidates = []
    for p in ctrl_links:
        pc = find_portchannel_from_member(p, portchannels)
        if pc and (len(pc["members"]) == 1) == want_single:
            candidates.append((p, pc["name"], pc))
    if not candidates:
        return None, None, []
    if duthost is not None:
        for p, pc_name, _pc in candidates:
            if (portchannel_status(duthost, p) == "Up"
                    and teamd_member_selected(duthost, pc_name, p)):
                return p, pc_name, candidates
    return candidates[0][0], candidates[0][1], candidates


class TestFaultHandling():
    MKA_TIMEOUT = 6
    LACP_TIMEOUT = 90

    @pytest.mark.disable_loganalyzer
    def test_link_flap(self, duthost, ctrl_links, wait_mka_establish):
        # Only pick one link for link flap test
        assert ctrl_links, (
            "No control links found. Expected at least one control link, but got {}.\n"
            "Actual ctrl_links: {}"
        ).format(len(ctrl_links), ctrl_links)

        port_name, nbr = list(ctrl_links.items())[0]
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])
        _, _, _, dut_egress_sa_table_orig, dut_ingress_sa_table_orig = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])

        # Flap < 6 seconds
        # Not working on eos neighbour
        if not isinstance(nbr["host"], EosHost):
            # Rekey may happen during the following assertions, so we need to get the SA tables again
            retry = 3
            while retry > 0:
                retry -= 1
                try:
                    nbr["host"].shell("config interface shutdown {}  && sleep 1 && config interface startup {}".format(
                        nbr["port"], nbr["port"]))
                    _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
                        duthost, port_name, nbr["host"], nbr["port"])
                    assert dut_egress_sa_table_orig == dut_egress_sa_table_new, (
                        "DUT egress SA table mismatch. Original table: {}, New table: {}. "
                    ).format(dut_egress_sa_table_orig, dut_egress_sa_table_new)

                    assert dut_ingress_sa_table_orig == dut_ingress_sa_table_new, (
                        "DUT ingress SA table mismatch. Original table: {}, New table: {}. "
                    ).format(dut_ingress_sa_table_orig, dut_ingress_sa_table_new)
                    break
                except AssertionError as e:
                    if retry == 0:
                        raise e
                    # This test may fail due to the lag of DUT exceeding MKA_TIMEOUT that triggers a rekey.
                    # To mitigate this, retry the test after a while with a few seconds of idle time.
                    sleep(30)
                dut_egress_sa_table_orig, dut_ingress_sa_table_orig = dut_egress_sa_table_new, dut_ingress_sa_table_new

        # Flap > 6 seconds but < 90 seconds
        if isinstance(nbr["host"], EosHost):
            nbr["host"].shutdown(nbr_eth_port)
            sleep(TestFaultHandling.MKA_TIMEOUT)
            nbr["host"].no_shutdown(nbr_eth_port)
        else:
            nbr["host"].shell("config interface shutdown {}  && sleep {} && config interface startup {}".format(
                nbr["port"], TestFaultHandling.MKA_TIMEOUT, nbr["port"]))

        def check_new_mka_session():
            _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            assert dut_egress_sa_table_new, (
                "DUT egress SA table is empty. Expected non-empty table, but got {}. "
            ).format(dut_egress_sa_table_new)
            assert dut_ingress_sa_table_new, (
                "DUT ingress SA table is empty. Expected non-empty table, but got {}. "
            ).format(dut_ingress_sa_table_new)
            assert dut_egress_sa_table_orig != dut_egress_sa_table_new, (
                "DUT egress SA table remains the same. Original table: {}, New table: {}. "
                "Expected tables to be different, but they are identical. "
            ).format(dut_egress_sa_table_orig, dut_egress_sa_table_new)
            assert dut_ingress_sa_table_orig != dut_ingress_sa_table_new, (
                "DUT ingress SA table remains the same. Original table: {}, New table: {}. "
                "Expected tables to be different, but they are identical. "
            ).format(dut_ingress_sa_table_orig, dut_ingress_sa_table_new)
            return True
        assert wait_until(30, 5, 2, check_new_mka_session), (
            "New MKA session not established within expected time. ")

        # Flap > 90 seconds
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up"), (
            "Portchannel {} did not come up within expected time. "
            "Portchannel status: {} "
            "Find portchannel from member: {} "
        ).format(
            port_name,
            find_portchannel_from_member(port_name, get_portchannel(duthost))["status"],
            find_portchannel_from_member(port_name, get_portchannel(duthost))
        )

        if isinstance(nbr["host"], EosHost):
            nbr["host"].shutdown(nbr_eth_port)
            sleep(TestFaultHandling.LACP_TIMEOUT)
        else:
            nbr["host"].shell("ifconfig {} down && sleep {}".format(
                nbr_eth_port, TestFaultHandling.LACP_TIMEOUT))
        assert wait_until(6, 1, 0, lambda: find_portchannel_from_member(
                    port_name, get_portchannel(duthost))["status"] == "Dw"), (
            "Portchannel {} did not go down within expected time. "
            "Portchannel status: {} "
            "Find portchannel from member: {} "
        ).format(
            port_name,
            find_portchannel_from_member(port_name, get_portchannel(duthost))["status"],
            find_portchannel_from_member(port_name, get_portchannel(duthost))
        )

        if isinstance(nbr["host"], EosHost):
            nbr["host"].no_shutdown(nbr_eth_port)
        else:
            nbr["host"].shell("ifconfig {} up".format(nbr_eth_port))
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up"), (
            "Portchannel {} did not come up within expected time. "
            "Portchannel status: {} "
            "Find portchannel from member: {} "
        ).format(
            port_name,
            find_portchannel_from_member(port_name, get_portchannel(duthost))["status"],
            find_portchannel_from_member(port_name, get_portchannel(duthost))
        )

    @pytest.mark.disable_loganalyzer
<<<<<<< HEAD
    def test_mismatch_macsec_configuration(self, duthost, unctrl_links, port_profiles,
=======
    @pytest.mark.parametrize("lag_kind", ["single_member", "multi_member"])
    def test_macsec_down_disables_lag_member(self, duthost, ctrl_links,
                                             upstream_links, lag_kind, wait_mka_establish):
        """Blocking inbound EAPOL (ethertype 0x888e, which carries MKA PDUs) on the DUT's
        ingress expires the MKA session within MKA_TIMEOUT (~6s) while the link stays
        physically up. The DUT can no longer receive peer MKA hellos, so its session times
        out without depending on the neighbor OS.
        orchagent must then disable the LAG member's collection/distribution and flap the
        host interface so teamd drops the member immediately -- instead of waiting for the
        90s LACP timeout -- and must keep it down (a teamsyncd APP_LAG_MEMBER_TABLE refresh
        must not silently re-enable it while MACsec is down). For a single-member LAG the
        whole PortChannel goes down, which withdraws the BGP session over it; for a
        multi-member LAG the PortChannel stays up on the other members, so BGP must NOT be
        affected. Removing the block lets MACsec recover so the member, LAG and BGP come back.
        """
        assert ctrl_links, (
            "No control links found. Actual ctrl_links: {}".format(ctrl_links))

        # Pick a control-link port whose PortChannel has the requested membership, using the
        # live member list from `show interfaces portchannel`. (minigraph_portchannels can be
        # stale or renamed vs the runtime LAG, which previously made the multi-member case
        # skip.) A single-member LAG lets us assert the LAG (and therefore BGP) goes down; a
        # multi-member LAG exercises the per-member path while the LAG stays up.
        want_single = lag_kind == "single_member"
        portchannels = get_portchannel(duthost)
        port_name, pc_name, _lag_members = pick_ctrl_lag_port(
            ctrl_links, portchannels, want_single, duthost)
        ctrl_lags = {p: find_portchannel_from_member(p, portchannels) for p in ctrl_links}
        if port_name is None:
            ctrl_lag_summary = {
                p: (pc["name"], pc["members"]) if pc else None for p, pc in ctrl_lags.items()}
            multi_member_pcs = {
                pc["name"]: pc["members"]
                for pc in portchannels.values() if len(pc["members"]) > 1}
            logger.info("No %s control-link LAG found. ctrl_link -> (portchannel, members): %s; "
                        "multi-member LAGs on DUT (not necessarily MACsec control links): %s",
                        lag_kind, ctrl_lag_summary, multi_member_pcs)
            if not want_single and multi_member_pcs:
                pytest.skip(
                    "No MACsec control link sits on a multi-member PortChannel. "
                    "Control links map to: {}. Multi-member LAGs on DUT: {}. "
                    "Enable MACsec on an LT2 LAG member (e.g. VM01LT2 / PortChannel101)."
                    .format(ctrl_lag_summary, multi_member_pcs))
            pytest.skip("No {} control-link PortChannel available on this testbed.".format(lag_kind))

        nbr = ctrl_links[port_name]
        dut_eth_port = get_eth_ifname(duthost, port_name)

        def member_selected():
            return teamd_member_selected(duthost, pc_name, port_name)

        def lag_status():
            return portchannel_status(duthost, port_name)

        def bgp_established():
            return bgp_session_established(duthost, port_name, upstream_links)

        # Resolve the ASIC_DB LAG-member key once (the member object persists across
        # enable/disable) so the polling loops below don't rescan ASIC_DB every poll;
        # re-resolve lazily only if the cached key goes stale (member recreated).
        asic_ns, asic_member_key = find_lag_member_key(duthost, port_name)

        def asic_disable_state():
            """(egress_disabled, ingress_disabled) for the member at the ASIC, or None."""
            nonlocal asic_ns, asic_member_key
            if asic_member_key is None:
                asic_ns, asic_member_key = find_lag_member_key(duthost, port_name)
                if asic_member_key is None:
                    return None
            st = read_lag_member_disable(duthost, asic_ns, asic_member_key)
            if st is None:  # cached key went stale -> re-resolve once
                asic_ns, asic_member_key = find_lag_member_key(duthost, port_name)
                if asic_member_key is None:
                    return None
                st = read_lag_member_disable(duthost, asic_ns, asic_member_key)
            return st

        # BGP behaviour differs by LAG cardinality (single-member: session drops; multi-member:
        # session must stay up). check_bgp just gates on whether this link carries a BGP session.
        check_bgp = upstream_links.get(port_name) is not None
        if not check_bgp:
            logger.info("PortChannel %s has no upstream BGP link; skipping BGP checks.", pc_name)

        # --- Preconditions: MACsec up, member selected, LAG up, (BGP up). ---
        assert duthost.iface_macsec_ok(port_name), (
            "MACsec session on {} is not up before the test.".format(port_name))
        # Multi-member LAGs on LT2 links can take up to LACP_TIMEOUT to converge after a
        # prior test or macsec_profile module switch (MACsec STATE may be ok while teamd
        # is still forming the LAG).
        lag_precond_timeout = 30 if want_single else TestFaultHandling.LACP_TIMEOUT
        assert wait_until(lag_precond_timeout, 2, 0,
                          lambda: member_selected() and lag_status() == "Up"), (
            "PortChannel {} member {} not Up/selected before the test (waited {}s).".format(
                pc_name, port_name, lag_precond_timeout))
        if check_bgp:
            assert wait_until(90, 5, 0, bgp_established), (
                "BGP over {} not Established before the test.".format(pc_name))

        try:
            # Block inbound EAPOL on the DUT so the DUT cannot receive peer MKA hellos and
            # its session times out. del-before-add is idempotent.
            ns_prefix = get_ipnetns_prefix(duthost, port_name)
            duthost.shell("sudo tc qdisc del dev {} clsact".format(dut_eth_port),
                          module_ignore_errors=True)
            duthost.shell("sudo tc qdisc add dev {} clsact".format(dut_eth_port))
            duthost.shell(
                "sudo tc filter add dev {} ingress protocol 0x888e "
                "u32 match u32 0 0 action drop".format(dut_eth_port))

            sleep(TestFaultHandling.MKA_TIMEOUT)
            tc_show = duthost.shell(
                "{} tc -s filter show dev {} ingress".format(ns_prefix, dut_eth_port),
                module_ignore_errors=True)["stdout"]
            assert "action order" in tc_show, (
                "EAPOL drop filter is NOT installed on {} -- tc output: {!r}"
                .format(dut_eth_port, tc_show))
            dropped = re.search(r"dropped (\d+)", tc_show)
            assert dropped and int(dropped.group(1)) > 0, (
                "EAPOL drop filter on {} caught 0 packets after {}s -- tc output: {!r}"
                .format(dut_eth_port, TestFaultHandling.MKA_TIMEOUT, tc_show))

            # (1) MACsec session drops within ~2x MKA_TIMEOUT.
            t0 = time.time()
            assert wait_until(2 * TestFaultHandling.MKA_TIMEOUT + 15, 1, 0,
                              lambda: macsec_crypto_plane_down(duthost, port_name, nbr)), (
                "MACsec session on {} did not go down after EAPOL was blocked.".format(port_name))
            logger.info("MACsec on %s went down in %.1fs", port_name, time.time() - t0)

            # (2) teamd must drop the member fast -- well under the 90s LACP timeout.
            t0 = time.time()
            assert wait_until(2 * TestFaultHandling.MKA_TIMEOUT + 20, 1, 0,
                              lambda: not member_selected()), (
                "LAG member {} was not deselected by teamd after the MACsec session expired. "
                "It must be dropped shortly after the ~{}s MKA timeout, not wait for the {}s "
                "LACP timeout.".format(port_name, TestFaultHandling.MKA_TIMEOUT,
                                       TestFaultHandling.LACP_TIMEOUT))
            logger.info("teamd deselected %s in %.1fs", port_name, time.time() - t0)

            # (3) Single-member LAG: the whole PortChannel goes Down (this is what withdraws
            #     BGP in production).
            if want_single:
                assert wait_until(2 * TestFaultHandling.MKA_TIMEOUT + 20, 1, 0,
                                  lambda: lag_status() == "Dw"), (
                    "Single-member PortChannel {} did not go Down after MACsec expired.".format(pc_name))

            # (4) orchagent must disable the member's collection + distribution at the ASIC.
            #     This is the hardware state that teamd cannot reveal -- teamd keeps the
            #     member deselected whenever MACsec is down (LACP PDUs are dropped), so only
            #     ASIC_DB tells us what orchagent actually programmed.
            assert wait_until(2 * TestFaultHandling.MKA_TIMEOUT + 20, 1, 0,
                              lambda: asic_disable_state() == (True, True)), (
                "orchagent did not disable LAG member {} at the ASIC (EGRESS/INGRESS_DISABLE) "
                "after the MACsec session expired. ASIC state: {}".format(
                    port_name, asic_disable_state()))

            # (5) Race guard (the core of the fix): a teamsyncd APP_LAG_MEMBER_TABLE refresh
            #     with status=enabled must NOT re-enable the member while MACsec is down.
            #     teamd stays deselected regardless (LACP can't form), so we drive the race
            #     directly: inject status=enabled and assert orchagent leaves the ASIC member
            #     disabled (PortsOrch::doLagMemberTask suppresses the re-enable).
            push_lag_member_status(duthost, pc_name, port_name, "enabled")

            def member_reenabled_in_asic():
                st = asic_disable_state()
                return st is not None and st != (True, True)
            assert not wait_until(20, 2, 0, member_reenabled_in_asic), (
                "orchagent re-enabled LAG member {} at the ASIC after a teamsyncd status=enabled "
                "refresh while MACsec was down -- the re-enable race was not suppressed. "
                "ASIC state: {}".format(port_name, asic_disable_state()))

            # (6) BGP behaviour depends on LAG cardinality:
            if check_bgp and want_single:
                # single-member: the LAG goes down, so BGP over it must withdraw.
                t0 = time.time()
                assert wait_until(TestFaultHandling.LACP_TIMEOUT, 2, 0,
                                  lambda: not bgp_established()), (
                    "BGP over {} did not drop after the single-member LAG went down.".format(pc_name))
                logger.info("BGP over %s dropped in %.1fs", pc_name, time.time() - t0)
            elif check_bgp:
                # multi-member: the LAG stays up on the other members, so bringing one member
                # down must NOT flap BGP. Confirm it stays Established for a sustained window.
                assert not wait_until(30, 3, 0, lambda: not bgp_established()), (
                    "BGP over {} dropped when one member of a multi-member LAG went down; "
                    "bringing a single member down must not affect the LAG or its BGP "
                    "session.".format(pc_name))
                logger.info("BGP over %s stayed Established through the member-down event", pc_name)
        finally:
            # Always remove the tc rule so MACsec can recover, even on assertion failure.
            duthost.shell("sudo tc qdisc del dev {} clsact".format(dut_eth_port),
                          module_ignore_errors=True)

        # --- Recovery/startup case: MACsec re-establishes and everything comes back. ---
        t0 = time.time()
        assert wait_until(60, 2, 0, lambda: duthost.iface_macsec_ok(port_name)), (
            "MACsec session on {} did not recover after removing the EAPOL block.".format(port_name))
        logger.info("MACsec on %s recovered in %.1fs", port_name, time.time() - t0)

        # orchagent must re-enable the member at the ASIC once both MACsec directions are up
        # (this is what lets LACP re-form and the member rejoin the LAG).
        t0 = time.time()
        assert wait_until(TestFaultHandling.LACP_TIMEOUT, 2, 0,
                          lambda: asic_disable_state() == (False, False)), (
            "orchagent did not re-enable LAG member {} at the ASIC after MACsec recovered. "
            "ASIC state: {}".format(port_name, asic_disable_state()))
        logger.info("ASIC re-enabled %s in %.1fs", port_name, time.time() - t0)

        t0 = time.time()
        assert wait_until(TestFaultHandling.LACP_TIMEOUT, 2, 0,
                          lambda: member_selected() and lag_status() == "Up"), (
            "PortChannel {} member {} did not recover to Up/selected.".format(pc_name, port_name))
        logger.info("LAG member %s recovered in %.1fs", port_name, time.time() - t0)

        if check_bgp and want_single:
            t0 = time.time()
            assert wait_until(120, 5, 0, bgp_established), (
                "BGP over {} did not re-establish after MACsec recovered.".format(pc_name))
            logger.info("BGP over %s re-established in %.1fs", pc_name, time.time() - t0)
        elif check_bgp:
            # multi-member: BGP never dropped; confirm it is still Established.
            assert bgp_established(), (
                "BGP over {} is not Established after recovery.".format(pc_name))

    @pytest.mark.disable_loganalyzer
    def test_macsec_rekey_keeps_lag_member_up(self, duthost, ctrl_links,
                                              upstream_links, rekey_period, wait_mka_establish):
        """A MACsec rekey rotates the SAs (new SA installed, then the old SA removed) while
        the session stays up. orchagent disables the LAG member only when the *last* SA is
        removed, so a rekey must NOT disable or flap the member. Verify that across a full
        rekey period the member is never disabled/flapped, that a rekey actually happened,
        and that the member, LAG and BGP stay up.
        """
        if rekey_period == 0:
            pytest.skip("Rekey-by-period is not active for this profile (rekey_period == 0).")
        assert ctrl_links, (
            "No control links found. Actual ctrl_links: {}".format(ctrl_links))

        # Prefer a single-member LAG (a spurious flap there also drops BGP); fall back to
        # any control-link PortChannel member.
        portchannels = get_portchannel(duthost)
        selected = None
        for p, n in list(ctrl_links.items()):
            pc = find_portchannel_from_member(p, portchannels)
            if not pc:
                continue
            single = len(pc["members"]) == 1
            if selected is None or single:
                selected = (p, pc["name"], n)
            if single:
                break
        if selected is None:
            pytest.skip("No control-link PortChannel member available on this testbed.")
        port_name, pc_name, nbr = selected
        check_bgp = upstream_links.get(port_name) is not None

        # Preconditions: session up, member enabled at the ASIC, selected, LAG up, (BGP up).
        assert duthost.iface_macsec_ok(port_name), (
            "MACsec session on {} is not up before the test.".format(port_name))
        assert wait_until(30, 2, 0, lambda: lag_member_disabled(duthost, port_name) == (False, False)
                          and teamd_member_selected(duthost, pc_name, port_name)
                          and portchannel_status(duthost, port_name) == "Up"), (
            "PortChannel {} member {} not enabled/Up before the test.".format(pc_name, port_name))
        if check_bgp:
            assert wait_until(90, 5, 0,
                              lambda: bgp_session_established(duthost, port_name, upstream_links)), (
                "BGP over {} not Established before the test.".format(pc_name))

        # Snapshot the SA tables (to confirm a rekey occurs) and the fix's disable-log count.
        _, _, _, egress_sa_before, ingress_sa_before = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        disable_logs_before = macsec_lag_disable_log_count(duthost, port_name)

        # Observe across ~2 rekey periods so at least one rekey rotates the SAs, sampling
        # the ASIC member state so a *persistent* disable also fails fast.
        logger.info("Observing %s across ~2x rekey_period (%ss) for spurious LAG-member flaps",
                    port_name, 2 * rekey_period)
        for _ in range(max(1, (2 * rekey_period) // 10)):
            sleep(10)
            # Tolerate a transient None (DB read hiccup); fail only on an actual disable.
            st = lag_member_disabled(duthost, port_name)
            assert not (st and (st[0] or st[1])), (
                "LAG member {} became disabled at the ASIC during a MACsec rekey (spurious "
                "flap). ASIC state: {}".format(port_name, st))

        # A rekey must actually have happened, otherwise the test is vacuous.
        _, _, _, egress_sa_after, ingress_sa_after = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        assert egress_sa_before != egress_sa_after and ingress_sa_before != ingress_sa_after, (
            "No rekey observed within 2x rekey_period ({}s) on {}; the test did not exercise "
            "rekey.".format(2 * rekey_period, port_name))

        # The fix must not have disabled/flapped the member during the (healthy) rekey.
        disable_logs_after = macsec_lag_disable_log_count(duthost, port_name)
        assert disable_logs_after == disable_logs_before, (
            "orchagent disabled/flapped LAG member {} during a MACsec rekey (the session "
            "stayed up). Disable-log line count went {} -> {}.".format(
                port_name, disable_logs_before, disable_logs_after))

        # End state: everything still up after the rekey.
        assert teamd_member_selected(duthost, pc_name, port_name), (
            "teamd deselected {} after the rekey.".format(port_name))
        assert portchannel_status(duthost, port_name) == "Up", (
            "PortChannel {} is not Up after the rekey.".format(pc_name))
        if check_bgp:
            assert bgp_session_established(duthost, port_name, upstream_links), (
                "BGP over {} is not Established after the rekey.".format(pc_name))

    @pytest.mark.disable_loganalyzer
    def test_mismatch_macsec_configuration(self, duthost, unctrl_links,
>>>>>>> 9b1994b20 (NOS-10638: [macsec] Add fault-handling test for MKA timeout on LAG member (#2092))
                                           profile_name, default_priority, cipher_suite,
                                           primary_cak, primary_ckn, policy, send_sci, wait_mka_establish):
        if port_profiles:
            pytest.skip("Mismatch test uses single-profile CAK/CKN fixtures")
        # Only pick one uncontrolled link for mismatch macsec configuration test
        if not unctrl_links:
            pytest.skip('SKIP this test as there are no uncontrolled links in this dut')

        port_name, nbr = list(unctrl_links.items())[0]

        # Wait till macsec session has gone down.
        wait_until(20, 3, 0,
                   lambda: not duthost.iface_macsec_ok(port_name) and
                   not nbr["host"].iface_macsec_ok(nbr["port"]))

        # Set a wrong cak to the profile
        primary_cak = "0" * len(primary_cak)
        enable_macsec_port(duthost, port_name, profile_name)
        set_macsec_profile(nbr["host"], profile_name, default_priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)

        def check_mka_establishment():
            _, _, dut_ingress_sc_table, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            return dut_ingress_sc_table or dut_egress_sa_table or dut_ingress_sa_table
        # The mka should be establishing or established
        # To check whether the MKA establishment happened within 90 seconds
        assert not wait_until(90, 1, 12, check_mka_establishment), (
            "MKA establishment failed. Expected MKA to not establish within expected time, but it did. "
        )

        # Teardown
        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], profile_name)
        sleep(300)
