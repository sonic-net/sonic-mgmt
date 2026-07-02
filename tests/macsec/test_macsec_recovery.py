import logging
import pytest

from tests.common.macsec.recovery_helpers import (
    advance_egress_encoding_an,
    assert_appl_db_sak_programmed_in_asic,
    assert_one_egress_sa_per_sc,
    dirty_kill_macsec_container,
    get_egress_encoding_ans,
    graceful_restart_macsec,
    set_rekey_period,
    snapshot_appl_db_saks,
    wait_for_macsec_container,
    wait_for_mka_converged,
    MKA_CONVERGE_TIMEOUT,
)


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic", "any"),
]


@pytest.fixture
def force_dut_key_server(rand_selected_dut, profile_name, ctrl_links,
                         policy, cipher_suite, send_sci):
    """
    Lower the DUT's MACSEC_PROFILE priority below the peer's so the DUT
    deterministically wins MKA Key Server election on every ctrl_link.

    Required by the stale-AN test: the egress encoding AN must differ
    between the surviving (pre-kill) SC and the fresh post-restart session.
    With the DUT as key server, a fresh restart resets its egress AN to 0,
    so advancing the AN to >=1 before the kill guarantees the asymmetry the
    bug needs.  (Not needed for the stale-SAK test, where the AN is fixed.)

    Setup: HSET priority 0; graceful-restart; wait for re-converge.
    Teardown: restore original priority AND rekey_period, then graceful-
    restart.  rekey_period is restored here (not just in the test body) so
    that an advance-timeout error mid-test can't leak a non-zero rekey_period
    into the next profile's run.
    """
    duthost = rand_selected_dut

    orig_priority = duthost.shell(
        "sonic-db-cli CONFIG_DB HGET 'MACSEC_PROFILE|{}' priority".format(
            profile_name),
        module_ignore_errors=True,
    )["stdout"].strip() or "64"
    orig_rekey = duthost.shell(
        "sonic-db-cli CONFIG_DB HGET 'MACSEC_PROFILE|{}' rekey_period".format(
            profile_name),
        module_ignore_errors=True,
    )["stdout"].strip() or "0"
    logger.info("force_dut_key_server: original priority=%s rekey_period=%s, "
                "forcing priority to 0", orig_priority, orig_rekey)

    duthost.shell(
        "sonic-db-cli CONFIG_DB HSET 'MACSEC_PROFILE|{}' priority 0".format(
            profile_name),
        module_ignore_errors=False,
    )
    graceful_restart_macsec(duthost)
    assert wait_for_mka_converged(
        duthost, ctrl_links, policy, cipher_suite, send_sci), \
        "MKA did not converge after forcing DUT KS priority"

    yield

    logger.info("force_dut_key_server teardown: restoring priority=%s "
                "rekey_period=%s", orig_priority, orig_rekey)
    duthost.shell(
        "sonic-db-cli CONFIG_DB HSET 'MACSEC_PROFILE|{}' priority {} "
        "rekey_period {}".format(profile_name, orig_priority, orig_rekey),
        module_ignore_errors=False,
    )
    graceful_restart_macsec(duthost)


@pytest.mark.backstop
def test_dirty_container_kill_preserves_sak_consistency(
        rand_selected_dut, ctrl_links, policy, cipher_suite, send_sci):
    """
    SIGKILL the macsec container so macsecmgrd has no chance to gracefully
    disable per-port MACsec.  After respawn + MKA re-convergence, the SAK
    advertised in APPL_DB must actually be programmed into the ASIC
    (ASIC_DB SAI_OBJECT_TYPE_MACSEC_SA.SAI_MACSEC_SA_ATTR_SAK).

    The stale-SAK class of bug shows up here: on respawn wpa
    renegotiates a new SAK at the same (port, sci, AN), but the pre-kill SA
    object survives in orchagent's MACsecSC::m_sa_ids, so createMACsecSA
    short-circuits and never reprograms SAI.  SAI_MACSEC_SA_ATTR_SAK is
    CREATE-ONLY, so the ASIC keeps the prior cycle's key while APPL_DB
    carries the fresh one.  This is deterministic per dirty kill; the
    ASIC_DB comparison is what surfaces it (`show macsec` reads APPL_DB and
    cannot).
    """
    duthost = rand_selected_dut

    logger.info("Step 1: verifying initial MKA convergence on %s",
                duthost.hostname)
    assert wait_for_mka_converged(
        duthost, ctrl_links, policy, cipher_suite, send_sci), \
        "MKA did not converge before dirty-restart test"

    logger.info("Step 2: snapshotting pre-kill SAK values")
    pre_kill_saks = snapshot_appl_db_saks(duthost, ctrl_links)
    logger.info("Pre-kill SAK snapshot has %d entries", len(pre_kill_saks))

    logger.info("Step 3: dirty-killing macsec container on %s",
                duthost.hostname)
    dirty_kill_macsec_container(duthost)

    logger.info("Step 4: waiting for macsec container to respawn")
    wait_for_macsec_container(duthost)

    logger.info("Step 5: waiting for MKA re-convergence (timeout=%ds)",
                MKA_CONVERGE_TIMEOUT)
    assert wait_for_mka_converged(
        duthost, ctrl_links, policy, cipher_suite, send_sci), \
        "MKA did not re-converge within {}s after dirty restart".format(
            MKA_CONVERGE_TIMEOUT)

    logger.info("Step 6a: confirming MKA actually re-keyed (silent-pass guard)")
    post_recovery_saks = snapshot_appl_db_saks(duthost, ctrl_links)
    changed = [
        k for k, v in pre_kill_saks.items()
        if k in post_recovery_saks and post_recovery_saks[k] != v
    ]
    assert changed, (
        "MKA did not re-key after dirty restart: pre-kill and post-recovery "
        "SAKs identical on all {} entry/entries.  The SAK consistency check "
        "below would be vacuous — failing now to catch this silent-pass mode."
    ).format(len(pre_kill_saks))
    logger.info("MKA re-keyed on %d/%d SA entries",
                len(changed), len(pre_kill_saks))

    logger.info("Step 6b: verifying APPL_DB SAKs are programmed into ASIC_DB")
    assert_appl_db_sak_programmed_in_asic(duthost, ctrl_links)
    logger.info("APPL_DB SAKs confirmed in ASIC_DB on all %d ctrl_link ports",
                len(ctrl_links))


@pytest.mark.backstop
def test_dirty_container_kill_recovers_encoding_an(
        rand_selected_dut, profile_name, ctrl_links, policy, cipher_suite,
        send_sci, force_dut_key_server):
    """
    Stale-AN regression guard.  Distinct from the stale-SAK case: here the
    egress encoding AN must CHANGE across the dirty restart, because the fix
    (and thus the bug) is gated on `new_an != sc.m_encoding_an` in
    setEncodingAN — an unchanged AN hits the idempotent early-return and is
    never swept.

    Recipe:
      1. DUT is key server (fixture), so its egress AN is locally controlled
         and a fresh restart resets it to AN=0.
      2. Advance the egress encoding AN to >=1 via a brief rekey.
      3. Dirty kill: the surviving egress SC keeps m_encoding_an>=1 and its
         AN>=1 SA in sc.m_sa_ids / SAI.
      4. Restore rekey_period=0 while down so the respawned DUT-KS session is
         stable at AN=0.
      5. After recovery the fresh session sets encoding_an=0; with the
         surviving AN>=1 SA still installed, an unfixed orchagent leaves two
         egress SAs on the SC (the chip then encrypts with the stale one and
         the peer drops every frame).

    Detector: ASIC_DB must show exactly one egress SA per SC.

    Scoped to the 128/256 GCM-AES-XPN profiles — the two most common in
    production.  The bug is in AN/SC bookkeeping, not crypto, so it is
    cipher-suite-independent; running every profile only multiplied runtime
    and exposed cumulative testbed degradation across the long sweep.
    """
    if profile_name not in ("128_XPN", "256_XPN"):
        pytest.skip(
            "stale-AN test runs only on 128_XPN/256_XPN (most common in "
            "production); the bug is cipher-suite-independent")

    duthost = rand_selected_dut

    logger.info("Step 1: verifying initial MKA convergence on %s",
                duthost.hostname)
    assert wait_for_mka_converged(
        duthost, ctrl_links, policy, cipher_suite, send_sci), \
        "MKA did not converge before stale-AN test"

    logger.info("Step 2: advancing egress encoding AN past 0 via brief rekey")
    advanced = advance_egress_encoding_an(
        duthost, profile_name, ctrl_links, policy, cipher_suite, send_sci)
    logger.info("Pre-kill egress encoding_an: %s", advanced)

    logger.info("Step 3: dirty-killing macsec container on %s",
                duthost.hostname)
    dirty_kill_macsec_container(duthost)

    logger.info("Step 4: restoring rekey_period=0 so the respawned session "
                "is stable at AN=0")
    set_rekey_period(duthost, profile_name, 0)

    logger.info("Step 5: waiting for macsec container to respawn")
    wait_for_macsec_container(duthost)

    logger.info("Step 6: waiting for MKA re-convergence (timeout=%ds)",
                MKA_CONVERGE_TIMEOUT)
    assert wait_for_mka_converged(
        duthost, ctrl_links, policy, cipher_suite, send_sci), \
        "MKA did not re-converge within {}s after dirty restart".format(
            MKA_CONVERGE_TIMEOUT)

    post = get_egress_encoding_ans(duthost, ctrl_links)
    logger.info("Post-recovery egress encoding_an: %s", post)

    logger.info("Step 7: verifying exactly one egress SA per SC in ASIC_DB")
    assert_one_egress_sa_per_sc(duthost, ctrl_links)
    logger.info("One-SA-per-SC invariant holds on all %d ctrl_link ports",
                len(ctrl_links))
