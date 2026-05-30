import logging
import pytest

from tests.common.macsec.recovery_helpers import (
    assert_appl_db_sak_programmed_in_asic,
    dirty_kill_macsec_container,
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


# ---------------------------------------------------------------------------
# Backstop: dirty container kill (NOS-7806 regression guard)
# ---------------------------------------------------------------------------

@pytest.mark.backstop
def test_dirty_container_kill_preserves_sak_consistency(
        rand_selected_dut, ctrl_links, policy, cipher_suite, send_sci):
    """
    SIGKILL the macsec container so macsecmgrd has no chance to gracefully
    disable per-port MACsec.  After respawn + MKA re-convergence, the SAK
    advertised in APPL_DB must actually be programmed into the ASIC
    (ASIC_DB SAI_OBJECT_TYPE_MACSEC_SA.SAI_MACSEC_SA_ATTR_SAK).

    The stale-SAK class of bug (NOS-7806) shows up here: on respawn wpa
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
