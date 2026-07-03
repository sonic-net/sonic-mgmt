import logging

logger = logging.getLogger(__name__)

# Hard ceiling for the apply-patch probe. ``config apply-patch`` runs vtysh and
# other FRR/DB queries under the hood, which block forever when the DUT's FRR
# VTY socket is wedged (observed on T2 multi-ASIC KVM after a config reload).
# Without a bound this teardown hangs the whole test module until the harness
# kills it, producing no junit XML. A generous timeout keeps a healthy DUT
# (an empty patch applies in a few seconds) while turning a wedged DUT into a
# fast, reported failure.
APPLY_PATCH_TIMEOUT = 300


def run_yang_validation(duthost, stage="validation"):
    """
    Run YANG validation on a single DUT by applying an empty patch.

    Args:
        duthost: DUT host object to run validation on
        stage: Label for logging (e.g., "pre-test", "post-test")

    Returns:
        dict: {'failed': bool, 'error': str (only if failed)}
    """
    logger.info(f"Running YANG validation on {duthost.hostname} ({stage})")
    try:
        result = duthost.shell(
            "timeout {} bash -c 'echo \"[]\" | sudo config apply-patch /dev/stdin'".format(
                APPLY_PATCH_TIMEOUT),
            module_ignore_errors=True
        )

        if result['rc'] == 124:
            error = (
                f"config apply-patch did not complete within {APPLY_PATCH_TIMEOUT}s "
                f"(DUT likely unresponsive)"
            )
            logger.error(f"YANG validation timed out on {duthost.hostname} ({stage}): {error}")
            return {'failed': True, 'error': error}
        elif result['rc'] != 0:
            error = result.get('stderr', result.get('stdout', 'Unknown error'))
            logger.error(f"YANG validation failed on {duthost.hostname} ({stage}): {error}")
            return {'failed': True, 'error': error}
        else:
            logger.info(f"YANG validation passed on {duthost.hostname} ({stage})")
            return {'failed': False, 'error': ''}

    except Exception as e:
        logger.error(f"Exception during YANG validation on {duthost.hostname} ({stage}): {str(e)}")
        return {'failed': True, 'error': str(e)}
