import logging

logger = logging.getLogger(__name__)


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
            'patch_file="/home/admin/yang_validation_empty_patch.json"; '
            'echo "[]" > "$patch_file" && sudo config apply-patch "$patch_file"; '
            'rc=$?; rm -f "$patch_file"; exit $rc',
            module_ignore_errors=True
        )

        if result['rc'] != 0:
            error = result.get('stderr', result.get('stdout', 'Unknown error'))
            logger.error(f"YANG validation failed on {duthost.hostname} ({stage}): {error}")
            return {'failed': True, 'error': error}
        else:
            logger.info(f"YANG validation passed on {duthost.hostname} ({stage})")
            return {'failed': False, 'error': ''}

    except Exception as e:
        logger.error(f"Exception during YANG validation on {duthost.hostname} ({stage}): {str(e)}")
        return {'failed': True, 'error': str(e)}
