import json
import re
import logging
from tests.common.helpers.assertions import pytest_assert
from sonic_py_common import device_info

logger = logging.getLogger(__name__)

DEFAULT_CHECKPOINT_NAME = "backup"


def list_checkpoints(duthost, with_date=False):
    """
    List checkpoints on target duthost.

    Args:
        duthost: Device Under Test (DUT)
        with_date (bool): If True, include checkpoint creation date/time in the output
        (requires SONiC version >= 202505 or master).

    Returns:
        dict: Output from duthost.shell command.
    """
    cmds = 'config list-checkpoints'
    if with_date:
        cmds += " -t"

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc'],
        "Failed to list all checkpoint file"
    )

    return output


def verify_checkpoints_exist(duthost, cp):
    """Check if checkpoint file exist in duthost
    """
    checkpoints_output = list_checkpoints(duthost)
    checkpoint_exists = f'"{cp}"' in checkpoints_output['stdout']

    output_version = device_info.get_sonic_version_info()
    build_version = output_version['build_version']

    # Detect version_number or bail out early
    if not (re.match(r'^(\d{6})', build_version) or "master" in build_version):
        return checkpoint_exists

    # Resolve version_number
    if "master" in build_version:
        version_number = 999999
    else:
        version_number = int(re.findall(r'\d{6}', build_version)[0])

    # Old versions: simple check
    if version_number < 202505:
        return checkpoint_exists

    # Newer versions: need date-aware check
    checkpoints_output = list_checkpoints(duthost, with_date=True)
    try:
        checkpoints = json.loads(checkpoints_output['stdout'])
    except Exception:
        checkpoints = []

    checkpoint_exists_with_date = any(item.get("name") == cp for item in checkpoints)
    return checkpoint_exists and checkpoint_exists_with_date


def create_checkpoint(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    cmds = 'config checkpoint {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc']
        and "Checkpoint created successfully" in output['stdout']
        and verify_checkpoints_exist(duthost, cp),
        "Failed to config a checkpoint file: {}".format(cp)
    )


def delete_checkpoint(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    pytest_assert(
        verify_checkpoints_exist(duthost, cp),
        "Failed to find the checkpoint file: {}".format(cp)
    )

    cmds = 'config delete-checkpoint {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc'] and "Checkpoint deleted successfully" in output['stdout'],
        "Failed to delete a checkpoint file: {}".format(cp)
    )


def rollback(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run rollback on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: rollback filename
    """
    cmds = 'config rollback {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output
