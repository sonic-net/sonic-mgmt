import logging
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

DEFAULT_CHECKPOINT_NAME = "backup"


def list_checkpoints(duthost):
    """List checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    cmds = 'config list-checkpoints'

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
    output = list_checkpoints(duthost)
    return '"{}"'.format(cp) in output['stdout']


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
