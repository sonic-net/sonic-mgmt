import json
import logging

import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)
DEFAULT_CHECKPOINT_NAME = "test"


def generate_tmpfile(duthost):
    """Generate temp file
    """
    return duthost.shell('mktemp')['stdout']


def apply_patch(duthost, json_data, dest_file, ignore_tables=None):
    """Run apply-patch on target duthost

    Args:
        duthost: Device Under Test (DUT)
        json_data: Source json patch to apply
        dest_file: Destination file on duthost
        ignore_tables: to be ignored tables, "-i table_name"
    """
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {} {}'.format(dest_file, ignore_tables if ignore_tables else "")

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output


def delete_tmpfile(duthost, tmpfile):
    """Delete temp file
    """
    duthost.file(path=tmpfile, state='absent')


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


def list_checkpoints(duthost):
    """List checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
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


def rollback_or_reload(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run rollback on target duthost. config_reload if rollback failed.

    Args:
        duthost: Device Under Test (DUT)
    """
    output = rollback(duthost, cp)

    if output['rc'] or "Config rolled back successfully" not in output['stdout']:
        config_reload(duthost)
        pytest.fail("config rollback failed. Restored by config_reload")


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


def expect_op_success(duthost, output):
    """Expected success from apply-patch output
    """
    pytest_assert(not output['rc'], "Command is not running successfully")
    pytest_assert(
        "Patch applied successfully" in output['stdout'],
        "Please check if json file is validate"
    )