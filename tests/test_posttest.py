import pytest
import logging
import os.path
import os
import json

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.posttest,
    pytest.mark.topology('util'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]


def test_collect_techsupport(duthost):
    """
    A util for collecting techsupport after tests.

    Since nightly test on Jenkins will do a cleanup at the beginning of tests,
    we need a method to save history logs and dumps. This util does the job.
    """
    logger.info("Collecting techsupport since yesterday")
    # Because Jenkins is configured to save artifacts from tests/logs,
    # and this util is mainly designed for running on Jenkins,
    # save path is fixed to logs for now.
    TECHSUPPORT_SAVE_PATH = 'logs/'
    out = duthost.command("generate_dump -s yesterday", module_ignore_errors=True)
    if out['rc'] == 0:
        tar_file = out['stdout_lines'][-1]
        duthost.fetch(src=tar_file, dest=TECHSUPPORT_SAVE_PATH, flat=True)

    assert True

def test_restore_container_autorestart(duthost):
    state_file_name = "/tmp/autorestart_state_{}.json".format(duthost.hostname)
    if not os.path.exists(state_file_name):
        return
    stored_autorestart_states = {}
    with open(state_file_name, "r") as f:
        stored_autorestart_states = json.load(f)
    container_autorestart_states = duthost.get_container_autorestart_states()
    # Recover autorestart states
    logging.info("Recover container autorestart")
    cmd_enable = "config feature autorestart {} enabled"
    cmds_enable = []
    for name, state in container_autorestart_states.items():
        if state == "disabled" \
                and stored_autorestart_states.has_key(name) \
                and stored_autorestart_states[name] == "enabled":
            cmds_enable.append(cmd_enable.format(name))
    # Write into config_db
    cmds_enable.append("config save -y")
    duthost.shell_cmds(cmds=cmds_enable)
    os.remove(state_file_name)
