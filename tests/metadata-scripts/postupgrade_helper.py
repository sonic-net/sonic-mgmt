import pytest
import os
import logging
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

def run_postupgrade_actions(duthost, tbinfo, metadata_process, skip_postupgrade_actions):
    if not metadata_process:
        return
    if skip_postupgrade_actions:
        logger.info("Skipping postupgrade_actions")
        return
    base_path = os.path.dirname(__file__)
    postupgrade_actions_data_dir_path = os.path.join(base_path, "../../../sonic-metadata/scripts/postupgrade_actions_data")
    postupgrade_actions_path = os.path.join(base_path, "../../../sonic-metadata/scripts/postupgrade_actions")
    pytest_assert(os.path.exists(postupgrade_actions_path), "SONiC Metadata postupgrade_action script not found in {}"
            .format(postupgrade_actions_path))
    pytest_assert(os.path.exists(postupgrade_actions_data_dir_path), "SONiC Metadata postupgrade_action data directory not found in {}"
            .format(postupgrade_actions_data_dir_path))

    logger.info("Step 1 Copy the scripts and data directory to the DUT")
    duthost.file(path="/tmp/anpscripts", state="absent")
    duthost.file(path="/tmp/anpscripts", state="directory")
    metadata_tar_stat = duthost.stat(path="/host/metadata.tar.gz")
    if metadata_tar_stat["stat"]["exists"]:
        duthost.unarchive(src="/host/metadata.tar.gz", dest="/tmp/anpscripts/", remote_src="yes")
        duthost.file(path="/host/metadata.tar.gz", state="absent")
    else:
        duthost.unarchive(src="metadata.tar.gz", dest="/tmp/anpscripts/")

    duthost.command("chmod +x /tmp/anpscripts/postupgrade_actions")
    result = duthost.command("/usr/bin/sudo /tmp/anpscripts/postupgrade_actions", module_ignore_errors=True)
    logger.info("Postupgrade_actions result: {}".format(str(result)))
    if "stderr" in result:
        errors = result.get("stderr")
        platform_info = duthost.command("show platform summary")["stdout"]
        if "DCS-7050CX3-32S" in platform_info and "DCS-7050CX3-32S-SSD" not in platform_info:
            logger.warn("Failed executing postupgrade_actions, not failing due to running on unexpected hardware. Errors: {}".format(errors))
        else:
            pytest_assert(not errors, "Failed executing postupgrade_actions. Errors: {}".format(errors))
    duthost.command("rm -rf /tmp/anpscripts", module_ignore_errors=True)