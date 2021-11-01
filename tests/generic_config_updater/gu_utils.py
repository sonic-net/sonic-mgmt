import json
import time
import logging
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

def generate_tmpfile(duthost):
    return duthost.shell('mktemp')['stdout']

def delete_tmpfile(duthost, tmpfile):
    duthost.file(path=tmpfile, state='absent')

def apply_patch(duthost, json_data, dest_file):
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {}'.format(dest_file)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)
    # output = duthost.shell(cmds)

    return output

def expect_op_success(duthost, output):
    pytest_assert(not output['rc'], "Command is not running successfully")
    pytest_assert(
        "Patch applied successfully" in output['stdout'],
        "Please check if json file is validate"
    )

def expect_res_success(duthost, output, expected_content_list, unexpected_content_list):
    for expected_content in expected_content_list:
        pytest_assert(
            expected_content in output['stdout'],
            "{} is expected content".format(expected_content)
        )

    for unexpected_content in unexpected_content_list:
        pytest_assert(
            unexpected_content not in output['stdout'],
            "{} is unexpected content".format(unexpected_content)
        )

def expect_op_failure(output):
    logger.info("return code {}".format(output['rc']))
    pytest_assert(output['rc'], "The command should fail with non zero return code")