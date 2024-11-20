import os
import logging
import json
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "../generic_config_updater/templates")
TMP_DIR = '/tmp'

logger = logging.getLogger(__name__)


def format_and_apply_template(duthost, template_name, extra_vars, setup):
    dest_path = os.path.join(TMP_DIR, template_name)

    duts_to_apply = [duthost]
    outputs = []
    if setup["is_dualtor"]:
        duts_to_apply.append(setup["rand_unselected_dut"])

    for dut in duts_to_apply:
        dut.host.options['variable_manager'].extra_vars.update(extra_vars)
        dut.file(path=dest_path, state='absent')
        dut.template(src=os.path.join(TEMPLATES_DIR, template_name), dest=dest_path)

        try:
            # duthost.template uses single quotes, which breaks apply-patch. this replaces them with double quotes
            dut.shell("sed -i \"s/'/\\\"/g\" " + dest_path)
            output = dut.shell("config apply-patch {}".format(dest_path))
            outputs.append(output)
        finally:
            dut.file(path=dest_path, state='absent')

    return outputs


def load_and_apply_json_patch(duthost, file_name, setup):
    with open(os.path.join(TEMPLATES_DIR, file_name)) as file:
        json_patch = json.load(file)

    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    duts_to_apply = [duthost]
    outputs = []
    if setup["is_dualtor"]:
        duts_to_apply.append(setup["rand_unselected_dut"])

    for dut in duts_to_apply:

        tmpfile = generate_tmpfile(dut)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(dut, json_data=json_patch, dest_file=tmpfile)
            outputs.append(output)
        finally:
            delete_tmpfile(dut, tmpfile)

    return outputs
