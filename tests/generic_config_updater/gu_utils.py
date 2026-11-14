import os
import logging
import json
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert


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


def load_and_apply_json_patch(duthost, file_name, setup, is_asic_specific=False, is_host_specific=False):
    with open(os.path.join(TEMPLATES_DIR, file_name)) as file:
        json_patch = json.load(file)

    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=is_asic_specific,
                                                 is_host_specific=is_host_specific)
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


def get_dualtor_duts(duthost, rand_unselected_dut):
    """Return list of DUTs to apply changes to (dualtor aware)."""
    duts = [duthost]
    if rand_unselected_dut:
        duts.append(rand_unselected_dut)
    return duts


def apply_json_patch_to_duts(duthost, rand_unselected_dut, json_patch):
    """Apply json patch to the selected DUTs and return list of (dut, output)."""
    duts = get_dualtor_duts(duthost, rand_unselected_dut)
    outputs = []

    for dut in duts:
        tmpfile = generate_tmpfile(dut)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(dut, json_data=json_patch, dest_file=tmpfile)
            outputs.append((dut, output))
        finally:
            delete_tmpfile(dut, tmpfile)

    return outputs


def checkpoint_and_rollback(duthost, rand_unselected_dut):
    """Context helper: create checkpoints on DUTs and rollback on exit."""
    duts = get_dualtor_duts(duthost, rand_unselected_dut)
    for dut in duts:
        verify_orchagent_running_or_assert(dut)
        create_checkpoint(dut)

    try:
        yield duts
    finally:
        for dut in duts:
            try:
                verify_orchagent_running_or_assert(dut)
                rollback_or_reload(dut)
            finally:
                delete_checkpoint(dut)
