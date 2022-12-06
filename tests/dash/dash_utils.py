import json
import logging

from jinja2 import Template
from os import path
from time import sleep
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def safe_open_template(template_path):
    """
    Safely loads Jinja2 template from given path

    Note:
        All Jinja2 templates should be accessed with this method to ensure proper garbage disposal

    Args:
        template_path: String containing the location of the template file to be opened

    Returns:
        A Jinja2 Template object read from the provided file
    """

    with open(template_path) as template_file:
        return Template(template_file.read())


def combine_dicts(*args):
    """
    Combines multiple Python dictionaries into a single dictionary

    Used primarily to pass arguments contained in multiple dictionaries to the `render()` method for Jinja2 templates

    Args:
        *args: The dictionaries to be combined

    Returns:
        A single Python dictionary containing the key/value pairs of all the input dictionaries
    """

    combined_args = {}

    for arg in args:
        combined_args.update(arg)

    return combined_args


def render_template_to_host(template_name, host, dest_file, *template_args, **template_kwargs):
    """
    Renders a template with the given arguments and copies it to the host

    Args:
        template_name: A template inside the "templates" folder (without the preceding "templates/")
        host: The host device to copy the rendered template to (either a PTF or DUT host object)
        dest_file: The location on the host to copy the rendered template to
        *template_args: Any arguments to be passed to j2 during rendering
        **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """

    combined_args = combine_dicts(*template_args)

    rendered = safe_open_template(path.join(TEMPLATE_DIR, template_name)).render(combined_args, **template_kwargs)

    host.copy(content=rendered, dest=dest_file)


def copy_dut_config_files(duthost):
    """
    Copy DASH config files and copy them to DUT

    Note:
        Does not actually apply any of these new configs

    Args
        duthost: DUT host object
    """

    logger.info("Generating config files and copying to DUT")

    duthost.copy(src="./dash/files/dash_basic_config_set.json", dest="/var/tmp/dash_basic_config_set.json")
    duthost.copy(src="./dash/files/dash_basic_config_del.json", dest="/var/tmp/dash_basic_config_del.json")


def apply_dut_config_files(duthost):
    """
    Applies config files that are stored on the given DUT

    Args:
        duthost: DUT host object
    """
    logger.info("Applying config files on DUT")

    duthost.shell("docker cp /var/tmp/dash_basic_config_set.json  swss:/dash_basic_config_set.json")
    duthost.shell("docker exec swss sh -c \"swssconfig /dash_basic_config_set.json\"")
    sleep(3)


def remove_dut_config_files(duthost):
    """
    Removes config files that are stored on the given DUT

    Args:
        duthost: DUT host object
    """
    logger.info("Removing config files on DUT")

    duthost.shell("docker cp /var/tmp/dash_basic_config_del.json  swss:/dash_basic_config_del.json")
    duthost.shell("docker exec swss sh -c \"swssconfig /dash_basic_config_del.json\"")
    sleep(3)
