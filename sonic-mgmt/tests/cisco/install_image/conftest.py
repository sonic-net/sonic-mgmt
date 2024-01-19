import glob
import json
import pytest
import os
import re
import logging
from collections import OrderedDict
from datetime import datetime

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.plugins.sanity_check.recover import neighbor_vm_restore


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
FMT = "%b %d %H:%M:%S.%f"
FMT_SHORT = "%b %d %H:%M:%S"

def pytest_addoption(parser):
    """
        Adding arguments required for installing an image
    """
    install_group = parser.getgroup("Read MAC metadata test suite options")

    install_group.addoption(
        "--image_loc",
        action="store",
        type=str,
        help="Location of image",
        required=True,
    )
    
    install_group.addoption(
        "--enable_bfd",
        action="store_true",
        default=False,
        help="Enabled bfd on all LCs",
    )

    install_group.addoption(
        "--build_id",
        action="store",
        type=str,
        help="Build ID of image",
        required=True,
    )

@pytest.fixture(scope="module")
def xcvr_skip_list(duthosts):
    intf_skip_list = {}
    for dut in duthosts:
        platform = dut.facts['platform']
        hwsku = dut.facts['hwsku']
        f_path = os.path.join('/usr/share/sonic/device', platform, hwsku, 'hwsku.json')
        intf_skip_list[dut.hostname] = []
        dut.has_sku = True
        try:
            out = dut.command("cat {}".format(f_path))
            hwsku_info = json.loads(out["stdout"])
            for int_n in hwsku_info['interfaces']:
                if hwsku_info['interfaces'][int_n].get('port_type') == "RJ45":
                    intf_skip_list[dut.hostname].append(int_n)

        except Exception:
            # hwsku.json does not exist will return empty skip list
            dut.has_sku = False
            logging.debug(
                "hwsku.json absent or port_type for interfaces not included for hwsku {}".format(hwsku))

    return intf_skip_list
