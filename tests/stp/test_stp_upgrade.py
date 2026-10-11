# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Spanning-tree configuration across an image switch.

The STP tables are new, so nothing had checked that a configuration written
on one image is still valid, and still running, when another image boots it.
Each image boots from its own /etc/sonic/config_db.json, so the saved file is
placed in the other image's overlay by hand; the test then switches to that
image and back, and asserts the CONFIG_DB rows read back unchanged and the
tree comes up each time. Both files are put back afterwards. It needs two
images in ``sonic-installer list``; with one it stands down.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.stp import stp_base
from tests.stp import stp_utils
from tests.stp.stp_base import StpTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
]

STP_ROWS = ("STP|GLOBAL", "STP_VLAN|Vlan{vlan}", "STP_PORT|{port}")


CONFIG_PATH = "/etc/sonic/config_db.json"
BACKUP_SUFFIX = ".stp_upgrade.bak"


def _installed_images(duthost, strict=True):
    res = duthost.shell("sudo sonic-installer list", module_ignore_errors=True)
    if res.get("rc", 1) != 0:
        if strict:
            pytest.fail("sonic-installer list failed: {}".format(
                (res.get("stderr") or res.get("stdout") or "").strip()), pytrace=False)
        return "", []
    out = res.get("stdout_lines", [])
    current, images = "", []
    for line in out:
        if line.startswith("Current:"):
            current = line.split(":", 1)[1].strip()
        elif line.startswith("SONiC-OS-"):
            images.append(line.strip())
    return current, images


def _image_config_path(image):
    """Where an installed image reads its startup config: its own overlay."""
    return "/host/image-{}/rw{}".format(image.replace("SONiC-OS-", "", 1), CONFIG_PATH)


def _snapshot(duthost, vlan_id, port):
    # Parsed into dicts: after a reboot the rows are loaded from config_db.json,
    # so the field order in redis can differ while the content is the same.
    return {key: stp_utils._hgetall(duthost, key, dbnum=4)
            for key in (k.format(vlan=vlan_id, port=port) for k in STP_ROWS)}


def _tree_up(duthost, vlan_id, port):
    return (stp_base.stp_container_up(duthost)
            and stp_utils.is_self_root(duthost, stp_utils.PVST, vlan_id)
            and stp_utils.get_port_data(duthost, stp_utils.PVST, vlan_id, port) != {})


def _boot_into(duthost, localhost, image, vlan_id, port):
    duthost.shell("sudo sonic-installer set-default {}".format(image))
    reboot(duthost, localhost, wait=300)
    current, _ = _installed_images(duthost)
    pytest_assert(current == image, "the switch booted {} instead of {}".format(current, image))
    pytest_assert(wait_until(240, 5, 0, lambda: _tree_up(duthost, vlan_id, port)),
                  "no PVST tree on VLAN {} after booting {}".format(vlan_id, image))


class TestPvstUpgrade(StpTestBase):
    STP_MODE = stp_base.PVST

    def test_pvst_config_survives_image_switch(self, duthosts, rand_one_dut_hostname, localhost,
                                               setup_stp_test_data):
        """Save a PVST configuration, boot the other installed image, boot back:
        every STP row reads back unchanged and the tree comes up both times."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        vlan_id, port = d["vlan"]["id"], d["dut_ports"]["dut_port_1"]

        current, images = _installed_images(duthost)
        others = [i for i in images if i != current]
        if not others:
            pytest.skip("only one image installed ({}); the switch needs a second one to boot".format(current))
        other = others[0]
        other_cfg = _image_config_path(other)
        # An image that has never booted runs its first-boot config migration,
        # which overwrites whatever startup config is placed in it, and may
        # come up without the management address. Nothing to prove there.
        firsttime = "/host/image-{}/platform/firsttime".format(other.replace("SONiC-OS-", "", 1))
        if duthost.shell("test -e {}".format(firsttime), module_ignore_errors=True).get("rc") == 0:
            pytest.skip("{} has never booted; its first boot would replace the saved config".format(other))

        # Both images' startup config goes back exactly as found; nothing the
        # test saves may outlive it.
        duthost.shell("sudo cp -p {0} {0}{1}".format(CONFIG_PATH, BACKUP_SUFFIX))
        duthost.shell("if [ -f {0} ]; then sudo cp -p {0} {0}{1}; fi".format(other_cfg, BACKUP_SUFFIX))
        try:
            # A non-default value in each table, so a dropped table shows.
            self.set_bridge_priority(duthost, vlan_id, 8192)
            duthost.shell("config spanning-tree interface bpdu-guard enable {}".format(port))
            pytest_assert(wait_until(120, 5, 0, lambda: _tree_up(duthost, vlan_id, port)),
                          "no PVST tree on VLAN {} before the switch".format(vlan_id))
            duthost.shell("config save -y")
            # The save lands in this image's overlay only; the other image
            # boots from its own, so hand it the same file.
            duthost.shell("sudo mkdir -p $(dirname {1}) && sudo cp -p {0} {1}".format(CONFIG_PATH, other_cfg))
            before = _snapshot(duthost, vlan_id, port)
            pytest_assert(all(before.values()), "an STP table is empty before the switch: {}".format(before))

            _boot_into(duthost, localhost, other, vlan_id, port)
            pytest_assert(_snapshot(duthost, vlan_id, port) == before,
                          "STP tables changed after booting {}".format(other))

            _boot_into(duthost, localhost, current, vlan_id, port)
            pytest_assert(_snapshot(duthost, vlan_id, port) == before,
                          "STP tables changed after booting back into {}".format(current))
        finally:
            # Never leave the switch on, or booting into, the other image. The
            # default is put back whatever happened: a reboot that never went
            # down leaves it pointing at the other image otherwise.
            duthost.shell("sudo sonic-installer set-default {}".format(current), module_ignore_errors=True)
            booted, _ = _installed_images(duthost, strict=False)
            if booted and booted != current:
                reboot(duthost, localhost, wait=300)
            # Put both startup configs back as they were found.
            duthost.shell("sudo mv -f {0}{1} {0}".format(CONFIG_PATH, BACKUP_SUFFIX),
                          module_ignore_errors=True)
            duthost.shell("if [ -f {0}{1} ]; then sudo mv -f {0}{1} {0}; else sudo rm -f {0}; fi".format(
                other_cfg, BACKUP_SUFFIX), module_ignore_errors=True)
            duthost.shell("config spanning-tree interface bpdu-guard disable {}".format(port),
                          module_ignore_errors=True)
            self.set_bridge_priority(duthost, vlan_id, 32768)
