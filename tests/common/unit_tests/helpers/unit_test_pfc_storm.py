import os
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from tests.common.helpers.pfc_storm import (
    PFCStorm,
    get_chip_name_if_asic_pfc_storm_supported,
)


@pytest.mark.parametrize("hwsku,chip,generator,template", [
    ("Arista-7060X6-64PE", "Tomahawk5", "pfc_gen_brcm_xgs.py", "arista_sonic"),
    ("NH-4210-F-O256", "Tomahawk6", "pfc_gen_brcm_xgs.py", "arista_sonic"),
    ("DellEMC-Z9332f-O32", None, "pfc_gen.py", "sonic_t2"),
    (None, None, "pfc_gen.py", "sonic_t2"),
])
def test_sonic_deploy_and_templates_use_same_hwsku(
    hwsku, chip, generator, template
):
    storm = PFCStorm.__new__(PFCStorm)
    storm.asic_type = "broadcom"
    storm.fanout_asic_type = "broadcom"
    storm.dut = SimpleNamespace(topo_type="t2")
    storm.peer_info = {"hwsku": hwsku}
    storm.peer_device = SimpleNamespace(os="sonic", copy=Mock(), shell=Mock())
    storm.pfc_gen_file = "pfc_gen.py"
    storm.pfc_gen_chip_name = None

    with patch.object(storm, "_create_pfc_gen"), patch.object(
        storm, "_update_template_args",
        side_effect=lambda: setattr(storm, "extra_vars", {})
    ):
        storm.deploy_pfc_gen()
        storm._prepare_start_template()
        assert os.path.basename(storm.pfc_start_template) == (
            "pfc_storm_{}.j2".format(template)
        )
        storm._prepare_stop_template()
        assert os.path.basename(storm.pfc_stop_template) == (
            "pfc_storm_stop_{}.j2".format(template)
        )

    assert storm.pfc_gen_file == generator
    assert storm.pfc_gen_chip_name == chip
    assert storm.peer_device.copy.call_args.kwargs["src"] == (
        "common/helpers/{}".format(generator)
    )
    storm.peer_device.shell.assert_not_called()


def test_vs_selectors_do_not_access_peer_device():
    storm = PFCStorm.__new__(PFCStorm)
    storm.asic_type = "vs"
    storm.peer_device = {}
    with patch.object(
        storm, "_update_template_args",
        side_effect=lambda: setattr(storm, "extra_vars", {})
    ):
        storm._prepare_start_template()
        storm._prepare_stop_template()
    assert os.path.basename(storm.pfc_start_template) == "pfc_storm_eos.j2"
    assert os.path.basename(storm.pfc_stop_template) == "pfc_storm_stop_eos.j2"


def test_missing_hwsku_is_not_chip_capable():
    assert get_chip_name_if_asic_pfc_storm_supported(None) is None
