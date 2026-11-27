from types import SimpleNamespace

import pytest

from tests.common.plugins.custom_markers import check_asic


class DummyItem:
    def __init__(self, selected_asic, marker_args):
        self.config = SimpleNamespace(getoption=lambda option: selected_asic)
        self._markers = [SimpleNamespace(args=args) for args in marker_args]

    def iter_markers(self, name):
        assert name == "asic"
        return self._markers


@pytest.mark.parametrize("selected_asic", ["cisco", "cisco-8000"])
def test_check_asic_accepts_each_marker_argument(selected_asic):
    item = DummyItem(selected_asic, [("cisco", "cisco-8000")])

    check_asic(item)


def test_check_asic_rejects_unlisted_asic():
    item = DummyItem("broadcom", [("cisco", "cisco-8000")])

    with pytest.raises(pytest.skip.Exception):
        check_asic(item)
