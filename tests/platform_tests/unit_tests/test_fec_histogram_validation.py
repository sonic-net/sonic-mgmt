"""Unit tests for helpers owned by the platform FEC test module."""

import pytest

from tests.platform_tests import test_intf_fec


pytestmark = [
    pytest.mark.topology("any"),
]


@pytest.mark.parametrize(
    "init,current,previous,snapshot_name",
    [
        (True, [{"codewords": "0"}] * 2, None, "current"),
        (False, [{"codewords": "0"}] * 3, [{"codewords": "0"}] * 2, "previous"),
    ],
)
def test_fec_histogram_reports_unavailable_configured_bins(
    monkeypatch,
    init,
    current,
    previous,
    snapshot_name,
):
    monkeypatch.setattr(test_intf_fec, "get_fec_histogram", lambda *args, **kwargs: current)

    with pytest.raises(
        pytest.fail.Exception,
        match=f"critical_histogram_bins.*{snapshot_name} histogram",
    ):
        test_intf_fec.validate_fec_histogram(
            object(),
            "Ethernet0",
            init,
            previous,
            critical_bins=[2],
        )


def test_fec_histogram_accepts_highest_available_bin(monkeypatch):
    histogram = [{"codewords": "0"}] * 8
    monkeypatch.setattr(test_intf_fec, "get_fec_histogram", lambda *args, **kwargs: histogram)

    valid, snapshot = test_intf_fec.validate_fec_histogram(
        object(),
        "Ethernet0",
        True,
        critical_bins=[7],
    )

    assert valid
    assert snapshot is histogram
