import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "smoke: union of smoke_breakout and smoke_non_breakout; "
        "auto-applied. Hoisted to the front of any fx3/qos/ collection "
        "so the full suite runs smoke first.",
    )
    config.addinivalue_line(
        "markers",
        "smoke_breakout: smoke tests targeted at the breakout testbed "
        "(fx3_qos_testbed_breakout.yaml).",
    )
    config.addinivalue_line(
        "markers",
        "smoke_non_breakout: smoke tests targeted at the non-breakout "
        "testbed (fx3_qos_testbed.yaml).",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_itemcollected(item):
    if (item.get_closest_marker("smoke_breakout")
            or item.get_closest_marker("smoke_non_breakout")):
        item.add_marker(pytest.mark.smoke)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    smoke, rest = [], []
    for item in items:
        (smoke if item.get_closest_marker("smoke") else rest).append(item)
    if smoke and rest:
        items[:] = smoke + rest
