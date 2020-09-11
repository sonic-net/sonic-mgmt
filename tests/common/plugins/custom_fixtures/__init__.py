import pytest
from check_dut_asic_type import check_dut_asic_type # lgtm [py/unused-import]

@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    for item in items:
        asic_marks = [mark for mark in item.iter_markers(name="asic")]
        if asic_marks:
            item.fixturenames.append("check_dut_asic_type")

