import pytest
from check_dut_asic_type import check_dut_asic_type # lgtm [py/unused-import]

@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    for item in items:
        asic_marks = [mark for mark in item.iter_markers(name="asic")]
        if asic_marks:
            for pos, name in enumerate(item.fixturenames):
                try:
                    if item._fixtureinfo.name2fixturedefs[name][0].scope == 'module':
                        break
                except:
                    pos = len(item.fixturenames)
            item.fixturenames.insert(pos, "check_dut_asic_type")

