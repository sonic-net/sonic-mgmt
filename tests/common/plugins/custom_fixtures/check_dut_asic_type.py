import pytest
from tests.common.helpers.assertions import pytest_require

@pytest.fixture(scope="function")
def check_dut_asic_type(request, duthost):
    asic_marks = [mark for mark in request.node.iter_markers(name="asic")]
    if not asic_marks:
        return
    supported_asics = [x.lower() for x in asic_marks[0].args]
    if not supported_asics:
        return
    dut_asic_type = duthost.facts["asic_type"].lower()
    pytest_require((dut_asic_type in supported_asics), "Unsupported platform")

