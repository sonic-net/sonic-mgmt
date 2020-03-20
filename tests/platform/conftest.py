import pytest

@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(testbed_devices):
    platform = testbed_devices["dut"].facts["platform"]
    if "simx" in platform:
        pytest.skip('skipped on this platform: {}'.format(platform))