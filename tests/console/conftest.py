import pytest

@pytest.fixture(scope="module", autouse=True)
def skip_if_os_not_support(duthost):
    not_support_os_versions = ['201803', '201807', '201811', '201911']
    dut_os_version = duthost.os_version
    if any(os_version in dut_os_version for os_version in not_support_os_versions):
        pytest.skip("Skip test due to the console switch feature is not supported on {}".format(dut_os_version))
    yield

@pytest.fixture(scope="module", autouse=True)
def skip_if_console_feature_disabled(console_facts):
    if not console_facts['enabled']:
        pytest.skip("Skip test due to the console switch feature is not enabled for current DUT.")
    yield

@pytest.fixture(scope='module')
def console_facts(duthost):
    return duthost.console_facts()['ansible_facts']['console_facts']
