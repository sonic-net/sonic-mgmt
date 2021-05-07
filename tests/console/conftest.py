import logging
import pytest

@pytest.fixture(scope="module", autouse=True)
def skip_if_console_feature_disabled(console_facts):
    if not console_facts['enabled']:
        pytest.skip("Skip test due to the console switch feature is not enabled for current DUT.")
    yield

@pytest.fixture(scope='module')
def console_facts(duthost):
    return duthost.console_facts()['ansible_facts']['console_facts']
