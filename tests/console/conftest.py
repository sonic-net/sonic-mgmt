import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401


console_lines = list(map(str, range(1, 49)))


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
def setup_c0(request, duthost, tbinfo):
    if tbinfo["topo"]["name"] == "c0":
        fanouthosts = request.getfixturevalue("fanouthosts")
        console_fanouts = list(filter(lambda fanouthost: fanouthost.is_console_switch(), fanouthosts))
        if len(console_fanouts) != 1:
            pytest.fail("Test requires exactly one console switch fanout device (could be dut itself)")
        console_fanout = console_fanouts[0]
    elif tbinfo["topo"]["name"] == "c0-lo":
        console_fanout = duthost
    else:
        pytest.fail("Test requires c0 or c0-lo topology")

    console_facts = duthost.console_facts()['ansible_facts']['console_facts']
    if len(console_facts["lines"]) != len(console_lines):
        pytest.fail("Loopback test requires DUT with 48 console lines configured, got {}"
                    .format(len(console_facts["lines"])))

    return duthost, console_fanout


@pytest.fixture(scope='module')
def console_facts(duthost):
    return duthost.console_facts()['ansible_facts']['console_facts']
