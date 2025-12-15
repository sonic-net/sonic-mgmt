import pytest
import random
from tests.common.snappi_tests.common_helpers import enable_packet_aging, start_pfcwd
from tests.conftest import generate_priority_lists
from tests.common.helpers.parallel import parallel_run
from tests.common.helpers.xml_utils import modify_minigraph
from tests.common.config_reload import config_reload


@pytest.fixture(autouse=True, scope="module")
def rand_lossless_prio(request):
    """
    Fixture that randomly selects a lossless priority

    Args:
        request (object): pytest request object

    Yields:
        lossless priority (str): string containing 'hostname|lossless priority'

    """
    lossless_prios = generate_priority_lists(request, "lossless")
    if lossless_prios:
        yield random.sample(lossless_prios, 1)[0]
    else:
        yield 'unknown|unknown'


@pytest.fixture(autouse=True, scope="module")
def rand_lossy_prio(request):
    """
    Fixture that randomly selects a lossy priority

    Args:
        request (object): pytest request object

    Yields:
        lossy priority (str): string containing 'hostname|lossy priority'

    """
    lossy_prios = generate_priority_lists(request, "lossy")
    if lossy_prios:
        yield random.sample(lossy_prios, 1)[0]
    else:
        yield 'unknown|unknown'


@pytest.fixture(autouse=True, scope="module")
def start_pfcwd_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that PFC watchdog is enabled with default setting after tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    start_pfcwd(duthost)


@pytest.fixture(autouse=True, scope="module")
def enable_packet_aging_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that packet aging is enabled after tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    enable_packet_aging(duthost)


def pytest_addoption(parser):
    '''
    Add any cmd line arguments we want to introduce for snappi scripts.
    '''
    snappi_group = parser.getgroup("Snappi Test suite Options")
    snappi_group.addoption(
        "--test_gcu_snappi",
        action="store",
        type=str,
        default="",
        choices=("no_front_panel_ports", "one_front_panel_port", ""),
        help="Control execution of GCU feature in Snappi Tests."
    )


@pytest.fixture(scope="session")
def gcu_mode_enabled(request):
    return request.config.getoption("--test_gcu_snappi")


@pytest.fixture(autouse=True, scope="session")
def convert_to_rsb(duthosts, duts_minigraph_facts, gcu_mode_enabled):

    '''
       Change the DUTs to Reduced-Set-Base configs. These configs have no
       front-panel port configured. This is done by removing the front-panel
       ports from the minigraph, and loading the new minigraph.
    '''
    if gcu_mode_enabled == "":
        yield
        return

    minigraph_xml = "/etc/sonic/minigraph.xml"

    def convert_dut_to_rsb(node, duts_minigraph_facts, rsb_mode, results):
        if node.is_supervisor_node():
            return
        node.shell("rm /etc/sonic/running_golden*", module_ignore_errors=True)
        filename = node.fetch(src=minigraph_xml, dest="/tmp")['dest']
        for entry in duts_minigraph_facts[node.hostname]:
            modify_minigraph(filename, entry[1], rsb_mode)

        backup_config_files(node, "full_configs")
        copy_and_load_minigraph_to_dut(node, filename)
        backup_config_files(node, "rsb_configs")
        prepare_gcu_patches(node, "full_configs", "rsb_configs")
        copy_minigraph_back(node, "full_configs")

    # for dut in duthosts:
    #     convert_dut_to_rsb(dut, duts_minigraph_facts, rsb_mode)
    parallel_run(
        convert_dut_to_rsb,
        [],
        {'duts_minigraph_facts': duts_minigraph_facts, 'rsb_mode': gcu_mode_enabled},
        duthosts)

    yield

    for dut in duthosts:
        config_reload(dut, config_source="minigraph", start_bgp=True)
        dut.shell("rm /etc/sonic/running_golden*", module_ignore_errors=True)
        dut.shell("config save -y")


def backup_config_files(dut, path):
    dut.shell(cmd=f"mkdir {path}", module_ignore_errors=True)
    dut.shell(cmd=f"cp /etc/sonic/config_db*json {path}")
    dut.shell(cmd=f"cp /etc/sonic/minigraph.xml {path}")


def copy_and_load_minigraph_to_dut(dut, path):
    dut.copy(src=path, dest="/etc/sonic/minigraph.xml")
    config_reload(dut, config_source="minigraph", start_bgp=True)
    dut.shell("config save -y")


def prepare_gcu_patches(duthost, full_configs, rsb_configs, gcu_patches="gcu_patches"):
    duthost.shell(f"mkdir {gcu_patches}", module_ignore_errors=True)
    for asic in range(3):
        cmds = [
            f'''jsondiff --indent 2 {rsb_configs}/config_db{asic}.json {full_configs}/config_db{asic}.json > /tmp/f; mv /tmp/f {gcu_patches}/patch{asic}.json''',   # noqa: E501
            f'''jq 'map(select(.op != "remove"))' {gcu_patches}/patch{asic}.json > /tmp/f; mv /tmp/f {gcu_patches}/patch{asic}.json''',  # noqa: E501
            f'''jq 'map(select(.op != "move"))' {gcu_patches}/patch{asic}.json > /tmp/f; mv /tmp/f {gcu_patches}/patch{asic}.json''',  # noqa: E501
            f'''jq 'map(select(.path | contains("BUFFER_PROFILE") | not))' {gcu_patches}/patch{asic}.json > /tmp/f; mv /tmp/f {gcu_patches}/patch{asic}.json''',  # noqa: E501
            f'''jq 'map(select(.path | contains("BUFFER_POOL") | not))' {gcu_patches}/patch{asic}.json > /tmp/f; mv /tmp/f {gcu_patches}/patch{asic}.json''',   # noqa: E501
            f'''jq 'map(select(.path | contains("BUFFER_PG") | not))' {gcu_patches}/patch{asic}.json > /tmp/f; mv /tmp/f  {gcu_patches}/patch{asic}.json''',    # noqa: E501
            f'''sed -i 's@path": "@path": "/asic'{asic}'@' {gcu_patches}/patch{asic}.json''',
            f'''sed -i 's@from": "@from": "/asic'{asic}'@' {gcu_patches}/patch{asic}.json'''
        ]
        for cmd in cmds:
            duthost.shell(cmd=cmd)


def copy_minigraph_back(duthost, source):
    duthost.shell(f"cp {source}/minigraph.xml /etc/sonic/minigraph.xml")


@pytest.fixture(autouse=True,  scope="module")
def load_gcu_config(duthosts, gcu_mode_enabled):

    if gcu_mode_enabled == "":
        yield
        return

    def load_file(dut, filename):
        if dut.stat(path=filename)['stat']['exists']:
            result = dut.shell(f"config apply-patch {filename}")
            if result['stdout_lines'][-1] != 'Patch applied successfully.':
                raise RuntimeError(f"GCU patch{filename} was not applied successfully: Result: {result}")
            return True
        else:
            return False

    for dut in duthosts:
        path = "gcu_patches"
        if dut.stat(path=path)['stat']['exists']:
            if dut.is_multi_asic:
                for asic in range(16):
                    filename = f"{path}/patch{asic}.json"
                    if load_file(dut, filename):
                        continue
                    else:
                        break
            else:
                filename = f"{path}/patch.json"
                load_file(dut, filename)

    yield
    return
