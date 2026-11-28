import pytest
from tests.common.helpers.dut_ports import decode_dut_port_name

pytestmark = [pytest.mark.topology('any')]

@pytest.fixture
def temporary_file(tmp_path):
    file_path = tmp_path / "dut_state.txt"
    file_path.write_text("DUT state verification")

    yield file_path

    file_path.unlink(missing_ok=True)


def test_temporary_file(temporary_file):
    assert temporary_file.exists()
    assert temporary_file.read_text() == "DUT state verification"


def test_dut_show_version(duthosts, enum_frontend_dut_hostname, enum_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    res = duthost.command('show version')

    # check command execution
    assert res['rc'] == 0, "show version failed: {}".format(res["stderr"])
    assert res["stdout_lines"], "show version returned no output"

    # check output
    fields = ("SONiC Software Version", "Platform", "HwSKU", "ASIC", "Kernel")
    for field in fields:
        assert field in res["stdout"], "'{}' missing from show version".format(field)

    # check against facts
    assert duthost.facts['platform'] in res["stdout"]
    assert duthost.facts['hwsku'] in res["stdout"]


def test_dut_show_interfaces(duthosts, enum_frontend_dut_hostname, enum_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    res = duthost.command('show interfaces status')
    # check command execution
    assert res['rc'] == 0, "show interfaces status failed: {}".format(res["stderr"])
    #check output format
    lines = res["stdout_lines"]
    assert lines and "Interface" in lines[0]

    rows = lines[2:]
    assert rows, "no interface found"


def test_interface_status(duthosts, enum_dut_portname):
    dut_name, port = decode_dut_port_name(enum_dut_portname)
    if dut_name == "unknown" or port == "unknown":
        pytest.skip("port metadata is unavailable")

    duthost = duthosts[dut_name]
    status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]

    # check that the expected interface is present on the DUT
    if port not in status:
        pytest.fail(f"{port} is missing from show interfaces status")

    # check that interface state information is available
    assert "admin_state" in status[port]
    assert "oper_state" in status[port]

    # check that interface states contain valid values
    assert status[port]["admin_state"] in ("up", "down")
    assert status[port]["oper_state"] in ("up", "down")



