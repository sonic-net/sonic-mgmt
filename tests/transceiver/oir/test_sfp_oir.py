import logging
import pytest

from tests.common.platform.interface_utils import (
    get_pport_presence_data,
    get_physical_port_indices,
    get_physical_to_logical_port_mapping,
    expect_interface_status
)
from tests.common.platform.transceiver_utils import parse_sfp_eeprom_infos

from tests.common.helpers.dut_utils import get_program_info

try:
    from tests.common.physical_oir import PhysicalOir
except ImportError:
    # PhysicalOir class does not exist, skip the test
    # To run these tests, please implement the API defined in
    # docs/testplan/transceiver_onboarding/optics_insertion_removal_testplan.md#physical-oir-api .
    pytest.skip("physical_oir.py does not exist. Skipping all the SFP OIR tests.", allow_module_level=True)

logger = logging.getLogger(__name__)

# List of processes to monitor for crash during the test.
# The key is the process name and the value is the docker name where the process is running.
processes_to_monitor = {"orchagent": "swss", "syncd": "syncd", "xcvrd": "pmon"}


@pytest.fixture(scope="session")
def physical_oir(duthost, ansible_adhoc, port_attributes_dict):
    physical_oir = PhysicalOir(duthost, ansible_adhoc, port_attributes_dict)
    if not physical_oir.is_available():
        pytest.skip("OIR capability is not available on this testbed.")
    yield physical_oir
    physical_oir.cleanup()


@pytest.fixture
def oir_remove_sfps_setup(physical_oir):
    yield physical_oir
    physical_oir.insert_sfps()


@pytest.fixture
def oir_insert_sfps_setup(physical_oir, duthost, port_attributes_dict):
    physical_oir.remove_sfps()
    yield physical_oir
    presence_dict = get_pport_presence_data(duthost)
    ports_under_test = next(iter(port_attributes_dict.values()))["PHYSICAL_OIR_ATTRIBUTES"]["ports_under_test"]
    if any(not presence_dict[port] for port in ports_under_test):
        physical_oir.insert_sfps()


def get_process_status_dict(duthost, processes_to_monitor):
    process_status_dict = {}
    for process, container in processes_to_monitor.items():
        process_info = get_program_info(duthost, container, process)
        process_status_dict[process] = process_info
    return process_status_dict


def test_oir_remove_sfps(duthost, oir_remove_sfps_setup, port_attributes_dict):   # noqa: F811
    presence_dict = get_pport_presence_data(duthost)
    # check if the ports under test have transceivers present
    failures = []

    oir_attributes = next(iter(port_attributes_dict.values()))["PHYSICAL_OIR_ATTRIBUTES"]
    ports_under_test = oir_attributes["ports_under_test"]

    for port in ports_under_test:
        if not presence_dict[port]:
            failures.append(f"Transceiver not present on port {port}")

    baseline_process_status = get_process_status_dict(duthost, processes_to_monitor)
    for process, info in baseline_process_status.items():
        logger.info(f"Baseline process status - {process}: Status: {info[0]}, PID: {info[1]}")
        if info[0].lower() != "running":
            failures.append(f"Process {process} is not running before the test. Status: {info[0]}, PID: {info[1]}")
    assert not failures, " ; ".join(failures)

    oir_remove_sfps_setup.remove_sfps()

    presence_dict = get_pport_presence_data(duthost)
    for port in ports_under_test:
        if presence_dict[port]:
            failures.append(f"Transceiver still present on port {port}")
    # assert not failures, " ; ".join(failures)

    physical_port_indices = get_physical_port_indices(duthost)
    pport_to_lport_mapping = get_physical_to_logical_port_mapping(physical_port_indices)
    lports_under_test = []
    for port in ports_under_test:
        logical_ports = pport_to_lport_mapping[port]
        lports_under_test.extend(logical_ports)
    eeprom_infos = duthost.command("show interface transceiver eeprom -d")["stdout"]
    parsed_eeprom_infos = parse_sfp_eeprom_infos(eeprom_infos)
    for lport in lports_under_test:
        if expect_interface_status(duthost, lport, "up"):
            failures.append(f"Interface {lport} is still up after transceiver removal.")
        if "not detected" not in parsed_eeprom_infos.get(lport, {}).get(lport, "").lower():
            failures.append(f"EEPROM information for interface {lport} is still available after transceiver removal.")

    # Check if any of the critical processes have crashed during the test
    current_process_status = get_process_status_dict(duthost, processes_to_monitor)
    for process, info in current_process_status.items():
        if info[0].lower() != "running":
            failures.append(f"Process {process} is not running after the test. Status: {info[0]}, PID: {info[1]}")
        if info[1] != baseline_process_status[process][1]:
            failures.append(f"Process {process} restarted during the test. \
                            Baseline PID: {baseline_process_status[process][1]}, Current PID: {info[1]}")

    assert not failures, " ; ".join(failures)


def test_oir_insert_sfps(duthost, oir_insert_sfps_setup, port_attributes_dict):   # noqa: F811
    presence_dict = get_pport_presence_data(duthost)
    # check if the ports under test have transceivers present already
    failures = []
    oir_attributes = next(iter(port_attributes_dict.values()))["PHYSICAL_OIR_ATTRIBUTES"]
    ports_under_test = oir_attributes["ports_under_test"]
    for port in ports_under_test:
        if presence_dict[port]:
            failures.append(f"Transceiver already present on port {port}")

    assert not failures, " ; ".join(failures)

    baseline_process_status = get_process_status_dict(duthost, processes_to_monitor)
    for process, info in baseline_process_status.items():
        logger.info(f"Baseline process status - {process}: Status: {info[0]}, PID: {info[1]}")
        if info[0].lower() != "running":
            failures.append(f"Process {process} is not running before the test. Status: {info[0]}, PID: {info[1]}")
    assert not failures, " ; ".join(failures)

    oir_insert_sfps_setup.insert_sfps()

    presence_dict = get_pport_presence_data(duthost)
    for port in ports_under_test:
        if not presence_dict[port]:
            failures.append(f"Transceiver not present on port {port}")
    # assert not failures, " ; ".join(failures)

    physical_port_indices = get_physical_port_indices(duthost)
    pport_to_lport_mapping = get_physical_to_logical_port_mapping(physical_port_indices)
    lports_under_test = []
    for port in ports_under_test:
        logical_ports = pport_to_lport_mapping[port]
        lports_under_test.extend(logical_ports)
    eeprom_infos = duthost.command("show interface transceiver eeprom -d")["stdout"]
    parsed_eeprom_infos = parse_sfp_eeprom_infos(eeprom_infos)
    for lport in lports_under_test:
        if expect_interface_status(duthost, lport, "up"):
            failures.append(f"Interface {lport} is still up after transceiver removal.")
        if "not detected" in parsed_eeprom_infos.get(lport, {}).get(lport, "").lower():
            failures.append(f"EEPROM information for interface {lport} is not available after transceiver insertion.")

    # Check if any of the critical processes have crashed during the test
    current_process_status = get_process_status_dict(duthost, processes_to_monitor)
    for process, info in current_process_status.items():
        if info[0].lower() != "running":
            failures.append(f"Process {process} is not running after the test. Status: {info[0]}, PID: {info[1]}")
        if info[1] != baseline_process_status[process][1]:
            failures.append(f"Process {process} restarted during the test. \
                            Baseline PID: {baseline_process_status[process][1]}, Current PID: {info[1]}")

    assert not failures, " ; ".join(failures)
