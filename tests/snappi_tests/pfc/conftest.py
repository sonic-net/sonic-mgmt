import pytest
import random
from tests.conftest import generate_port_lists, generate_priority_lists


@pytest.fixture(scope="module")
def rand_one_dut_portname_oper_up_for_pfc_test(rand_one_dut_front_end_hostname, request):
    """
    Return a single random oper_up port for the selected DUT.
    This ensures port selection is constrained to the same DUT as rand_one_dut_front_end_hostname.
    """
    oper_up_ports = generate_port_lists(request, "oper_up_ports")

    # generate_port_lists() returns a flat list like ['dut|Ethernet0', ...]
    selected_dut_ports = [p for p in oper_up_ports
                          if p.startswith(f"{rand_one_dut_front_end_hostname}|")]

    if not selected_dut_ports:
        pytest.skip(f"No oper_up ports found for selected DUT: {rand_one_dut_front_end_hostname}")

    if len(selected_dut_ports) > 1:
        return random.choice(selected_dut_ports)

    return selected_dut_ports[0]


@pytest.fixture(scope="module")
def rand_one_dut_lossless_prio_for_pfc_test(rand_one_dut_front_end_hostname, request):
    """
    Return a single random lossless priority for the selected DUT.
    This ensures priority selection is constrained to the same DUT as rand_one_dut_front_end_hostname.
    """
    lossless_prios = generate_priority_lists(request, 'lossless')

    # generate_priority_lists() returns a flat list like ['dut|3', ...]
    selected_dut_prios = [p for p in lossless_prios
                          if p.startswith(f"{rand_one_dut_front_end_hostname}|")]

    if not selected_dut_prios:
        pytest.skip(f"No lossless priorities found for selected DUT: {rand_one_dut_front_end_hostname}")

    return random.choice(selected_dut_prios)

