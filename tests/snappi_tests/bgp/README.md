### Description

This document explains pre-requisites and pytest markers used for the BGP convergence cases.

### Pre Requisites

The interfaces used for the test needs to be routed ports with IPv4 and IPv6 configured, due to the requirement of dual stack and port channel configuration. If they are not pre configured , the pre_configure_dut_interface() fixture from snappi_fixtures.py configures the interface with the IP subnet mentioned in the variables.py file under tests/snappi_tests/variables.py.
- Example:
    1. dut_ip_start = '20.1.1.1'
    2. snappi_ip_start = '20.1.1.2'
    3. prefix_length = 8
    4. dut_ipv6_start = '2000:1::1'
    5. snappi_ipv6_start = '2000:1::2'
    6. v6_prefix_length = 16

### Pytest Makers

The BGP cases take into account the user input for customized run using pytest markers (example - @pytest.mark.parametrize('multipath', [2]))

Here are the list of markers available in most of the testcases

1. @pytest.mark.parametrize('multipath', [2])
    - multipath is the number of BGP peers , we need minimum of 2 BGP peers for this test, the total ports used in the test is multipath + 1, since Tx is plain IPv4/IPv6

2.	@pytest.mark.parametrize('convergence_test_iterations', [1])
    - The number of iterations to which the convergence test needs to be run, if more than 1 iterations, the results will be the average of cumulative run

3.	@pytest.mark.parametrize('number_of_routes', [1000])
    - The number of routes that needs to be advertised for the bgp sessions

4.	@pytest.mark.parametrize('route_type', ['IPv4'])
    - If the IP and BGP sessions needs to be IPv4 or BGP+

5.	@pytest.mark.parametrize('port_speed', ['speed_100_gbps'])
    - Speed of the ports that are used for the test
