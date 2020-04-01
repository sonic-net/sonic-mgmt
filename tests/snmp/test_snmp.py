from common.utilities import wait_until

def check_snmp_ready(testbed, testbed_devices):
    dut = testbed_devices['dut']
    assert wait_until(300, 20, dut.is_service_fully_started, "snmp"), "SNMP service is not running"
