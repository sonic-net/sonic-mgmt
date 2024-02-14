import pytest


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, loganalyzer):
    """
        In Mellanox, when techsupport is taken, it invokes fw dump.
        While taking the fw dump, the fw is busy and doesn't respond to other calls.
        The access of sfp eeprom happens through firmware and xcvrd gets the DOM fields
        every 60 seconds which fails during the fw dump.
        This is a temporary issue and this log can be ignored.
        Issue link: https://github.com/sonic-net/sonic-buildimage/issues/12621
        The fixture is auto used to all test scripts in this directory.
    """
    ignoreRegex = [
        ".*ERR kernel:.*Reg cmd access status failed.*",
        ".*ERR kernel:.*Reg cmd access failed.*",
        ".*ERR kernel:.*Eeprom query failed.*",
        ".*ERR kernel:.*Fails to access.*register MCIA.*",
        ".*ERR kernel:.*Fails to read module eeprom.*",
        ".*ERR kernel:.*Fails to access.*module eeprom.*",
        ".*ERR kernel:.*Fails to get module type.*",
        ".*ERR pmon#xcvrd:.*Failed to read sfp.*",
        ".*DEBUG systemd.*",
        ".*ERR syncd#SDK:.*mlnx_sai_object.* mlnx_(?:allocate|deallocate)_sx_bulk_buffer: Failed to (?:create|destroy) "
        "buffer: Driver.* Return Status is Non-Zero.*",
        ".*ERR syncd#SDK: .*mlnx_sai_queue.c.*- mlnx_sai_bulk_queue_stats_get: "
        "Failed to prepare bulk counter for queue stats.*",
        ".*ERR syncd#SDK: .*mlnx_sai_buffer.c.*Failed to prepare bulk counter for pg occupancy stats.*",
        ".*ERR syncd#SDK: .*mlnx_sai_buffer.c.*Failed to deallocate SDK occupancy buffer.*",
        ".*WARNING kernel:.*syncd: page allocation failure: order:.*, mode:.*GFP_KERNEL.__GFP_COMP., "
        "nodemask=.null.,cpuset=.*,mems_allowed=.*"
    ]
    for dut in duthosts:
        if loganalyzer and loganalyzer[dut.hostname]:
            loganalyzer[dut.hostname].ignore_regex.extend(ignoreRegex)
