##### Overview
Please find HLD for dut_monitor plugin - https://github.com/Azure/SONiC/blob/master/doc/DUT_monitor_HLD.md

Current plugin implements verification the hardware resources consumed by a device. The hardware resources which are currently verified are CPU, RAM and HDD.
Verification is based on thresholds defind in "thresholds.yml" file.

##### Usage example
To enable "dut_monitor" plugin, use "--dut_monitor" pytest option.
It will monitor hardware resources per each test case.

To specify custom thresholds file use "--thresholds_file" pytest option.
Example:
--thresholds_file THRESHOLDS_FILE_PATH

##### General flow:

- Starts DUT monitoring before test start
- Stops DUT monitoring after test finish
- Get measured values and compare them with defined thresholds
- Pytest error will be generated if any of resources exceed the defined threshold
