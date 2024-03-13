# HLD - Dynamic PSU Support in Sensor Test #

# Table of Content 

- [Revision](#revision)
- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
    - [Design](#design)
- [Tests](#tests)

## Revision  

| Rev  |   Date   |    Author     |       Change Description                  |
| :--: | :------: | :-----------: | ------------------------------------------|
| 0.1  | 13/03/24 | Mor Hen       | Initial version                           |
## Overview
The current test checks the sensors per platform, using a predefined list of sensors called "sku-sensors-data.yml". This means any modification to the PSU on the switch will result in failure of the test and require modification of the predefined yml file. 
We want to modify the test to depend on the PSUs sensors of the PSUs installed currently on the device and not those in the yml file.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test sensor validation after change of test.

### Testbed
The test could run on any testbed.

### Design

The original design of the test is as follows:

![test_sensors-Original Design drawio](https://github.com/mhen1/sonic-mgmt/assets/155874991/e9056e64-52d4-468b-b58e-d0b4f3b18985)

As can be seen, the sensor data of the platform is loaded from the static sku-sensors-data.yml file and is then sent for validation.
The PSUs sesnors checked are those present in this file.

The new design of the test will be as follows:

![test_sensors-New Design drawio](https://github.com/mhen1/sonic-mgmt/assets/155874991/e8260544-60e6-463c-9003-6cb99cf97876)

As can be seen, there are now two static files in play. The original sku-sensors-data.yml file is still used to fetch the sensors unrelated to the PSUs. 
However, there is a second file, called psu-sensors-data.yml which will be used to fetch the sensors relevant to the PSUs installed on the device. That is, we will check dynamically which PSUs are installed on the device and, using that information, fetch the relevant sensor information from the psu-sensors-data.yml file which will act as a mapping between PSUs and their relevant sesnors.

After fetching the information from both files, we will merge them together to a single source of data for the validation. This data will contain
all the non-psu sensors from the original sku-sensors-data.yml, and the PSU sensors as listed in the new psu-sensors-data.yml file. The merged data will be sent
for validation and the process will proceed as it did in the old design.

In the case the PSU is not found in the psu-sensors-data.yml file, we will use the old approach and fetch all sensors from sku-sensors-data.yml file.

## Tests
The flow of the test by itself does not change - we validate the values of sensors that reside on our system. We run the test with diffreent scenarios to verify the modification works as expected.

We will check the following scenarios:
- New functionality check with a single PSU source - run the test on platforms whose PSUs are all of the same model and are listed in psu-sensors-data.yml.
- New functionality check with multiple PSU sources - run the test on platforms with different PSUs, all listed in psu-sensors-data.yml.
- Regression check with a single PSU source - run the test on platforms whose PSUs are all of the same model and are not listed in psu-sensors-data.yml.
- Regression check with multiple PSU sources - run the test on platforms with different PSUs, some (or all) not listed in psu-sensors-data.yml. 
