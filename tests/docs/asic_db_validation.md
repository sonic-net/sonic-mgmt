## ASIC DB Validation for SONiC Management Tests
## Overview of Design

## Purpose of this Document

In order to facilitate validating entries from ASIC DB, helper methods and Pytest fixtures have been added. This document outlines the available functionality to access ASIC DB and other Redis database objects via sonic-db-cli.

## Methodology

The enhancements to test utilities and fixtures for ASIC DB validation leverage the existing `sonic-db-cli` wrappers and modules detailed in [../common/helpers/sonic_db.py](../common/helpers/sonic_db.py) within the SONiC Management testing framework. It also introduces PyTest fixtures to facilitate ASIC db access.

## Application

The `sonic_db.py` [../common/helpers/sonic_db.py](../common/helpers/sonic_db.py) module offers a set of classes with various methods for interfacing with ASIC DB and other database objects using `sonic-db-cli`. Test scripts can utilize fixtures to interact with the `AsicDbCli` methods, allowing them to retrieve information from different ASIC_DB tables. The following fixtures are available:

- `asic_db_dut` provides an `AsicDbCli` instance for the Device Under Test (DUT).
- `asic_db_dut_rand` offers a random `AsicDbCli` instance for setups with Multi-ASIC configurations.
- `asic_db_supervisor` grants access to an `AsicDbCli` instance from the supervisor SONiC instance in a disaggregated chassis setup.

`AsicDbCli` class allows caller to access various ASIC_DB object types. Access to the following object types are supported. Access to additional object types, key-values and complex querying can be incorporated into `AsicDbCli` using calls to `SonicDbCli` methods.

### Example

```
def test_asicdb_duthost(asic_db_dut):
    key = asic_db_dut.get_switch_key()
    logger.info(f'switch key from asic db for duthost {key}')
    host_if_list = asic_db_dut.get_hostif_list()
    logger.info(f'duthost host interfaces {host_if_list}')
    assert host_if_list is not None
    assert key is not None

def test_asic_db_get_nexthop_entries(asic_db_dut):
    nexthop_entries = asic_db_dut.get_next_hop_entries()
    logger.info(f'nexthop entries = {nexthop_entries}')
    assert nexthop_entries is not None
```
