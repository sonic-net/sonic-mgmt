# get_crm_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Parses `crm show` commands to gather facts on CRM.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    crm_facts = duthost.get_crm_facts()
```

## Arguments
This method takes no arguments

## Expected Output
Returns a dictionary with gather CRM facts. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `acl_group` - Lists of dictionaries, one for each ACL group. The dicitonaries contain information on the group
    - `resource name` - resource name of group
    - `bind point`
    - `available count`
    - `used count`
    - `stage` - INGRESS or EGRESS
- `acl_table` - List of dictionaries, one for each ACL table. THe dicitonaries contain info on the table
    - `table_id` - id for the ACL table
    - `resource name` - resource name for table
    - `used count`
    - `available count`
- `thresholds` - Dictionary that maps route names to their thresholds
    - `{ROUTE_NAME}` - dictionary that provides info on thresholds for given route
        - `high` - high end threshold
        - `low` - low end threshold
        - `type` - type of threshold
- `resources` - Dictionary describing resources for routes
    - `{ROUTE_NAME}` - Dictionary describing resources for provided route
        - `available`
        - `used`
- `polling_interval` - How often polling occured