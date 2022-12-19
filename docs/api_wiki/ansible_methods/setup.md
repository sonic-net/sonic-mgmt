# setup

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gather facts about the duthost.

[docs](https://docs.ansible.com/ansible/2.3/setup_module.html) used to help write this page.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    setup_facts = duthost.setup()
```

## Arguments
This method takes no arguments

## Expected Output

The output for this command is far too long to reasonably document. Commonly used properties should be documented at some point.