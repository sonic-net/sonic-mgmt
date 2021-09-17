# image_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get information on image from remote host.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    im_facts = duthost.image_facts()
```

## Arguments
This method take no arguments.

## Expected Output
A dictionary is returned with information on the remote host's laoded image. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `ansible_image_facts` - Dictionary containing image facts
        - `available` - List of available images
        - `current` - Currently loaded image
        - `next` - latest available image
        