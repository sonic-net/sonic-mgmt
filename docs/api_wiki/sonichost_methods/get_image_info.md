# get_image_info

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get list of images installed on the DUT.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    images = duthost.get_image_info()
```

## Arguments
Takes no arguments.

## Expected Output
Returns dicitonary with information on installed images:

- `images` - list of images that are available
- `current` - current image installed
- `next` - next version of image available