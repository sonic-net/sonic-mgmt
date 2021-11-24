# reduce_and_add_sonic_images

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Removes excess sonic images and installs a new image if requested.

## Examples
duthost.reduce_and_add_sonic_images(new_image_url={URL_TO_SONIC_IMAGE})

## Arguments
- `disk_used_pcent` - If disk_space usage is above this percent after old disks are removed, module makes best effort to remove uneeded files
    - Required: `False`
    - Type: `Integer`
    - Default: `50`
- `new_image_url` - URL for new sonic image. If URL is not provided, no image will be downloaded.
    - Required: `False`
    - Type: `String`
    - Default: `None`

## Expected Output
Simple dictionary showing which image was downloaded. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `downlaoded_iamge_version` - version of image downloaded