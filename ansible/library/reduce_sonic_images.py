#!/usr/bin/python

DOCUMENTATION = '''
module:  reduce_sonic_images
version_added:  "1.0"

short_description: remove excessive sonic images.
description: remove excessive sonic images from the target device.
Note that this version doesn't guarantee to remove older images. Images
in the 'Available' list that are not 'Current' or 'Next' wil subject to
removal. retain_copies of images will be kept after the removal. When
device has less than retain_copies copies of images installed, no image
will be removed.

Options:
    - option-name: retain_copies
      description: max number of sonic images to keep.
      required: False
      Default: 8

'''

import sys
from ansible.module_utils.basic import *

def get_sonic_image_list(module):
    keep   = set()
    images = set()

    rc, out, err = module.run_command("sonic_installer list")
    if rc != 0:
        module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                (rc, out, err))

    lines = out.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith("Current:") or line.startswith("Next:"):
            keep.add(line.split()[1].strip())
        elif line != "Available:" and len(line) > 0:
            images.add(line)

    return keep, images


def reduce_sonic_image_copies(module, retain_copies):
    keep, images = get_sonic_image_list(module)

    discard = set()
    for img in images:
        if (len(images) - len(discard)) <= retain_copies:
            break
        if img in keep:
            continue
        discard.add(img)

    for img in discard:
        module.run_command("sonic_installer remove %s -y" % img)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            retain_copies=dict(required=False, type='int', default=8),
        ),
        supports_check_mode=False)

    retain_copies = module.params['retain_copies']

    try:
        reduce_sonic_image_copies(module, retain_copies)
    except:
        err = str(sys.exc_info())
        module.fail_json(msg="Error: %s" % err)

    module.exit_json()

if __name__ == '__main__':
    main()
