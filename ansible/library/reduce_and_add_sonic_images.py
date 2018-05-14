#!/usr/bin/python

DOCUMENTATION = '''
module:  reduce_and_add_sonic_images
version_added:  "1.0"

short_description: remove excessive sonic images and install new image if specified
description: remove excessive sonic images from the target device.
Note that this version doesn't guarantee to remove older images. Images
in the 'Available' list that are not 'Current' or 'Next' wil subject to
removal.

Options:
    - option-name: disk_used_pcent
      description: maximum disk used percentage after removing old images
      required: False
      Default: 50
    - option-name: new_image_url
      description: url pointing to the new image
      required: False
      Default: None

'''

import sys
from ansible.module_utils.basic import *

def exec_command(module, cmd, ignore_error=False, msg="executing command"):
    rc, out, err = module.run_command(cmd)
    if not ignore_error and rc != 0:
        module.fail_json(msg="Failed %s: rc=%d, out=%s, err=%s" %
                         (msg, rc, out, err))
    return out


def get_sonic_image_removal_candidates(module):
    keep   = set()
    images = set()

    out = exec_command(module, cmd="sonic_installer list",
                       msg="listing sonic images")

    lines = out.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith("Current:") or line.startswith("Next:"):
            keep.add(line.split()[1].strip())
        elif line != "Available:" and len(line) > 0:
            images.add(line)

    return (images - keep)


def get_disk_free_size(module, partition):
    out   = exec_command(module, cmd="df -BM --output=avail %s" % partition,
                         msg="checking disk available size")
    avail = int(out.split('\n')[1][:-1])

    return avail


def get_disk_used_percent(module, partition):
    out   = exec_command(module, cmd="df -BM --output=pcent %s" % partition,
                         msg="checking disk available percent")
    pcent = int(out.split('\n')[1][:-1])

    return pcent


def reduce_installed_sonic_images(module, disk_used_pcent):
    images = get_sonic_image_removal_candidates(module)

    while len(images) > 0:
        pcent = get_disk_used_percent(module, "/host")
        if pcent < disk_used_pcent:
            break
        # Randomly choose an old image to remove. On a system with
        # developer built images and offical build images mix-installed
        # it is hard to compare image tag to find 'oldest' image.
        img = images.pop()
        exec_command(module, cmd="sonic_installer remove %s -y" % img,
                     ignore_error=True)


def install_new_sonic_image(module, new_image_url):
    if not new_image_url:
        return

    avail = get_disk_free_size(module, "/host")
    if avail >= 1500:
        # There is enough space to install directly
        exec_command(module,
                     cmd="sonic_installer install %s -y" % new_image_url,
                     msg="installing new image")
    else:
        # Create a tmpfs partition to download image to install
        exec_command(module, cmd="mkdir -p /tmp/tmpfs", ignore_error=True)
        exec_command(module, cmd="umount /tmp/tmpfs", ignore_error=True)

        exec_command(module,
                     cmd="mount -t tmpfs -o size=1000M tmpfs /tmp/tmpfs",
                     msg="mounting tmpfs")
        exec_command(module,
                     cmd="curl -o /tmp/tmpfs/sonic-image %s" % new_image_url,
                     msg="downloading new image")
        exec_command(module,
                     cmd="sonic_installer install /tmp/tmpfs/sonic-image -y",
                     msg="installing new image")

        exec_command(module, cmd="sync", ignore_error=True)
        exec_command(module, cmd="umount /tmp/tmpfs", ignore_error=True)
        exec_command(module, cmd="rm -rf /tmp/tmpfs", ignore_error=True)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            disk_used_pcent=dict(required=False, type='int', default=8),
            new_image_url=dict(required=False, type='str', default=None),
        ),
        supports_check_mode=False)

    disk_used_pcent = module.params['disk_used_pcent']
    new_image_url   = module.params['new_image_url']

    try:
        reduce_installed_sonic_images(module, disk_used_pcent)
        install_new_sonic_image(module, new_image_url)
    except:
        err = str(sys.exc_info())
        module.fail_json(msg="Error: %s" % err)

    module.exit_json()

if __name__ == '__main__':
    main()
