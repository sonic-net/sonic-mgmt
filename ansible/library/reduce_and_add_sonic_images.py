#!/usr/bin/python

import logging
import sys
import time
from os import path
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.debug_utils import config_module_logging

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

config_module_logging("reduce_and_add_sonic_images")

results = {"downloaded_image_version": "Unknown", "current_stage": "Unknown", "messages": []}


def log(msg):
    global results

    current_time = time.time()
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time))
    results["messages"].append("{} {}".format(str(timestamp), msg))
    logging.debug(msg)


def exec_command(module, cmd, ignore_error=False, msg="executing command"):
    logging.debug("*** cmd: %s ***" % cmd)
    rc, out, err = module.run_command(cmd, use_unsafe_shell=True)
    logging.debug("*** rc: %d, out: %s, err: %s ***" % (rc, out, err))

    if not ignore_error and rc != 0:
        module.fail_json(msg="Failed %s: rc=%d, out=%s, err=%s" % (msg, rc, out, err))
    return rc, out, err


def get_disk_free_size(module, partition):
    """Return available disk size in MB
    """
    _, out, _ = exec_command(module, cmd="df -BM --output=avail %s" % partition, msg="checking disk available size")
    avail = int(out.split('\n')[1][:-1])

    return avail


def get_memory_sizes(module):
    """Return total/available memory size in MB, -1, -1 means failed to get the sizes
    """
    _, out, _ = exec_command(module, cmd="free -m", msg="checking memory total/free sizes")
    lines = out.split('\n')

    for line in lines:
        if line.startswith("Mem:"):
            fields = line.split()
            if len(fields) < 3:
                return -1, -1
            else:
                total_mem, avail_mem = int(fields[1]), int(fields[-1])
        elif line.startswith("Swap:"):
            fields = line.split()
            if len(fields) < 3:
                return -1, -1
            else:
                total_swap, avail_swap = int(fields[1]), int(fields[-1])

    total = total_mem + total_swap
    avail = avail_mem + avail_swap
    return total, avail


def setup_swap_if_necessary(module):
    log("Setup swap if necessary")
    df = get_disk_free_size(module, '/host')
    total, avail = get_memory_sizes(module)
    if df < 4000 or total < 0 or avail < 0:
        log("Disk free space low or failed to obtain memory information")
        return

    if total < 2048 or avail < 1200:
        log("Low free memory. Creating temp swap to avoid possible OOM during image installation")
        exec_command(
            module,
            cmd="if [ -f {0} ]; then sudo swapoff {0}; sudo rm -f {0}; fi; "
                "sudo fallocate -l 1G {0}; sudo chmod 600 {0}; sudo mkswap {0}; sudo swapon {0}"
                .format('/host/swapfile'),
            msg="Create a temporary swap file")
        log("Done creating tmp swap")
    else:
        log("No need to setup swap")


def reduce_installed_sonic_images(module):
    log("reduce_installed_sonic_images")

    rc, out, _ = exec_command(module, cmd="sonic_installer list", ignore_error=True)
    if rc != 0:
        log("Failed to get sonic image list. Will try to install new image anyway.")
        return

    lines = out.split('\n')

    # if next boot image not same with current, set current as next boot, and delete the original next image
    curr_image = ""
    next_image = ""
    for line in lines:
        if 'Current:' in line:
            curr_image = line.split(':')[1].strip()
        elif 'Next:' in line:
            next_image = line.split(':')[1].strip()

    if curr_image == "":
        log("Failed to get current image. Will try to install new image anyway.")
        return

    if next_image == "":
        log("Failed to get next image. Will try to install new image anyway.")
        return

    if curr_image != next_image:
        log("set-next-boot")
        exec_command(module, cmd="sonic_installer set-next-boot {}".format(curr_image), ignore_error=True)

    log("cleanup old image")
    exec_command(module, cmd="sonic_installer cleanup -y", ignore_error=True)

    log("Done reduce_installed_sonic_images")


def download_new_sonic_image(module, new_image_url, save_as):
    log("download_new_sonic_image")

    global results

    if new_image_url:
        log("Before downloading new image, clean-up previous downloads first")
        exec_command(
            module,
            cmd="rm -f {}".format(save_as),
            msg="clean up previously downloaded image",
            ignore_error=True
        )
        log("Downloading new image using curl")
        exec_command(
            module,
            cmd="curl -Lo {} {}".format(save_as, new_image_url),
            msg="downloading new image"
        )
        log("Completed downloading image")

    free_disk_size = get_disk_free_size(module, "/")
    total, avail = get_memory_sizes(module)
    log("After downloaded sonic image, latest free disk size: {}, "
        "memory total {} available {}".format(free_disk_size, total, avail))

    if path.exists(save_as):
        log("Checking downloaded image version")
        _, out, _ = exec_command(module, cmd="sonic_installer binary_version {}".format(save_as))
        results["downloaded_image_version"] = out.rstrip('\n')
        log("Downloaded image version: {}".format(results["downloaded_image_version"]))
        # Save the binary version to file
        exec_command(module, cmd="sudo echo {} > /tmp/downloaded-sonic-image-version".format(
            results["downloaded_image_version"]))


def install_new_sonic_image(module, new_image_url, save_as=None, required_space=1600):
    log("install new sonic image")
    if not save_as:
        log("Clean-up previous downloads first")
        exec_command(
            module,
            cmd="rm -f {}".format("/host/downloaded-sonic-image"),
            msg="clean up previously downloaded image",
            ignore_error=True
        )
        avail = get_disk_free_size(module, "/host")
        save_as = "/host/downloaded-sonic-image" if avail >= 2000 else "/tmp/tmpfs/downloaded-sonic-image"

    free_disk_size = get_disk_free_size(module, "/")
    total, avail = get_memory_sizes(module)
    log("Before install sonic image, free disk {}, memory total {} available {}".format(free_disk_size, total, avail))
    if avail < 1024 or free_disk_size < required_space:
        log("free memory or disk space size is not enough to install a new image")
        module.fail_json(
            msg="Image installation failed: rc=%d, out=%s, err=%s" % (
                -1,
                "free memory or disk space size is not enough to install a new image",
                ""
            )
        )
        return

    skip_package_migrate_param = ""
    _, output, _ = exec_command(module, cmd="sonic_installer install --help", ignore_error=True)
    if "skip-package-migration" in output:
        skip_package_migrate_param = "--skip-package-migration"

    if save_as.startswith("/tmp/tmpfs"):
        log("Create a tmpfs partition to download image to install")
        exec_command(module, cmd="mkdir -p /tmp/tmpfs", ignore_error=True)
        exec_command(module, cmd="umount /tmp/tmpfs", ignore_error=True)

        exec_command(
            module,
            cmd="mount -t tmpfs -o size=1300M tmpfs /tmp/tmpfs",
            msg="mounting tmpfs"
        )
        download_new_sonic_image(module, new_image_url, save_as)
        log("Running sonic_installer to install image at {}".format(save_as))
        rc, out, err = exec_command(
            module,
            cmd="sonic_installer install {} {} -y".format(save_as, skip_package_migrate_param),
            msg="installing new image", ignore_error=True
        )
        log("Done running sonic_installer to install image")

        exec_command(module, cmd="sync", ignore_error=True)
        exec_command(module, cmd="umount /tmp/tmpfs", ignore_error=True)
        exec_command(module, cmd="rm -rf /tmp/tmpfs", ignore_error=True)
        log("Done umount and cleanup tmpfs")

        if rc != 0:
            module.fail_json(msg="Image installation failed: rc=%d, out=%s, err=%s" % (rc, out, err))
    else:
        log("There is enough space on /host to download and install directly")
        download_new_sonic_image(module, new_image_url, save_as)

        log("Running sonic_installer to install image at {}".format(save_as))
        rc, out, err = exec_command(
            module,
            cmd="sonic_installer install {} {} -y".format(
                save_as, skip_package_migrate_param),
            msg="installing new image", ignore_error=True
        )
        log("Always remove the downloaded temp image inside /host/ before proceeding")
        exec_command(module, cmd="rm -f {}".format(save_as))
        if rc != 0:
            module.fail_json(msg="Image installation failed: rc=%d, out=%s, err=%s" % (rc, out, err))

    # If sonic device is configured with minigraph, remove config_db.json
    # to force next image to load minigraph.
    if path.exists("/host/old_config/minigraph.xml"):
        log("Remove /host/old_config/config_db.json when /etc/old_config/minigraph.xml exists")
        exec_command(
            module,
            cmd="rm -f /host/old_config/config_db.json",
            msg="Remove config_db.json in preference of minigraph.xml"
        )


def work_around_for_slow_disks(module):
    # Increase hung task timeout to 600 seconds to avoid kernel panic
    # while writing lots of data to a slow disk.
    log("work around for slow disks, increase hung task timeout to 600 seconds")
    exec_command(module, cmd="sysctl -w kernel.hung_task_timeout_secs=600", ignore_error=True)
    log("Done work around for slow disks")


def free_up_disk_space(module, disk_used_pcent):
    """Remove old log, core and dump files."""
    log("free up disk space at best effort")

    def get_disk_used_percent(module):
        output = exec_command(module, cmd="df -BM --output=pcent /host")[1]
        return int(output.splitlines()[-1][:-1])

    def get_disk_total_size(module):
        output = exec_command(module, cmd="df -BM --output=size /host")[1]
        return int(output.splitlines()[-1][:-1])

    current_used_percent = get_disk_used_percent(module)
    total_size = get_disk_total_size(module)
    log("current used percent: {}, total_size {}".format(current_used_percent, total_size))
    if current_used_percent > disk_used_pcent or total_size < 4096:
        log("Trying to free up spaces at best effort")
        exec_command(module, "rm -f /var/log/*.gz", ignore_error=True)
        exec_command(module, "rm -f /var/core/*", ignore_error=True)
        exec_command(module, "rm -rf /var/dump/*", ignore_error=True)
        exec_command(module, "rm -rf /home/admin/*", ignore_error=True)
        latest_used_percent = get_disk_used_percent(module)
        log("Done free up, latest used percent: {}".format(latest_used_percent))
    else:
        log("No need to free up disk space")

    free_disk_size = get_disk_free_size(module, "/host")
    log("After free up disk space, latest free disk size: {}".format(free_disk_size))


def free_up_memory_drop_caches(module):
    """
    To free pagecache:
        echo 1 > /proc/sys/vm/drop_caches
    To free reclaimable slab objects (includes dentries and inodes):
        echo 2 > /proc/sys/vm/drop_caches
    To free slab objects and pagecache:
        echo 3 > /proc/sys/vm/drop_caches
    """
    for index in range(1, 4):
        cmd = 'echo {} >  /proc/sys/vm/drop_caches'.format(index)
        exec_command(module, cmd, ignore_error=True)
        cmd = 'sync'
        exec_command(module, cmd, ignore_error=True)
        log("drop {} cache to free up memory space".format(index))
    return


def free_up_memory_stop_process(module):
    """
    stop the process which not need during upgrade
    not start it here since it will be started after reboot
    sudo systemctl list-units --type=service --state=running
    """

    processes = ['monit.service', 'telemetry.service', 'stop pmon.service']
    for process in processes:
        cmd = 'systemctl stop {}'.format(process)
        exec_command(module, cmd, ignore_error=True)
        log("stop process {}".format(process))

    return


def free_up_memory_space(module, free_space_needed=1024):
    """for low memory device, drop cache and disable process which not need during upgrade."""
    log("free up memory space at best effort")

    total, avail = get_memory_sizes(module)
    if avail > free_space_needed:
        log("Available memory {}, no need to free up memory space".format(avail))
        return

    free_up_memory_drop_caches(module)
    free_up_memory_stop_process(module)

    total, avail = get_memory_sizes(module)
    log("After free up, current available memory {}".format(avail))

    return


def work_around_for_reboot(module):
    # work around reboot for s6100
    # Replace /usr/share/sonic/device/x86_64-dell_s6100_c2538-r0/platform_reboot_pre_check
    # Ignore any pre check and just return 0
    log("Start workaround for S6100 reboot")
    _, out, _ = exec_command(module, cmd="show platform summary", ignore_error=True)
    if 'Force10-S6100' in out:
        log("S6100 device, hack its platform_reboot_pre_check file")
        exec_command(
            module,
            cmd="sudo mv /usr/share/sonic/device/x86_64-dell_s6100_c2538-r0/platform_reboot_pre_check "
                "/usr/share/sonic/device/x86_64-dell_s6100_c2538-r0/platform_reboot_pre_check_bak",
            ignore_error=True
        )
        file_content = '''#!/bin/bash
exit 0
'''
        with open("/usr/share/sonic/device/x86_64-dell_s6100_c2538-r0/platform_reboot_pre_check", 'w') as out_file:
            out_file.write(file_content)
    log("Done workaround for S6100 reboot")


def main():
    global results

    module = AnsibleModule(
        argument_spec=dict(
            disk_used_pcent=dict(required=False, type='int', default=8),
            new_image_url=dict(required=False, type='str', default=None),
            save_as=dict(required=False, type='str', default=None),
            required_space=dict(required=False, type='int', default=1600),
        ),
        supports_check_mode=False)

    disk_used_pcent = module.params['disk_used_pcent']
    new_image_url = module.params['new_image_url']
    save_as = module.params['save_as']
    required_space = module.params['required_space']

    try:
        if new_image_url or save_as:
            results["current_stage"] = "start"

            work_around_for_reboot(module)
            work_around_for_slow_disks(module)
            reduce_installed_sonic_images(module)
            results["current_stage"] = "prepare"

            free_up_disk_space(module, disk_used_pcent)
            free_up_memory_space(module)
            setup_swap_if_necessary(module)
            results["current_stage"] = "install"

            install_new_sonic_image(module, new_image_url, save_as, required_space)
            results["current_stage"] = "complete"
        else:
            reduce_installed_sonic_images(module)
            free_up_disk_space(module, disk_used_pcent)
    except Exception:
        err = str(sys.exc_info())
        module.fail_json(msg="Exception raised during image upgrade", results=results, err=err)

    module.exit_json(ansible_facts=results)


if __name__ == '__main__':
    main()
