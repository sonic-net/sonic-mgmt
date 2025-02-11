
import inspect
import unittest
import time
import re
import yaml
from image_mgmt_helper import ImgMgmtTestHelper
import sys

# These tests run on a single router(HW only) and verifies various image management
# functions that are supported for A/B Paritioning and Immutable FS.
class ImageMgmtTests(unittest.TestCase):
    def get_image(self, image_name):
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        pattern = re.compile(fr'^{image_name}.*', re.MULTILINE)
        matches = pattern.findall(output)
        if len(matches) > 0 and matches[0].startswith(image_name):
            return matches[0]
        else:
            return ""

    def set_next_boot(self, image_name):
        _, _, err = im.exec_cmd("sudo -s sonic-installer set-next-boot " + str(image_name))
        if err != "":
            im.log("error on set-next-boot: err: " + err)
            _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
            im.log("set-next-boot: output: " + output)

        # check if the next boot was set properly
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        pattern = re.compile(fr'(?<=Next: ).*')
        matches = pattern.findall(output)

        if len(matches) < 1:
            im.log("Failed to set next boot image. Output: " + output)
            return False

        if image_name not in matches[0]:
            im.log(f"Failed to find {image_name} next boot image. set-next-boot image failed")
            return False
        im.log("Image " + image_name + " properly set as next boot")

        return True

    def install_new_image(self):
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        if "Current: IMAGE-A" in output:
            im.log("Running image A. Installing new image at IMAGE-B")
            new_image = "IMAGE-B"
        elif "Current: IMAGE-B" in output:
            im.log("Running image B. Installing new image at IMAGE-A")
            new_image = "IMAGE-A"
        else:
            im.log("Failed to determine current image, aborting install: output:" + output)
            return False, ""

        _, output, err = im.exec_cmd("sudo -s sonic-installer install -y " + im.img_path)
        im.log("Installed image, output: " + output + ", err: " + err)
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        pattern = re.compile(fr'^{new_image}.*', re.MULTILINE)
        matches = pattern.findall(output)

        if len(matches) < 1:
            im.log("Failed to install image. Output: " + output)
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return False, ""

        im.log("Successfully installed new image at: " + new_image)
        return True, new_image

    def image_upgrade_and_config_migration(self):
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        upgrade_image = ""
        if "Current: IMAGE-A" in output:
            im.log("Running image A. Upgrading image B")
            upgrade_image = "IMAGE-B"
        elif "Current: IMAGE-B" in output:
            im.log("Running image B. Upgrading image A")
            upgrade_image = "IMAGE-A"

        im.exec_cmd("sudo -s config ntp add 1.1.1.1")
        im.exec_cmd("sudo -s config save -y")

        _, output, _ = im.exec_cmd("sudo -s show runningconfiguration ntp")
        im.log(output)

        _, output, err = im.exec_cmd("sudo -s sonic-installer install -y " + im.img_path)
        im.log("\nOutput: " + output)
        im.log("\nErr: " + err)

        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        im.log(output)

        pattern = re.compile(fr'^{upgrade_image}.*', re.MULTILINE)
        matches = pattern.findall(output)

        if len(matches) < 1:
            im.log("Failed to install image. Output: " + output)
            return False

        # set the image as the default for next boot
        if matches[0].startswith(upgrade_image):
            img = matches[0]
            im.log("set-next-boot to " + img)

            _, _, err = im.exec_cmd("sudo -s sonic-installer set-next-boot " + str(img))
            if err != "":
                im.log("error on set-next-boot: err: " + err)
                _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
                im.log("set-next-boot: output: " + output)
        # check if the next boot was set properly
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        pattern = re.compile(fr'(?<=Next: ).*')
        matches = pattern.findall(output)

        if len(matches) < 1:
            im.log("Failed to set next boot image. Output: " + output)
            return False

        if upgrade_image not in matches[0]:
            im.log(f"Failed to find {upgrade_image} next boot image")
            return False

        # verify the image
        _, output, _ = im.exec_cmd("sudo -s sonic-installer verify-next-image")
        if "Image successfully verified" not in output:
            im.log(f"Failed to verify the installed image. Output: " + output)
            return False

        # add config after the install and we'll check if this
        # also makes it into the new image
        im.exec_cmd("sudo -s config ntp add 2.2.2.2")
        im.exec_cmd("sudo -s config save -y")

        _, output, _ = im.exec_cmd("sudo -s show runningconfiguration ntp")
        im.log(output)

        im.log("Performing save and reboot")
        im.config_save()

        im.log("Rebooting device")
        im.reboot()

        im.log("Looking to see if new image " + upgrade_image + " is running")
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        expected_running_image = "Current: " + upgrade_image
        if expected_running_image in output:
            im.log('Image upgrade worked. Checking config and interface state next')
        else:
            im.log("Image upgrade test failed, output: " + output)
            return False

        _, output, _ = im.exec_cmd("sudo -s show runningconfiguration ntp")
        if "1.1.1.1" in output and "2.2.2.2" in output:
            im.log('ntp migrations on image upgrade passed')
            # clean up
            im.exec_cmd("sudo -s config ntp del 1.1.1.1")
            im.exec_cmd("sudo -s config ntp del 2.2.2.2")
            im.exec_cmd("sudo -s config save -y")
            return True
        else:
            im.log("Image upgrade config migration failed, output: " + output)
            return False

    def test_immutablility_on_reboot(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        if not im.is_immutable_fs_enabled():
            im.log("Skip test: " + (str(inspect.currentframe().f_code.co_name)) + ". Not a immutable FS system")
            self.skipTest((str(inspect.currentframe().f_code.co_name)) + ". Not a immutable FS system")
            return

        im.config_save()

        im.log("Creating files on immutable filesystem")
        im.create_files_for_test()

        if im.do_files_exist():
            im.log("Created Files successfully")

        im.log("Rebooting device")
        im.reboot()

        for f in im.TestFiles:
            if im.does_file_exist(f):
                im.log("Test failed as file:" + f
                       + " still exists after reboot. Immutability did not work")
                im.report_fail(str(inspect.currentframe().f_code.co_name))
                return

        im.report_pass(str(inspect.currentframe().f_code.co_name))

    def test_config_retention_on_reboot(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        im.exec_cmd("sudo -s config ntp add 171.68.38.66")
        _, output, _ = im.exec_cmd("sudo -s show runningconfiguration ntp")
        if "171.68.38.66" in output:
            im.log('ntp config added to configuration')

        im.log("Performing save and reboot")
        im.config_save()

        im.log("Rebooting device")
        im.reboot()

        _, output, _ = im.exec_cmd("sudo -s show runningconfiguration ntp")
        if "171.68.38.66" in output:
            im.log('ntp config save worked')
        else:
            im.log("Test Failed as configured ntp server not found, output: " + output)
            im.report_fail(str(inspect.currentframe().f_code.co_name))

        im.report_pass(str(inspect.currentframe().f_code.co_name))

    def test_image_upgrade_and_config_migration(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        # make sure interface show up correctly before
        # we do any config changes.
        if im.wait_for_interfaces():
            im.log("Wait for interfaces worked")
        else:
            im.log("Wait for interfaces failed")
            im.report_fail(str(inspect.currentframe().f_code.co_name))

        # test image upgrade while running current image
        if not self.image_upgrade_and_config_migration():
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        # test image upgrade while running the new image now.
        if not self.image_upgrade_and_config_migration():
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        im.report_pass(str(inspect.currentframe().f_code.co_name))
    '''
    Skipping for now since this test never recovers the partition after corruption
    def test_z_partition_corruption_of_efi(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        efi_device = ""
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        current_image = ""
        if "Current: IMAGE-A" in output:
            im.log("Running image A. Make sure next-boot is image A")
            current_image = "IMAGE-A"
            efi_device = "/dev/sda3"
        elif "Current: IMAGE-B" in output:
            im.log("Running image B. Upgrading image A")
            current_image = "IMAGE-B"
            efi_device = "/dev/sda4"

        if "IMAGE-A" not in output or "IMAGE-B" not in output:
            im.log("No backup image available. Installing one")
            ok, image = self.install_new_image()
            if ok:
                im.log("Successfully installed new image " + image)
            else:
                im.log("Failed to install new image " + image + ", aborting")
                im.report_fail(str(inspect.currentframe().f_code.co_name))
                return

        # make sure next-boot-image is the one that we will corrupt
        image_name = self.get_image(current_image)
        if not self.set_next_boot(image_name):
            im.log("Failed to set next boot. aborting efi corruption test")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        try:
            efi_mnt = "/tmp/efi-corruption-mnt"
            im.exec_cmd("rm -fr " + efi_mnt)
            im.exec_cmd("mkdir -p " + efi_mnt)
            _, out, err = im.exec_cmd("sudo -S mount " + efi_device + " " + efi_mnt)
            if err != "":
                if "/dev/sda3 already mounted" in err or "/dev/sda4 already mounted" in err:
                    im.exec_cmd("sudo -S umount " + efi_mnt)
                    _, out, err = im.exec_cmd("sudo -S mount " + efi_device + " " + efi_mnt)
                    if err != "":
                        im.log("Failed to mount efi partition: " + out + ", err:" + err)
                        im.report_fail(str(inspect.currentframe().f_code.co_name))
                        im.exec_cmd("sudo -S umount " + efi_mnt)
                        im.exec_cmd("rm -fr " + efi_mnt)
                        return
            _, out, _ = im.exec_cmd("ls " + efi_mnt)

            rm_dir = efi_mnt + "/EFI"
            im.log("Deleting EFI for image " + current_image)
            im.exec_cmd("sudo -S rm -fr " + rm_dir)
            im.exec_cmd("sudo -S umount " + efi_mnt)
        except Exception as e:
            im.exec_cmd("sudo -S umount " + efi_mnt)
            im.exec_cmd("sudo -S rm -fr " + rm_dir)
            im.log("Failed to delete EFI mount, error: " + str(e))
            im.log('EFI partition corruption test failed. Failed to delete EFI data')
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        im.log("Rebooting device")
        im.reboot()

        # check if we booted back fine
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        img_str = "Current: " + current_image
        if img_str in output:
            im.log(current_image + " booted fine ")
            im.log('EFI partition corruption test passed')
            im.report_pass(str(inspect.currentframe().f_code.co_name))
        else:
            im.log('EFI partition corruption test failed. Did not find current image')
            im.report_fail(str(inspect.currentframe().f_code.co_name))
    '''

    def test_z_rootfs_signature_failure(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        if not im.is_immutable_fs_enabled():
            im.log("Skip test: " + (str(inspect.currentframe().f_code.co_name)) + ". Not a immutable FS system")
            self.skipTest((str(inspect.currentframe().f_code.co_name)) + ". Not a immutable FS system")
            return

        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        current_image = ""
        img_base_dir = ""
        if "Current: IMAGE-A" in output:
            im.log("Running image A.")
            current_image = "IMAGE-A"
            img_base_dir = "/image-a"
        elif "Current: IMAGE-B" in output:
            im.log("Running image B.")
            current_image = "IMAGE-B"
            img_base_dir = "/image-b"

        if "IMAGE-A" not in output or "IMAGE-B" not in output:
            im.log("No backup image available. Installing one")
            ok, image = self.install_new_image()
            if ok:
                im.log("Successfully installed new image " + image)
            else:
                im.log("Failed to install new image " + image + ", aborting")
                im.report_fail(str(inspect.currentframe().f_code.co_name))
                return

        # make sure next-boot-image is the one that we will corrupt
        image_name = self.get_image(current_image)
        if not self.set_next_boot(image_name):
            im.log("Failed to set next boot. aborting signature corruption test")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        img_dir = im.find_img_directory(img_base_dir, "image-")
        if img_dir is None:
            im.log("Failed to find the image sub directory")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return
        else:
            im.log("Img Subdirectory is " + str(img_base_dir + "/" + img_dir))

        sig_file = str(img_base_dir + "/" + img_dir) + "/" + "fs.squashfs.signature"
        bkp_sig_file = sig_file + ".test_signature_failure"

        im.exec_cmd("sudo mv " + sig_file + " " + bkp_sig_file)
        im.exec_cmd("touch " + sig_file)

        im.log("Rebooting device")
        im.reboot()

        time.sleep(5)
        # check if we booted back fine
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        img_str = "Current: " + current_image
        if img_str in output:
            im.log(current_image + " booted up.")
            im.log('Filesystem Signature corruption test failed. Corrupt signature image booted fine')
            # restore back the signature for other tests to continue
            im.log("Restore the signature file.")
            im.exec_cmd("sudo mv " + bkp_sig_file + " " + sig_file)
            im.report_fail(str(inspect.currentframe().f_code.co_name))
        else:
            im.log('Filesystem Signature corruption test passed. Recovery image booted up')
            im.report_pass(str(inspect.currentframe().f_code.co_name))

        # restore back the signature for other tests to continue
        im.log("Restore the signature file.")
        im.exec_cmd("sudo mv " + bkp_sig_file + " " + sig_file)

    def test_z_docker_pkg_signature_failure(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        if not im.is_immutable_fs_enabled():
            im.log("Skip test: " + (str(inspect.currentframe().f_code.co_name)) + ". Not a immutable FS system")
            self.skipTest((str(inspect.currentframe().f_code.co_name)) + ". Not a immutable FS system")
            return

        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        current_image = ""
        img_base_dir = ""
        if "Current: IMAGE-A" in output:
            im.log("Running image A.")
            current_image = "IMAGE-A"
            img_base_dir = "/image-a"
        elif "Current: IMAGE-B" in output:
            im.log("Running image B.")
            current_image = "IMAGE-B"
            img_base_dir = "/image-b"

        if "IMAGE-A" not in output or "IMAGE-B" not in output:
            im.log("No backup image available. Installing one")
            ok, image = self.install_new_image()
            if ok:
                im.log("Successfully installed new image " + image)
            else:
                im.log("Failed to install new image " + image + ", aborting")
                im.report_fail(str(inspect.currentframe().f_code.co_name))
                return

        # make sure next-boot-image is the one that we will corrupt
        image_name = self.get_image(current_image)
        if not self.set_next_boot(image_name):
            im.log("Failed to set next boot. aborting docker pkg signature failure test")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        img_dir = im.find_img_directory(img_base_dir, "image-")
        if img_dir is None:
            im.log("Failed to find the image sub directory")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return
        else:
            im.log("Img Subdirectory is " + str(img_base_dir + "/" + img_dir))

        sig_file = str(img_base_dir + "/" + img_dir) + "/" + "dockerfs.tar.signature"
        bkp_sig_file = sig_file + ".test_signature_failure"

        im.exec_cmd("sudo mv " + sig_file + " " + bkp_sig_file)

        im.log("Rebooting device")
        im.reboot()

        time.sleep(5)
        # check if we booted back fine
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        img_str = "Current: " + current_image
        if img_str in output:
            im.log(current_image + " booted up.")
            im.log('Docker pkg signature failure test failed. Corrupt docker pkg signature image booted fine')
            # restore back the signature for other tests to continue
            im.log("Restore the signature file.")
            im.exec_cmd("sudo mv " + bkp_sig_file + " " + sig_file)
            im.report_fail(str(inspect.currentframe().f_code.co_name))
        else:
            # restore back the signature for other tests to continue
            im.log("Restore the signature file.")
            im.exec_cmd("sudo mv " + bkp_sig_file + " " + sig_file)
            im.log('Docker pkg Signature corruption test passed. Recovery image booted up')
            im.report_pass(str(inspect.currentframe().f_code.co_name))

    def test_z_kernel_corruption(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        current_image = ""
        img_base_dir = ""
        img_to_test = ""
        if "Current: IMAGE-A" in output:
            im.log("Running image A. Make sure next-boot is image A")
            current_image = "IMAGE-A"
            img_to_test = "IMAGE-B"
            img_base_dir = "/image-b"
        elif "Current: IMAGE-B" in output:
            im.log("Running image B. Upgrading image A")
            current_image = "IMAGE-B"
            img_to_test = "IMAGE-A"
            img_base_dir = "/image-a"

        if "IMAGE-A" not in output or "IMAGE-B" not in output:
            im.log("No backup image available. Installing one")
            ok, image = self.install_new_image()
            if ok:
                im.log("Successfully installed new image " + image)
            else:
                im.log("Failed to install new image " + image + ", aborting")
                im.report_fail(str(inspect.currentframe().f_code.co_name))
                return

        # make sure next-boot-image is the one that we will corrupt
        image_name = self.get_image(img_to_test)
        if not self.set_next_boot(image_name):
            im.log("Failed to set next boot. aborting kernel corruption test")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return

        img_dir = im.find_img_directory(img_base_dir, "image-")
        if img_dir is None:
            im.log("Failed to find the image sub directory")
            im.report_fail(str(inspect.currentframe().f_code.co_name))
            return
        else:
            im.log("Img Subdirectory is " + str(img_base_dir + "/" + img_dir))

        kernel_file = str(img_base_dir + "/" + img_dir) + "/boot/" + "vmlinuz-5.10.0-23-2-amd64"
        bkp_kernel_file = kernel_file + ".test_kernel_failure"

        im.exec_cmd("sudo mv " + kernel_file + " " + bkp_kernel_file)

        # touch to create a dummy empty kernel file. This will fail to boot.
        im.exec_cmd("sudo touch " + kernel_file)

        im.log("Rebooting device to check if device recovers from corrupt " + img_to_test)
        im.reboot()

        time.sleep(5)
        # check if we booted back fine to the image the device was running before.
        _, output, _ = im.exec_cmd("sudo -s sonic-installer list")
        img_str = "Current: " + current_image
        if img_str in output:
            im.log(current_image + " booted up.")
            im.log('Kernel corruption test passed as recovery image booted fine')
            # restore back the signature for other tests to continue
            im.log("Restore the kernel file.")
            im.exec_cmd("sudo mv " + bkp_kernel_file + " " + kernel_file)
            im.report_pass(str(inspect.currentframe().f_code.co_name))
        else:
            im.log("Restore the kernel file.")
            im.exec_cmd("sudo mv " + bkp_kernel_file + " " + kernel_file)
            im.log('Filesystem Signature corruption test failed.')
            im.report_fail(str(inspect.currentframe().f_code.co_name))

    def test_check_efibootmgr_order(self):
        im.log("========================================")
        im.log((str(inspect.currentframe().f_code.co_name)))

        _, output, _ = im.exec_cmd("efibootmgr")

        # boot oder should be as specified below and nothing else.
        patterns = [
            r"BootOrder: 0002,0003,0001,0000",
            r"Boot0000\* iPXE",
            r"Boot0001\* System Installer",
            r"Boot0002\* IMAGE-A",
            r"Boot0003\* IMAGE-B",
        ]

        bootordersearchfailed = False
        for pattern in patterns:
            if not re.search(pattern, output):
                im.log("Boot order: pattern: " + pattern)
                im.log("Boot order did not match expected data. output: " + output)
                bootorderfailed = True

        if bootordersearchfailed:
            # search for the alternative which is also supported in case only 1 image
            patterns = [
                r"BootOrder: 0002,0003,0001,0000",
                r"Boot0000\* iPXE",
                r"Boot0001\* System Installer",
                r"Boot0002\* IMAGE-A",
                r"Boot0003\* IMAGE-B",
            ]

            bootordersearchfailed = False
            for pattern in patterns:
                if not re.search(pattern, output):
                    im.log("Boot order: pattern: " + pattern)
                    im.log("Boot order did not match expected data. output: " + output)
                    bootorderfailed = True

        if bootordersearchfailed:
            im.report_fail(str(inspect.currentframe().f_code.co_name))
        else:
            im.report_pass(str(inspect.currentframe().f_code.co_name))


def read_config():
    # Specify the path to your YAML file
    yaml_file_path = 'testbed_config.yaml'

    # Open and read the YAML file
    with open(yaml_file_path, 'r') as file:
        # Load the YAML content into a Python dictionary
        config_data = yaml.safe_load(file)

    return config_data


if __name__ == '__main__':
    config_data = read_config()
    print (sys.argv)
    ip_address = config_data['ip_address']
    port = config_data['port']
    uname = config_data['uname']
    pw = config_data['pw']
    img_path = config_data['img_path']
    if len(sys.argv) > 2:
        ip_address = sys.argv[1]
        img_path = sys.argv[2]
        print("IP address: , " + ip_address + ", image path: " + img_path)
        sys.argv=sys.argv[:1]
    im = ImgMgmtTestHelper(ip_address, port, uname, pw, img_path)
    unittest.main(verbosity=2)
