import re
from spytest import st, cutils
from apis.system.rest import get_rest

def sonic_installer_cleanup(dut):
    command = "sudo sonic_installer cleanup -y"
    output = st.config(dut, command)
    retval = re.search(r".*No image\(s\) to remove.*", output)
    if retval is None:
        return True
    else:
        st.log("No image(s) to remove")
        return False

def sonic_installer_remove(dut,image):
    command = "sudo sonic_installer remove {} -y".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False

def sonic_installer_set_default(dut,image):
    command = "sudo sonic_installer set_default {}".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False

def sonic_installer_set_next_boot(dut,image):
    command = "sudo sonic_installer set_next_boot {}".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False

def sonic_installer_install(dut,image_path):
    command = "sudo sonic_installer install {} -y".format(image_path)
    output = st.config(dut, command)
    retval = re.search(".*No such file or directory.*|.*Image file '.*' does not exist or is not a regular file. Aborting.*", output)
    if retval is None:
        return True
    else:
        st.log("No such file or directory | Image file does not exist or is not a regular file. Aborting")
        return False

def sonic_installer_install2(dut, url, max_time=1800, skip_error_check=False, migartion=False):
    cli_type = st.get_ui_type(dut)
    if cli_type == 'click':
        if migartion:
            cmd = "sudo sonic_installer install {} -y".format(url)
        else:
            cmd = "sudo sonic_installer install --skip_migration {} -y".format(url)

        st.log("installing {}".format(cmd))
        output = st.config(dut, cmd, skip_error_check=skip_error_check, max_time=max_time)
        if re.search("Installed SONiC base image SONiC-OS successfully", output):
            return "success"
        if re.search("Not installing SONiC version", output) and \
           re.search("as current running SONiC has the same version", output):
            return "skipped"
        return "error"
    elif cli_type == 'klish':
        cmd = "image install {}".format(url)
        st.log("installing {}".format(cmd))
        st.config(dut, cmd, skip_error_check=skip_error_check, max_time=max_time, type=cli_type)
        return "success"

def sonic_installer_binary_version(dut,image_path):
    command = "sudo sonic_installer binary_version {} -y".format(image_path)
    output = st.config(dut, command)
    retval = re.search(".*File does not appear to be a vaild SONiC image file.*", output)
    if retval is None:
        return True
    else:
        st.log("File does not appear to be a vaild SONiC image file")
        return False

def sonic_installer_upgrade_docker(dut,container_name,image_path):
    command = "sudo sonic_installer upgrade_docker {} {} -y".format(container_name,image_path)
    output = st.config(dut, command)
    retval = re.search(".*No such file or directory.*|.*Image file '.*' does not exist or is not a regular file. Aborting.*", output)
    if retval is None:
        return True
    else:
        st.log("No such file or directory | Image file does not exist or is not a regular file. Aborting")
        return False

def sonic_installer_list(dut, **kwargs):
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    if cli_type == "click":
        command = "sudo sonic_installer list"
    elif cli_type == "klish":
        command = "show image list"
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['sonic_installer_list']
        rest_get_output = get_rest(dut, rest_url=url)
        actual_data = rest_get_output['output']['openconfig-image-management:image-management']['state']['image-globals']['image-global'][0]
        actual_data2 = rest_get_output['output']['openconfig-image-management:image-management']['state']['images']['image'][0]
        entries = []
        temp = {}
        temp['current'] = actual_data['state']['current']
        temp['next'] = actual_data['state']['next-boot']
        temp['available'] = actual_data2['image-name']
        entries.append(temp)
    else:
        st.log("UNSUPPORTED CLI TYPE")
    if cli_type in ['click','klish']:
        output = st.show(dut, command, type=cli_type)
        entries = cutils.filter_and_select(output, ["current","next","available"])
    retval = dict()
    currentList = []
    nextList = []
    availableList = []
    for ent in entries:
        if ent["current"]: currentList.append(ent["current"])
        if ent["next"]: nextList.append(ent["next"])
        if ent["available"]: availableList.append(ent["available"])
    retval["Current"] = currentList
    retval["Next"] = nextList
    retval["Available"] = availableList
    return retval

def get_onie_grub_config(dut, mode):
    errs = ["/dev/sda2 does not exist",
            "/mnt/onie-boot/onie/tools/bin/onie-boot-mode: command not found",
            "No such file or directory",
            "/mnt/onie-boot/: not mounted"]
    cmds = """
    sudo apt-get -f install -y grub-common
    sudo mkdir -p /mnt/onie-boot/
    sudo mount /dev/sda2 /mnt/onie-boot/
    sudo /mnt/onie-boot/onie/tools/bin/onie-boot-mode -o {0}
    sudo grub-editenv /mnt/onie-boot/grub/grubenv set diag_mode=none
    sudo grub-editenv /mnt/onie-boot/grub/grubenv set onie_mode={0}
    sudo grub-editenv /host/grub/grubenv set next_entry=ONIE
    sudo grub-reboot --boot-directory=/host/ ONIE
    sudo umount /mnt/onie-boot/
    sudo sync
    sleep 5
    sudo sed -i 's|DEVPATH=./usr/share/sonic/device.|set -x ; \\n &|g' /usr/local/bin/reboot
    """.format(mode).strip().splitlines()
    return cmds, errs

