import re
from spytest import st, cutils
from apis.system.rest import get_rest
from utilities.common import filter_and_select, get_query_params
import utilities.utils as util_api
from utilities.utils import retry_api, get_supported_ui_type_list

try:
    # import apis.yang.codegen.messages.image_management.Base.ImageManagementRpc as umf_img_mgmt
    import apis.yang.codegen.messages.image_management.ImageManagementRpc as umf_img_mgmt
    import apis.yang.codegen.messages.image_management as umf_img
    from apis.yang.codegen.yang_rpc_service import YangRpcService
except ImportError:
    pass


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in util_api.get_supported_ui_type_list() else cli_type
    return cli_type


def sonic_installer_cleanup(dut):
    command = "sudo sonic_installer cleanup -y"
    output = st.config(dut, command)
    retval = re.search(r".*No image\(s\) to remove.*", output)
    if retval is None:
        return True
    else:
        st.log("No image(s) to remove")
        return False


def sonic_installer_remove(dut, image):
    command = "sudo sonic_installer remove {} -y".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False


def sonic_installer_set_default(dut, image):
    command = "sudo sonic_installer set_default {}".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False


def sonic_installer_set_next_boot(dut, image):
    command = "sudo sonic_installer set_next_boot {}".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False


def sonic_installer_install(dut, image_path):
    command = "sudo sonic_installer install {} -y".format(image_path)
    output = st.config(dut, command)
    retval = re.search(".*No such file or directory.*|.*Image file '.*' does not exist or is not a regular file. Aborting.*", output)
    if retval is None:
        return True
    else:
        st.log("No such file or directory | Image file does not exist or is not a regular file. Aborting")
        return False


def sonic_installer_install2(dut, url, max_time=1800, skip_error_check=False, migartion=True, cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type in util_api.get_supported_ui_type_list() + ['rest-patch', "rest-put"]:
        service = YangRpcService()
        rpc = umf_img_mgmt.ImageInstallRpcBase()
        rpc.Input.image_name = url
        rpc.Output.result = ''
        result = service.execute(dut, rpc, timeout=60)
        if not result.ok():
            st.log('test_step_failed: image install {}'.format(result.data))
            return False
        if retry_api(verify_image_status, dut, retry_count=100, delay=60):
            st.log('Image has been downloaded successfully')
            return "success"
        else:
            st.error('Image has not been downloaded even after 1200 seconds')
            return False
    elif cli_type == 'click' or migartion is False:
        if migartion:
            cmd = "sudo sonic_installer install {} -y".format(url)
        else:
            cmd = "sudo sonic_installer install --skip_migration {} -y".format(url)

        output = st.config(dut, cmd, skip_error_check=skip_error_check, max_time=max_time)
        if re.search("Did not receive a response from remote machine", output):
            return "aborted"
        if re.search("Installed SONiC base image SONiC-OS successfully", output):
            return "success"
        if re.search("Not installing SONiC version", output) and \
           re.search("as current running SONiC has the same version", output):
            return "skipped"
        return "error"
    elif cli_type == 'klish':
        cmd = "image install {}".format(url)
        st.config(dut, cmd, conf=False, skip_error_check=skip_error_check, max_time=max_time, type=cli_type)

        if retry_api(verify_image_status, dut, retry_count=100, delay=60):
            st.log('Image has been downloaded successfully')
            return "success"
        else:
            st.error('Image has not been downloaded even after 1200 seconds')
            return False
    else:
        st.error("Invalid UI type {}".format(cli_type))
        return False
    return "error"


def sonic_installer_binary_version(dut, image_path):
    command = "sudo sonic_installer binary_version {} -y".format(image_path)
    output = st.config(dut, command)
    retval = re.search(".*File does not appear to be a vaild SONiC image file.*", output)
    if retval is None:
        return True
    else:
        st.log("File does not appear to be a vaild SONiC image file")
        return False


def sonic_installer_upgrade_docker(dut, container_name, image_path):
    command = "sudo sonic_installer upgrade_docker {} {} -y".format(container_name, image_path)
    output = st.config(dut, command)
    retval = re.search(".*No such file or directory.*|.*Image file '.*' does not exist or is not a regular file. Aborting.*", output)
    if retval is None:
        return True
    else:
        st.log("No such file or directory | Image file does not exist or is not a regular file. Aborting")
        return False


def sonic_installer_list(dut, **kwargs):
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    skip_error_check = kwargs.get("skip_error_check", False)
    if cli_type == "click":
        command = "sudo sonic_installer list"
    elif cli_type == "klish":
        command = "show image list"
    elif cli_type in ["rest-put", "rest-patch"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['sonic_installer_list']
        rest_get_output = get_rest(dut, rest_url=url)
        actual_data = rest_get_output['output']['openconfig-image-management:image-management']['global']['state']
        available_images = rest_get_output['output']['openconfig-image-management:image-management']['images']['image']
        entries = []
        for available_image in available_images:
            temp = {}
            temp['current'] = actual_data['current']
            temp['next'] = actual_data['next-boot']
            temp['available'] = available_image['image-name']
            actual_data['current'], actual_data['next-boot'] = '', ''
            entries.append(temp)
    else:
        st.log("UNSUPPORTED CLI TYPE")
    if cli_type in ['click', 'klish']:
        output = st.show(dut, command, skip_error_check=skip_error_check, type=cli_type)
        entries = cutils.filter_and_select(output, ["current", "next", "available"])
    retval = dict()
    currentList = []
    nextList = []
    availableList = []
    for ent in entries:
        if ent["current"]:
            currentList.append(ent["current"])
        if ent["next"]:
            nextList.append(ent["next"])
        if ent["available"]:
            availableList.append(ent["available"])
    retval["Current"] = currentList
    retval["Next"] = nextList
    retval["Available"] = availableList
    return retval


def get_onie_grub_config(dut, mode):
    errs = ["/mnt/onie-boot/onie/tools/bin/onie-boot-mode: command not found",
            "No such file or directory",
            "/mnt/onie-boot/: not mounted"]
    cmds = """
    sudo apt-get -f install -y grub-common
    sudo mkdir -p /mnt/onie-boot/
    sudo mount -L ONIE-BOOT /mnt/onie-boot/
    sudo mount /dev/sda2 /mnt/onie-boot/
    sudo mount /dev/sdb /mnt/onie-boot/
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


def do_image_download(dut, release, reboot_type='warm', verify=True):
    # release = image_330 or image_320 or complete path
    build_params = util_api.ensure_service_params(dut, "fwdl_info")
    if '/' in release:
        build_path = build_params.protocol + '://' + build_params.server_ip + ':' + build_params.port + release
    else:
        build_path = build_params.protocol + '://' + build_params.server_ip + ':' + build_params.port + build_params[release]

    result = sonic_installer_install2(dut, build_path)
    if result != 'success':
        st.log('Same Image used or Image Download/Installation Failed')
        return False

    if reboot_type is None:
        st.log('Image installed but not rebooted')
    else:
        if st.reboot(dut, reboot_type):
            st.log('Device rebooted with reboot_type:{}'.format(reboot_type))

    return True


def get_image_status(dut, **kwargs):
    """
         Author:naveen.nagaraju@broadcom.com
        :param dut
        :return: [{u'transfer_start': '2022-08-24 18:02:57+0000', u'install_end': u'', u'file_bytes': '3282946030',
        u'file_progress': '100%', u'global_operation_status': 'GLOBAL_STATE_SUCCESS', u'install_start': u'', u'file_size': u'',
        u'file_operation_status': 'TRANSFER_STATE_SUCCESS', u'install_operation_status': u'', u'transfer_end': '2022-08-24 18:03:53+0000'}]

        :rtype:

        :Usuage :  image_status(dut1,status)

        """
    patch_image = kwargs.get("patch_image", False)
    rollback = kwargs.get("rollback", False)
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        if patch_image or rollback:
            output = st.show(dut, "show image patch status", type=cli_type)
        else:
            output = st.show(dut, "show image status", type=cli_type)
        entries = filter_and_select(output)

        if entries:
            if entries[0]['global_operation_status'] == "GLOBAL_STATE_IDLE":
                st.error("No image has been downloaded on this node")
                return False
            else:
                return entries
    return True


def verify_image_status(dut, **kwargs):
    """
         Author:naveen.nagaraju@broadcom.com
        :param dut
        :return: True|False

        :rtype:

        :Usuage :  verify_image_status(dut1)

        """
    patch_image = kwargs.get("patch_image", False)
    rollback = kwargs.get("rollback", False)
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list():
        if patch_image:
            patch_obj = umf_img.PatchManagement(InstallStatus="INSTALL_STATE_SUCCESS")
        elif rollback:
            patch_obj = umf_img.PatchManagement(RollbackStatus="ROLLBACK_STATE_SUCCESS")
        else:
            patch_obj = umf_img.ImageManagement(OperationStatus="GLOBAL_STATE_SUCCESS")
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        result = patch_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verification of image status {}'.format(result.data))
            return False
        else:
            return True

    output = get_image_status(dut, **kwargs)
    if output:
        if output[0]['global_operation_status'] == 'GLOBAL_STATE_SUCCESS':
            return True

    return False


def install_patch_image(dut, image, **kwargs):

    install_type = kwargs.get("install_type", True)
    max_time = kwargs.get("max_time", 1800)
    expect_reboot = kwargs.get("expect_reboot", False)
    skip_error_check = kwargs.get("skip_error_check", False)
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))

    if cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        if install_type:
            rpc = umf_img_mgmt.DoPatchInstallRpc()
            rpc.Input.skip_image_check = "skip-image-check"
        else:
            rpc = umf_img_mgmt.DoPatchRollbackRpc()
        rpc.Input.image_source = "file"
        rpc.Input.patch_name = image
        result = service.execute(dut, rpc, timeout=60, expect_reboot=expect_reboot)
        if not result.ok():
            st.log('test_step_failed: Installation of patch {} failed as: {}'.format(image, result.data))
            return False
        else:
            return True
    elif cli_type == 'klish':
        if install_type:
            cmd = "image patch install {} skip-image-check".format(image)
        else:
            cmd = "image patch rollback {}".format(image)

        if "Error" in st.config(dut, cmd, conf=False, skip_error_check=skip_error_check, max_time=max_time, type=cli_type, expect_reboot=expect_reboot):
            return False

    return True


def verify_patch_image_list(dut, **kwargs):
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = "show image patch list"
        output = st.show(dut, command, type=cli_type)
        if len(output) == 0:
            st.error("OUTPUT is Empty")
            return False
        if 'return_output' in kwargs:
            return output
        for each in kwargs.keys():
            match = {each: kwargs[each]}
            entries = filter_and_select(output, None, match)
            if not entries:
                st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], output[0][each]))
                return False
    return True


def verify_patch_image_history(dut, **kwargs):
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut, **kwargs))
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'klish':
        command = "show image patch history"
        output = st.show(dut, command, type=cli_type)
        if len(output) == 0:
            st.error("OUTPUT is Empty")
            return False
        if 'return_output' in kwargs:
            return output
        for each in kwargs.keys():
            match = {each: kwargs[each]}
            entries = filter_and_select(output, None, match)
            if not entries:
                st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], output[0][each]))
                return False
    return True
