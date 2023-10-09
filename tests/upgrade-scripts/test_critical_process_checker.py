import json
import os
import pytest
import logging

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

UPGRADE_TAR = 'sonic-upgrade-package-1.0.0.tar'
UPGRADE_TAR_MD5 = 'sonic-upgrade-package-1.0.0.tar.md5'
UPGRADE_FOLDER = '/tmp/sonic-upgrade-scripts'
INSTALLER = 'installer.py'

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'files')


def test_critical_process(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.command("mkdir -p {}".format(UPGRADE_FOLDER))

    # Transfer tar file to device /tmp/sonic-upgrade-scripts folder
    transfer_tar = duthost.copy(src=os.path.join(FILES_DIR, UPGRADE_TAR),
                     dest=UPGRADE_FOLDER)

    assert not transfer_tar['failed'], "Failed to copy {} to device - {}".format(UPGRADE_TAR, transfer_tar)

    # Untar sonic-upgrade-package-1.0.0.tar
    untar_cmd = 'cd {} && tar -xvf {}'.format(UPGRADE_FOLDER, UPGRADE_TAR)
    untar_result = duthost.shell(untar_cmd)
    untar_exit_code = untar_result["rc"]

    assert untar_exit_code == 0, "Failed to untar sonic-upgrade-package-1.0.0.tar"

    # Validate package is not present on device
    validate_cmd = 'python {} --validate'.format(os.path.join(UPGRADE_FOLDER, INSTALLER))
    validate_result = duthost.shell(validate_cmd)
    validate_exit_code = validate_result["rc"]

    assert validate_exit_code == 0, "Failed to run installer.py --validate"
    assert validate_result['stdout'] == \
       "Package sonic_critical_process_checker is not installed", \
       ("Failed to validate if sonic-critical-process-checker is installed: {}"
        .format(validate_result['stdout']))


    # Install package
    install_cmd = 'python {} --install'.format(os.path.join(UPGRADE_FOLDER, INSTALLER))
    install_result = duthost.shell(install_cmd)
    install_exit_code = install_result["rc"]

    assert install_exit_code == 0, "Failed to install sonic-critical-process-checker"

    # Validate package is installed on device
    validate_result = duthost.shell(validate_cmd)
    validate_exit_code = validate_result["rc"]

    assert validate_exit_code == 0, "Failed to run installer.py --validate"
    assert validate_result['stdout'] == \
        "Package sonic_critical_process_checker is installed", \
        ("Failed to validate if sonic-critical-process-checker is installed: {}"
         .format(validate_result['stdout']))

    # Run checker caller command
    checker_cmd = 'sudo sonic_critical_process_checker_caller -m "{}"'.format("09/12/2023 16:06:48,09/13/2023 16:06:48")
    output = duthost.shell(checker_cmd)['stdout']
    logger.info("Critical Process Checker output: {}".format(output))
    json_data = json.loads(output)

    assert json_data['succeeded'], \
        ("Critical Process Checker execution failed, succeeded = {}"
         .format(json_data['succeeded']))

    # Check status of all services and processes
    for service, service_list in json_data["service_dict"].items():
        for service_info in service_list:
            assert service_info["status"], "Service {} is not running".format(service)
            if "process_dict" in service_info:
                for process, process_info in service_info["process_dict"].items():
                    assert process_info["status"], "Process {} is not running".format(process)
                    logger.info("Service: {}, Process: {}, Status: {}".format(service, process, process_info['status']))

    # Clean Up
    uninstall_cmd = 'python {} --uninstall'.format(os.path.join(UPGRADE_FOLDER, INSTALLER))
    uninstall_result = duthost.shell(uninstall_cmd)
    uninstall_exit_code = uninstall_result["rc"]
    assert uninstall_exit_code == 0, "Failed to uninstall sonic-critical-process-checker"

    duthost.command("rm -r {}".format(UPGRADE_FOLDER))
