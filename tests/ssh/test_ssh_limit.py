import json 
import logging
import paramiko
import pytest
import time
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.tacacs.test_authorization import ssh_connect_remote
from tests.tacacs.conftest import tacacs_creds
from tests.tacacs.utils import setup_local_user

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

HOSTSERVICE_RELOADING_COMMAND = "sudo systemctl restart hostcfgd.service"
HOSTSERVICE_RELOADING_TIME = 5

LOGIN_MESSAGE_TIMEOUT = 10
LOGIN_MESSAGE_BUFFER_SIZE = 1000

TEMPLATE_BACKUP_COMMAND = "sudo mv {0} {0}.backup"
TEMPLATE_RESTORE_COMMAND = "sudo mv {0}.backup {0}"
TEMPLATE_CREATE_COMMAND = "sudo touch {0}"

PAM_LIMITS_TEMPLATE_PATH = "/usr/share/sonic/templates/pam_limits.j2"
LIMITS_CONF_TEMPLATE_PATH = "/usr/share/sonic/templates/limits.conf.j2"
LIMITS_CONF_TEMPLATE_TO_HOME = "echo \"{{% if hwsku == '{0}' and type == '{1}'%}}\n{2}\n{{% endif %}}\"  > ~/temp_config_file"
TEMPLATE_MOVE_COMMAND = "sudo mv ~/temp_config_file {0}"

def get_device_type(duthost):
    device_config_db = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    dut_type = None

    if "DEVICE_METADATA" in device_config_db and \
        "localhost" in device_config_db["DEVICE_METADATA"] and \
        "type" in device_config_db["DEVICE_METADATA"]["localhost"]:
            dut_type = device_config_db["DEVICE_METADATA"]["localhost"]["type"]

    return dut_type

def modify_template(admin_session, template_path, additional_content, hwsku, type):
    admin_session.exec_command(TEMPLATE_BACKUP_COMMAND.format(template_path))
    admin_session.exec_command(TEMPLATE_CREATE_COMMAND.format(template_path))
    admin_session.exec_command(LIMITS_CONF_TEMPLATE_TO_HOME.format(hwsku, type, additional_content))
    admin_session.exec_command(TEMPLATE_MOVE_COMMAND.format(template_path))

    stdin, stdout, stderr = admin_session.exec_command('sudo cat {0}'.format(template_path))
    config_file_content = stdout.readlines()
    logging.info("Updated template file: {0}".format(config_file_content))

def modify_templates(duthost, tacacs_creds, creds):
    dut_ip = duthost.mgmt_ip
    hwsku = duthost.facts["hwsku"]
    type = get_device_type(duthost)
    user = tacacs_creds['local_user']

    try:
        # Duthost shell not support run command with J2 template in command text.
        admin_session = ssh_connect_remote(dut_ip, creds['sonicadmin_user'], creds['sonicadmin_password'])
    except paramiko.AuthenticationException:
        # try ssh with ansible_altpassword again
        sonic_admin_alt_password = duthost.host.options['variable_manager']._hostvars[duthost.hostname].get("ansible_altpassword")
        admin_session = ssh_connect_remote(dut_ip, creds['sonicadmin_user'], sonic_admin_alt_password)

    # Backup and change /usr/share/sonic/templates/pam_limits.j2
    additional_content = "session  required  pam_limits.so"
    modify_template(admin_session, PAM_LIMITS_TEMPLATE_PATH, additional_content, hwsku, type)

    # Backup and change /usr/share/sonic/templates/limits.conf.j2
    additional_content = "{0}  hard  maxlogins  1".format(user)
    modify_template(admin_session, LIMITS_CONF_TEMPLATE_PATH, additional_content, hwsku, type)

def restore_templates(duthost):
    duthost.shell(TEMPLATE_RESTORE_COMMAND.format(PAM_LIMITS_TEMPLATE_PATH))
    duthost.shell(TEMPLATE_RESTORE_COMMAND.format(LIMITS_CONF_TEMPLATE_PATH))

def restart_hostcfgd(duthost):
    duthost.shell(HOSTSERVICE_RELOADING_COMMAND)
    time.sleep(HOSTSERVICE_RELOADING_TIME)

def limit_template_exist(duthost):
    return duthost.stat(path=LIMITS_CONF_TEMPLATE_PATH).get('stat', {}).get('exists', False)

@pytest.fixture(scope="module")
def setup_limit(duthosts, rand_one_dut_hostname, tacacs_creds, creds):
    duthost = duthosts[rand_one_dut_hostname]

    # if template file not exist on duthost, ignore this UT
    # However still need yield, if not yield, UT will failed with StopIteration error.
    template_file_exist = limit_template_exist(duthost)
    if template_file_exist:
        setup_local_user(duthost, tacacs_creds)

        # Modify templates and restart hostcfgd to render config files
        modify_templates(duthost, tacacs_creds, creds)
        restart_hostcfgd(duthost)

    yield

    if template_file_exist:
        # Restore SSH session limit
        restore_templates(duthost)
        restart_hostcfgd(duthost)

def get_login_result(ssh_session):
    login_channel = ssh_session.invoke_shell()
    login_message = ""
    start_time = time.time()
    while (time.time() - start_time) <= LOGIN_MESSAGE_TIMEOUT:
        if login_channel.recv_ready():
            data = login_channel.recv(LOGIN_MESSAGE_BUFFER_SIZE)
            if len(data) == 0:
                # when receive zero length data, channel closed
                break
            login_message += data

        time.sleep(1)

    return login_message

def test_ssh_limits(duthosts, rand_one_dut_hostname, tacacs_creds, setup_limit):
    """
        This test case will test following 2 scenarios:
            1. Following 2 templates can be render by hostcfgd correctly:
                    /usr/share/sonic/templates/pam_limits.j2
                    /usr/share/sonic/templates/limits.conf.j2
            2. SSH login session limit works correctly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # if template file not exist on duthost, ignore this UT
    pytest_require(limit_template_exist(duthost), "Template file {0} not exist, ignore test case.".format(LIMITS_CONF_TEMPLATE_PATH))

    dut_ip = duthost.mgmt_ip
    local_user = tacacs_creds['local_user']
    local_user_password = tacacs_creds['local_user_passwd']

    # Create multiple login session to test maxlogins limit, first session will success
    ssh_session_1 = ssh_connect_remote(dut_ip, local_user, local_user_password)
    login_message_1 = get_login_result(ssh_session_1)

    logging.debug("Login session 1 result:\n{0}\n".format(login_message_1))
    pytest_assert("There were too many logins for" not in login_message_1)

    # The second session will be disconnect by device
    ssh_session_2 = ssh_connect_remote(dut_ip, local_user, local_user_password)
    login_message_2 = get_login_result(ssh_session_2)

    logging.debug("Login session 2 result:\n{0}\n".format(login_message_2))
    pytest_assert("There were too many logins for" in login_message_2)

    ssh_session_1.close()
    ssh_session_2.close()
