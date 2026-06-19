'''
This script will install a given image passed in the parameters
to the device using ONIE install mode.
Assumptions:
    1. The system is up
    2. Login username is 'admin' and default password: 'YourPaSsWoRd'
    3. ONIE system with either no password to enter ONIE cli or 'root' password
    4. Enough space to upload restore image to ONIE, otherwise it will fail
    5. "onie_insall.sh" script in the same folder as this script
    6. Existing image, will not check if the image path is existing, should be accessible without password!

Detailed logic of manufacture script:
    1. Connect to dut
    2. upload the "onie_install.sh" file in the same folder to dut
    3. run the bash file, the script "onie_install.sh" is responsible for entering ONIE install mode
    4. upload image to ONIE
    5. install image using onie-nos-install
'''
import pexpect
import time
import logging
from tests.platform_tests.test_first_time_boot_password_change.default_consts import DefaultConsts


logger = logging.getLogger(__name__)


def print_log(msg, color=''):
    '''
    @summary: will print the msg to log, used to add color to messages,
    since the manufacture script is long ~6 mins total
    :param msg: msg to print to log
    :param color: colot to print
    '''
    logger.info(color + msg + DefaultConsts.ENDC)


def ping_till_state(dut_ip, should_be_alive=True, timeout=300):
    '''
    @summary: this function will ping system till the desired
    :param dut_ip: device under test ip address
    :param should_be_alive: if True, will ping system till alive, if False will ping till down
    :param timeout: fail if the desired state is not achieved
    '''
    # create an engine
    localhost_engine = pexpect.spawn('sudo su', env={'TERM': 'dumb'})
    localhost_engine.expect(['.*#', '.$'])
    time_passed = 0
    result = 'Fail'
    while time_passed <= timeout:
        print_log("Pinging system {} till {}".format(dut_ip, 'alive' if should_be_alive else 'down'))
        localhost_engine.sendline('ping -c 1 ' + dut_ip)
        response = localhost_engine.expect(['1 packets received', '0 packets received'])
        if response == 0:
            if should_be_alive:
                result = 'Success'
                break
        else:
            if not should_be_alive:
                result = 'Success'
                break

        print_log("Sleeping 2 secs between pings")
        time.sleep(2)
        time_passed += 2

    if result == 'Fail':
        fail_msg = "Expected system to be {} after timeout of {} but the system was {}".format(
            'alive' if should_be_alive else 'down',
            timeout,
            'down' if should_be_alive else 'alive'
        )
        print_log(fail_msg)
    localhost_engine.close()


def ping_till_alive(dut_ip, timeout=300):
    '''
    @summary: this function will ping system till alive
    :param dut_ip: device under test ip address
    '''
    ping_till_state(dut_ip, should_be_alive=True, timeout=timeout)


def ping_till_down(dut_ip, timeout=300):
    '''
    @summary: this function will ping system till down
    :param dut_ip: device under test ip address
    '''
    ping_till_state(dut_ip, should_be_alive=False, timeout=timeout)


def create_engine(dut_ip, username, password, timeout=30):
    '''
    @summary: this command will create an ssh engine to run command
    on the device under test
    :param dut_ip: device under test ip address
    :param username: user name to login
    :param password: password for username
    :param timeout: default timeout for engine
    '''
    print_log("Creating engine for {} with username: {} and password: {}".format(dut_ip, username, password))
    child = pexpect.spawn(DefaultConsts.SSH_COMMAND.format(username) + dut_ip, env={'TERM': 'dumb'}, timeout=timeout)
    index = child.expect([DefaultConsts.PASSWORD_REGEX,
                          DefaultConsts.DEFAULT_PROMPT[0],
                          DefaultConsts.DEFAULT_PROMPT[1]])
    if index == 0:
        child.sendline(password + '\r')

    print_log("Engine created successfully")
    return child


def upload_file_to_dut(dut_ip, filename, destination, username, password, timeout=30):
    '''
    @summary: this function will upload the given file to dut under destination folder
    :param dut_ip: device under test
    :param filename: path to filenmae
    :param username: username of the device
    :param password: password to username
    :param timeout: timeout
    '''
    print_log('Uploading file {} to dut {} under \'{}\' dir'.format(filename, dut_ip, destination))
    if timeout > DefaultConsts.LONG_PERIOD:
        print_log('Please be patient this may take some time')
    cmd = DefaultConsts.SCP_COMMNAD.format(filename, username, dut_ip, destination)
    child = pexpect.spawn(cmd, timeout=timeout)
    # sometimes the system requires password to login into, we need to consider this case
    index = child.expect(["100%",
                          DefaultConsts.PASSWORD_REGEX])
    if index == 0:
        print_log('Done Uploading file - 100%', DefaultConsts.OKGREEN)
        return
    # enter password
    child.sendline(password + '\r')
    child.expect(['100%'])
    print_log('Done Uploading file - 100%', DefaultConsts.OKGREEN)


def enter_onie_install_mode(dut_ip):
    '''
    @summary: this function will upload the "onie_install.sh" bash script under '/tmp' folder on dut.
    The script is found in the same folder of this script. The script is executed from the dut.
    The script "onie_install.sh" is responsible for loading ONIE install mode after reboot.
    For more info please read the documentation in the bash script and its usage.
    :param dut_ip: device under test ip address
    '''
    print_log("Entering ONIE install mode by running \"{}\" bash script on DUT".format(
        DefaultConsts.ONIE_INSTALL_PATH.split('/')[-1]),
              DefaultConsts.WARNING + DefaultConsts.BOLD)

    upload_file_to_dut(dut_ip, DefaultConsts.ONIE_INSTALL_PATH, '/tmp',
                       DefaultConsts.DEFAULT_USER,
                       DefaultConsts.DEFAULT_PASSWORD)
    # create ssh connection device
    sonic_engine = create_engine(dut_ip, DefaultConsts.DEFAULT_USER, DefaultConsts.DEFAULT_PASSWORD)
    sonic_engine.sendline('sudo su')
    sonic_engine.expect(DefaultConsts.SONIC_PROMPT)
    sonic_engine.sendline('cd /tmp')
    sonic_engine.expect(DefaultConsts.SONIC_PROMPT)
    print_log("Validating file \"{}\" existence".format(DefaultConsts.ONIE_INSTALL_PATH.split('/')[-1]))
    # validate the file is there
    sonic_engine.sendline('ls')
    sonic_engine.expect('{}'.format(DefaultConsts.ONIE_INSTALL_PATH.split('/')[-1]))
    # # change permissions
    print_log("Executing the bash script uploaded")
    sonic_engine.sendline('sudo chmod +777 onie_install.sh')
    sonic_engine.expect(DefaultConsts.SONIC_PROMPT)
    sonic_engine.sendline('sudo ./onie_install.sh install')
    sonic_engine.expect('Reboot will be done after 3 sec')
    # # close session, the system will perform reboot
    ping_till_down(dut_ip)
    print_log("System is Down!", DefaultConsts.BOLD + DefaultConsts.OKGREEN)
    sonic_engine.close()


def install_image_from_onie(dut_ip, restore_image_path):
    '''
    @summary: this function will upload the image given to ONIE and perform
    install to the image using "onie-nos-install"
    :param dut_ip: device under test ip address
    :param restore_image_path: path to restore image should be in the format /../../../your_image_name.bin
    '''
    ping_till_alive(dut_ip)
    print_log("System is UP!", DefaultConsts.BOLD + DefaultConsts.OKGREEN)
    upload_file_to_dut(dut_ip, restore_image_path, '/', DefaultConsts.ONIE_USER, DefaultConsts.ONIE_PASSWORD,
                       timeout=420)

    restore_image_name = restore_image_path.split('/')[-1]
    print_log('restore image name is {}'.format(restore_image_name))
    # SSH to ONIE
    child = create_engine(dut_ip, DefaultConsts.ONIE_USER, DefaultConsts.ONIE_PASSWORD)
    print_log("Install the image from ONIE")
    child.sendline('cd /')
    child.expect(DefaultConsts.ONIE_PROMPT)
    child.sendline('onie-stop')
    child.expect(DefaultConsts.ONIE_PROMPT)
    child.sendline('onie-nos-install {}'.format(restore_image_name) + '\r')
    print_log("Ping system till down")
    ping_till_down(dut_ip)
    print_log("Ping system till alive")
    ping_till_alive(dut_ip)
    child.close()


def manufacture(dut_ip, restore_image_path):
    '''
    @summary: will remove the installed image and intsall the image given in the restore_image_path
        Assumptions:
        1. The system is up
        2. Login username is 'admin' and default password: 'YourPaSsWoRd'
        3. ONIE system with either no password to enter ONIE cli or 'root' password
        4. Enough space to upload restore image to ONIE, otherwise it will fail, and will leave system in ONIE mode!
        5. "onie_insall.sh" script in the same folder as this script,
            under "tests/platform_tests/test_first_time_boot_password_change"
        6. Existing image, will not check if the image path is existing, should be accessible without password!
    Detailed logic of manufacture script:
        1. Connect to dut
        2. upload the "onie_install.sh" file in the same folder to dut
        3. run the bash file, the script "onie_install.sh" is responsible for entering ONIE install mode
        4. upload image to ONIE
        5. install image using onie-nos-install
    :param dut_ip: device to manufacture
    :param restore_image_path: path to the image
    '''
    # create engine for the localhost running this script
    print_log("Manufacture started", DefaultConsts.OKGREEN + DefaultConsts.BOLD)
    # perform manufacture
    enter_onie_install_mode(dut_ip)
    install_image_from_onie(dut_ip, restore_image_path)
    print_log("Sleeping for {} secs to stabilize system after reboot".format(DefaultConsts.SLEEP_AFTER_MANUFACTURE))
    time.sleep(DefaultConsts.SLEEP_AFTER_MANUFACTURE)
    print_log("Manufacture is completed - SUCCESS", DefaultConsts.OKGREEN + DefaultConsts.BOLD)
