import logging

from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)

def prepare_testbed_ssh_keys(duthost, ptfhost, dut_username):
    '''
    Prepares testbed ssh keys by generating ssh key on ptf host and adding this key to known_hosts on duthost

    @param duthost: instance of AnsibleHost class for DUT
    @param ptfhost: instance of AnsibleHost class for PTF
    @param dut_username: DUT username
    '''
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    logger.info('Remove old keys from ptfhost')
    ptfhost.shell('rm -f /root/.ssh/id_rsa*')
    try:
        ptfhost.shell('stat /root/.ssh/known_hosts')
    except RunAnsibleModuleFail:
        pass # files does not exist
    else:
        ptfhost.shell('ssh-keygen -f /root/.ssh/known_hosts -R ' + dut_ip)

    logger.info('Generate public key for ptf host')
    ptfhost.file(path='/root/.ssh/', mode='u+rwx,g-rwx,o-rwx', state='directory')
    result = ptfhost.openssh_keypair(
        path='/root/.ssh/id_rsa',
        size=2048,
        force=True,
        type='rsa',
        mode='u=rw,g=,o='
    )
    # There is an error with id_rsa.pub access permissions documented in:
    # https://github.com/ansible/ansible/issues/61411
    # @TODO: remove the following line when upgrading to Ansible 2.9x
    ptfhost.file(path='/root/.ssh/id_rsa.pub', mode='u=rw,g=,o=')

    cmd = '''
        mkdir -p /home/{0}/.ssh &&
        echo "{1}" >> /home/{0}/.ssh/authorized_keys &&
        chown -R {0}:{0} /home/{0}/.ssh/
    '''.format(dut_username, result['public_key'])
    duthost.shell(cmd)


def ssh_authorize_local_user(duthost):
    """
    Generate public private key and authorize user on the host.
    Used to ssh into localhost without password
    """
    logger.info("Remove old keys from DUT")
    duthost.shell("mkdir -p /root/.ssh")
    duthost.shell("rm -f /root/.ssh/known_hosts")
    duthost.shell("rm -f /root/.ssh/id_rsa*")
    duthost.shell("ssh-keygen -q -t rsa -N '' -f /root/.ssh/id_rsa")
    duthost.shell("cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys")
