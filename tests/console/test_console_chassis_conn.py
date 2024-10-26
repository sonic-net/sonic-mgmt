import pexpect
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import  get_target_lines, handle_pexpect_exceptions

pytestmark = [
    pytest.mark.topology("t2") #Test is only for T2 Chassis
]

def test_console_availability_serial_ports(duthost, creds):
   
    if not duthost.is_supervisor_node():
        pytest.skip("Skipping test because the device is not a supervisor node.")
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    dutuser, dutpass = creds['sonicadmin_user'], creds['sonicadmin_password'] 

    target_lines = get_target_lines(duthost) #List of Serial port numbers connected from supervisor to linecards

    for target_line in target_lines:
        if 'arista' in duthost.facts['hwsku'].lower():
            console_command = f"sudo /usr/bin/picocom /dev/ttySCD{target_line}"
            try:
                client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                                    .format(dutuser, dutip)) 
                client.expect('[Pp]assword:')
                client.sendline(dutpass)
                client.sendline(console_command)
                time.sleep(5)
                client.sendline('\n')  
                client.expect(['login:'], timeout=20)
                client.sendline(dutuser)
                client.expect(['[Pp]assword:'], timeout=10) 
                client.sendline(dutpass)
              
                i = client.expect([r'.*Software\s+for\s+Open\s+Networking\s+in\s+the\s+Cloud.*', 'Login incorrect'], timeout=100)
                pytest_assert(i == 0, f"Failed to connect to line card {target_line} on Arista device. Please check credentials.")
                
                client.sendline('exit')
                time.sleep(2)  
                client.sendcontrol('a')
                time.sleep(2)
                client.sendcontrol('x')
            except Exception as e:
                    handle_pexpect_exceptions(target_line)(e)  

        elif 'cisco' in duthost.facts['hwsku'].lower():
            console_command = f"sudo /opt/cisco/bin/rconsole.py -s {target_line}"
            try:
                client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                                    .format(dutuser, dutip))
                client.expect('[Pp]assword:')
                client.sendline(dutpass)
                time.sleep(10)
                client.sendline(console_command)
                time.sleep(10)
                client.sendline(dutuser) 
                client.expect(['[Pp]assword:'], timeout=10) 
                time.sleep(10)
                client.sendline(dutpass)
                time.sleep(10)

                i = client.expect([r'.*Software\s+for\s+Open\s+Networking\s+in\s+the\s+Cloud.*', 'Login incorrect'], timeout=100)
                pytest_assert(i == 0, f"Failed to connect to line card {target_line} on Cisco device. Please check credentials.")

                client.sendline('exit')
                time.sleep(2)  
                client.sendcontrol('\\')
                time.sleep(2)
                client.sendline('quit')

            except Exception as e:
                    handle_pexpect_exceptions(target_line)(e)

        else:
            pytest.skip("Skipping test because test is not supported on this hwsku.")                        
            
