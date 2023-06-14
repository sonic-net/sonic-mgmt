import pytest
import paramiko
import time
import logging

logging.basicConfig(level=logging.DEBUG)

@pytest.fixture(scope="module")
def ssh_clients():
    ip_address1 = '172.30.25.67'
    username1 = 'sonic'
    password1 = 'admin123'
    ip_address2 = '172.30.25.102'
    username2 = 'admin'
    password2 = 'YourPaSsWoRd'
    ip_address3 = '172.30.25.93'
    username3 = 'sonic'
    password3 = 'admin123'

    # Create SSH clients for the devices
    client1 = paramiko.SSHClient()
    client1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client2 = paramiko.SSHClient()
    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client3 = paramiko.SSHClient()
    client3.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the devices
    client1.connect(ip_address1, username=username1, password=password1)
    client2.connect(ip_address2, username=username2, password=password2)
    client3.connect(ip_address3, username=username3, password=password3)

    yield client1, client2, client3

    # Close the SSH connections after the tests
    client1.close()
    client2.close()
    client3.close()

def test_nac_functionality(ssh_clients):
    client1, client2, client3 = ssh_clients

    # Configuring IP on the Supplicant PC
    cmd_sup_ip = "sudo ifconfig enp7s0f3 70.0.0.10"  # sample
    stdin, stdout, stderr = client1.exec_command(cmd_sup_ip)
    cmd_sup_ip_output = stdout.read().decode()
    logging.info(cmd_sup_ip_output)

    cmd_show_int = "ifconfig enp7s0f3"
    stdin, stdout, stderr = client1.exec_command(cmd_show_int)
    cmd_show_int_output = stdout.read().decode()
    logging.info(cmd_show_int_output)  

    # To enable NAC Globally
    cmd_enable_global = "sudo config nac enable"
    stdin, stdout, stderr = client2.exec_command(cmd_enable_global)
    cmd_enable_global = stdout.read().decode()
    logging.info(cmd_enable_global)

    cmd_show_nac = "sudo show nac"
    stdin, stdout, stderr = client2.exec_command(cmd_show_nac)
    cmd_show_nac_output = stdout.read().decode()
    logging.info(cmd_show_nac_output)  

    # To enable NAC Interface
    cmd_enable_int = "sudo config nac interface enable Ethernet16"
    stdin, stdout, stderr = client2.exec_command(cmd_enable_int)
    cmd_enable_int = stdout.read().decode()
    logging.info(cmd_enable_int)

    cmd_show_enable_int = "sudo show nac interface Ethernet16"
    stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
    cmd_show_enable_int_output = stdout.read().decode()
    logging.info(cmd_show_enable_int_output)  

    # Login to the root user
    cmd_goto_root_user = "sudo su"
    stdin, stdout, stderr = client1.exec_command(cmd_goto_root_user)
    
    # To start the Supplicant
    cmd_sup_start = "sudo wpa_supplicant -c./wpa_supplicant.conf -Dwired -ienp7s0f3"
    _, stdout, stderr = client1.exec_command(cmd_sup_start)
    cmd_sup_start_output = stdout.read().decode()
    logging.info("To start the supplicant: " + cmd_sup_start_output)
    time.sleep(20)

    channel = stdin.channel
    channel.send("\x03")
    time.sleep(2)

    output = channel.recv(1024).decode()

    logging.info(output) 

    # To verify Show NAC Interface Output
    cmd_show_enable_int = "sudo show nac interface Ethernet16"
    stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
    cmd_show_enable_int_output = stdout.read().decode()
    # Print the output
    logging.info(cmd_show_enable_int_output)

    # Configuring IP on the ping receiver
    cmd_ping_ip = "sudo ifconfig eth4 70.0.0.20"  # sample
    stdin, stdout, stderr = client3.exec_command(cmd_ping_ip)
    cmd_ping_ip = stdout.read().decode()
    logging.info(cmd_ping_ip)

    cmd_show_int1 = "sudo ifconfig eth4"
    stdin, stdout, stderr = client3.exec_command(cmd_show_int1)
    cmd_show_int1_output = stdout.read().decode()
    logging.info(cmd_show_int1_output) 

    # To check ping
    cmd_ping_check = "ping 70.0.0.20"
    _, stdout, stderr = client1.exec_command(cmd_ping_check)
    time.sleep(10)
    channel = stdout.channel
    channel.send("\x03")
    time.sleep(2)
    output = ""
    while channel.recv_ready():
        output += channel.recv(1024).decode()
    logging.info(output)  # Optional, for debugging

    # Assertions and verification code
   # assert "expected_result" in output
