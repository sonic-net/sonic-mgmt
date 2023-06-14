import paramiko
import time
import pytest

@pytest.fixture(scope="module")
def ssh_clients():
    # Create SSH clients for the devices
    client1 = paramiko.SSHClient()
    client1.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client2 = paramiko.SSHClient()
    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client3 = paramiko.SSHClient()
    client3.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    yield client1, client2, client3

    # Close the SSH connections
    client1.close()
    client2.close()
    client3.close()

def test_nac_functionality(ssh_clients):
    client1, client2, client3 = ssh_clients

    # Connect to the first device (Supplicant PC)
    client1.connect('172.30.25.82', 'root', 'admin123')

    cmd_sup_ip = "ifconfig enp1s0f1 20.0.0.2"  # sample
    stdin, stdout, stderr = client1.exec_command(cmd_sup_ip)
    input = cmd_sup_ip
    assert "Configuring IP on the Supplicant PC: " + input in stdout.read().decode()

    cmd_show_int = "ifconfig enp1s0f1"
    stdin, stdout, stderr = client1.exec_command(cmd_show_int)
    cmd_show_int = stdout.read().decode()
    print(cmd_show_int)

    # Connect to the second device (DUT)
    client2.connect(ip_address2='172.30.25.102', username2='admin', password2='YourPaSsWoRd')

    # To enable NAC Globally
    cmd_enable_global = "sudo config nac enable"
    stdin, stdout, stderr = client2.exec_command(cmd_enable_global)
    input = cmd_enable_global
    print("To enable NAC Globally: " + input)

    cmd_show_nac = "sudo show nac"
    stdin, stdout, stderr = client2.exec_command(cmd_show_nac)
    cmd_show_nac = stdout.read().decode()
    print(cmd_show_nac)

    # To enable NAC Interface
    cmd_enable_int = "sudo config nac interface enable Ethernet16"
    stdin, stdout, stderr = client2.exec_command(cmd_enable_int)
    input = cmd_enable_int
    print("To enable NAC on Ethernet16: " + input)

    cmd_show_enable_int = "sudo show nac interface Ethernet16"
    stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
    cmd_show_enable_int = stdout.read().decode()
    print(cmd_show_enable_int)

    # Connect to the first device (Supplicant PC) - 2
    #client1.connect(ip_address1, username=username1, password=password1)

    # Goto the Supplicant file path
    cmd_goto_path = "cd /root"
    stdin, stdout, stderr = client1.exec_command(cmd_goto_path)

    # To start the Supplicant
    cmd_sup_start = "sudo wpa_supplicant -c./wpa_supplicant.conf -Dwired -ienp1s0f1"
    _, stdout, stderr = client1.exec_command(cmd_sup_start)
    input = cmd_sup_start
    print("To start the Supplicant: " + input)
    time.sleep(20)

    channel = stdout.channel
    channel.send("\x03")
    time.sleep(2)

    output = channel.recv(1024).decode()
    print(output)

    # Connect to the second device (DUT) - 2
    #client2.connect(ip_address2, username=username2, password=password2)

    # To verify Show NAC Interface Output
    cmd_show_enable_int = "sudo show nac interface Ethernet16"
    stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
    cmd_show_enable_int = stdout.read().decode()
    # Print the output
    print(cmd_show_enable_int)


    # Connect to the third device (Ping receiver)
    client3.connect(ip_address3='172.30.25.93', username3='sonic', password3='admin123')

    # Configuring IP on the ping receiver
    cmd_ping_ip = "sudo ifconfig eth4 20.0.0.17"  # sample
    stdin, stdout, stderr = client3.exec_command(cmd_ping_ip)
    input = cmd_ping_ip
    print("Configuring IP on the ping receiver: " + input)

    cmd_show_int1 = "sudo ifconfig eth4"
    stdin, stdout, stderr = client3.exec_command(cmd_show_int1)
    assert cmd_show_int1 in stdout.read().decode()

    # To check ping
    cmd_ping_check = "ping 20.0.0.17"
    _, stdout, stderr = client1.exec_command(cmd_ping_check)
    time.sleep(10)
    channel = stdout.channel
    channel.send("\x03")
    time.sleep(2)
    output = ""
    while channel.recv_ready():
        output +=  channel.recv(1024).decode()
    print(output)


# Run the test
def test_nac_functionality():

