import pytest
import paramiko
import time

def test_nac_functionality():
    ip_address1 = '172.30.25.67'
    username1 = 'sonic'
    password1 = 'admin123'
    ip_address2 = '172.30.25.102'
    username2 = 'admin'
    password2 = 'YourPaSsWoRd'
    ip_address3 = '172.30.25.93'
    username3 = 'sonic'
    password3 = 'admin123'

    # Create an SSH client for the Supplicant
    client1 = paramiko.SSHClient()
    client1.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Create an SSH client for the DUT
    client2 = paramiko.SSHClient()
    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Create an SSH client for the Ping Receiver
    client3 = paramiko.SSHClient()
    client3.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the first device (Supplicant PC)
        client1.connect(ip_address1, username=username1, password=password1)

        # Configuring IP on the Supplicant PC
        cmd_sup_ip = "sudo ifconfig enp7s0f3 70.0.0.10"  # sample
        stdin, stdout, stderr = client1.exec_command(cmd_sup_ip)
        cmd_sup_ip_output = stdout.read().decode()
        print(cmd_sup_ip_output)


        cmd_show_int = "sudo ifconfig enp7s0f3"
        stdin, stdout, stderr = client1.exec_command(cmd_show_int)
        cmd_show_int_output = stdout.read().decode()
        print(cmd_show_int_output)  

        # Connect to the second device (DUT)
        client2.connect(ip_address2, username=username2, password=password2)

        # To enable NAC Globally
        cmd_enable_global = "sudo config nac enable"
        stdin, stdout, stderr = client2.exec_command(cmd_enable_global)
        cmd_enable_global = stdout.read().decode()
        print(cmd_enable_global)

        cmd_show_nac = "sudo show nac"
        stdin, stdout, stderr = client2.exec_command(cmd_show_nac)
        cmd_show_nac_output = stdout.read().decode()
        print(cmd_show_nac_output)

        # To enable NAC Interface
        cmd_enable_int = "sudo config nac interface enable Ethernet16"
        stdin, stdout, stderr = client2.exec_command(cmd_enable_int)
        cmd_enable_int = stdout.read().decode()
        print(cmd_enable_int)

        cmd_show_enable_int = "sudo show nac interface Ethernet16"
        stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
        cmd_show_enable_int_output = stdout.read().decode()
        print(cmd_show_enable_int_output)  

        # Connect to the first device (Supplicant PC) - 2
        # client1.connect(ip_address1, username=username1, password=password1)

        # Goto the Supplicant file path
        cmd_goto_root_user = "sudo su"
        stdin, stdout, stderr = client1.exec_command(cmd_goto_root_user)

        # To start the Supplicant
        cmd_sup_start = "sudo wpa_supplicant -c./wpa_supplicant.conf -Dwired -ienp7s0f3"
        _, stdout, stderr = client1.exec_command(cmd_sup_start)
        cmd_sup_start_output = stdout.read().decode()
        print("To start the supplicant: " + cmd_sup_start_output)
        time.sleep(20)

        channel = stdin.channel
        channel.send("\x03")
        time.sleep(2)

        output = channel.recv(1024).decode()
   
        print(output)  

        # Connect to the second device (DUT) - 2
        # client2.connect(ip_address2, username=username2, password=password2)

        # To verify Show NAC Interface Output
        cmd_show_enable_int = "sudo show nac interface Ethernet16"
        stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
        cmd_show_enable_int_output = stdout.read().decode()
        # Print the output
        print(cmd_show_enable_int_output)

        # Connect to the third device (Ping receiver)
        client3.connect(ip_address3, username=username3, password=password3)

        # Configuring IP on the ping receiver
        cmd_ping_ip = "sudo ifconfig eth4 70.0.0.20"  # sample
        stdin, stdout, stderr = client3.exec_command(cmd_ping_ip)
        cmd_ping_ip = stdout.read().decode()
        print(cmd_ping_ip)

        cmd_show_int1 = "sudo ifconfig eth4"
        stdin, stdout, stderr = client3.exec_command(cmd_show_int1)
        cmd_show_int1_output = stdout.read().decode()
        print(cmd_show_int1_output)  

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
        print(output)  

    except paramiko.AuthenticationException:
        pytest.fail("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as ssh_exception:
        pytest.fail("Error connecting to the remote PC: {}".format(str(ssh_exception)))
    finally:
        # Close the SSH connections
        client1.close()
        client2.close()
        client3.close()
