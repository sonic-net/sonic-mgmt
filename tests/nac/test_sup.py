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
        client1.connect(ip_address1, username=username1, password=password1)
        cmd_goto_root_user = "sudo su"
        stdin, stdout, stderr = client1.exec_command(cmd_goto_root_user)
        # To start the Supplicant
        cmd_sup_start = "sudo wpa_supplicant -c./wpa_supplicant.conf -Dwired -ienp7s0f3"
        _, stdout, stderr = client1.exec_command(cmd_sup_start)
        cmd_sup_start_output = stdout.read().decode()
        print("To start the supplicant: " + cmd_sup_start_output)
        time.sleep(20)
        shell = client1.invoke_shell()  # Start an interactive shell
        shell.send(cmd_sup_start + "\n")  # Send the command
        time.sleep(2)  # Wait for the command to execute
        shell.send("\x03")  # Send Ctrl+C to terminate the command
        time.sleep(2)  # Wait for the termination
        output = ""
        while shell.recv_ready():
            data = shell.recv(1024).decode()
            output += data
        print(output)





        #channel = stdout.channel
        #channel.send("\x03")
        #time.sleep(2)
        #output =  channel.recv(1024).decode()
        #print(output) 
        #output = channel.recv(1024).decode()
        #print(output)
        if "CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully" in output:
            print("Yes")
        else:
            print("Authentication Failed")

    except paramiko.AuthenticationException:
        pytest.fail("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as ssh_exception:
        pytest.fail("Error connecting to the remote PC: {}".format(str(ssh_exception)))
    finally:
        # Close the SSH connections
        client1.close()

