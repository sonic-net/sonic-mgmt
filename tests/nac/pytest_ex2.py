import pytest
import math
import paramiko
import logging
import os
import time

def parse_colon_speparated_lines(lines):
    """
    @summary: Helper function for parsing lines which consist of key-value pairs
    formatted like "<key>: <value>", where the colon can be surrounded
    by 0 or more whitespace characters
    @return: A dictionary containing key-value pairs of the output
    """
    res = {}
    for line in lines:
        fields = line.split(":")
        if len(fields) != 2:
            continue
        res[fields[0].strip()] = fields[1].strip()
    return res

def show_and_parse_tabledata(stdout_lines):
    table_data = []
    result = []
    for line in stdout_lines:
        if '|' in line:
            row = line.strip('\n').split('|')
            row = [r.strip() for r in row if r != '']
            table_data.append(row)
        #key_data = table_data[0]
        for row in table_data[1:]:
            row_map = {}
            for i, value in enumerate(row):
                row_map.update({key_data[i]: value})
            result.append(row_map)
        return result

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


    client1 = paramiko.SSHClient()
    client1.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client2 = paramiko.SSHClient()
    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
        if "inet 70.0.0.10" in cmd_sup_ip_output:
            pass
        else:
            print("inet address not matching")
    
        
        client2.connect(ip_address2, username=username2, password=password2)
        
        cmd_reboot = "sudo reboot"
        stdin, stdout, stderr = client2.exec_command(cmd_reboot)
        cmd_reboot = stdout.read().decode()
    
        client2.close()
        
        time.sleep(180)

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

        summary_output_lines = cmd_show_nac_output
        #logging.info("Parse Show output")
        summary_dict = parse_colon_speparated_lines(summary_output_lines)
        logging.info("Parse Output- {}".format(summary_dict))
        for k, v in summary_dict.items():
            logging.info("Key - {}, Value - {}".format(k, v))
            err_list = []
        if 'NAC Authentication Type' in summary_dict:
            if summary_dict['NAC Authentication Type'] != 'local':
                err_list.append("NAC Authentication Type observed value - {}, expected value as local".format(summary_dict['NAC Authentication Type']))
        else:
                err_list.append("NAC Authentication Type not in the show nac response")
        if 'NAC Admin State' in summary_dict:
            if summary_dict['NAC Admin State'] != 'up':
                err_list.append("NAC Admin State observed value - {}, expected value as up".format(summary_dict['NAC Admin State']))
        else:
                err_list.append("NAC Admin State not in the show nac response")
        if 'NAC Type' in summary_dict:
            if summary_dict['NAC Type'] != 'port':
                err_list.append("NAC Type observed value - {}, expected value as port".format(summary_dict['NAC Type']))
        else:
            err_list.append("NAC Type not in the show nac response")
        #assert len(err_list) == 0, ', '.join([str(err) for err in err_list])

        # To enable NAC Interface
        cmd_enable_int = "sudo config nac interface enable Ethernet16"
        stdin, stdout, stderr = client2.exec_command(cmd_enable_int)
        cmd_enable_int = stdout.read().decode()
        print(cmd_enable_int)
        
        cmd_show_enable_int = "sudo show nac interface Ethernet16"
        stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
        cmd_show_enable_int_output = stdout.read().decode()
        print(cmd_show_enable_int_output)

        summary_output_lines = cmd_show_enable_int_output
        #logging.info(summary_output_lines)
        nac_enable_data = show_and_parse_tabledata(summary_output_lines)
        logging.info(nac_enable_data)
        err_list = []
        for row in nac_enable_data:
            if 'InterfaceName' in row:
                if row['InterfaceName'] != 'Ethernet116':
                    err_list.append("InterfaceName observed value - {}, expected value as local".format(row['InterfaceName']))
            else:
                err_list.append("InterfaceName not in the show interface nac response")
            if 'NAC AdminState' in row:
                if row['NAC AdminState'] != 'up':
                    err_list.append("NAC AdminState observed value - {}, expected value as up".format(row['NAC AdminState']))
            else:
                err_list.append("NAC AdminState not in the show nac interface response")
            if 'Authorization State' in row:
                if row['Authorization State'] != 'unauthorized':
                    err_list.append("Authorization State observed value - {}, expected value as port".format(row['Authorization State']))
            else:
                err_list.append("Authorization State not in the show nac interface response")
            if 'Mapped Profile' in row:
                if row['Mapped Profile'] != '':
                    err_list.append("Mapped Profile observed value - {}, expected value as local".format(row['Mapped Profile']))
            else:
                err_list.append("Mapped Profile not in the show nac interface response")
                #assert len(err_list) == 0, ', '.join([str(err) for err in err_list])

  
        cmd_goto_root_user = "sudo su"
        stdin, stdout, stderr = client1.exec_command(cmd_goto_root_user)
        # To start the Supplicant
        cmd_sup_start = "sudo wpa_supplicant -c./wpa_supplicant.conf -Dwired -ienp7s0f3 > reboot_sup.txt" 
        _, stdout, stderr = client1.exec_command(cmd_sup_start, timeout=15)
        #cmd_sup_start_output = stdout.read().decode()
        #print("To start the supplicant: " + cmd_sup_start_output)
        file_name = "output.txt"
        if os.access(file_name, os.R_OK):
            with open(file_name, "r") as file:
                file_content = file.read()
                if "CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully" in file_content:
                    print("Yes")
                else:
                    print("Authentication Failed")

        cmd_show_enable_int = "sudo show nac interface Ethernet16"
        stdin, stdout, stderr = client2.exec_command(cmd_show_enable_int)
        cmd_show_enable_int_output = stdout.read().decode()
        # Print the output
        print(cmd_show_enable_int_output)
        
        summary_output_lines = cmd_show_enable_int_output
        #logging.info(summary_output_lines)
        nac_enable_data = show_and_parse_tabledata(summary_output_lines)
        logging.info(nac_enable_data)
        err_list = []
        for row in nac_enable_data:
            if 'InterfaceName' in row:
                if row['InterfaceName'] != 'Ethernet116':
                    err_list.append("InterfaceName observed value - {}, expected value as local".format(row['InterfaceName']))
            else:
                err_list.append("InterfaceName not in the show interface nac response")
            if 'NAC AdminState' in row:
                if row['NAC AdminState'] != 'up':
                    err_list.append("NAC AdminState observed value - {}, expected value as up".format(row['NAC AdminState']))
            else:
                err_list.append("NAC AdminState not in the show nac interface response")
            if 'Authorization State' in row:
                if row['Authorization State'] != 'authorized':
                    err_list.append("Authorization State observed value - {}, expected value as port".format(row['Authorization State']))
            else:
                err_list.append("Authorization State not in the show nac interface response")
            if 'Mapped Profile' in row:
                if row['Mapped Profile'] != '':
                    err_list.append("Mapped Profile observed value - {}, expected value as local".format(row['Mapped Profile'])) 
            else:
                err_list.append("Mapped Profile not in the show nac interface response")
                #assert len(err_list) == 0, ', '.join([str(err) for err in err_list])

        #Connect to the third device (Ping receiver)
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
        cmd_ping_check = "ping 70.0.0.20 > reboot_ping.txt"
        _, stdout, stderr = client1.exec_command(cmd_ping_check, timeout=7)
        file_name = "output.txt"
        if os.access(file_name, os.R_OK):
            with open(file_name, "r") as file:
                file_content = file.read()
                if "Destination Host Unreachable" in file_content:
                    print("Ping Failed")
                else:
                    pass
        

    finally:
        # Close the SSH connections
        client1.close()
        client2.close()
        client3.close()
