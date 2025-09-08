import pytest
import yaml, re, time, sys, os
from spytest import st

def parse_platform_syseeprom_output(dut, output=None):
    '''Function to parse the output of "show platform syseeprom" 
       Parameter: 
           dut: the test device 
           output -- output of st.config(dut, "show platform syseeprom")
       Return: 
             example: 
    ''' 

    if not output:
        output=st.config(dut,"show platform syseeprom")

    toggle=0
    tlv_name_list=["Product Name","Part Number","Serial Number","Base MAC Address","Device Version","Platform Name","MAC Addresses","Manufacturer","Manufacture Country","Vendor Name","CRC-32"]
    result_dict=dict((l,None) for l in tlv_name_list)

    def find_matching_keys(line, dictionary):
        matching_keys = []
        for key in dictionary:
            if re.search(key,line):
                result_dict[key]={}
                out=line.split()
                result_dict[key]['Code']=out[-3]
                result_dict[key]['Len']=out[-2]
                result_dict[key]['Value']=out[-1]

    for line in output.split('\n'):
        if re.search(r"TLV Name.+Code.+Len.+Value",line):
            toggle=1
        elif not toggle:
            continue
        else:
            find_matching_keys(line,result_dict)

    return result_dict

def parse_ping_output(ping_output):
    match=re.findall('([\d]+) +packets transmitted.*([\d]+) +received.*([\d]+)% +packet loss.*time ([\w]+)',ping_output)

    if match:
        return (100-int(match[0][2]))
    else:
        return False

def get_show_ip_interfaces(dut, interface_name=''):
    '''Parse and return output of "show ip interfaces"
             or "show ip interfaces | grep Ethernet0"
       Return:
             {}
    '''
    cmd = "show ip interfaces "
    cmd_out = st.config(dut, cmd)
    result = {}
    toggle = 0

    for line in cmd_out.split('\n'):
        if not toggle or not line:
            continue
        elif re.search("Interface\s+Master\s+IPv4 address\/mask\s+Admin\/Oper\s+BGP Neighbor\s+Neighbor IP", line):
            toggle=1
            continue 
        else: 
            if len(line.split())<5 or not re.search(r'[\d]+\.[\d]+\.[\d]+\.[\d]+].*[up|down]',line):
                raise AssertionError('Can not parse "show ip interfaces" output')

            fields = line.split() 
            if len(fields)==6 and re.search('Vrf[\d]',line):
                result[fields[0]]={}
                result[fields[0]]["master"]=fields[1]  
                result[fields[0]]["ipv4_addr_mask"]=fields[2] 
                result[fields[0]]["admin_oper"]=fields[3] 
                result[fields[0]]["bgp_neighbor"]=fields[4] 
                result[fields[0]]["neighbor_ip"]=fields[5] 
            elif len(fields)==5 and not re.search('Vrf[\d]',line):
                result[field[0]]={}
                result[fields[0]]["master"]=" " 
                result[fields[0]]["ipv4_addr_mask"]=fields[1]
                result[fields[0]]["admin_oper"]=fields[2]
                result[fields[0]]["bgp_neighbor"]=fields[3]
                result[fields[0]]["neighbor_ip"]=fields[4]

            if re.search(interface_name, line):
                return result 

    return result 

def get_platform_summary(dut, output=None): 
    '''Function to return a dict with information of "show platform summary" 
       Parameter: 
           dut: test device 
    ''' 
    if not output:
        output=st.config(dut,"show platform summary") 

    toggle=0
    result_dict={} 

    for line in output.split('\n'):
        line_out=line.split(":") 
        if line and len(line_out)==2: 
            result_dict[line_out[0]]=line_out[1] 

    return result_dict

def verify_optics_presence(dut, intf):
    '''Function to check transceiver presence by "show interfaces transceiver presencei Ethernetx" 
       Parameter: 
           dut: test device 
           intf: interface name, e.g, 'Ethernet0' 
       Return:
           True for transceiver existed, False for transceiver not present
    '''

    out = st.config(dut, "show interfaces transceiver presence {}".format(intf)) 
    toggle=0 

    for line in out.split('\n'):
        if not toggle: 
            if re.match(r'Port\s+Presence', line):
                toggle=1 
                continue 

        else: 
            if re.search(r'Not\s+Present', line):
                return False
            elif re.search(r'Present', line) and not re.search(r'Not', line):
                return True
            else:
                continue 

    return False 

def get_port_no_by_interface(dut, intf):
    '''
        Procedure to obtain the port number from interface name for Optics OIR
        Parameters:
            dut: the Device under test
            intf: interface name, e.g, Ethernet0 
        Return: 
            port: the port number for the interface, e.g, 4 for Ethernet32 
    '''
    import apis.system.interface as intapi

    intf_out=intapi.interface_status_show(dut,intf)
    intf_port_name=intf_out[0].get("alias")

    if re.match(r"etp([\d]+)\D*$",intf_port_name): 
        match_str=re.match(r"etp([\d]+)\D*$",intf_port_name) 
        return  match_str.group(1) 

    else:
        raise AssertionError("Can not find port number for {}".format(intf)) 

def optics_oir(dut,  port, action="in"):
    '''
        Procedure to simulate Optics OIR 
        Parameters:
            dut: the Device under test 
            namespace: namespace where the optics/interface belongs to, e.g, asic0 
            port: the port that the optics is in, e.g, Ethernet2 
            action: there are two type of action for the OIR: pullout and plugin 
    '''

    command="sudo /opt/cisco/bin/sfp-OIR.py -p "+port.lstrip("Ethernet")+"  "+action
    st.config(dut, command)

def show_intf_transceiver_info(dut, info, intf=''):
    '''command to run "show interface transceiver eeprom/presence/status Ethernet0"
       Parameters:
          dut: device to test
          info: (one of the following choices)  
              eeprom        Show interface transceiver EEPROM information
              error-status  Show transceiver error-status
              info          Show interface transceiver information
              lpmode        Show interface transceiver low-power mode status
              pm            Show interface transceiver performance monitoring...
              presence      Show interface transceiver presence
              status        Show interface transceiver status information
          intf:
              default is '', meaning all interfaces
              Else: specify Ethernet0 etc. 
        Return:
            output of the show command 
    ''' 

    return st.config(dut, "show interface transceiver {} {}".format(info, intf))


def YamlFileParser(filename):
    ''' Convert a Yaml file to a dictionary
        Parameter: 
             filename: yaml file abs path name, 
        Return:
             {}   

    '''
    with open(filename, 'r') as stream:
        return yaml.safe_load(stream)

