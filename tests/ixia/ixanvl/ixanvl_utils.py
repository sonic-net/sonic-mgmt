import logging
import json
import re

logger = logging.getLogger(__name__)

LIC_SERVER_STR = "License Server Location"
DUT_HOSTNAME_STR = "DUT Hostname"
ETH_INTF_STR = "Ethernet Interface"
IP_ADDR_ANVL_STR = "IP ANVL Address"
IP_ADDR_DUT_STR = "IP DUT Address"
IP_SUBNET_STR = "IP Subnet Mask"
IP_FST_UNUSED_NET_STR = "IP First Unused Net"
IP_UNUSED_NMASK_STR = "IP Unused Net Mask"
IP_NUM_UNUSED_NET_STR = "IP Number Unused Nets"
BGP_UNUSED_ASN_STR = "BGP4 First Unused Autonomous System"

def emit_intf_block(ptfhost, ptf_intf, anvl_ip, dut_ip, subnet):
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(ETH_INTF_STR, ptf_intf))
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(IP_ADDR_ANVL_STR, anvl_ip))
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(IP_ADDR_DUT_STR, dut_ip))
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(IP_SUBNET_STR, subnet))

def emit_global_block(ptfhost, duthost, lic_server, unused_net, unused_net_mask):
    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(LIC_SERVER_STR, lic_server))
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(DUT_HOSTNAME_STR, dutip))
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(IP_FST_UNUSED_NET_STR, unused_net))
    ptfhost.shell('echo \"{} {}\" >> /tmp/anvl.cfg'.format(IP_UNUSED_NMASK_STR, unused_net_mask))
    ptfhost.shell('echo \"{} 10\" >> /tmp/anvl.cfg'.format(IP_NUM_UNUSED_NET_STR))

def emit_bgp_global(ptfhost, asn):
    ptfhost.shell("echo \"{} {}\" >> /tmp/anvl.cfg".format(BGP_UNUSED_ASN_STR, asn))

def delete_tmp_file(ptfhost):
    ptfhost.shell("rm /tmp/anvl.cfg")
    ptfhost.shell("rm /tmp/anvl.prm")

def collect_info(duthost):
    if duthost.facts['asic_type'] == "mellanox":
        logger.info('************* Collect information for debug *************')
        duthost.shell('ip link')
        duthost.shell('ip addr')
        duthost.shell('grep . /sys/class/net/Ethernet*/address', module_ignore_errors=True)
        duthost.shell('grep . /sys/class/net/PortChannel*/address', module_ignore_errors=True)

def create_json_output(filepath):
    try:
        with open(filepath,"r") as log_file:

           summary ={"Number of tests run": "", "Number of tests passed": "", "Number of tests failed": "", "Number of tests inconclusive": ""}
           test_suite ={}
           test_name = ""
           status =""
           comment = ""
           curr_line=""

           for l in log_file.readlines():

            if re.search("TEST_DESCRIPTION", l, re.I):
                comment=""
                status=""
                test_name = curr_line.replace(">","").replace(" ","").replace("\n","")

            if (test_name in l) and len(test_name)>0:
                if(re.search("PASSED", l, re.I)):
                    status="Passed"
                elif(re.search("FAILED", l, re.I)):
                    status="Failed"
                elif (re.search("INCONCLUSIVE", l, re.I)):
                    status ="Inconclusive"

            if re.search("^!", l) and len(test_name)>1 and  len(comment)==0:
                comment = l
            curr_line= l

            if(len(test_name)>0):
               test_suite[test_name]={'status':status, 'comment':comment}

            if(re.search("^Number of test", l)):
                if(re.search("RUN", l, re.I)):
                    summary["Number of tests run"]=l.replace(" ","").replace("\n","").split(":")[1]
                elif(re.search("PASSED", l, re.I)):
                    summary["Number of tests passed"]=l.replace(" ","").replace("\n","").split(":")[1]
                elif(re.search("FAILED", l, re.I)):
                    summary["Number of tests failed"]=l.replace(" ","").replace("\n","").split(":")[1]
                elif (re.search("INCONCLUSIVE", l, re.I)):
                    summary["Number of tests inconclusive"]=l.replace(" ","").replace("\n","").split(":")[1]

           with open('TestCase_wise_report.json', 'w') as json_file:
               json.dump(test_suite, json_file, indent=2)

           with open('Summary.json', 'w') as summary_file:
                json.dump(summary, summary_file, indent=4)

    except:
        print("Can't open file:", filepath)
        return

def increment_ipv4_addr(ipv4_addr, incr=1):
    octets = str(ipv4_addr).split('.')
    last_octet = int(octets[-1])
    last_octet += incr
    octets[-1] = str(last_octet)

    return '.'.join(octets)

def increment_ipv6_addr(ipv6_addr, incr=1):
    octets = str(ipv6_addr).split(':')
    last_octet = octets[-1]
    if last_octet == '':
        last_octet = '0'
    incremented_octet = int(last_octet, 16) + incr
    new_octet_str = '{:x}'.format(incremented_octet)

    return ':'.join(octets[:-1]) + ':' + new_octet_str
