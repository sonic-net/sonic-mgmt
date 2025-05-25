#!/usr/bin/env python

import pexpect
import time

if __name__ == '__main__':
    cmd = "docker exec -it syncd bash"
    print("execute syncd bash", flush=True)
    child = pexpect.spawn(cmd)
    child.expect('/#')
    print("entered syncd", flush=True)
    child.sendline("supervisorctl start dshell_client")
    child.expect('/#')
    print("started dhsell", flush=True)
    retry = 5
    while retry:
        try:
            print("enter dshell_client interactive mode", flush=True)
            child.sendline("/usr/bin/dshell_client.py -i")
            child.expect('>>>')
            child.sendline('\r\r\r')
            break
        except:  # noqa: E722
            print("dshell client timeout, retry again", flush=True)
            time.sleep(120)
            retry -= 1
    else:
        exit(1)

    CLI = [
       "d0 = sdk.la_get_device(0)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP0)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_LACP)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP2)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)",
       "d0.clear_trap_configuration(sdk.LA_EVENT_L3_ISIS_OVER_L3)"
    ]
    for cli in CLI:
        child.sendline(cli)
        print(cli)
        child.sendline('\r\r\r')
        child.expect('>>>')
    child.sendline("quit()")
    exit(0)
