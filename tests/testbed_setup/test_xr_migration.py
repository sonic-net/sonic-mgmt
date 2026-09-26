'''
This test is to verify the process of converting from Sonic to Cisco IOS XR and back to Sonic behaves as expected.
The 2 file_path variables and 3 scp variables must be updated to point at where the files are staged.

The following files are required to be staged in their respective directories:

Rollback:
8000-goldenk9-x64-7.3.6-fabric_2.iso
sonic_migration_xr.py

Migration:
8000-x64-7.5.41.04I.iso
sonic-cisco-8000.bin.openssl.ipxcontainer
sonic_migration_xr.py
customer_av.auth
sonic-migutil.py
customer_ov.tar.gz
onie-recovery-x86_64-cisco_8000-r0.efi64.pxe

Console access to the DUT is also required.
'''

import logging
from time import sleep
import pytest
import re


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


mig_script = "sonic_migration_xr.py"
xr_user = ""
xr_pass = ""
xr_prompt = "RP/0/RP0/CPU0:.*#"
mgmt_int = "Mg0/RP0/CPU0/0"
mgmt_ip_mask = "10.250.0.20 255.255.255.0"
mgmt_gw = "10.250.0.1"
rollback_file_path = "/home/cisco/Secureboot/Rollback-Files/"  # File paths must have trailing slash
mig_file_path = "/home/cisco/Secureboot/Migration-Files/"
scp_user = ""
scp_pass = ""
scp_host = "10.250.0.245"


def read_con(duthost_console, prompt):
    output = ''
    logger.debug(f"reading console until: {prompt}")
    while True:
        try:
            line = duthost_console.read_until_pattern(duthost_console.RETURN)
            logger.debug(line)
            output = output + line
            found = re.search(prompt, line)
            if found:
                break
        except Exception:
            continue
    return output


def test_xr_migration(duthost_console, duthosts, enum_supervisor_dut_hostname, creds, tbinfo, request):
    duthost = duthosts[enum_supervisor_dut_hostname]
    dut_hostname = duthost.hostname

    # Test can only be run on Cisco hardware with CLI switch given
    hwsku = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_hwsku'].lower()
    if 'cisco' not in hwsku:
        pytest.skip("Test must be run on a Cisco chassis")

    if not request.config.getoption("--enable_xr_mig"):
        pytest.skip("Test must be run with CLI switch")

    # gather console information
    duthost_console.timeout = 300
    console_user = creds['console_user']['console_ssh']
    console_password = creds['console_password']['console_ssh'][0]
    prompt = duthost_console.find_prompt()[:-1]

    # gather minigraph files from DUT for config restore
    duthost_console.write_channel("show chassis modules midplane-status" + duthost_console.RETURN +
                                  duthost_console.RETURN)
    split = read_con(duthost_console, prompt).split("\n")
    for line in split[3:-2]:
        split_line = line.split(" ")
        if split_line[len(split_line) - 1].strip() == "True":
            card_index = split_line[1][-1]
            logger.debug(f"found card: {split_line[1]} with index: {card_index}")
            logger.debug(f"split line: {split_line}")
            logger.debug(f"ip is: {split_line[8]}")
            filename = "minigraph-" + dut_hostname + "-lc0" + split_line[1][-1] + ".xml"
            logger.debug(f"filename: {filename}")
            duthost_console.write_and_poll(f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                                           {console_user}@{split_line[8]}:/etc/sonic/minigraph.xml \
                                           {scp_user}@{scp_host}:{mig_file_path}{filename}" + duthost_console.RETURN,
                                           "password:")
            duthost_console.write_and_poll(scp_pass + duthost_console.RETURN, "password:")
            duthost_console.write_channel(console_password + duthost_console.RETURN)
            read_con(duthost_console, prompt)

    # copy RP minigraph
    filename = "minigraph-" + dut_hostname + "-sup00.xml"
    logger.debug(f"filename: {filename}")
    duthost_console.write_and_poll(f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                                    /etc/sonic/minigraph.xml {scp_user}@{scp_host}:{mig_file_path}{filename}" +
                                   duthost_console.RETURN, "password:")
    # duthost_console.write_and_poll(scp_pass + duthost_console.RETURN, "password:")
    duthost_console.write_channel(scp_pass + duthost_console.RETURN)
    read_con(duthost_console, prompt)

    # copy all files from rollback-files directory to duthost
    duthost_console.write_and_poll(f"sudo scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                                   {scp_user}@{scp_host}:{rollback_file_path}* /host/", "password:")
    duthost_console.write_channel(scp_pass + duthost_console.RETURN)
    read_con(duthost_console, prompt)

    # Migrate to XR Rollback Image
    duthost_console.write_channel(f"sudo python /host/{mig_script} --rollback{duthost_console.RETURN}")
    read_con(duthost_console, "ROLLBACK_SONIC: Execute xrmigration.sh - device will reload")
    duthost_console.timeout = 2000
    read_con(duthost_console, "Press RETURN to get started.")
    logger.debug("sleeping for 10 minutes")
    sleep(600)
    duthost_console.write_and_poll(duthost_console.RETURN, "Enter root-system username:")
    duthost_console.write_and_poll(console_user, "Enter secret:")
    duthost_console.write_and_poll(console_password, "Enter secret again:")
    duthost_console.write_and_poll(console_password, "Username:")
    duthost_console.write_and_poll(console_user, "Password:")
    duthost_console.write_and_poll(console_password, xr_prompt)
    logger.debug("after XR rollback cred reset")
    sleep(60)

    # XR Rollback FPD
    duthost_console.timeout = 300
    duthost_console.write_channel(f"run python /mnt/mtd0/{mig_script} --rollback" + duthost_console.RETURN)
    out = read_con(duthost_console, "XR_ROLLBACK: Reloading line cards to initiate migration of line cards to IOS XR")
    duthost_console.timeout = 2000
    out2 = read_con(duthost_console, "Press RETURN to get started.")
    output = out + out2
    if "[ERROR]" in output:
        duthost_console.disconnect()
        raise Exception("Error occured in fpd rollback, exiting.")
    sleep(60)
    duthost_console.write_and_poll(duthost_console.RETURN, "Username:")
    duthost_console.write_and_poll(console_user, "Password:")
    duthost_console.write_and_poll(console_password, xr_prompt)
    logger.debug("after xr login")
    sleep(60)

    # XR Rollback Verify
    duthost_console.timeout = 300
    duthost_console.write_channel(f"run python /mnt/mtd0/{mig_script} --rollback" + duthost_console.RETURN)
    out = read_con(duthost_console, "XR_ROLLBACK: Performing module healthcheck for IOS XR")
    duthost_console.timeout = 2000
    out2 = read_con(duthost_console, "EXIT_ON_SUCCESS: SONiC migration script exiting due to successful completion")
    output = out + out2
    if "[ERROR]" in output:
        duthost_console.disconnect()
        raise Exception("Error occured in rollback verification, exiting.")
    sleep(5)

    # Reconfigure the management IP
    duthost_console.write_channel("config" + duthost_console.RETURN)
    duthost_console.write_channel("line console" + duthost_console.RETURN)
    duthost_console.write_channel("width 0" + duthost_console.RETURN)
    duthost_console.write_channel("length 0" + duthost_console.RETURN)
    duthost_console.write_channel(f"interface {mgmt_int}" + duthost_console.RETURN)
    duthost_console.write_channel(f"ipv4 address {mgmt_ip_mask}" + duthost_console.RETURN)
    duthost_console.write_channel("no shut" + duthost_console.RETURN)
    duthost_console.write_channel("router static" + duthost_console.RETURN)
    duthost_console.write_channel("address-family ipv4 unicast" + duthost_console.RETURN)
    duthost_console.write_channel(f"0.0.0.0/0 {mgmt_gw}" + duthost_console.RETURN)
    duthost_console.write_channel("ssh server v2" + duthost_console.RETURN)
    duthost_console.write_channel("ssh server vrf default" + duthost_console.RETURN)
    duthost_console.write_channel("commit" + duthost_console.RETURN)
    duthost_console.write_channel("end" + duthost_console.RETURN)
    logger.debug("after mgmt config")

    # XR to Sonic Migration steps
    duthost_console.timeout = 300
    # Copy Required Files to Harddisk from migration file location
    duthost_console.write_and_poll(f"scp {scp_user}@{scp_host}:{mig_file_path}* /harddisk:/", "Password:")
    duthost_console.write_channel(scp_pass + duthost_console.RETURN)
    read_con(duthost_console, xr_prompt)

    # Run XR Upgrade Check
    duthost_console.write_channel(f"run python /harddisk:/{mig_script} --xr_upgrade --check" + duthost_console.RETURN)
    out = read_con(duthost_console, xr_prompt)
    if "EXIT_ON_SUCCESS" not in out:
        duthost_console.disconnect()
        raise Exception("Error occured in XR upgrade check, exiting.")

    # Upgrade to XR Migration Image
    duthost_console.write_channel(f"run python /harddisk:/{mig_script} --xr_upgrade" + duthost_console.RETURN)
    out = read_con(duthost_console, "XR_UPGRADE: Device will now reload for IOS XR upgrade to")
    duthost_console.timeout = 2000
    out2 = read_con(duthost_console, "Press RETURN to get started.")
    output = out + out2
    if "[ERROR]" in output:
        duthost_console.disconnect()
        raise Exception("An error happened during XR upgrade, exiting")
    duthost_console.write_and_poll(duthost_console.RETURN, "Username:")
    duthost_console.write_and_poll(console_user, "Password:")
    duthost_console.write_and_poll(console_password, xr_prompt)
    logger.debug("after migration image upgrade login")
    sleep(120)

    # Install Authenticated Variable and Migrate to SONiC
    duthost_console.write_channel(f"run python /harddisk:/{mig_script} --av_install --sonic_migration_rp" +
                                  duthost_console.RETURN)

    # Login and migrate line cards to Sonic
    read_con(duthost_console, "sonic login:")
    duthost_console.write_channel(console_user + duthost_console.RETURN)
    read_con(duthost_console, "Password:")
    duthost_console.write_channel(console_password + duthost_console.RETURN)
    sleep(120)
    duthost_console.write_channel(f"sudo python /mnt/obfl/{mig_script} --sonic_migration_lc" +
                                  duthost_console.RETURN)
    read_con(duthost_console, "user power cycle")
    read_con(duthost_console, "sonic login:")
    duthost_console.write_channel(console_user + duthost_console.RETURN)
    read_con(duthost_console, "Password:")
    duthost_console.write_channel(console_password + duthost_console.RETURN)
    sleep(360)

    # Sonic Postcheck
    duthost_console.write_channel(f"sudo python /mnt/obfl/{mig_script} --sonic_migration_postcheck" +
                                  duthost_console.RETURN)
    output = read_con(duthost_console, "EXIT_ON_SUCCESS: SONiC migration script exiting due to successful completion")
    if "[ERROR]" in output:
        duthost_console.disconnect()
        raise Exception("Error occured during post check, exiting")

    # Test complete, close console connection
    duthost_console.disconnect()
