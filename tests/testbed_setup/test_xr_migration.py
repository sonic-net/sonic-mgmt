import logging
from time import sleep
import pytest
import re


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


mig_script = "sonic_migration_xr736.py"
xr_user = ""
xr_pass = ""
xr_prompt = "RP/0/RP0/CPU0:.*#"
mgmt_int = "Mg0/RP0/CPU0/0"
mgmt_ip_mask = "10.250.0.20 255.255.255.0"
mgmt_gw = "10.250.0.1"
rollback_file_path = "/home/cisco/Secureboot/Rollback-Files/*"
mig_file_path = "/home/cisco/Secureboot/Migration-Files/*"
scp_user = ""
scp_pass = ""
scp_host = "10.250.0.245"


def read_con(duthost_console, prompt):
    output = ''
    logger.debug(f"reading console until: {prompt}")
    while True:
        try:
            line = duthost_console.read_until_pattern(duthost_console.RETURN)  # .decode('ascii')
            logger.debug(line)
            output = output + line
            found = re.search(prompt, line)
            if found:
                break
        except Exception:
            continue
    return output


def test_xr_migration(duthost_console, duthosts, enum_supervisor_dut_hostname, conn_graph_facts, creds):
    duthost = duthosts[enum_supervisor_dut_hostname]
    dut_hostname = duthost.hostname

    # gather console information
    duthost_console.timeout = 300
    console_user = creds['console_user']['console_ssh']
    console_password = creds['console_password']['console_ssh'][0]

    # copy all files from rollback-files directory to duthost
    duthost_console.write_and_poll(f"sudo scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                                   {scp_user}@{scp_host}:{rollback_file_path} /host/", "password:")
    duthost_console.write_channel(scp_pass + duthost_console.RETURN)
    read_con(duthost_console, f"{console_user}@{dut_hostname}:~")

    # Migrate to XR Rollback Image
    duthost_console.write_channel(f"sudo python /host/{mig_script} --rollback{duthost_console.RETURN}")
    read_con(duthost_console, "ROLLBACK_SONIC: Execute xrmigration.sh - device will reload")
    duthost_console.timeout = 2000
    read_con(duthost_console, "Press RETURN to get started.")
    logger.debug("sleeping for 10 minutes")
    sleep(600)    # TODO: Investigate reducing this timer
    # TODO: switch to read_con
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
    logger.info("after mgmt config")

    # XR to Sonic Migration steps
    duthost_console.timeout = 300
    # Copy Required Files to Harddisk from migration file location
    # TODO: change to use read_con instead of write/poll
    duthost_console.write_and_poll(f"scp {scp_user}@{scp_host}:{mig_file_path} /harddisk:/", "Password:")
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
    duthost_console.timeout = 300
    duthost_console.write_channel(f"run python /harddisk:/{mig_script} --av_install --sonic_migration" +
                                  duthost_console.RETURN)
    read_con(duthost_console, "SONIC_MIGRATION: Reloading RP to perform SONiC migration")
    duthost_console.timeout = 2000
    read_con(duthost_console, "sonic login:")
    read_con(duthost_console, "user power cycle")
    read_con(duthost_console, "sonic login:")
    duthost_console.write_channel(console_user + duthost_console.RETURN)
    read_con(duthost_console, "Password:")
    duthost_console.write_channel(console_password + duthost_console.RETURN)

    # Sonic Postcheck
    read_con(duthost_console, f"{console_user}@sonic:~$")
    duthost_console.write_channel(f"sudo python /mnt/obfl/{mig_script} --sonic_migration_postcheck" +
                                  duthost_console.RETURN)
    output = read_con(duthost_console, f"{console_user}@sonic:~$")
    if "EXIT_ON_SUCCESS" not in output:
        duthost_console.disconnect()
        raise Exception("Error occured during post check, exiting")

    # Test complete, close console connection
    duthost_console.disconnect()
