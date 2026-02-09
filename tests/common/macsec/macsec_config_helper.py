import logging
import time
from tests.common.macsec.macsec_helper import get_mka_session, getns_prefix, wait_all_complete, \
     submit_async_task, load_all_macsec_info
from tests.common.macsec.macsec_platform_helper import global_cmd, find_portchannel_from_member, get_portchannel
from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

__all__ = [
    'enable_macsec_feature',
    'disable_macsec_feature',
    'setup_macsec_configuration',
    'cleanup_macsec_configuration',
    'set_macsec_profile',
    'delete_macsec_profile',
    'enable_macsec_port',
    'disable_macsec_port',
    'get_macsec_enable_status',
    'get_macsec_profile',
    'wait_for_macsec_cleanup'
]

logger = logging.getLogger(__name__)


def get_macsec_enable_status(host):
    # Retrieve the enable_macsec flag passed by user for this testrun
    request = host.duthosts.request
    return request.config.getoption("--enable_macsec", default=False)


def get_macsec_profile(host):
    # Retrieve the macsec_profile passed by user for this testrun
    request = host.duthosts.request
    return request.config.getoption("--macsec_profile", default=None)


def set_macsec_profile(host, port, profile_name, priority, cipher_suite,
                       primary_cak, primary_ckn, policy, send_sci, rekey_period=0):
    if isinstance(host, EosHost):
        eos_cipher_suite = {
            "GCM-AES-128": "aes128-gcm",
            "GCM-AES-256": "aes256-gcm",
            "GCM-AES-XPN-128": "aes128-gcm-xpn",
            "GCM-AES-XPN-256": "aes256-gcm-xpn"
        }
        lines = [
            'cipher {}'.format(eos_cipher_suite[cipher_suite]),
            'key {} 7 {}'.format(primary_ckn, primary_cak),
            'mka key-server priority {}'.format(priority)
            ]
        if rekey_period:
            lines.append('mka session rekey-period {}'.format(rekey_period))
        if send_sci == 'true':
            lines.append('sci')
        host.eos_config(
            lines=lines,
            parents=['mac security', 'profile {}'.format(profile_name)])
        return

    macsec_profile = {
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci": send_sci,
        "rekey_period": rekey_period,
    }
    cmd = "sonic-db-cli {} CONFIG_DB HMSET 'MACSEC_PROFILE|{}' ".format(
        getns_prefix(host, port), profile_name)
    for k, v in list(macsec_profile.items()):
        cmd += " '{}' '{}' ".format(k, v)
    host.command(cmd)
    if send_sci == "false":
        # The MAC address of SONiC host is locally administrated
        # So, LLDPd will use an arbitrary fixed value (00:60:08:69:97:ef)
        # as the source MAC address of LLDP packet (https://lldpd.github.io/usage.html)
        # But the MACsec driver in Linux used by SONiC VM has a bug that
        # cannot handle the packet with different source MAC address to SCI if the send_sci = false
        # So, if send_sci = false and the neighbor device is SONiC VM,
        # LLDPd need to use the real MAC address as the source MAC address
        host.command("lldpcli configure system bond-slave-src-mac-type real")


def is_macsec_configured(host, mac_profile, ctrl_links):
    is_profile_present = False
    is_port_profile_present = False
    profile_name = mac_profile['name']

    # Check macsec profile is configured in all namespaces
    if host.is_multi_asic:
        for ns in host.get_asic_namespace_list():
            CMD_PREFIX = "-n {}".format(ns) if ns is not None else " "
            cmd = "sonic-db-cli {} CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(CMD_PREFIX, profile_name)
            output = host.command(cmd)['stdout'].strip()
            profile = output.split('|')[1] if output else None
            is_profile_present = (profile == profile_name)
    else:
        cmd = "sonic-db-cli CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(profile_name)
        output = host.command(cmd)['stdout'].strip()
        profile = output.split('|')[1] if output else None
        is_profile_present = (profile == profile_name)

    # Check if macsec profile is configured on interfaces
    for port, nbr in ctrl_links.items():
        cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec' ".format(getns_prefix(host, port), port)
        output = host.command(cmd)['stdout'].strip()
        is_port_profile_present = (output == profile_name)

    return is_profile_present and is_port_profile_present


def delete_macsec_profile(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no profile {}'.format(profile_name)],
            parents=['mac security'])
        return

    # if port is None, the macsec profile is deleted from all namespaces if multi-asic
    if host.is_multi_asic and port is None:
        for ns in host.get_asic_namespace_list():
            CMD_PREFIX = "-n {}".format(ns) if ns is not None else " "
            cmd = "sonic-db-cli {} CONFIG_DB DEL 'MACSEC_PROFILE|{}'".format(CMD_PREFIX, profile_name)
            host.command(cmd)
    else:
        cmd = ("sonic-db-cli {} CONFIG_DB DEL 'MACSEC_PROFILE|{}'"
               .format(getns_prefix(host, port), profile_name))
        host.command(cmd)


def enable_macsec_port(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['mac security profile {}'.format(profile_name)],
            parents=['interface {}'.format(port)])
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))

    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "sonic-db-cli {} CONFIG_DB HSET 'PORT|{}' 'macsec' '{}'".format(getns_prefix(host, port), port, profile_name)
    host.command(cmd)

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member add {} {}".format(getns_prefix(host, port), pc["name"], port))


def disable_macsec_port(host, port):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no mac security profile'],
            parents=['interface {}'.format(port)])
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))
    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "sonic-db-cli {} CONFIG_DB HDEL 'PORT|{}' 'macsec'".format(getns_prefix(host, port), port)
    host.command(cmd)

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member add {} {}".format(getns_prefix(host, port), pc["name"], port))


def enable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = macsec_nbrhosts
    num_asics = duthost.num_asics()
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")

    def check_macsec_enabled():
        if len(duthost.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < num_asics:
            return False
        if len(duthost.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < num_asics:
            return False
        for nbr in [n["host"] for n in list(nbrhosts.values())]:
            if isinstance(nbr, EosHost):
                continue
            if len(nbr.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < 1:
                return False
            if len(nbr.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < 1:
                return False
        return True
    assert wait_until(180, 5, 10, check_macsec_enabled)


def disable_macsec_feature(duthost, macsec_nbrhosts):
    global_cmd(duthost, macsec_nbrhosts, "sudo config feature state macsec disabled")


def cleanup_macsec_configuration(duthost, ctrl_links, profile_name):
    devices = set()
    if duthost.facts["asic_type"] == "vs":
        devices.add(duthost)

    logger.info("Cleanup macsec configuration step1: disable macsec port")
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        submit_async_task(disable_macsec_port, (duthost, dut_port))
        submit_async_task(disable_macsec_port, (nbr["host"], nbr["port"]))
        devices.add(nbr["host"])
    wait_all_complete(timeout=300)

    logger.info("Cleanup macsec configuration step2: delete macsec profile")
    # Delete the macsec profile once after it is removed from all interfaces. if we pass port as None,
    # the profile is removed from the DB in all namespaces.
    submit_async_task(delete_macsec_profile, (duthost, None, profile_name))

    # Delete the macsec profile in neighbors
    for d in devices:
        submit_async_task(delete_macsec_profile, (d, None, profile_name))
    wait_all_complete(timeout=300)

    logger.info("Cleanup macsec configuration step3: wait for automatic cleanup")

    # Extract DUT interface names from ctrl_links and wait for automatic
    # MACsec cleanup on the DUT side.
    interfaces = list(ctrl_links.keys())
    wait_for_macsec_cleanup(duthost, interfaces)

    # Also wait for neighbor devices to complete automatic cleanup for their
    # corresponding ports.
    for dut_port, nbr in list(ctrl_links.items()):
        wait_for_macsec_cleanup(nbr["host"], [nbr["port"]])

    logger.info("Cleanup macsec configuration finished")

    # Waiting for all MKA sessions to be cleared on neighbor devices.
    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo):
    logger.info("Setup macsec configuration step1: set macsec profile")
    # 1. Set macsec profile
    i = 0
    for dut_port, nbr in ctrl_links.items():
        submit_async_task(set_macsec_profile, (duthost, dut_port, profile_name, default_priority,
                          cipher_suite, primary_cak, primary_ckn, policy,
                          send_sci, rekey_period))
        if i % 2 == 0:
            priority = default_priority - 1
        else:
            priority = default_priority + 1
        submit_async_task(set_macsec_profile,
                          (nbr["host"], nbr["port"], profile_name, priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period))
        i += 1
    wait_all_complete(timeout=180)

    logger.info("Setup macsec configuration step2: enable macsec profile")
    # 2. Enable macsec profile
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        submit_async_task(enable_macsec_port, (duthost, dut_port, profile_name))
        submit_async_task(enable_macsec_port, (nbr["host"], nbr["port"], profile_name))
    wait_all_complete(timeout=180)

    # 3. Wait for interface's macsec ready
    for dut_port, nbr in list(ctrl_links.items()):
        assert wait_until(300, 3, 0,
                          lambda: duthost.iface_macsec_ok(dut_port) and
                          nbr["host"].iface_macsec_ok(nbr["port"]))

    # Enabling macsec may cause link flap, which impacts LACP, BGP, etc
    # protocols. To hold some time for protocol recovery.
    time.sleep(60)
    logger.info("Setup macsec configuration finished")

    # Load the MACSEC_INFO, to have data of all macsec sessions
    load_all_macsec_info(duthost, ctrl_links, tbinfo)


def wait_for_macsec_cleanup(host, interfaces, timeout=90):
    """Wait for MACsec daemon to automatically clean up all MACsec entries.

    This function implements proper synchronization to wait for the automatic
    cleanup process to complete, preserving the intended MACsec cleanup behavior.

    Args:
        host: SONiC DUT or neighbor host object
        interfaces: List of interface names to check
        timeout: Maximum time to wait in seconds for MACsec cleanup to finish (default: 90).

    Returns:
        bool: True if cleanup completed, False if timeout
    """
    if isinstance(host, EosHost):
        # EOS hosts don't use Redis databases
        logger.info("EOS host detected, skipping Redis cleanup verification")
        return True

    logger.info(f"Waiting for automatic MACsec cleanup (timeout: {timeout}s)")

    start_time = time.time()
    # Poll at most ~10 times over the full timeout, capped at 10 seconds between checks.
    poll_interval = min(10, max(1, timeout / 10.0))

    # We only care about APPL_DB and STATE_DB for MACsec tables. Instead of
    # trying to reverse-engineer numeric DB IDs from CONFIG_DB, rely on
    # sonic-db-cli with logical DB names and the same namespace logic used
    # elsewhere in MACsec helpers.

    while time.time() - start_time < timeout:
        all_clean = True
        remaining_entries = {}

        for interface in interfaces:
            ns_prefix = getns_prefix(host, interface)

            for db_name, sep in (("APPL_DB", ":"), ("STATE_DB", "|")):
                pattern = f"MACSEC_*{sep}{interface}*"
                cmd = f"sonic-db-cli {ns_prefix} {db_name} KEYS '{pattern}'"

                try:
                    result = host.command(cmd, verbose=False)
                    out_lines = result.get("stdout_lines", [])
                except Exception as e:
                    logger.warning(
                        "Failed to query MACsec keys on host %s, DB %s, interface %s: %r",
                        getattr(host, 'hostname', host),
                        db_name,
                        interface,
                        e,
                    )
                    # If we cannot query Redis for this DB/interface, be
                    # conservative and assume cleanup is not complete yet.
                    all_clean = False
                    continue

                keys = [k.strip() for k in out_lines if k.strip()]
                if keys:
                    all_clean = False
                    remaining_entries.setdefault((db_name, interface), []).extend(keys)

        elapsed = time.time() - start_time

        if all_clean:
            logger.info(
                f"Automatic MACsec cleanup completed successfully in {elapsed:.1f}s"
            )
            return True

        # Log progress every 30 seconds to reduce verbosity
        if int(elapsed) % 30 == 0 and elapsed > 0:
            logger.info(f"Still waiting for cleanup... ({elapsed:.0f}s elapsed)")

        time.sleep(poll_interval)

    # Timeout reached
    elapsed = time.time() - start_time
    logger.warning(f"Automatic MACsec cleanup timeout after {elapsed:.1f}s")

    # Log summary of remaining entries
    total_remaining = sum(len(entries) for entries in remaining_entries.values())
    if total_remaining > 0:
        logger.warning(
            f"  {total_remaining} MACsec entries still remain after timeout"
        )

    return False
