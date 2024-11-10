import logging
import time

from tests.common.macsec.macsec_helper import get_mka_session, getns_prefix, wait_all_complete, submit_async_task
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
    'disable_macsec_port'
]

logger = logging.getLogger(__name__)


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

    logger.info("Cleanup macsec configuration finished")

    # Waiting for all mka session were cleared in all devices
    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period):
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
