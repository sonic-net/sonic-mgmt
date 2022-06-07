import time
from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from macsec_platform_helper import global_cmd
from macsec_helper import get_mka_session, getns_prefix


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


def set_macsec_profile(host, port, profile_name, priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period = 0):
    if isinstance(host, EosHost):
        eos_cipher_suite = {
            "GCM-AES-128": "aes128-gcm",
            "GCM-AES-256": "aes256-gcm",
            "GCM-AES-XPN-128": "aes128-gcm-xpn",
            "GCM-AES-XPN-256": "aes256-gcm-xpn"
        }
        lines = [
            'cipher {}'.format(eos_cipher_suite[cipher_suite]),
            'key {} 0 {}'.format(primary_ckn, primary_cak),
            'mka key-server priority {}'.format(priority)
            ]
        if send_sci == 'true':
            lines.append('sci')
        host.eos_config(
            lines = lines,
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
    for k, v in macsec_profile.items():
        cmd += " '{}' '{}' ".format(k, v)
    host.command(cmd)
    if send_sci == "false":
        # The MAC address of SONiC host is locally administrated
        # So, LLDPd will use an arbitrary fixed value (00:60:08:69:97:ef) as the source MAC address of LLDP packet (https://lldpd.github.io/usage.html)
        # But the MACsec driver in Linux used by SONiC VM has a bug that cannot handle the packet with different source MAC address to SCI if the send_sci = false
        # So, if send_sci = false and the neighbor device is SONiC VM, LLDPd need to use the real MAC address as the source MAC address
        host.command("lldpcli configure system bond-slave-src-mac-type real")


def delete_macsec_profile(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no profile {}'.format(profile_name)],
            parents=['mac security'])
        return

    cmd = "sonic-db-cli {} CONFIG_DB DEL 'MACSEC_PROFILE|{}'".format(getns_prefix(host, port), profile_name)
    host.command(cmd)


def enable_macsec_port(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['mac security profile {}'.format(profile_name)],
            parents=['interface {}'.format(port)])
        return

    cmd = "sonic-db-cli {} CONFIG_DB HSET 'PORT|{}' 'macsec' '{}'".format(
        getns_prefix(host, port), port, profile_name)
    host.command(cmd)


def disable_macsec_port(host, port):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no mac security profile'],
            parents=['interface {}'.format(port)])
        return

    cmd = "sonic-db-cli {} CONFIG_DB HDEL 'PORT|{}' 'macsec'".format(getns_prefix(host, port), port)
    host.command(cmd)


def enable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = macsec_nbrhosts
    num_asics = duthost.num_asics()
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")

    def check_macsec_enabled():
        if len(duthost.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < num_asics:
            return False
        if len(duthost.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < num_asics:
            return False
        for nbr in [n["host"] for n in nbrhosts.values()]:
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
    for dut_port, nbr in ctrl_links.items():
        disable_macsec_port(duthost, dut_port)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], nbr["port"], profile_name)
        devices.add(nbr["host"])
        delete_macsec_profile(duthost, dut_port, profile_name)
    # Waiting for all mka session were cleared in all devices
    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period):
    i = 0
    for dut_port, nbr in ctrl_links.items():
        set_macsec_profile(duthost, dut_port, profile_name, default_priority,
                       cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period)
        enable_macsec_port(duthost, dut_port, profile_name)
        if i % 2 == 0:
            priority = default_priority - 1
        else:
            priority = default_priority + 1
        set_macsec_profile(nbr["host"], nbr["port"], profile_name, priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)
        wait_until(20, 3, 0,
                   lambda: duthost.iface_macsec_ok(dut_port) and
                           nbr["host"].iface_macsec_ok(nbr["port"]))
        i += 1

    # Enabling macsec may cause link flap, which impacts LACP, BGP, etc
    # protocols. To hold some time for protocol recovery.
    time.sleep(60)
