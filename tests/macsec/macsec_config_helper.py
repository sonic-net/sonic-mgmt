from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from macsec_helper import *


def set_macsec_profile(host, profile_name, priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci):
    if isinstance(host, EosHost):
        eos_cipher_suite = {
            "GCM-AES-128": "aes128-gcm",
            "GCM-AES-256": "aes256-gcm",
            "GCM-AES-XPN-128": "aes128-gcm-xpn",
            "GCM-AES-XPN-256": "aes256-gcm-xpn"
        }
        host.eos_config(
            lines = [
                'cipher {}'.format(eos_cipher_suite[cipher_suite]),
                'key {} 0 {}'.format(primary_ckn, primary_cak),
                'sci'
                ],
            parents=['mac security', 'profile {}'.format(profile_name)])
        return

    macsec_profile = {
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci": send_sci,
    }
    cmd = "sonic-db-cli CONFIG_DB HMSET 'MACSEC_PROFILE|{}' ".format(
        profile_name)
    for k, v in macsec_profile.items():
        cmd += " '{}' '{}' ".format(k, v)
    host.command(cmd)


def delete_macsec_profile(host, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no profile {}'.format(profile_name)],
            parents=['mac security'])
        return

    cmd = "sonic-db-cli CONFIG_DB DEL 'MACSEC_PROFILE|{}'".format(profile_name)
    host.command(cmd)


def enable_macsec_port(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['mac security profile {}'.format(profile_name)],
            parents=['interface {}'.format(port)])
        return

    cmd = "sonic-db-cli CONFIG_DB HSET 'PORT|{}' 'macsec' '{}'".format(
        port, profile_name)
    host.command(cmd)


def disable_macsec_port(host, port):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no mac security profile'],
            parents=['interface {}'.format(port)])
        return

    cmd = "sonic-db-cli CONFIG_DB HDEL 'PORT|{}' 'macsec'".format(port)
    host.command(cmd)


def cleanup_macsec_configuration(duthost, ctrl_links, profile_name):
    devices = set()
    devices.add(duthost)
    for dut_port, nbr in ctrl_links.items():
        disable_macsec_port(duthost, dut_port)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], profile_name)
        devices.add(nbr["host"])
    delete_macsec_profile(duthost, profile_name)
    # Waiting for all mka session were cleared in all devices
    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda: not get_mka_session(d))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci):
    set_macsec_profile(duthost, profile_name, default_priority,
                       cipher_suite, primary_cak, primary_ckn, policy, send_sci)
    i = 0
    for dut_port, nbr in ctrl_links.items():
        enable_macsec_port(duthost, dut_port, profile_name)
        if i % 2 == 0:
            priority = default_priority - 1
        else:
            priority = default_priority + 1
        set_macsec_profile(nbr["host"], profile_name, priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)
        i += 1


def startup_all_ctrl_links(ctrl_links):
    # The ctrl links may be shutdowned by unexpected exit on the TestFaultHandling
    # So, startup all ctrl links
    for _, nbr in ctrl_links.items():
        if isinstance(nbr["host"], EosHost):
            continue
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])
        nbr["host"].shell("ifconfig {} up".format(nbr_eth_port))
