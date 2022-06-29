from collections import defaultdict
import struct
import binascii
import time
import re
import ast

import cryptography.exceptions
import ptf
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import scapy.all as scapy
import scapy.contrib.macsec as scapy_macsec

from macsec_common_helper import convert_on_off_to_boolean
from macsec_platform_helper import sonic_db_cli


__all__ = [
    'check_wpa_supplicant_process',
    'check_appl_db',
    'check_mka_session',
    'check_macsec_pkt',
    'create_pkt',
    'create_exp_pkt',
    'get_appl_db',
    'get_macsec_attr',
    'get_mka_session',
    'get_macsec_sa_name',
    'get_macsec_counters',
    'get_sci'
]


def check_wpa_supplicant_process(host, ctrl_port_name):
    cmd = "ps aux | grep -w 'wpa_supplicant' | grep -w '{}' | grep -v 'grep'".format(
        ctrl_port_name)
    output = host.shell(cmd)["stdout_lines"]
    assert len(output) == 1, "The wpa_supplicant for the port {} wasn't started on the host {}".format(
        host, ctrl_port_name)


def get_sci(macaddress, port_identifer=1):
    system_identifier = macaddress.replace(":", "").replace("-", "")
    sci = "{}{}".format(
        system_identifier,
        str(port_identifer).zfill(4))
    return sci


QUERY_MACSEC_PORT = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_PORT_TABLE:{}'"

QUERY_MACSEC_INGRESS_SC = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_INGRESS_SC_TABLE:{}:{}'"

QUERY_MACSEC_EGRESS_SC = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_EGRESS_SC_TABLE:{}:{}'"

QUERY_MACSEC_INGRESS_SA = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_INGRESS_SA_TABLE:{}:{}:{}'"

QUERY_MACSEC_EGRESS_SA = "sonic-db-cli {} APPL_DB HGETALL 'MACSEC_EGRESS_SA_TABLE:{}:{}:{}'"


def getns_prefix(host, intf):
    ns_prefix = " "
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(intf)
        ns = host.get_namespace_from_asic_id(asic.asic_index)
        ns_prefix = "-n {}".format(ns)

    return ns_prefix

def get_macsec_sa_name(sonic_asic, port_name, egress = True):
    if egress:
        table = 'MACSEC_EGRESS_SA_TABLE'
    else:
        table = 'MACSEC_INGRESS_SA_TABLE'

    cmd = "APPL_DB KEYS '{}:{}:*'".format(table, port_name)
    names = sonic_asic.run_sonic_db_cli_cmd(cmd)['stdout_lines']
    if names:
        names.sort()
        return ':'.join(names[0].split(':')[1:])
    return None


def get_appl_db(host, host_port_name, peer, peer_port_name):
    port_table = sonic_db_cli(
        host, QUERY_MACSEC_PORT.format(getns_prefix(host, host_port_name), host_port_name))
    host_sci = get_sci(host.get_dut_iface_mac(host_port_name))
    peer_sci = get_sci(peer.get_dut_iface_mac(peer_port_name))
    egress_sc_table = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SC.format(getns_prefix(host, host_port_name), host_port_name, host_sci))
    ingress_sc_table = sonic_db_cli(
        host, QUERY_MACSEC_INGRESS_SC.format(getns_prefix(host, host_port_name), host_port_name, peer_sci))
    egress_sa_table = {}
    ingress_sa_table = {}
    for an in range(4):
        sa_table = sonic_db_cli(host, QUERY_MACSEC_EGRESS_SA.format(
            getns_prefix(host, host_port_name), host_port_name, host_sci, an))
        if sa_table:
            egress_sa_table[an] = sa_table
        sa_table = sonic_db_cli(host, QUERY_MACSEC_INGRESS_SA.format(
            getns_prefix(host, host_port_name), host_port_name, peer_sci, an))
        if sa_table:
            ingress_sa_table[an] = sa_table
    return port_table, egress_sc_table, ingress_sc_table, egress_sa_table, ingress_sa_table


def check_appl_db(duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name, policy, cipher_suite, send_sci):
    # Check MACsec port table
    dut_port_table, dut_egress_sc_table, dut_ingress_sc_table, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
        duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name)
    nbr_port_table, nbr_egress_sc_table, nbr_ingress_sc_table, nbr_egress_sa_table, nbr_ingress_sa_table = get_appl_db(
        nbrhost, nbr_ctrl_port_name, duthost, dut_ctrl_port_name)
    assert dut_port_table and nbr_port_table
    for port_table in (dut_port_table, nbr_port_table):
        assert port_table["enable"] == "true"
        assert port_table["cipher_suite"] == cipher_suite
        assert port_table["enable_protect"] == "true"
        if policy == "security":
            assert port_table["enable_encrypt"] == "true"
        else:
            assert port_table["enable_encrypt"] == "false"
        assert port_table["send_sci"] == send_sci

    # Check MACsec SC table
    assert dut_ingress_sc_table and nbr_ingress_sc_table
    assert dut_egress_sc_table and nbr_egress_sc_table

    # CHeck MACsec SA Table
    assert int(dut_egress_sc_table["encoding_an"]) in dut_egress_sa_table
    assert int(nbr_egress_sc_table["encoding_an"]) in nbr_egress_sa_table
    assert len(dut_ingress_sa_table) >= len(nbr_egress_sa_table)
    assert len(nbr_ingress_sa_table) >= len(dut_egress_sa_table)
    for egress_sas, ingress_sas in \
            ((dut_egress_sa_table, nbr_ingress_sa_table), (nbr_egress_sa_table, dut_ingress_sa_table)):
        for an, sa in egress_sas.items():
            assert an in ingress_sas
            assert sa["sak"] == ingress_sas[an]["sak"]
            assert sa["auth_key"] == ingress_sas[an]["auth_key"]
            assert sa["next_pn"] >= ingress_sas[an]["lowest_acceptable_pn"]


def get_mka_session(host):
    cmd = "docker exec syncd ip macsec show"
    '''
    Here is an output example of `ip macsec show`
    admin@vlab-01:~$ ip macsec show
    130: macsec_eth29: protect on validate strict sc off sa off encrypt on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 2044, state off, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
        RXSC: 525400b5be690001, state on
            0: PN 1041, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 0, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
    131: macsec_eth30: protect on validate strict sc off sa off encrypt on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279
        RXSC: 525400fb9b220001, state on
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279
    '''
    output = host.command(cmd)["stdout_lines"]
    output = "\n".join(output)
    mka_session = {}

    port_pattern = r"(\d+): (\w+): protect (on|off) validate (disabled|checked|strict) sc (on|off) sa (on|off) encrypt (on|off) send_sci (on|off) end_station (on|off) scb (on|off) replay (on|off)\s*\n +cipher suite: ([\w-]+), using ICV length (\d+)\n?((?: +[\w:, ]+\n?)*)"
    ports = re.finditer(port_pattern, output)
    for port in ports:
        port_obj = {
            "protect": port.group(3),
            "validate": {
                "mode": port.group(4),
                "sc": port.group(5),
                "sa": port.group(6),
            },
            "encrypt": port.group(7),
            "send_sci": port.group(8),
            "end_station": port.group(9),
            "scb": port.group(10),
            "replay": port.group(11),
            "cipher_suite": port.group(12),
            "ICV_length": int(port.group(13)),
            "egress_scs": {},
            "ingress_scs": {},
        }
        sc_pattern = r" +(TXSC|RXSC): ([\da-fA-F]+),? (?:(on|off) SA ([0-3])|state (on|off))\n?((?: {8}[\w:, ]+\n?)*)"
        scs = re.finditer(sc_pattern, port.group(14))
        for sc in scs:
            sc_obj = {
                "sas": {}
            }
            sa_pattern = r" +([0-3]): PN (\d+), state (on|off),.* key ([\da-fA-F]+)"
            sas = re.finditer(sa_pattern, sc.group(6))
            for sa in sas:
                sa_obj = {
                    "pn": int(sa.group(2)),
                    "enabled": sa.group(3),
                    "key": sa.group(4)
                }
                sc_obj["sas"][int(sa.group(1))] = sa_obj
            if sc.group(1) == "TXSC":
                sc_obj["enabled"] = sc.group(3)
                sc_obj["active_an"] = int(sc.group(4))
                port_obj["egress_scs"][sc.group(2)] = sc_obj
            elif sc.group(1) == "RXSC":
                sc_obj["enabled"] = sc.group(5)
                port_obj["ingress_scs"][sc.group(2)] = sc_obj
        # Convert on|off to boolean
        port_obj = convert_on_off_to_boolean(port_obj)
        mka_session[port.group(2)] = port_obj
    return mka_session


def check_mka_sc(egress_sc, ingress_sc):
    assert egress_sc["enabled"]
    assert ingress_sc["enabled"]
    active_an = egress_sc["active_an"]
    assert active_an in egress_sc["sas"]
    assert active_an in ingress_sc["sas"]
    assert egress_sc["sas"][active_an]["enabled"]
    assert ingress_sc["sas"][active_an]["enabled"]
    assert egress_sc["sas"][active_an]["key"] == ingress_sc["sas"][active_an]["key"]


def check_mka_session(dut_mka_session, dut_sci, nbr_mka_session, nbr_sci, policy, cipher_suite, send_sci):
    assert dut_mka_session["protect"]
    assert nbr_mka_session["protect"]
    if policy == "security":
        assert dut_mka_session["encrypt"]
        assert nbr_mka_session["encrypt"]
    else:
        assert not dut_mka_session["encrypt"]
        assert not nbr_mka_session["encrypt"]
    if send_sci == "true":
        assert dut_mka_session["send_sci"]
        assert nbr_mka_session["send_sci"]
    else:
        assert not dut_mka_session["send_sci"]
        assert not nbr_mka_session["send_sci"]
    assert dut_mka_session["cipher_suite"] == cipher_suite
    assert nbr_mka_session["cipher_suite"] == cipher_suite
    assert dut_sci in nbr_mka_session["ingress_scs"]
    assert dut_sci in dut_mka_session["egress_scs"]
    assert nbr_sci in dut_mka_session["ingress_scs"]
    assert nbr_sci in nbr_mka_session["egress_scs"]
    check_mka_sc(dut_mka_session["egress_scs"][dut_sci],
                 nbr_mka_session["ingress_scs"][dut_sci])
    check_mka_sc(nbr_mka_session["egress_scs"][nbr_sci],
                 dut_mka_session["ingress_scs"][nbr_sci])


def create_pkt(eth_src, eth_dst, ip_src, ip_dst, payload=None):
    pkt = testutils.simple_ipv4ip_packet(
        eth_src=eth_src, eth_dst=eth_dst, ip_src=ip_src, ip_dst=ip_dst, inner_frame=payload)
    return pkt


def create_exp_pkt(pkt, ttl):
    exp_pkt = pkt.copy()
    exp_pkt[scapy.IP].ttl = ttl
    exp_pkt = mask.Mask(exp_pkt, ignore_extra_bytes=True)
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
    return exp_pkt


def get_macsec_attr(host, port):
    eth_src = host.get_dut_iface_mac(port)
    macsec_port = sonic_db_cli(host, QUERY_MACSEC_PORT.format(getns_prefix(host, port), port))
    if macsec_port["enable_encrypt"] == "true":
        encrypt = 1
    else:
        encrypt = 0
    if macsec_port["send_sci"] == "true":
        send_sci = 1
    else:
        send_sci = 0
    xpn_en = "XPN" in macsec_port["cipher_suite"]
    sci = get_sci(eth_src)
    macsec_sc = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SC.format(getns_prefix(host, port), port, sci))
    an = int(macsec_sc["encoding_an"])
    macsec_sa = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SA.format(getns_prefix(host, port), port, sci, an))
    sak = binascii.unhexlify(macsec_sa["sak"])
    sci = int(get_sci(eth_src), 16)
    if xpn_en:
        ssci = struct.pack('!I', int(macsec_sa["ssci"]))
        salt = binascii.unhexlify(macsec_sa["salt"])
    else:
        ssci = None
        salt = None
    return encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt


def decap_macsec_pkt(macsec_pkt, sci, an, sak, encrypt, send_sci, pn, xpn_en=False, ssci=None, salt=None):
    sa = scapy_macsec.MACsecSA(sci=sci,
                               an=an,
                               pn=pn,
                               key=sak,
                               icvlen=16,
                               encrypt=encrypt,
                               send_sci=send_sci,
                               xpn_en=xpn_en,
                               ssci=ssci,
                               salt=salt)
    try:
        pkt = sa.decrypt(macsec_pkt)
    except cryptography.exceptions.InvalidTag:
        # Invalid MACsec packets
        return None
    pkt = sa.decap(pkt)
    return pkt


def check_macsec_pkt(test, ptf_port_id, exp_pkt, timeout=3):
    device, ptf_port = testutils.port_to_tuple(ptf_port_id)
    ret = testutils.dp_poll(
        test, device_number=device, port_number=ptf_port, timeout=timeout, exp_pkt=exp_pkt)
    if isinstance(ret, test.dataplane.PollSuccess):
        return
    else:
        return ret.format()


def find_portname_from_ptf_id(mg_facts, ptf_id):
    for k, v in mg_facts["minigraph_ptf_indices"].items():
        if ptf_id == v:
            return k
    return None


def load_macsec_info(duthost, port, force_reload = None):
    if force_reload  or port not in __macsec_infos:
        __macsec_infos[port] = get_macsec_attr(duthost, port)
    return __macsec_infos[port]


def macsec_dp_poll(test, device_number=0, port_number=None, timeout=None, exp_pkt=None):
    recent_packets = []
    packet_count = 0
    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    force_reload = defaultdict(lambda: False)
    if hasattr(test, "force_reload_macsec"):
        force_reload = defaultdict(lambda: test.force_reload_macsec)
    while True:
        start_time = time.time()
        ret = __origin_dp_poll(
            test, device_number=device_number, port_number=port_number, timeout=timeout, exp_pkt=None)
        timeout -= time.time() - start_time
        # The device number of PTF host is 0, if the target port isn't a injected port(belong to ptf host), Don't need to do MACsec further.
        if ret.device != 0 \
            or isinstance(ret, test.dataplane.PollFailure) \
                or exp_pkt is None:
            return ret
        pkt = scapy.Ether(ret.packet)
        if pkt[scapy.Ether].type != 0x88e5:
            if ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
            else:
                continue
        macsec_info = load_macsec_info(test.duthost, find_portname_from_ptf_id(test.mg_facts, ret.port), force_reload[ret.port])
        if macsec_info:
            encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt = macsec_info
            force_reload[ret.port] = False
            pkt = decap_macsec_pkt(pkt, sci, an, sak, encrypt,
                                send_sci, 0, xpn_en, ssci, salt)
            if pkt is not None and ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
        recent_packets.append(pkt)
        packet_count += 1
        if timeout <= 0:
            break
    return test.dataplane.PollFailure(exp_pkt, recent_packets,packet_count)


def get_macsec_counters(sonic_asic, name):
    lines = [
        'from swsscommon.swsscommon import DBConnector, CounterTable, MacsecCounter',
        'counterTable = CounterTable(DBConnector("COUNTERS_DB", 0))',
        '_, values = counterTable.get(MacsecCounter(), "{}")'.format(name),
        'print(dict(values))'
        ]
    cmd = "python -c '{}'".format(';'.join(lines))
    output = sonic_asic.command(cmd)["stdout_lines"][0]
    return {k:int(v) for k,v in ast.literal_eval(output).items()}


__origin_dp_poll = testutils.dp_poll
__macsec_infos = defaultdict(lambda: None)
testutils.dp_poll = macsec_dp_poll

