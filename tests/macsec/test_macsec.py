import logging
import time
import ast
import struct
import re
import binascii
import sys
import cryptography.exceptions

import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import scapy.all as scapy
import scapy.contrib.macsec as scapy_macsec

from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0"),
]


def set_macsec_profile(host, profile_name, priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci):
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
    cmd = "sonic-db-cli CONFIG_DB DEL 'MACSEC_PROFILE|{}'".format(profile_name)
    host.command(cmd)


def enable_macsec_port(host, port, profile_name):
    cmd = "sonic-db-cli CONFIG_DB HSET 'PORT|{}' 'macsec' '{}'".format(
        port, profile_name)
    host.command(cmd)


def disable_macsec_port(host, port):
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
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])
        nbr["host"].shell("ifconfig {} up".format(nbr_eth_port))


@pytest.fixture(scope="module", autouse=True)
def setup(duthost, ctrl_links, unctrl_links, enable_macsec_feature, profile_name, default_priority, cipher_suite,
          primary_cak, primary_ckn, policy, send_sci, request):
    if request.session.testsfailed > 0:
        return
    all_links = {}
    all_links.update(ctrl_links)
    all_links.update(unctrl_links)
    startup_all_ctrl_links(ctrl_links)
    cleanup_macsec_configuration(duthost, all_links, profile_name)
    setup_macsec_configuration(duthost, ctrl_links, profile_name,
                               default_priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci)
    logger.info(
        "Setup MACsec configuration with arguments:\n{}".format(locals()))
    yield
    if request.session.testsfailed > 0:
        return
    cleanup_macsec_configuration(duthost, all_links, profile_name)


def check_wpa_supplicant_process(host, ctrl_port_name):
    cmd = "ps aux | grep 'wpa_supplicant' | grep '{}' | grep -v 'grep'".format(
        ctrl_port_name)
    output = host.shell(cmd)["stdout_lines"]
    assert len(output) == 1, "The wpa_supplicant for the port {} wasn't started on the host {}".format(
        host, ctrl_port_name)


def get_sci(macaddress, port_identifer=1, order="network"):
    assert order in ("host", "network")
    system_identifier = macaddress.replace(":", "").replace("-", "")
    sci = "{}{}".format(
        system_identifier,
        str(port_identifer).zfill(4))
    if order == "host":
        return sci
    sci = int(sci, 16)
    if sys.byteorder == "little":
        sci = struct.pack(">Q", sci)
        sci = struct.unpack("<Q", sci)[0]
    return str(sci)


def sonic_db_cli(host, cmd):
    return ast.literal_eval(host.shell(cmd)["stdout_lines"][0])


QUERY_MACSEC_PORT = "sonic-db-cli APPL_DB HGETALL 'MACSEC_PORT_TABLE:{}'"

QUERY_MACSEC_INGRESS_SC = "sonic-db-cli APPL_DB HGETALL 'MACSEC_INGRESS_SC_TABLE:{}:{}'"

QUERY_MACSEC_EGRESS_SC = "sonic-db-cli APPL_DB HGETALL 'MACSEC_EGRESS_SC_TABLE:{}:{}'"

QUERY_MACSEC_INGRESS_SA = "sonic-db-cli APPL_DB HGETALL 'MACSEC_INGRESS_SA_TABLE:{}:{}:{}'"

QUERY_MACSEC_EGRESS_SA = "sonic-db-cli APPL_DB HGETALL 'MACSEC_EGRESS_SA_TABLE:{}:{}:{}'"


def get_appl_db(host, host_port_name, peer, peer_port_name):
    port_table = sonic_db_cli(
        host, QUERY_MACSEC_PORT.format(host_port_name))
    host_sci = get_sci(host.get_dut_iface_mac(host_port_name))
    peer_sci = get_sci(peer.get_dut_iface_mac(peer_port_name))
    egress_sc_table = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SC.format(host_port_name, host_sci))
    ingress_sc_table = sonic_db_cli(
        host, QUERY_MACSEC_INGRESS_SC.format(host_port_name, peer_sci))
    egress_sa_table = {}
    ingress_sa_table = {}
    for an in range(4):
        sa_table = sonic_db_cli(host, QUERY_MACSEC_EGRESS_SA.format(
            host_port_name, host_sci, an))
        if sa_table:
            egress_sa_table[an] = sa_table
        sa_table = sonic_db_cli(host, QUERY_MACSEC_INGRESS_SA.format(
            host_port_name, peer_sci, an))
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


def convert_on_off_to_boolean(obj):
    for k, v in obj.items():
        if v == "on":
            obj[k] = True
        elif v == "off":
            obj[k] = False
        elif isinstance(v, dict):
            obj[k] = convert_on_off_to_boolean(v)
    return obj


def get_mka_session(host):
    cmd = "docker exec syncd ip macsec show"
    '''
    Here is an output example of `ip macsec show`
    admin@vlab-01:~$ ip macsec show
    130: macsec_eth29: protect on validate strict sc off sa off encrypt on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 2044, state off, key 0ecddfe0f462491c13400dbf7433465d
        RXSC: 525400b5be690001, state on
            0: PN 1041, state on, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 0, state on, key 0ecddfe0f462491c13400dbf7433465d
    131: macsec_eth30: protect on validate strict sc off sa off encrypt on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279
        RXSC: 525400fb9b220001, state on
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279
    '''
    output = host.command(cmd)["stdout_lines"]
    output = "\n".join(output)
    logging.info(output)
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
            sa_pattern = r" +([0-3]): PN (\d+), state (on|off), key ([\da-fA-F]+)"
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


def get_all_ifnames(host):
    cmd = "ls /sys/class/net/"
    output = host.command(cmd)["stdout_lines"]
    ports = {
        "Ethernet": [],
        "eth": [],
        "macsec": [],
    }
    for type in ports.keys():
        ports[type] = [port.decode("utf-8")
                       for port in output if port.startswith(type)]
        ports[type].sort(key=lambda no: int(re.search(r'\d+', no).group(0)))
    # Remove the eth0
    ports["eth"].pop(0)
    return ports


def get_eth_ifname(host, port_name):
    if u"x86_64-kvm_x86_64" not in get_platform(host):
        logging.info("Can only get the eth ifname on the virtual SONiC switch")
        return None
    ports = get_all_ifnames(host)
    assert port_name in ports["Ethernet"]
    return ports["eth"][ports["Ethernet"].index(port_name)]


def get_macsec_ifname(host, port_name):
    if u"x86_64-kvm_x86_64" not in get_platform(host):
        logging.info(
            "Can only get the macsec ifname on the virtual SONiC switch")
        return None
    ports = get_all_ifnames(host)
    assert port_name in ports["Ethernet"]
    eth_port = ports["eth"][ports["Ethernet"].index(port_name)]
    macsec_infname = "macsec_"+eth_port
    assert macsec_infname in ports["macsec"]
    return macsec_infname


def get_platform(host):
    for line in host.command("show platform summary")["stdout_lines"]:
        if "Platform" == line.split(":")[0]:
            return line.split(":")[1].strip()
    pytest.fail("No platform was found.")


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


class TestControlPlane():
    def test_wpa_supplicant_processes(self, duthost, ctrl_links):
        def _test_wpa_supplicant_processes():
            for port_name, nbr in ctrl_links.items():
                check_wpa_supplicant_process(duthost, port_name)
                check_wpa_supplicant_process(nbr["host"], nbr["port"])
            return True
        assert wait_until(300, 1, 1, _test_wpa_supplicant_processes)

    def test_appl_db(self, duthost, ctrl_links, policy, cipher_suite, send_sci):
        def _test_appl_db():
            for port_name, nbr in ctrl_links.items():
                check_appl_db(duthost, port_name, nbr["host"],
                              nbr["port"], policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 6, 12, _test_appl_db)

    def test_mka_session(self, duthost, ctrl_links, policy, cipher_suite, send_sci):
        def _test_mka_session():
            # If the DUT isn't a virtual switch that cannot support "get mka session" by "ip macsec show"
            # So, skip this test for physical switch
            # TODO: Support "get mka session" in the physical switch
            if u"x86_64-kvm_x86_64" not in get_platform(duthost):
                logging.info(
                    "Skip to check mka session due to the DUT isn't a virtual switch")
                return True
            dut_mka_session = get_mka_session(duthost)
            assert len(dut_mka_session) == len(ctrl_links)
            for port_name, nbr in ctrl_links.items():
                nbr_mka_session = get_mka_session(nbr["host"])
                dut_macsec_port = get_macsec_ifname(duthost, port_name)
                nbr_macsec_port = get_macsec_ifname(
                    nbr["host"], nbr["port"])
                dut_macaddress = duthost.get_dut_iface_mac(port_name)
                nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
                dut_sci = get_sci(dut_macaddress, order="host")
                nbr_sci = get_sci(nbr_macaddress, order="host")
                check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                                  nbr_mka_session[nbr_macsec_port], nbr_sci,
                                  policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 1, 1, _test_mka_session)


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
    macsec_port = sonic_db_cli(host, QUERY_MACSEC_PORT.format(port))
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
        host, QUERY_MACSEC_EGRESS_SC.format(port, sci))
    an = int(macsec_sc["encoding_an"])
    macsec_sa = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SA.format(port, sci, an))
    sak = binascii.unhexlify(macsec_sa["sak"])
    sci = int(get_sci(eth_src, order="host"), 16)
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


def check_macsec_pkt(macsec_attr, test, ptf_port_id, exp_pkt, timeout=3):
    device, ptf_port = testutils.port_to_tuple(ptf_port_id)
    received_packets = []
    encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt = macsec_attr
    end_time = time.time() + timeout
    while True:
        cur_time = time.time()
        if cur_time > end_time:
            break
        ret = testutils.dp_poll(
            test, device_number=device, port_number=ptf_port, timeout=end_time - cur_time, exp_pkt=None)
        if isinstance(ret, test.dataplane.PollFailure):
            break
        # If the packet isn't MACsec type
        pkt = scapy.Ether(ret.packet)
        if pkt[scapy.Ether].type != 0x88e5:
            continue
        received_packets.append(pkt)
    for i in range(len(received_packets)):
        pkt = received_packets[i]
        pn = 0
        pkt = decap_macsec_pkt(pkt, sci, an, sak, encrypt,
                               send_sci, pn, xpn_en, ssci, salt)
        if not pkt:
            continue
        received_packets[i] = pkt
        if exp_pkt.pkt_match(pkt):
            return
    fail_message = "Expect pkt \n{}\n{}\nBut received \n".format(
        exp_pkt, exp_pkt.exp_pkt.show(dump=True))
    for packet in received_packets:
        fail_message += "\n{}\n".format(packet.show(dump=True))
    pytest.fail(fail_message)


class TestDataPlane():
    BATCH_COUNT = 100

    def test_server_to_neighbor(self, duthost, ctrl_links, downstream_links, upstream_links, nbr_device_numbers, nbr_ptfadapter):
        nbr_ptfadapter.dataplane.set_qlen(TestDataPlane.BATCH_COUNT * 10)
        down_port, down_link = downstream_links.items()[0]
        for ctrl_port in ctrl_links.keys():
            up_link = upstream_links[ctrl_port]
            dut_macaddress = duthost.get_dut_iface_mac(ctrl_port)
            payload = "{} -> {}".format(down_link["name"], up_link["name"])
            logging.info(payload)
            # Source mac address is not useful in this test case and we use an arbitrary mac address as the source
            pkt = create_pkt(
                "00:01:02:03:04:05", dut_macaddress, "1.2.3.4", up_link["ipv4_addr"], bytes(payload))
            exp_pkt = create_exp_pkt(pkt, pkt[scapy.IP].ttl - 1)
            testutils.send_packet(
                nbr_ptfadapter, down_link["ptf_port_id"], pkt, TestDataPlane.BATCH_COUNT)
            nbr_ctrl_port_id = int(
                re.search(r"(\d+)", ctrl_links[ctrl_port]["port"]).group(1))
            testutils.verify_packet(nbr_ptfadapter, exp_pkt, port_id=(
                nbr_device_numbers[up_link["name"]], nbr_ctrl_port_id))
            macsec_attr = get_macsec_attr(duthost, ctrl_port)
            testutils.send_packet(
                nbr_ptfadapter, down_link["ptf_port_id"], pkt, TestDataPlane.BATCH_COUNT)
            check_macsec_pkt(macsec_attr=macsec_attr, test=nbr_ptfadapter,
                             ptf_port_id=up_link["ptf_port_id"],  exp_pkt=exp_pkt, timeout=10)

    def test_neighbor_to_neighbor(self, duthost, ctrl_links, upstream_links, nbr_device_numbers, nbr_ptfadapter):
        for ctrl_port, nbr in ctrl_links.items():
            for up_port, up_link in upstream_links.items():
                if up_port == ctrl_port:
                    continue
                ctrl_link = upstream_links[ctrl_port]
                dut_macaddress = duthost.get_dut_iface_mac(ctrl_port)
                nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
                payload = "{} -> {}".format(ctrl_link["name"], up_link["name"])
                logging.info(payload)
                pkt = create_pkt(
                    nbr_macaddress, dut_macaddress, ctrl_link["ipv4_addr"], up_link["ipv4_addr"], bytes(payload))
                nbr_ctrl_port_id = int(
                    re.search(r"(\d+)", ctrl_links[ctrl_port]["port"]).group(1))
                testutils.send_packet(
                    nbr_ptfadapter, (nbr_device_numbers[ctrl_link["name"]], nbr_ctrl_port_id), pkt, TestDataPlane.BATCH_COUNT)
                exp_pkt = create_exp_pkt(pkt, pkt[scapy.IP].ttl - 1)
                nbr_up_port_id = int(
                    re.search(r"(\d+)", upstream_links[up_port]["port"]).group(1))
                testutils.verify_packet(nbr_ptfadapter, exp_pkt, port_id=(
                    nbr_device_numbers[up_link["name"]], nbr_up_port_id))


def get_portchannel(host):
    '''
        Here is an output example of `show interfaces portchannel`
        admin@sonic:~$ show interfaces portchannel
        Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
            S - selected, D - deselected, * - not synced
        No.  Team Dev         Protocol     Ports
        -----  ---------------  -----------  ---------------------------
        0001  PortChannel0001  LACP(A)(Up)  Ethernet112(S) Ethernet108(D)
        0002  PortChannel0002  LACP(A)(Up)  Ethernet116(S)
        0003  PortChannel0003  LACP(A)(Up)  Ethernet120(S)
        0004  PortChannel0004  LACP(A)(Up)  N/A
    '''
    lines = host.command("show interfaces portchannel")["stdout_lines"]
    lines = lines[4:]  # Remove the output header
    portchannel_list = {}
    for line in lines:
        items = line.split()
        portchannel = items[1]
        portchannel_list[portchannel] = {"status": None, "members": []}
        if items[-1] == "N/A":
            continue
        portchannel_list[portchannel]["status"] = re.search(
            r"\((Up|Dw)\)", items[2]).group(1)
        for item in items[3:]:
            port = re.search(r"(Ethernet.*)\(", item).group(1)
            portchannel_list[portchannel]["members"].append(port)
    return portchannel_list


def find_portchannel_from_member(port_name, portchannel_list):
    for k, v in portchannel_list.items():
        if port_name in v["members"]:
            return v
    return None


class TestFaultHandling():
    MKA_TIMEOUT = 6
    LACP_TIMEOUT = 90

    def test_link_flap(self, duthost, ctrl_links):
        # Only pick one link for link flap test
        assert ctrl_links
        port_name, nbr = ctrl_links.items()[0]

        _, _, _, dut_egress_sa_table_orig, dut_ingress_sa_table_orig = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])

        # Flap < 6 seconds
        nbr["host"].shell("ifconfig {} down && sleep 1 && ifconfig {} up".format(
            nbr_eth_port, nbr_eth_port))
        _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        assert dut_egress_sa_table_orig == dut_egress_sa_table_new
        assert dut_ingress_sa_table_orig == dut_ingress_sa_table_new

        # Flap > 6 seconds but < 90 seconds
        nbr["host"].shell("ifconfig {} down && sleep {} && ifconfig {} up".format(
            nbr_eth_port, TestFaultHandling.MKA_TIMEOUT, nbr_eth_port))
        def check_new_mka_session():
            _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
            assert dut_egress_sa_table_new
            assert dut_ingress_sa_table_new
            assert dut_egress_sa_table_orig != dut_egress_sa_table_new
            assert dut_ingress_sa_table_orig != dut_ingress_sa_table_new
            return True
        assert wait_until(12, 1, 0, check_new_mka_session)

        # Flap > 90 seconds
        pc = find_portchannel_from_member(
            port_name, get_portchannel(duthost))
        assert pc["status"] == "Up"
        nbr["host"].shell("ifconfig {} down && sleep {}".format(
            nbr_eth_port, TestFaultHandling.LACP_TIMEOUT))
        assert wait_until(6, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Dw")
        nbr["host"].shell("ifconfig {} up".format(nbr_eth_port))
        pc = find_portchannel_from_member(
            port_name, get_portchannel(duthost))
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up")

    def test_mismatch_macsec_configuration(self, duthost, unctrl_links,
                                           profile_name, default_priority, cipher_suite,
                                           primary_cak, primary_ckn, policy, send_sci, request):
        # Only pick one uncontrolled link for mismatch macsec configuration test
        assert unctrl_links
        port_name, nbr = unctrl_links.items()[0]

        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], profile_name)

        # Set a wrong cak to the profile
        primary_cak = "0" * len(primary_cak)
        enable_macsec_port(duthost, port_name, profile_name)
        set_macsec_profile(nbr["host"], profile_name, default_priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)

        def check_mka_establishment():
            _, _, dut_ingress_sc_table, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            return dut_ingress_sc_table or dut_egress_sa_table or dut_ingress_sa_table
        # The mka should be establishing or established
        # To check whether the MKA establishment happened within 90 seconds
        assert not wait_until(90, 1, 12, check_mka_establishment)

        # Teardown
        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], profile_name)
