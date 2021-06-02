import pytest
import logging
import time
import ast
import struct
import re

# import ptf.testutils as testutils
# import ptf.mask as mask
# import ptf.packet as packet

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0"),
]


def set_macsec_profile(host, profile_name, priority, cipher_suite, primary_cak, primary_ckn, policy):
    macsec_profile = {
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
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
    for nbr in ctrl_links:
        disable_macsec_port(duthost, nbr["dut_ctrl_port"])
        disable_macsec_port(nbr["host"], nbr["host_ctrl_port"])
        delete_macsec_profile(nbr["host"], profile_name)
    delete_macsec_profile(duthost, profile_name)


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy):
    set_macsec_profile(duthost, profile_name, default_priority,
                       cipher_suite, primary_cak, primary_ckn, policy)
    for nbr in ctrl_links:
        enable_macsec_port(duthost, nbr["dut_ctrl_port"], profile_name)
        set_macsec_profile(nbr["host"], profile_name, default_priority,
                           cipher_suite, primary_cak, primary_ckn, policy)
        enable_macsec_port(nbr["host"], nbr["host_ctrl_port"], profile_name)


@pytest.fixture(scope="module", autouse=True)
def setup(duthost, ctrl_links, profile_name, default_priority, cipher_suite,
          primary_cak, primary_ckn, policy, enable_macsec_feature, cleanup_portchannel, request):
    cleanup_macsec_configuration(duthost, ctrl_links, profile_name)
    time.sleep(30)
    setup_macsec_configuration(duthost, ctrl_links, profile_name,
                               default_priority, cipher_suite, primary_cak, primary_ckn, policy)
    logger.info("Setup MACsec configuration with arguments:\n{}".format(locals()))
    time.sleep(120)
    yield
    if request.session.testsfailed > 0:
        return
    cleanup_macsec_configuration(duthost, ctrl_links, profile_name)
    time.sleep(30)


def check_wpa_supplicant_process(host, ctrl_port_name):
    cmd = "ps aux | grep 'wpa_supplicant' | grep '{}' | grep -v 'grep'".format(
        ctrl_port_name)
    output = host.shell(cmd)["stdout_lines"]
    pytest_assert(len(output) == 1, "The wpa_supplicant for the port {} wasn't started on the host {}".format(
        host, ctrl_port_name))


def get_macaddress(host, port_name):
    cmd = "cat /sys/class/net/{}/address".format(port_name)
    return host.command(cmd)["stdout_lines"][0]


def get_sci(macaddress, port_identifer = 1, order = "network"):
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


def check_appl_db(duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name, policy, cipher_suite):
    # Check MACsec port table
    cmd = "sonic-db-cli APPL_DB HGETALL 'MACSEC_PORT_TABLE:{}'"
    dut_port_table = sonic_db_cli(duthost, cmd.format(dut_ctrl_port_name))
    nbr_port_table = sonic_db_cli(nbrhost, cmd.format(nbr_ctrl_port_name))
    assert dut_port_table and nbr_port_table
    for port_table in (dut_port_table, nbr_port_table):
        assert port_table["enable"] == "true"
        assert port_table["cipher_suite"] == cipher_suite
        assert port_table["enable_protect"] == "true"
        if policy == "security":
            assert port_table["enable_encrypt"] == "true"
        else:
            assert port_table["enable_encrypt"] == "false"

    # Check MACsec SC table
    dut_sci = get_sci(get_macaddress(duthost, dut_ctrl_port_name))
    nbr_sci = get_sci(get_macaddress(nbrhost, nbr_ctrl_port_name))
    cmd = "sonic-db-cli APPL_DB HGETALL 'MACSEC_INGRESS_SC_TABLE:{}:{}'"
    dut_ingress_sc_table = sonic_db_cli(
        duthost, cmd.format(dut_ctrl_port_name, nbr_sci))
    nbr_ingress_sc_table = sonic_db_cli(
        nbrhost, cmd.format(nbr_ctrl_port_name, dut_sci))
    assert dut_ingress_sc_table and nbr_ingress_sc_table
    cmd = "sonic-db-cli APPL_DB HGETALL 'MACSEC_EGRESS_SC_TABLE:{}:{}'"
    dut_egress_sc_table = sonic_db_cli(
        duthost, cmd.format(dut_ctrl_port_name, dut_sci))
    nbr_egress_sc_table = sonic_db_cli(
        nbrhost, cmd.format(nbr_ctrl_port_name, nbr_sci))
    assert dut_egress_sc_table and nbr_egress_sc_table

    # CHeck MACsec SA Table
    cmd = "sonic-db-cli APPL_DB HGETALL 'MACSEC_INGRESS_SA_TABLE:{}:{}:{}'"
    dut_ingress_sa_table = {}
    nbr_ingress_sa_table = {}
    for an in range(4):
        sa_table = sonic_db_cli(duthost, cmd.format(dut_ctrl_port_name, nbr_sci, an))
        if sa_table:
            dut_ingress_sa_table[an] = sa_table
        sa_table = sonic_db_cli(nbrhost, cmd.format(nbr_ctrl_port_name, dut_sci, an))
        if sa_table:
            nbr_ingress_sa_table[an] = sa_table
    cmd = "sonic-db-cli APPL_DB HGETALL 'MACSEC_EGRESS_SA_TABLE:{}:{}:{}'"
    dut_egress_sa_table = {}
    nbr_egress_sa_table = {}
    for an in range(4):
        sa_table = sonic_db_cli(duthost, cmd.format(dut_ctrl_port_name, dut_sci, an))
        if sa_table:
            dut_egress_sa_table[an] = sa_table
        sa_table = sonic_db_cli(nbrhost, cmd.format(nbr_ctrl_port_name, nbr_sci, an))
        if sa_table:
            nbr_egress_sa_table[an] = sa_table
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
    cmd = "ip macsec show"
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


def get_macsec_infname(host, port_name):
    cmd = "ls /sys/class/net/"
    output = host.command(cmd)["stdout_lines"]
    ports = {
        "Ethernet": [],
        "eth": [],
        "macsec": [],
    }
    for type in ports.keys():
        ports[type] = [port.decode("utf-8") for port in output if port.startswith(type)]
        ports[type].sort(key = lambda no: int(re.search(r'\d+', no).group(0)))
    # Remove the eth0
    ports["eth"].pop(0)
    assert port_name in ports["Ethernet"]
    eth_port = ports["eth"][ports["Ethernet"].index(port_name)]
    macsec_infname = "macsec_"+eth_port
    assert macsec_infname in ports["macsec"]
    return macsec_infname


def check_mka_sc(egress_sc, ingress_sc):
    assert egress_sc["enabled"]
    assert ingress_sc["enabled"]
    active_an = egress_sc["active_an"]
    assert active_an in egress_sc["sas"]
    assert active_an in ingress_sc["sas"]
    assert egress_sc["sas"][active_an]["enabled"]
    assert ingress_sc["sas"][active_an]["enabled"]
    assert egress_sc["sas"][active_an]["key"] == ingress_sc["sas"][active_an]["key"]


def check_mka_session(dut_mka_session, dut_sci, nbr_mka_session, nbr_sci, policy, cipher_suite):
    assert dut_mka_session["protect"]
    assert nbr_mka_session["protect"]
    if policy == "security":
        assert dut_mka_session["encrypt"]
        assert nbr_mka_session["encrypt"]
    else:
        assert not dut_mka_session["encrypt"]
        assert not nbr_mka_session["encrypt"]
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
        for nbr in ctrl_links:
            check_wpa_supplicant_process(duthost, nbr["dut_ctrl_port"])
            check_wpa_supplicant_process(nbr["host"], nbr["host_ctrl_port"])

    def test_appl_db(self, duthost, ctrl_links, policy, cipher_suite):
        for nbr in ctrl_links:
            check_appl_db(duthost, nbr["dut_ctrl_port"], nbr["host"],
                        nbr["host_ctrl_port"], policy, cipher_suite)

    def test_mka_session(self, duthost, ctrl_links, policy, cipher_suite):
        dut_mka_session = get_mka_session(duthost)
        assert len(dut_mka_session) == len(ctrl_links)
        for nbr in ctrl_links:
            nbr_mka_session = get_mka_session(nbr["host"])
            dut_macsec_port = get_macsec_infname(duthost, nbr["dut_ctrl_port"])
            nbr_macsec_port = get_macsec_infname(nbr["host"], nbr["host_ctrl_port"])
            dut_macaddress = get_macaddress(duthost, nbr["dut_ctrl_port"])
            nbr_macaddress = get_macaddress(nbr["host"], nbr["host_ctrl_port"])
            dut_sci = get_sci(dut_macaddress, order="host")
            nbr_sci = get_sci(nbr_macaddress, order="host")
            check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                            nbr_mka_session[nbr_macsec_port], nbr_sci,
                            policy, cipher_suite)


# class TestDataPlane():
#     def test_pkt(self, duthost, tbinfo, ptfadapter):
#         downstream_ports = defaultdict(list)
#         downstream_port_ids = []
#         mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
#         topo = tbinfo["topo"]["type"]
#         logging.info("mg_facts")
#         for interface, neighbor in mg_facts["minigraph_neighbors"].items():
#             port_id = mg_facts["minigraph_ptf_indices"][interface]
#             # if (topo == "t1" and "T0" in neighbor["name"]) or (topo == "t0" and "Server" in neighbor["name"]):
#             if  neighbor["name"] == "ARISTA01T1":
#                 downstream_ports[neighbor['namespace']].append(interface)
#                 downstream_port_ids.append(port_id)

#         # pkt = testutils.simple_tcp_packet(
#         #     eth_dst="52:54:00:41:30:3f",
#         #     eth_src="52:54:00:b5:be:69",
#         #     ip_dst="10.0.0.57",
#         #     ip_src="10.0.0.56",
#         #     tcp_sport=4321,
#         #     tcp_dport=1234,
#         #     ip_ttl=64
#         # )
#         pkt = testutils.simple_icmp_packet(
#             eth_dst="52:54:00:41:30:3f",
#             eth_src="52:54:00:b5:be:69",
#             ip_dst="10.0.1.56",
#             ip_src="10.0.1.57",
#             icmp_type=8,
#             icmp_code=0,
#             ip_ttl = 64,
#         )
#         exp_pkt = pkt.copy()
#         exp_pkt = mask.Mask(exp_pkt, ignore_extra_bytes=True)
#         exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
#         exp_pkt.set_do_not_care_scapy(packet.Ether, "src")
#         exp_pkt.set_do_not_care(14*8, (3*16 - 2)*8)
#         exp_pkt.mask = [0x00] * exp_pkt.size
#         exp_pkt.mask[12] = 0xff
#         exp_pkt.mask[13] = 0xff
#         logging.info(ptfadapter.dataplane)
#         ptfadapter.dataplane.flush()
#         import threading
#         import time
#         def run_send():
#             time.sleep(1)
#             testutils.send(ptfadapter, downstream_port_ids[0], pkt, 10)
#         t = threading.Thread(target=run_send)
#         t.start()
#         testutils.send(ptfadapter, downstream_port_ids[0], pkt)
#         result = testutils.verify_packet_any_port(ptfadapter)
#         testutils.send(ptfadapter, downstream_port_ids[0], pkt)
#         testutils.verify_packet(ptfadapter, exp_pkt, port_id=downstream_port_ids[0])
#         t.join()
#         i = 10
#         while True:
#             (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(
#                 ptfadapter, port_number=downstream_port_ids[0], exp_pkt=exp_pkt)
#             # if not rcv_device or not rcv_port or not rcv_pkt or not pkt_time or i == 0:
#             #     break
#             if i == 0:
#                 break
#             i -= 1
#             logging.info((rcv_device, rcv_port, rcv_pkt, pkt_time))



