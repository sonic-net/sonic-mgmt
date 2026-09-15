import ast
import base64
import binascii
import re
import json
import logging
import time
from collections import defaultdict, deque
from multiprocessing import Process

import cryptography.exceptions
import ptf
import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils
import scapy.all as scapy
import scapy.contrib.macsec as scapy_macsec

from tests.common.macsec.macsec_platform_helper import sonic_db_cli
from tests.common.devices.eos import EosHost
from tests.common.utilities import convert_scapy_packet_to_bytes, wait_until

__all__ = [
    'check_wpa_supplicant_process',
    'check_appl_db',
    'check_mka_session',
    'check_macsec_pkt',
    'create_pkt',
    'create_exp_pkt',
    'get_appl_db',
    'get_macsec_attr',
    'prepare_ptf_macsec',
    'program_ptf_ingress_sa',
    'remove_ptf_ingress_sa',
    'remove_ptf_ingress_sas',
    'get_mka_session',
    'get_macsec_sa_name',
    'get_macsec_counters',
    'get_sci',
    'getns_prefix',
    'get_ipnetns_prefix',
]

logger = logging.getLogger(__name__)
process_queue = []

# APPL_DB field marking an ingress SA the test harness programmed for PTF.
PTF_SA_TAG = "ptf_sa"
# (hostname, port) -> (APPL_DB key, sak hex) of the PTF ingress SA this process
# programmed. Ownership is decided by this registry; the tag alone is not
# reliable because ProducerStateTable SETs merge into an existing row, so a
# live MKA SA that later lands on the same AN inherits the tag.
_PTF_SA_KEYS = {}


def submit_async_task(target, args):
    global process_queue
    proc = Process(target=target, args=args)
    process_queue.append(proc)
    proc.start()
    return proc


def wait_all_complete(timeout=300):
    global process_queue
    for proc in process_queue:
        proc.join(timeout)
        # If process timeout, terminate all processes, otherwise the pytest process will never finish.
        if proc.is_alive():
            [p.terminate() for p in process_queue]
            raise RuntimeError("Process {} timeout {}".format(proc, timeout))
    process_queue = []


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


def _port_namespace(host, intf):
    """asic namespace owning ``intf`` ('' on single-ASIC DUTs)."""
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(intf)
        return host.get_namespace_from_asic_id(asic.asic_index)
    return ""


def getns_prefix(host, intf):
    ns = _port_namespace(host, intf)
    return "-n {}".format(ns) if ns else " "


def get_ipnetns_prefix(host, intf):
    ns_prefix = " "
    if host.is_multi_asic:
        asic = host.get_port_asic_instance(intf)
        ns = host.get_namespace_from_asic_id(asic.asic_index)
        ns_prefix = "sudo ip netns exec {}".format(ns)

    return ns_prefix


def get_dict_macsec_counters(duthost, port):  # noqa: F811
    '''
    Queries get_macsec_counter and returns flattened dictionary.
    '''
    egr_counter, ing_counter = get_macsec_counters(duthost, port)
    new_stats = {}
    new_stats[duthost.hostname] = {}
    new_stats[duthost.hostname][port] = egr_counter
    new_stats[duthost.hostname][port].update(ing_counter)

    return (new_stats)


def get_macsec_sa_name(sonic_asic, port_name, egress=True):
    if egress:
        table = 'MACSEC_EGRESS_SA_TABLE'
    else:
        table = 'MACSEC_INGRESS_SA_TABLE'

    cmd = "APPL_DB KEYS '{}:{}:*'".format(table, port_name)
    names = sonic_asic.run_sonic_db_cli_cmd(cmd)['stdout_lines']
    if not egress and names:
        # Never return the PTF SA this process programmed (see _PTF_SA_KEYS); a
        # PTF AN can sort before the live MKA AN. Rows merely tagged ptf_sa are
        # skipped only while an untagged row exists: MKA may have rekeyed onto
        # a PTF AN and inherited the tag, in which case the tagged row IS live.
        owned = _PTF_SA_KEYS.get((sonic_asic.sonichost.hostname, port_name), (None,))[0]
        names = [n for n in names if n != "{}:{}".format(table, owned)]
        ns = "-n {}".format(sonic_asic.namespace) if sonic_asic.namespace else ""
        tags = sonic_asic.sonichost.shell(
            "for k in {}; do echo \"$k=$(sonic-db-cli {} APPL_DB HGET $k {})\"; done; true".format(
                " ".join(names), ns, PTF_SA_TAG), module_ignore_errors=True)["stdout"]
        tagged = {ln.split("=", 1)[0] for ln in tags.splitlines() if ln.endswith("=true")}
        untagged = [n for n in names if n not in tagged]
        names = untagged or names
    if names:
        names.sort()
        return ':'.join(names[0].split(':')[1:])
    return None


def get_appl_db(host, host_port_name, peer, peer_port_name):
    port_table = sonic_db_cli(
        host, QUERY_MACSEC_PORT.format(getns_prefix(host, host_port_name), host_port_name))
    host_sci = get_sci(host.get_dut_iface_mac(host_port_name))
    if isinstance(peer, EosHost):
        re_match = re.search(r'\d+', peer_port_name)
        peer_port_identifer = int(re_match.group())
        peer_sci = get_sci(peer.get_dut_iface_mac(peer_port_name), peer_port_identifer)
    else:
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


def __check_appl_db(duthost, dut_ctrl_port_name, nbrhost, nbr_ctrl_port_name, policy, cipher_suite, send_sci):
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

    # Check MACsec SA Table.  Only the active encoding_an SA needs to be
    # consistent between egress and peer ingress.  Non-encoding ANs may linger
    # in APPL_DB after a dirty container kill (macsecmgrd had no chance to
    # clean them up), while the peer correctly only re-installs the current AN
    # after MKA re-establishes.  Checking all ANs would cause spurious
    # convergence failures in the post-dirty-kill window.
    for egress_sc, egress_sa_table, peer_ingress_sa_table in \
            ((dut_egress_sc_table, dut_egress_sa_table, nbr_ingress_sa_table),
             (nbr_egress_sc_table, nbr_egress_sa_table, dut_ingress_sa_table)):
        encoding_an = int(egress_sc["encoding_an"])
        assert encoding_an in egress_sa_table
        assert encoding_an in peer_ingress_sa_table
        egress_sa = egress_sa_table[encoding_an]
        ingress_sa = peer_ingress_sa_table[encoding_an]
        assert egress_sa["sak"] == ingress_sa["sak"]
        assert egress_sa["auth_key"] == ingress_sa["auth_key"]
        assert egress_sa["next_pn"] >= ingress_sa["lowest_acceptable_pn"]


def check_appl_db(duthost, ctrl_links, policy, cipher_suite, send_sci):
    logger.info("Check appl_db start")
    procs = []
    for port_name, nbr in list(ctrl_links.items()):
        if isinstance(nbr["host"], EosHost):
            assert wait_until(300, 3, 0,
                              lambda: duthost.iface_macsec_ok(port_name) and
                              nbr["host"].iface_macsec_ok(nbr["port"]))
            continue
        proc = submit_async_task(
            __check_appl_db,
            (duthost, port_name, nbr["host"], nbr["port"], policy, cipher_suite, send_sci))
        procs.append(proc)
    wait_all_complete(timeout=180)
    failed = [p.exitcode for p in procs if p.exitcode != 0]
    if failed:
        logger.warning("Check appl_db: %d/%d port pair(s) not yet ready", len(failed), len(procs))
        return False
    logger.info("Check appl_db finished")
    return True


def get_mka_session(host):
    cmd = "docker exec syncd ip -j macsec show"
    '''
    Here is an output example of `ip macsec show`
    admin@vlab-01:~$ ip macsec show
    130: macsec_eth29: protect on validate strict sc off sa off encrypt
    on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 2044, state off, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
        RXSC: 525400b5be690001, state on
            0: PN 1041, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
            3: PN 0, state on, SSCI 16777216, key 0ecddfe0f462491c13400dbf7433465d
    131: macsec_eth30: protect on validate strict sc off sa off encrypt
    on send_sci on end_station off scb off replay off
        cipher suite: GCM-AES-128, using ICV length 16
        TXSC: 52540041303f0001 on SA 0
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279
        RXSC: 525400fb9b220001, state on
            0: PN 1041, state on, key daa8169cde2fe1e238aaa83672e40279

    Here is an output example of `ip -j macsec show` (JSON format), not related to above output:
    admin@vlab-02:~$ ip -j macsec show | jq
    [
      {
        "ifindex": 219,
        "ifname": "macsec_eth1",
        "protect": true,
        "validate": "strict",
        "sc": false,
        "sa": false,
        "encrypt": true,
        "send_sci": true,
        "end_station": false,
        "scb": false,
        "replay": false,
        "cipher_suite": "GCM-AES-128",
        "icv_length": 16,
        "sci": "0x525400953a020001",
        "encoding_sa": 0,
        "sa_list": [
          {
            "an": 0,
            "pn": 153,
            "active": true,
            "key": "18f16ec57c97dcdd5d011d8161de34b5"
          }
        ],
        "rx_sc": [
          {
            "sci": "0x525400a00dc70001",
            "active": true,
            "sa_list": [
              {
                "an": 0,
                "pn": 127,
                "active": true,
                "key": "18f16ec57c97dcdd5d011d8161de34b5"
              }
            ]
          }
        ],
        "offload": "off"
      }
    [
    '''
    output = host.command(cmd)["stdout"]
    ports = json.loads(output)
    mka_session = {}

    for port in ports:
        port_obj = {
            "protect": port["protect"],
            "validate": {
                "mode": port["validate"],
                "sc": port["sc"],
                "sa": port["sa"],
            },
            "encrypt": port["encrypt"],
            "send_sci": port["send_sci"],
            "end_station": port["end_station"],
            "scb": port["scb"],
            "replay": port["replay"],
            "cipher_suite": port["cipher_suite"],
            "ICV_length": port["icv_length"],
            "egress_scs": {
                port["sci"].replace("0x", ""): {
                    "sas": {},
                    "enabled": True,
                    "active_an": port["encoding_sa"]
                }
            },
            "ingress_scs": {},
        }
        for sa in port["sa_list"]:
            sci = port["sci"].replace("0x", "")
            port_obj["egress_scs"][sci]["sas"][sa["an"]] = {}
            port_obj["egress_scs"][sci]["sas"][sa["an"]]["pn"] = sa["pn"]
            port_obj["egress_scs"][sci]["sas"][sa["an"]]["enabled"] = sa["active"]
            port_obj["egress_scs"][sci]["sas"][sa["an"]]["key"] = sa["key"]
        for rx_sc in port["rx_sc"]:
            sci = rx_sc["sci"].replace("0x", "")
            port_obj["ingress_scs"][sci] = {}
            port_obj["ingress_scs"][sci]["enabled"] = rx_sc["active"]
            port_obj["ingress_scs"][sci]["sas"] = {}
            for sa in rx_sc["sa_list"]:
                port_obj["ingress_scs"][sci]["sas"][sa["an"]] = {}
                port_obj["ingress_scs"][sci]["sas"][sa["an"]]["pn"] = sa["pn"]
                port_obj["ingress_scs"][sci]["sas"][sa["an"]]["enabled"] = sa["active"]
                port_obj["ingress_scs"][sci]["sas"][sa["an"]]["key"] = sa["key"]
        mka_session[port["ifname"]] = port_obj
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


def _ingress_sa_rows(host, port):
    """{'<port>:<sci>:<an>': fields} for every APPL_DB ingress SA on ``port`` (one round trip)."""
    ns = getns_prefix(host, port)
    out = host.shell(
        "for k in $(sonic-db-cli {ns} APPL_DB KEYS 'MACSEC_INGRESS_SA_TABLE:{port}:*'); do "
        "echo \"$k\t$(sonic-db-cli {ns} APPL_DB HGETALL $k)\"; done; true".format(ns=ns, port=port),
        module_ignore_errors=True)["stdout"]
    rows = {}
    for line in out.splitlines():
        if not line.startswith("MACSEC_INGRESS_SA_TABLE:") or "\t" not in line:
            continue
        key, fields = line.split("\t", 1)
        try:
            rows[key.split(":", 1)[1]] = ast.literal_eval(fields.strip())
        except (ValueError, SyntaxError):
            continue
    return rows


def _read_macsec_attrs(host, port):
    """Read the live MACsec state of ``port`` from APPL_DB. No side effects."""
    eth_src = host.get_dut_iface_mac(port)
    macsec_port = sonic_db_cli(host, QUERY_MACSEC_PORT.format(getns_prefix(host, port), port))
    encrypt = 1 if macsec_port["enable_encrypt"] == "true" else 0
    send_sci = 1 if macsec_port["send_sci"] == "true" else 0
    xpn_en = "XPN" in macsec_port["cipher_suite"]
    sci_hex = get_sci(eth_src)
    macsec_sc = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SC.format(getns_prefix(host, port), port, sci_hex))
    an = int(macsec_sc["encoding_an"])
    macsec_sa = sonic_db_cli(
        host, QUERY_MACSEC_EGRESS_SA.format(getns_prefix(host, port), port, sci_hex, an))
    sak_hex = macsec_sa["sak"]
    sak = binascii.unhexlify(sak_hex)
    # The salt is a per-SAK value shared by every SA of the CA, so the egress SA
    # is the authoritative source for what PTF encrypts with AND for the PTF
    # ingress SA programmed below; the ingress row only contributes the peer's
    # ssci / auth_key.
    salt_hex = macsec_sa.get("salt", "000000000000000000000000")
    if xpn_en:
        ssci = int(macsec_sa["ssci"])
        salt = binascii.unhexlify(salt_hex)
    else:
        ssci = None
        salt = None

    # Live peer SA: an ingress row that is not the PTF SA this process owns,
    # preferring rows carrying the current SAK (a stale PTF row from an earlier
    # session still holds the pre-rekey SAK) and rows without the PTF tag (a
    # tagged row is still live if MKA rekeyed onto that AN and inherited it).
    rows = _ingress_sa_rows(host, port)
    owned = _PTF_SA_KEYS.get((host.hostname, port), (None,))[0]
    candidates = [(k, r) for k, r in rows.items() if k != owned]
    same_sak = [c for c in candidates if c[1].get("sak") == sak_hex] or candidates
    untagged = [c for c in same_sak if c[1].get(PTF_SA_TAG) != "true"] or same_sak
    if not untagged:
        raise KeyError("no live MACsec ingress SA for {} on {}".format(port, host.hostname))
    live_key, live_row = sorted(untagged)[0]
    _, peer_sci, peer_an = live_key.split(":")
    peer_an = int(peer_an)
    peer_ssci = int(live_row["ssci"]) if xpn_en else None

    # PTF transmits on its own AN, (mka_an + 2) % 4: the MKA AN shares its XPN
    # counter with live peer traffic, so by the time PTF sends, the ASIC's
    # highest PN is already past the pickle value and PTF frames would be
    # dropped as late. A separate AN starts from PN=0 with no competing sender
    # and leaves the MKA SA untouched.
    ptf_an = (peer_an + 2) % 4
    return {
        "encrypt": encrypt, "send_sci": send_sci, "xpn_en": xpn_en,
        "sci": int(sci_hex, 16), "an": an, "sak": sak, "ssci": ssci, "salt": salt,
        "peer_sci": peer_sci, "peer_an": peer_an, "peer_ssci": peer_ssci, "ptf_an": ptf_an,
        "sak_hex": sak_hex, "salt_hex": salt_hex,
        "ssci_str": live_row.get("ssci", "0"), "auth_key": live_row.get("auth_key", sak_hex),
        "live_key": live_key, "clear_tag": live_row.get(PTF_SA_TAG) == "true",
    }


def _attr_tuple(a):
    return (a["encrypt"], a["send_sci"], a["xpn_en"], a["sci"], a["an"], a["sak"],
            a["ssci"], a["salt"], int(a["peer_sci"], 16), a["ptf_an"], a["peer_ssci"], 0)


def get_macsec_attr(host, port):
    """MACsec attributes of ``port`` as the MACSEC_INFO tuple. Read-only: use
    prepare_ptf_macsec() when PTF is going to transmit on the port."""
    return _attr_tuple(_read_macsec_attrs(host, port))


_SWSS_PREAMBLE = (
    "from swsscommon.swsscommon import SonicDBConfig, DBConnector, ProducerStateTable, Table\n"
    "ns = '{ns}'\n"
    # Namespaced redis is reached via unix socket and needs the global db config;
    # the default namespace keeps the plain TCP connection.
    "if ns and not SonicDBConfig.isGlobalInit():\n"
    "    SonicDBConfig.load_sonic_global_db_config()\n"
    "db = DBConnector('APPL_DB', 0, False, ns) if ns else DBConnector('APPL_DB', 0, True)\n"
    "tbl = ProducerStateTable(db, 'MACSEC_INGRESS_SA_TABLE')\n"
    "rt = Table(db, 'MACSEC_INGRESS_SA_TABLE')\n"
)


def _run_swss_script(host, ns, body, **shell_kwargs):
    """Run ``body`` on the DUT after _SWSS_PREAMBLE (sonic-db-cli HSET would
    write the row without notifying orchagent; ProducerStateTable does)."""
    script = _SWSS_PREAMBLE.format(ns=ns) + body
    b64 = base64.b64encode(script.encode()).decode()
    return host.shell("echo '{}' | base64 -d | sudo python3".format(b64), **shell_kwargs)


def program_ptf_ingress_sa(host, port, attrs):
    """Install the DUT ingress SA that accepts PTF's frames on ``port``.

    ``attrs`` is the dict from _read_macsec_attrs(). The SA is keyed on the
    peer SCI at PTF's AN, tagged ptf_sa=true, and carries the SAK's salt plus
    the peer's ssci / auth_key: XPN cipher suites derive the AES-GCM IV from
    (ssci || PN) XOR salt, so mismatched values would fail every ICV check.
    The key is recorded in _PTF_SA_KEYS so later reads and the teardown
    recognise it by identity rather than by tag.
    """
    key = "{}:{}:{}".format(port, attrs["peer_sci"], attrs["ptf_an"])
    prev = _PTF_SA_KEYS.get((host.hostname, port), (None,))[0]
    body = (
        "key, live, prev = '{key}', '{live}', '{prev}'\n"
        # A live MKA row that inherited the tag by landing on an old PTF AN.
        "if {clear_tag}:\n"
        "    rt.hdel(live, '{tag}')\n"
        # Our previous key (MKA rekeyed since) and cross-session tagged orphans
        # on this port; never the live SA, never the key being (re)programmed.
        "victims = set()\n"
        "if prev and prev not in (key, live):\n"
        "    victims.add(prev)\n"
        "for k in rt.getKeys():\n"
        "    if k.startswith('{port}:') and k not in (key, live):\n"
        "        ok, fvs = rt.get(k)\n"
        "        if ok and dict(fvs).get('{tag}') == 'true':\n"
        "            victims.add(k)\n"
        "for k in victims:\n"
        "    tbl.delete(k)\n"
        # A SET on an existing SA reaches orchagent as one SET (ConsumerStateTable
        # folds a preceding DEL into it); MACsecOrch recreates the SAI SA when
        # the SET carries 'sak', which resets its highest-received PN for the
        # fresh PN=1.. sequence PTF starts with.
        "fvs = [('active','true'),('sak','{sak}'),('auth_key','{auth}'),"
        "('lowest_acceptable_pn','1'),('ssci','{ssci}'),('salt','{salt}'),('{tag}','true')]\n"
        "tbl.set(key, fvs)\n"
        "print('PTF SA set:', key, 'removed:', sorted(victims))\n"
    ).format(key=key, live=attrs["live_key"], prev=prev or "", clear_tag=attrs["clear_tag"],
             port=port, tag=PTF_SA_TAG, sak=attrs["sak_hex"], auth=attrs["auth_key"],
             ssci=attrs["ssci_str"], salt=attrs["salt_hex"])
    _run_swss_script(host, _port_namespace(host, port), body)
    _PTF_SA_KEYS[(host.hostname, port)] = (key, attrs["sak_hex"])
    time.sleep(2)  # let orchagent program the SA in the ASIC


def remove_ptf_ingress_sas(host, ports=None):
    """Delete the PTF ingress SAs this process programmed on ``host`` (all
    ports, or only ``ports``). A registered key is left alone when its row no
    longer holds the SAK we wrote or is the only SA on the port: both mean MKA
    has taken that AN over and the row is the live peer SA."""
    owned = {p: v for (h, p), v in _PTF_SA_KEYS.items()
             if h == host.hostname and (ports is None or p in ports)}
    by_ns = {}
    for port, (key, sak_hex) in owned.items():
        by_ns.setdefault(_port_namespace(host, port), []).append((port, key, sak_hex))
    for ns, entries in by_ns.items():
        body = "entries = {!r}\n".format(entries) + (
            "for port, key, sak in entries:\n"
            "    ok, fvs = rt.get(key)\n"
            "    if not ok:\n"
            "        continue\n"
            "    others = [k for k in rt.getKeys() if k.startswith(port + ':') and k != key]\n"
            "    if dict(fvs).get('sak') != sak or not others:\n"
            "        print('PTF SA now live, kept:', key)\n"
            "        continue\n"
            "    tbl.delete(key)\n"
            "    print('PTF SA removed:', key)\n"
        )
        _run_swss_script(host, ns, body, module_ignore_errors=True)
    for port in owned:
        _PTF_SA_KEYS.pop((host.hostname, port), None)


def remove_ptf_ingress_sa(host, port):
    """Delete the PTF ingress SA this process programmed on one ``port``."""
    remove_ptf_ingress_sas(host, ports=[port])


def prepare_ptf_macsec(host, port):
    """Read ``port``'s MACsec attributes and program the DUT ingress SA PTF
    will transmit on. Returns the MACSEC_INFO tuple."""
    attrs = _read_macsec_attrs(host, port)
    program_ptf_ingress_sa(host, port, attrs)
    return _attr_tuple(attrs)


def encap_macsec_pkt(macsec_pkt, sci, an, sak, encrypt, send_sci, pn, xpn_en=False, ssci=None, salt=None):
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
    macsec_pkt = sa.encap(macsec_pkt)
    pkt = sa.encrypt(macsec_pkt)
    return pkt


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
        return macsec_pkt, False
    pkt = sa.decap(pkt)
    return convert_scapy_packet_to_bytes(pkt), True


def check_macsec_pkt(test, ptf_port_id, exp_pkt, timeout=3):
    device, ptf_port = testutils.port_to_tuple(ptf_port_id)
    ret = testutils.dp_poll(
        test, device_number=device, port_number=ptf_port, timeout=timeout, exp_pkt=exp_pkt)
    if isinstance(ret, test.dataplane.PollSuccess):
        return
    else:
        return ret.format()


def find_portname_from_ptf_id(mg_facts, ptf_id):
    for k, v in list(mg_facts["minigraph_ptf_indices"].items()):
        if ptf_id == v:
            return k
    return None


def load_macsec_info(duthost, port, force_reload=None):
    if force_reload or port not in __macsec_infos:
        __macsec_infos[port] = prepare_ptf_macsec(duthost, port)
    return __macsec_infos[port]


def load_macsec_info_for_ptf_id(duthost, ptf_id, port, force_reload=None):
    if force_reload:
        MACSEC_INFO[ptf_id] = prepare_ptf_macsec(duthost, port)


# This API load the macsec session details from all ctrl links
def load_all_macsec_info(duthost, ctrl_links, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for port, nbr in ctrl_links.items():
        ptf_id = mg_facts["minigraph_ptf_indices"][port]
        MACSEC_INFO[ptf_id] = prepare_ptf_macsec(duthost, port)


def macsec_send(test, port_id, pkt, count=1):
    # Check if the port is macsec enabled, if so send the macsec encap/encrypted frame
    device, port_number = testutils.port_to_tuple(port_id)
    if port_number in MACSEC_INFO and MACSEC_INFO[port_number]:
        encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = MACSEC_INFO[port_number]

        if port_number not in MACSEC_PORT_NEXT_PN:
            MACSEC_PORT_NEXT_PN[port_number] = pn + 1

        for n in range(count):
            if isinstance(pkt, bytes):
                # If in bytes, convert it to an Ether packet
                pkt = scapy.Ether(pkt)

            send_pn = MACSEC_PORT_NEXT_PN[port_number]
            MACSEC_PORT_NEXT_PN[port_number] += 1

            macsec_pkt = encap_macsec_pkt(
                pkt, peer_sci, peer_an, sak, encrypt, send_sci, send_pn,
                xpn_en, peer_ssci, salt,
            )
            # send the packet
            __origin_send_packet(test, port_id, macsec_pkt, 1)
    else:
        # send the packet
        __origin_send_packet(test, port_id, pkt, count)


def macsec_dp_poll(test, device_number=0, port_number=None, timeout=None, exp_pkt=None):
    recent_packets = deque(maxlen=test.dataplane.POLL_MAX_RECENT_PACKETS)
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
        # Since we call __origin_dp_poll with exp_pkt=None, it should only ever fail if no packets are received at all.
        # In this case, continue normally
        # until we exceed the timeout value provided to macsec_dp_poll.
        if isinstance(ret, test.dataplane.PollFailure):
            if timeout <= 0:
                break
            else:
                continue
        # The device number of PTF host is 0, if the target port isn't a injected port(belong to ptf host),
        # Don't need to do MACsec further.
        if ret.device != 0:
            return ret
        pkt = scapy.Ether(ret.packet)
        if pkt.haslayer(scapy.Ether):
            if pkt[scapy.Ether].type != 0x88e5:
                if exp_pkt is None or ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                    return ret
            else:
                if ret.port in MACSEC_INFO and MACSEC_INFO[ret.port]:
                    # Reload the macsec session if the session was restarted
                    if force_reload[ret.port]:
                        load_macsec_info_for_ptf_id(
                            test.duthost, ret.port, find_portname_from_ptf_id(test.mg_facts, ret.port),
                            force_reload[ret.port])
                    encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = \
                        MACSEC_INFO[ret.port]
                    force_reload[ret.port] = False
                    pkt, decap_success = decap_macsec_pkt(pkt, sci, an, sak, encrypt, send_sci, 0, xpn_en, ssci, salt)
                    if exp_pkt is None or decap_success and ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                        # Here we explicitly create the PollSuccess struct and send the pkt which us decoded
                        # and the caller test can validate the pkt fields. Without this fix in case of macsec
                        # the encrypted packet is being send back to caller which it will not be able to dissect
                        return test.dataplane.PollSuccess(ret.device, ret.port, pkt, exp_pkt, time.time())
        # Normally, if __origin_dp_poll returns a PollFailure, the PollFailure object will contain a list of
        # recently received packets to help with debugging. However, since we call __origin_dp_poll multiple times,
        # only the packets from the most recent call is retained. If we don't find a matching packet (either with or
        # without MACsec decoding), we need to manually store the packet we received. Later if we return a PollFailure,
        # we can provide the received packets to emulate the behavior of __origin_dp_poll.
        recent_packets.append(pkt)
        packet_count += 1
        if timeout <= 0:
            break
    return test.dataplane.PollFailure(exp_pkt, recent_packets, packet_count)


def _parse_show_macsec_counters(text):
    '''
    This function takes the output of a show macsec <interface> command, and returns a dict
    of the counters.
    Returns following dict format:
    {
        'egress': {<dict of counters>},
        'ingress': {<dict of counters>}
    }
    TODO: enhance show macsec command to output in json directly

    Here is an example of `show macsec Ethernet216`
    MACsec port(Ethernet216)
    ---------------------  ---------------
    cipher_suite           GCM-AES-XPN-256
    enable                 true
    enable_encrypt         true
    enable_protect         true
    enable_replay_protect  false
    profile                MACSEC_PROFILE
    replay_window          0
    send_sci               true
    ---------------------  ---------------
            MACsec Egress SC (XXX)
            -----------  -
            encoding_an  1
            -----------  -
            MACsec Egress SA (1)
            -------------------------------------  ----------------------------------------------------------------
            auth_key                               XXX
            next_pn                                1
            sak                                    XXX
            salt                                   XXX
            ssci                                   2
            SAI_MACSEC_SA_ATTR_CURRENT_XPN         8
            SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED    28532
            SAI_MACSEC_SA_STAT_OCTETS_PROTECTED    0
            SAI_MACSEC_SA_STAT_OUT_PKTS_ENCRYPTED  7
            SAI_MACSEC_SA_STAT_OUT_PKTS_PROTECTED  0
            -------------------------------------  ----------------------------------------------------------------
            MACsec Ingress SC (XXX)

            MACsec Ingress SA (1)
            ---------------------------------------  ----------------------------------------------------------------
            active                                   true
            auth_key                                 XXX
            lowest_acceptable_pn                     1
            sak                                      XXX
            salt                                     XXX
            ssci                                     1
            SAI_MACSEC_SA_ATTR_CURRENT_XPN           6661
            SAI_MACSEC_SA_STAT_IN_PKTS_DELAYED       0
            SAI_MACSEC_SA_STAT_IN_PKTS_INVALID       0
            SAI_MACSEC_SA_STAT_IN_PKTS_LATE          0
            SAI_MACSEC_SA_STAT_IN_PKTS_NOT_USING_SA  1
            SAI_MACSEC_SA_STAT_IN_PKTS_NOT_VALID     0
            SAI_MACSEC_SA_STAT_IN_PKTS_OK            8
            SAI_MACSEC_SA_STAT_IN_PKTS_UNCHECKED     0
            SAI_MACSEC_SA_STAT_IN_PKTS_UNUSED_SA     0
            SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED      523517
            SAI_MACSEC_SA_STAT_OCTETS_PROTECTED      0
            ---------------------------------------  ----------------------------------------------------------------
    '''
    out = {'egress': {}, 'ingress': {}}
    stats = None
    reg = re.compile(r'(SAI_MACSEC.*?) *(\d+)')
    for line in text.splitlines():
        line = line.strip()

        # Found the egress header, following stats will be for egress
        if line.startswith("MACsec Egress SA"):
            stats = 'egress'
            continue
        # Found the ingress header, following stats will be for ingress
        elif line.startswith("MACsec Ingress SA"):
            stats = 'ingress'
            continue
        # No header yet, so no stats coming
        if not stats:
            continue

        found = reg.match(line)
        if found:
            out[stats].update({found.group(1): int(found.group(2))})
    return out


def get_macsec_counters(duthost, port):
    cmd = f"show macsec {port}"
    output = duthost.command(cmd)["stdout"]

    out_dict = _parse_show_macsec_counters(output)

    return (out_dict['egress'], out_dict['ingress'])


def clear_macsec_counters(duthost):
    assert duthost.command("sonic-clear macsec")["failed"] is False


__origin_dp_poll = testutils.dp_poll
__origin_send_packet = testutils.send_packet
__macsec_infos = defaultdict(lambda: None)
MACSEC_INFO = defaultdict(lambda: None)
# Per-port next PN to send. Initialized to pn_at_pickle+1 on first use so PTF frames are
# always just ahead of the real peer, rather than a shared global that grows by 100 per
# send and inflates highest_PN on the ASIC far beyond the peer's actual position.
MACSEC_PORT_NEXT_PN = {}
testutils.dp_poll = macsec_dp_poll
testutils.send_packet = macsec_send
