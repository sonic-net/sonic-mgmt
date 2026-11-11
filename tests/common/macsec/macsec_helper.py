import ast
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
    'forget_macsec_ports',
    'get_macsec_port_states',
    'prepare_ptf_macsec',
    'prime_macsec_info',
    'refresh_macsec_info',
    'get_mka_session',
    'get_macsec_sa_name',
    'get_macsec_counters',
    'get_macsec_ingress_sa_counters',
    'get_sci',
    'getns_prefix',
    'get_ipnetns_prefix',
]

logger = logging.getLogger(__name__)
process_queue = []

# hostname -> {port: ptf index} loaded by prime_macsec_info(), so
# refresh_macsec_info() can re-read them without tbinfo.
_PRIMED_PORTS = {}
# PTF ports macsec_dp_poll has already warned about failing to decrypt.
_DECRYPT_WARNED = set()


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
    # is the authoritative source; the ingress row only contributes the peer's
    # ssci.
    salt_hex = macsec_sa.get("salt", "000000000000000000000000")
    if xpn_en:
        ssci = int(macsec_sa["ssci"])
        salt = binascii.unhexlify(salt_hex)
    else:
        ssci = None
        salt = None

    # Live peer SA: prefer rows carrying the current SAK (a row from before a
    # rekey still holds the old SAK).
    rows = _ingress_sa_rows(host, port)
    candidates = list(rows.items())
    same_sak = [c for c in candidates if c[1].get("sak") == sak_hex] or candidates
    if not same_sak:
        raise KeyError("no live MACsec ingress SA for {} on {}".format(port, host.hostname))
    live_key, live_row = sorted(same_sak)[0]
    _, peer_sci, peer_an = live_key.split(":")
    peer_an = int(peer_an)
    peer_ssci = int(live_row["ssci"]) if xpn_en else None

    # PTF transmits on the neighbour's AN. The topology runs without replay
    # protection, so the DUT accepts PTF's PNs wherever they interleave with
    # the neighbour's; PTF starts at the SA's current PN + 1 only because PN 0
    # is reserved and the XPN upper half is recovered from the SA's counter.
    ptf_an = peer_an
    return {
        "encrypt": encrypt, "send_sci": send_sci, "xpn_en": xpn_en,
        "sci": int(sci_hex, 16), "an": an, "sak": sak, "ssci": ssci, "salt": salt,
        "peer_sci": peer_sci, "peer_an": peer_an, "peer_ssci": peer_ssci, "ptf_an": ptf_an,
        "sak_hex": sak_hex, "salt_hex": salt_hex, "live_key": live_key,
        "peer_active": live_row.get("active"),
    }


def _attr_tuple(a):
    return (a["encrypt"], a["send_sci"], a["xpn_en"], a["sci"], a["an"], a["sak"],
            a["ssci"], a["salt"], int(a["peer_sci"], 16), a["ptf_an"], a["peer_ssci"], 0)


def get_macsec_attr(host, port):
    """MACsec attributes of ``port`` as the MACSEC_INFO tuple. Read-only: use
    prepare_ptf_macsec() when PTF is going to transmit on the port."""
    return _attr_tuple(_read_macsec_attrs(host, port))


class MacsecReplayProtectionOn(RuntimeError):
    """The ASIC still checks replay on a MACsec port, so PTF cannot share the neighbour's SA."""


class MacsecStateInvalid(RuntimeError):
    """The DUT's MACsec tables describe a session the ASIC is not running on ``port``."""

    def __init__(self, port, reason):
        super().__init__("{}: {}".format(port, reason))
        self.port = port
        self.reason = reason


# (hostname, port) -> (CURRENT_XPN of the peer SA, time read), the first
# liveness sample; ports whose XPN was seen moving this session.
_XPN_SAMPLES = {}
_LIVE_PORTS = set()
# CURRENT_XPN is polled into COUNTERS_DB every second (MACSEC_STAT_XPN_POLLING_INTERVAL_MS).
_LIVENESS_GAP = 3


def _namespace_macsec_state(host, ns):
    """One round trip over namespace ``ns``: every MACsec SC and SA in ASIC_DB
    and every ingress SA row in APPL_DB, as ({sc oid: fields}, {sc oid: {an}},
    {peer sci: {an}}). The APPL_DB ANs are those orchagent creates SAI SAs
    for: active=true rows.
    ASIC_DB does not tie an SC to its port; callers match on direction and SCI."""
    out = host.shell(
        "for t in SC SA; do "
        "for k in $(sonic-db-cli {ns} ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_MACSEC_$t:*\"); do "
        "echo \"$t\t${{k##*:MACSEC_$t:}}\t$(sonic-db-cli {ns} ASIC_DB HGETALL \"$k\")\"; "
        "done; done; "
        "for k in $(sonic-db-cli {ns} APPL_DB KEYS 'MACSEC_INGRESS_SA_TABLE:*'); do "
        "echo \"APPL\t${{k#MACSEC_INGRESS_SA_TABLE:}}\t$(sonic-db-cli {ns} APPL_DB HGETALL \"$k\")\"; "
        "done; true".format(ns=ns),
        module_ignore_errors=True)["stdout"]
    scs, sas, appl_ans = {}, {}, {}
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        try:
            fields = ast.literal_eval(parts[2].strip())
        except (ValueError, SyntaxError):
            continue
        # SAs reference their SC by bare "oid:0x..."; key the SCs the same way
        # whether or not the shell stripped the ASIC_STATE prefix.
        if parts[0] == "SC":
            scs[parts[1][parts[1].rfind("oid:"):]] = fields
        elif parts[0] == "SA" and str(fields.get("SAI_MACSEC_SA_ATTR_AN", "")).isdigit():
            sas.setdefault(fields.get("SAI_MACSEC_SA_ATTR_SC_ID"), set()).add(int(fields["SAI_MACSEC_SA_ATTR_AN"]))
        elif parts[0] == "APPL" and parts[1].count(":") == 2:
            _, sci, an = parts[1].split(":")
            if an.isdigit() and fields.get("active") == "true":
                appl_ans.setdefault(sci, set()).add(int(an))
    return scs, sas, appl_ans


def _check_asic_state(host, port, attrs, state):
    """Raise unless the ASIC runs the peer SC the way PTF needs: replay
    protection off (PTF shares the neighbour's SA, and with strict replay
    checking its frames and then the neighbour's are dropped as late; the
    profile's setting reaches the ASIC only with an orchagent that forwards
    it, sonic-net/sonic-swss#5037) and every ingress SA APPL_DB lists present.
    A macsec container that died without deleting its rows leaves APPL_DB
    describing SAs the ASIC never got (the SAK is create-only in SAI); the SAK
    is masked in ASIC_DB, so the AN set is the comparable signal.

    The check is per peer SCI, not per port: a vSONiC/cSONiC neighbour uses
    one MAC and port id 1 on all its links, so LAG members to the same VM
    share the SCI and the SC. The APPL_DB side is the union over every port
    with that peer SCI; the per-port signal is the STATE_DB SA state in
    _check_macsec_state. Extra ASIC ANs are allowed: an SA delete reaches the
    ASIC asynchronously."""
    scs, sas, appl_ans = state
    # orchagent hands SAI the SCI in network byte order (MACsecSCI keeps the
    # wire bytes), so ASIC_DB shows the byte-swapped integer.
    sci = str(int.from_bytes(binascii.unhexlify(attrs["peer_sci"]), "little"))
    sc_oids = [oid for oid, f in scs.items()
               if f.get("SAI_MACSEC_SC_ATTR_MACSEC_DIRECTION") == "SAI_MACSEC_DIRECTION_INGRESS"
               and f.get("SAI_MACSEC_SC_ATTR_MACSEC_SCI") == sci]
    if not sc_oids:
        raise MacsecStateInvalid(port, "ASIC_DB has no ingress SC for peer SCI {}".format(attrs["peer_sci"]))
    replay = {scs[oid].get("SAI_MACSEC_SC_ATTR_MACSEC_REPLAY_PROTECTION_ENABLE", "absent") for oid in sc_oids}
    if replay != {"false"}:
        raise MacsecReplayProtectionOn(
            "replay protection attribute absent in ASIC_DB (image without sonic-net/sonic-swss#5037) or set "
            "to true ({}) on the ingress SC of {} on {}; PTF cannot share the neighbour's SA.".format(
                ",".join(sorted(replay)), port, host.hostname))
    asic_ans = set().union(*(sas.get(oid, set()) for oid in sc_oids))
    missing = (appl_ans.get(attrs["peer_sci"], set()) | {attrs["peer_an"]}) - asic_ans
    if missing:
        raise MacsecStateInvalid(port, "ingress SA ANs {} of peer SCI {} are in APPL_DB but not in ASIC_DB ({})"
                                 .format(sorted(missing), attrs["peer_sci"], sorted(asic_ans)))


def _state_db_sa_key(port, attrs):
    """STATE_DB key of the peer SA. The SCI is spelled as in the APPL_DB key:
    wpa_supplicant writes it %016 PRIx64, orchagent's STATE_DB key
    (MACsecSCI::str()) and COUNTERS map key (the APPL_DB key itself) match."""
    return "MACSEC_INGRESS_SA_TABLE|{}|{}|{}".format(port, attrs["peer_sci"], attrs["peer_an"])


def _check_macsec_state(host, port, attrs):
    """Raise MacsecStateInvalid unless the peer SA PTF will transmit on is one
    the ASIC runs on a port that is up. Returns the SA's CURRENT_XPN from
    COUNTERS_DB (None if not published yet) for the PN seed and liveness."""
    if attrs["peer_active"] != "true":
        raise MacsecStateInvalid(port, "APPL_DB ingress SA {} has active={}".format(
            attrs["live_key"], attrs["peer_active"]))
    ns = getns_prefix(host, port)
    counter_name = "{}:{}:{}".format(port, attrs["peer_sci"], attrs["peer_an"])
    out = host.shell(
        "v=$(sonic-db-cli {ns} STATE_DB HGET '{sa_key}' state); echo \"sa_state=${{v:-absent}}\"; "
        "v=$(sonic-db-cli {ns} STATE_DB HGET 'PORT_TABLE|{port}' netdev_oper_status); echo \"oper=${{v:-absent}}\"; "
        "o=$(sonic-db-cli {ns} COUNTERS_DB HGET COUNTERS_MACSEC_NAME_MAP '{counter}'); "
        "v=$(sonic-db-cli {ns} COUNTERS_DB HGET \"COUNTERS:${{o:-none}}\" SAI_MACSEC_SA_ATTR_CURRENT_XPN); "
        "echo \"xpn=${{v:-absent}}\"; true".format(
            ns=ns, sa_key=_state_db_sa_key(port, attrs), port=port, counter=counter_name),
        module_ignore_errors=True)["stdout"]
    fields = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if fields.get("sa_state") != "ok":
        raise MacsecStateInvalid(port, "STATE_DB {} state={}: orchagent has not created the SAI SA".format(
            _state_db_sa_key(port, attrs), fields.get("sa_state")))
    if fields.get("oper") != "up":
        raise MacsecStateInvalid(port, "STATE_DB PORT_TABLE|{} netdev_oper_status={}".format(
            port, fields.get("oper")))
    xpn = int(fields["xpn"]) if fields.get("xpn", "absent").isdigit() else None
    if xpn is not None:
        _XPN_SAMPLES[(host.hostname, port)] = (xpn, time.time())
    return xpn


def _read_current_xpns(host, ports):
    """{port: CURRENT_XPN} of the peer SA of each port in ``ports``
    ({port: attrs}), one round trip per namespace."""
    by_ns = {}
    for port, attrs in ports.items():
        by_ns.setdefault(getns_prefix(host, port), []).append(
            (port, "{}:{}:{}".format(port, attrs["peer_sci"], attrs["peer_an"])))
    xpns = {}
    for ns, entries in by_ns.items():
        out = host.shell(
            "; ".join(
                "o=$(sonic-db-cli {ns} COUNTERS_DB HGET COUNTERS_MACSEC_NAME_MAP '{counter}'); "
                "v=$(sonic-db-cli {ns} COUNTERS_DB HGET \"COUNTERS:${{o:-none}}\" SAI_MACSEC_SA_ATTR_CURRENT_XPN); "
                "echo \"{port}=${{v:-absent}}\"".format(ns=ns, counter=counter, port=port)
                for port, counter in entries) + "; true",
            module_ignore_errors=True)["stdout"]
        for line in out.splitlines():
            port, _, value = line.partition("=")
            if value.isdigit():
                xpns[port] = int(value)
    return xpns


def _check_liveness(host, ports):
    """Best-effort, once per session per port: read the peer SA's CURRENT_XPN
    again and note if it has not moved since _check_macsec_state sampled it.
    Samples under _LIVENESS_GAP apart give no verdict; a quiet neighbour is
    legitimate, so this never fails the port. A stuck XPN with the tables all
    ok points at a stale ASIC SA."""
    now = time.time()
    pending = {port: attrs for port, attrs in ports.items()
               if (host.hostname, port) not in _LIVE_PORTS
               and now - _XPN_SAMPLES.get((host.hostname, port), (0, now))[1] >= _LIVENESS_GAP}
    if not pending:
        return
    xpns = _read_current_xpns(host, pending)
    for port in pending:
        first, sampled = _XPN_SAMPLES[(host.hostname, port)]
        if xpns.get(port, first) > first:
            _LIVE_PORTS.add((host.hostname, port))
        else:
            logger.info("peer SA CURRENT_XPN of %s on %s stayed at %d over %.1fs; nothing received on the SA "
                        "PTF was handed yet", port, host.hostname, first, time.time() - sampled)


def _ptf_macsec_info(host, port, attrs, asic_cache=None):
    """The MACSEC_INFO tuple for ``attrs`` of ``port``, after checking the
    DUT state is one PTF can use. PTF shares the neighbour's ingress SA; the
    tuple's last element is the first PN PTF sends, the SA's current PN + 1,
    and the codecs step by one from there. No harness SA is programmed.
    ``asic_cache`` ({namespace: walk}) shares one ASIC_DB walk across ports."""
    xpn = _check_macsec_state(host, port, attrs)
    ns = getns_prefix(host, port)
    asic_cache = {} if asic_cache is None else asic_cache
    if ns not in asic_cache:
        asic_cache[ns] = _namespace_macsec_state(host, ns)
    _check_asic_state(host, port, attrs, asic_cache[ns])
    if xpn is None:
        sa = get_macsec_ingress_sa_counters(host, port, attrs["peer_an"])
        if sa is None:
            # The AN is not shown yet (SA just created); the merged view is the
            # best available snapshot.
            _, sa = get_macsec_counters(host, port)
        xpn = int(sa.get("SAI_MACSEC_SA_ATTR_CURRENT_XPN", 0))
    return _attr_tuple(attrs)[:-1] + (xpn + 1,)


def _prepare_ptf_macsec(host, port, timeout, step, asic_cache):
    """prepare_ptf_macsec returning (info, attrs). The SA row, its STATE_DB
    and ASIC objects and the port's oper state settle one after another right
    after MKA comes up, so a missing row (KeyError) or a failing state check
    is retried until ``timeout`` (0: one attempt); the last error is raised
    then. The namespace walk in ``asic_cache`` is redone after a failure."""
    deadline = time.time() + timeout
    asic_cache = {} if asic_cache is None else asic_cache
    while True:
        try:
            attrs = _read_macsec_attrs(host, port)
            return _ptf_macsec_info(host, port, attrs, asic_cache), attrs
        except (KeyError, MacsecStateInvalid) as err:
            if time.time() >= deadline:
                raise
            logger.debug("MACsec state of %s on %s not usable yet, retrying: %s", port, host.hostname, err)
            asic_cache.pop(getns_prefix(host, port), None)
            time.sleep(step)


def prepare_ptf_macsec(host, port, timeout=30, step=5, asic_cache=None):
    """Read ``port``'s MACsec attributes for PTF once the DUT state is usable
    (retried for ``timeout`` s; 0 tries once). Returns the MACSEC_INFO tuple.
    ``asic_cache`` ({namespace: walk}) shares one DB walk across ports."""
    return _prepare_ptf_macsec(host, port, timeout, step, asic_cache)[0]


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


def load_macsec_info(duthost, port, force_reload=None, timeout=30, asic_cache=None):
    if force_reload or port not in __macsec_infos:
        __macsec_infos[port] = prepare_ptf_macsec(duthost, port, timeout=timeout, asic_cache=asic_cache)
    return __macsec_infos[port]


def load_macsec_info_for_ptf_id(duthost, ptf_id, port, force_reload=None, asic_cache=None):
    """Reload MACSEC_INFO[ptf_id] from the DUT in one attempt (called from the
    receive loop of macsec_dp_poll). The old entry is kept when the DUT state
    is not usable yet, so the poll reports a failure instead of aborting."""
    if not force_reload:
        return
    try:
        info = prepare_ptf_macsec(duthost, port, timeout=0, asic_cache=asic_cache)
    except (KeyError, MacsecStateInvalid) as err:
        logger.debug("MACsec reload of %s on %s skipped, keeping the current key: %s", port, duthost.hostname, err)
        return
    MACSEC_INFO[ptf_id] = info
    MACSEC_PORT_NEXT_PN.pop(ptf_id, None)


def get_macsec_port_states(host):
    """{port: MACSEC_PORT_TABLE state} for every MACsec port, one SSH call.

    Key presence signals a MACsec testbed (stable across MKA renegotiation).
    state == 'ok' only means orchagent created the SAI MACsec port object; it
    says nothing about MKA or the SAs (see _check_macsec_state for those).
    """
    namespaces = ['']
    try:
        if host.is_multi_asic:
            namespaces += host.get_asic_namespace_list()
    except Exception:
        # Namespace discovery is best effort; the host namespace is still probed.
        logger.debug("asic namespace discovery failed on %s; probing host namespace only",
                     host.hostname, exc_info=True)
    states = {}
    for ns in namespaces:
        ns_arg = "-n {} ".format(ns) if ns else ""
        out = host.shell(
            "for k in $(sonic-db-cli {ns}STATE_DB KEYS 'MACSEC_PORT_TABLE|*'); do "
            "echo \"${{k#MACSEC_PORT_TABLE|}}=$(sonic-db-cli {ns}STATE_DB HGET \"$k\" state)\"; "
            "done; true".format(ns=ns_arg),
            module_ignore_errors=True,
        ).get("stdout", "").strip()
        states.update(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return states


def prime_macsec_info(host, ports, timeout=60, step=5):
    """Load MACSEC_INFO for ``ports`` ({port: ptf index}) whose DUT state
    passes the checks within ``timeout`` s (one deadline for all; the DB walk
    is redone once per round) and remember them for refresh_macsec_info().
    A port the ASIC still checks replay on is left out with an error logged;
    the ptf_runner path raises for it. Returns the number of ports loaded."""
    pending = dict(ports)
    last_reason = {}
    loaded = {}
    attrs_by_port = {}
    deadline = time.time() + timeout
    while pending:
        asic_cache = {}
        for port, ptf_id in list(pending.items()):
            try:
                attrs = _read_macsec_attrs(host, port)
                MACSEC_INFO[ptf_id] = _ptf_macsec_info(host, port, attrs, asic_cache)
                attrs_by_port[port] = attrs
                MACSEC_PORT_NEXT_PN.pop(ptf_id, None)
                loaded[port] = ptf_id
                _DECRYPT_WARNED.discard(ptf_id)
            except MacsecReplayProtectionOn as err:
                # Every PTF frame on this port would be dropped as late; only
                # tests that inject through PTF fail for it (create_macsec_info).
                logger.error("MACsec on %s of %s refused for PTF: %s", port, host.hostname, err)
            except (KeyError, MacsecStateInvalid) as err:
                last_reason[port] = str(err)
                continue
            except Exception:
                logger.warning("prepare_ptf_macsec failed for %s on %s", port, host.hostname, exc_info=True)
            pending.pop(port)
        if pending and time.time() < deadline:
            time.sleep(step)
        else:
            break
    for port in pending:
        logger.warning("MACsec on %s of %s is not usable by PTF, leaving it out: %s",
                       port, host.hostname, last_reason[port])
    _PRIMED_PORTS.setdefault(host.hostname, {}).update(loaded)
    _check_liveness(host, attrs_by_port)
    return len(loaded)


def forget_macsec_ports(host, ports=None):
    """Stop refresh_macsec_info() tracking ``ports`` of ``host`` (all if None).
    Call wherever their MACSEC_INFO entries are torn down."""
    primed = _PRIMED_PORTS.get(host.hostname)
    if primed is None:
        return
    for port in list(primed) if ports is None else ports:
        ptf_id = primed.pop(port, None)
        _DECRYPT_WARNED.discard(ptf_id)
        MACSEC_PORT_NEXT_PN.pop(ptf_id, None)
        _LIVE_PORTS.discard((host.hostname, port))
        _XPN_SAMPLES.pop((host.hostname, port), None)
    if not primed:
        _PRIMED_PORTS.pop(host.hostname, None)


def _physical_ports(host, names):
    """The front-panel ports behind ``names``; a PortChannel expands to its members."""
    ports = set()
    for name in names:
        if name.startswith("PortChannel"):
            keys = host.shell("sonic-db-cli CONFIG_DB KEYS 'PORTCHANNEL_MEMBER|{}|*'".format(name),
                              module_ignore_errors=True).get("stdout", "").split()
            ports.update(key.split("|")[-1] for key in keys)
        else:
            ports.add(name)
    return ports


def refresh_macsec_info(host, ports=None, timeout=300, rekey_grace=60):
    """Reload the MACSEC_INFO entries prime_macsec_info() loaded for ``host``,
    or only those behind ``ports`` (port or PortChannel names).

    A swss restart (config reload, reboot, SRv6 enable) or a link flap makes
    MKA negotiate a new SAK. Keys read before it no longer decrypt the DUT's
    egress, so macsec_dp_poll hands back still-encrypted frames and every
    capture on those ports comes up empty.

    STATE_DB can still show the pre-restart session as ok, so a port only
    counts once APPL_DB carries a SAK different from the one loaded. A port
    whose SAK has not changed ``rekey_grace`` seconds after it was first seen
    ok keeps the current key: MKA did not re-key it. A port that no longer
    has MACsec is dropped. Returns False only if ports are still down and
    none came back.
    """
    primed = _PRIMED_PORTS.get(host.hostname)
    if not primed:
        return True
    pending = dict(primed)
    if ports is not None:
        wanted = _physical_ports(host, ports)
        pending = {port: ptf_id for port, ptf_id in pending.items() if port in wanted}
        if not pending:
            return True
    unchanged = {}  # port -> (first seen ok with the old SAK, attrs)
    loaded = {}  # port -> attrs
    dropped = []

    fatal = []

    def _install(port, attrs, asic_cache=None):
        info = _ptf_macsec_info(host, port, attrs, asic_cache)
        ptf_id = pending.pop(port)
        MACSEC_INFO[ptf_id] = info
        MACSEC_PORT_NEXT_PN.pop(ptf_id, None)
        _DECRYPT_WARNED.discard(ptf_id)
        unchanged.pop(port, None)
        loaded[port] = attrs

    def _poll():
        states = get_macsec_port_states(host)
        asic_cache = {}
        for port in list(pending):
            if port not in states:
                logger.info("MACsec is no longer configured on %s of %s; dropping it", port, host.hostname)
                pending.pop(port)
                dropped.append(port)
                forget_macsec_ports(host, [port])
                continue
            if states[port] != "ok":
                continue
            try:
                attrs = _read_macsec_attrs(host, port)
            except Exception as err:
                logger.debug("MACsec SA of %s on %s not readable yet: %s", port, host.hostname, err)
                continue
            old = MACSEC_INFO.get(pending[port])
            if old and attrs["sak"] == old[5]:
                first_seen = unchanged.get(port, (time.time(),))[0]
                unchanged[port] = (first_seen, attrs)
                if time.time() - first_seen < rekey_grace:
                    continue
                logger.warning("SAK of %s on %s did not change; keeping the current key", port, host.hostname)
            try:
                _install(port, attrs, asic_cache)
            except MacsecReplayProtectionOn as err:
                # Configuration error: stop polling and raise below.
                fatal.append(err)
                return True
            except Exception as err:
                # The SA or the port is not back in the ASIC yet; poll again.
                logger.debug("MACsec state of %s on %s not usable yet: %s", port, host.hostname, err)
        return not pending

    wait_until(timeout, 5, 0, _poll)
    if fatal:
        raise fatal[0]
    for port in list(pending):
        if port in unchanged:
            try:
                _install(port, unchanged[port][1])
            except Exception as err:
                logger.warning("Could not reload MACsec key of %s on %s: %s", port, host.hostname, err)
        else:
            logger.warning("MACsec session on %s of %s did not come back within %ss; PTF cannot decrypt it",
                           port, host.hostname, timeout)
    logger.info("Refreshed MACSEC_INFO for %d port(s) on %s (%d dropped, %d not back)",
                len(loaded), host.hostname, len(dropped), len(pending))
    _check_liveness(host, loaded)
    return bool(loaded) or not pending


# This API load the macsec session details from all ctrl links
def load_all_macsec_info(duthost, ctrl_links, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for port, nbr in ctrl_links.items():
        ptf_id = mg_facts["minigraph_ptf_indices"][port]
        MACSEC_INFO[ptf_id] = prepare_ptf_macsec(duthost, port)
        MACSEC_PORT_NEXT_PN.pop(ptf_id, None)


def macsec_send(test, port_id, pkt, count=1):
    # Check if the port is macsec enabled, if so send the macsec encap/encrypted frame
    device, port_number = testutils.port_to_tuple(port_id)
    if port_number in MACSEC_INFO and MACSEC_INFO[port_number]:
        encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = MACSEC_INFO[port_number]

        if port_number not in MACSEC_PORT_NEXT_PN:
            MACSEC_PORT_NEXT_PN[port_number] = pn

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
    asic_cache = {}  # one DUT walk per namespace for all the ports this poll reloads
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
        pkt = scapy.Ether(ret.packet)
        if ret.device != 0:
            if exp_pkt is None or ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
        elif pkt.haslayer(scapy.Ether):
            if pkt[scapy.Ether].type != 0x88e5:
                if exp_pkt is None or ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                    return ret
            else:
                if ret.port in MACSEC_INFO and MACSEC_INFO[ret.port]:
                    # Reload the macsec session if the session was restarted
                    if force_reload[ret.port]:
                        load_macsec_info_for_ptf_id(
                            test.duthost, ret.port, find_portname_from_ptf_id(test.mg_facts, ret.port),
                            force_reload[ret.port], asic_cache)
                    encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = \
                        MACSEC_INFO[ret.port]
                    force_reload[ret.port] = False
                    pkt, decap_success = decap_macsec_pkt(pkt, sci, an, sak, encrypt, send_sci, 0, xpn_en, ssci, salt)
                    if not decap_success and ret.port not in _DECRYPT_WARNED:
                        _DECRYPT_WARNED.add(ret.port)
                        logger.warning("Could not decrypt a MACsec frame on PTF port %s. If captures on it come up "
                                       "empty, MKA re-keyed since the SAK was read: call refresh_macsec_info() after "
                                       "the restart or link flap", ret.port)
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
    # Accumulate per SA block: during a rekey a port shows two ingress SAs
    # and callers need them apart.
    blocks = []
    stats = None
    block = None
    block_an = None
    reg = re.compile(r'(SAI_MACSEC.*?) *(\d+)')
    header = re.compile(r'MACsec (Egress|Ingress) SA \((\d+)\)')
    for line in text.splitlines():
        line = line.strip()

        # An SA header starts a new block; the number in parentheses is its AN.
        found_header = header.match(line)
        if found_header:
            if block is not None:
                blocks.append((stats, block_an, block))
            stats = found_header.group(1).lower()
            block_an, block = int(found_header.group(2)), {}
            continue
        # No header yet, so no stats coming
        if block is None:
            continue

        found = reg.match(line)
        if found:
            block[found.group(1)] = int(found.group(2))
    if block is not None:
        blocks.append((stats, block_an, block))

    # 'ingress_by_an' keeps each live ingress SA apart: during a rekey two are
    # up, and a caller that cares about one AN must not read the other's PN.
    out = {'egress': {}, 'ingress': {}, 'ingress_by_an': {}}
    for stats, an, block in blocks:
        out[stats].update(block)
        if stats == 'ingress':
            out['ingress_by_an'][an] = dict(block)
    return out


def get_macsec_counters(duthost, port):
    cmd = f"show macsec {port}"
    output = duthost.command(cmd)["stdout"]

    out_dict = _parse_show_macsec_counters(output)

    return (out_dict['egress'], out_dict['ingress'])


def get_macsec_ingress_sa_counters(duthost, port, an):
    """Counters of the ingress SA on ``an`` of ``port``, or None if that AN is
    not shown. Unlike get_macsec_counters this never merges SAs."""
    output = duthost.command(f"show macsec {port}")["stdout"]
    return _parse_show_macsec_counters(output)['ingress_by_an'].get(an)


def clear_macsec_counters(duthost):
    assert duthost.command("sonic-clear macsec")["failed"] is False


__origin_dp_poll = testutils.dp_poll
__origin_send_packet = testutils.send_packet
__macsec_infos = defaultdict(lambda: None)
MACSEC_INFO = defaultdict(lambda: None)
# Per-port next PN to send, seeded from the MACSEC_INFO pn (the first PN to
# send, as _ptf_macsec_info computes it) and stepped by one per frame; the
# entry is dropped wherever MACSEC_INFO is reloaded so the new seed applies.
MACSEC_PORT_NEXT_PN = {}
testutils.dp_poll = macsec_dp_poll
testutils.send_packet = macsec_send
