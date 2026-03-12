import jinja2
import logging
import requests
import ipaddress

from tests.common.utilities import wait_tcp_connection


NEIGHBOR_SAVE_DEST_TMPL = "/tmp/neighbor_%s.j2"
BGP_SAVE_DEST_TMPL = "/tmp/bgp_%s.j2"


def _write_variable_from_j2_to_configdb(duthost, template_file, **kwargs):
    save_dest_path = kwargs.pop("save_dest_path", "/tmp/temp.j2")
    keep_dest_file = kwargs.pop("keep_dest_file", True)
    namespace = kwargs.pop("namespace")
    config_template = jinja2.Template(open(template_file).read())
    duthost.copy(content=config_template.render(**kwargs), dest=save_dest_path)
    duthost.asic_instance_from_namespace(namespace).write_to_config_db(save_dest_path)
    if not keep_dest_file:
        duthost.file(path=save_dest_path, state="absent")


def _config_bgp_neighbor_with_vtysh(duthost, peer_addr, peer_asn, dut_addr, dut_asn):
    """Configure BGP neighbor using vtysh command"""
    cmd = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp {dut_asn}' "
        "-c 'neighbor {peer_addr} remote-as {peer_asn}' "
        "-c 'neighbor {peer_addr} activate' "
    )
    duthost.shell(cmd.format(peer_addr=peer_addr,
                             peer_asn=peer_asn,
                             dut_addr=dut_addr,
                             dut_asn=dut_asn))


def _remove_bgp_neighbor_with_vtysh(duthost, peer_addr, dut_asn):
    """Remove BGP neighbor using vtysh command"""
    cmd = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp {dut_asn}' "
        "-c 'no neighbor {peer_addr}' "
    )
    duthost.shell(cmd.format(peer_addr=peer_addr,
                             dut_asn=dut_asn))


def _shutdown_bgp_neighbor_with_vtysh(duthost, peer_addr, dut_asn):
    """Shutdown BGP neighbor using vtysh command"""
    cmd = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp {dut_asn}' "
        "-c 'neighbor {peer_addr} shutdown' "
    )
    duthost.shell(cmd.format(peer_addr=peer_addr,
                             dut_asn=dut_asn))


def run_bgp_facts(duthost, enum_asic_index):
    """compare the bgp facts between observed states and target state"""

    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    config_facts = duthost.config_facts(host=duthost.hostname, source="running", namespace=namespace)['ansible_facts']
    sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
    for k, v in list(bgp_facts['bgp_neighbors'].items()):
        # Verify bgp sessions are established
        assert v['state'] == 'established', (
            "BGP session not established for neighbor. Expected 'established', got '{}'."
        ).format(v['state'])
        # Verify local ASNs in bgp sessions
        assert v['local AS'] == int(config_facts['DEVICE_METADATA']['localhost']['bgp_asn'].encode().decode("utf-8")), (
            "Local AS mismatch for neighbor. Expected '{}', got '{}'."
        ).format(
            int(config_facts['DEVICE_METADATA']['localhost']['bgp_asn'].encode().decode("utf-8")),
            v['local AS']
        )
        # Check bgpmon functionality by validate STATE DB contains this neighbor as well
        state_fact = duthost.shell('{} STATE_DB HGET "NEIGH_STATE_TABLE|{}" "state"'
                                   .format(sonic_db_cmd, k), module_ignore_errors=False)['stdout_lines']
        peer_type = duthost.shell('{} STATE_DB HGET "NEIGH_STATE_TABLE|{}" "peerType"'
                                  .format(sonic_db_cmd, k),
                                  module_ignore_errors=False)['stdout_lines']
        assert state_fact[0] == "Established", (
            "BGP neighbor state in STATE_DB is not 'Established' for neighbor. "
            "Expected: 'Established', got: '{}'."
        ).format(
            state_fact[0] if state_fact else "No state found"
        )
        assert peer_type[0] == ("i-BGP" if v['remote AS'] == v['local AS'] else "e-BGP"), (
            "BGP peer type mismatch for neighbor. "
            "Expected '{}', got '{}'."
        ).format(
            "i-BGP" if v['remote AS'] == v['local AS'] else "e-BGP",
            peer_type[0] if peer_type else "No peer type found"
        )

    # In multi-asic, would have 'BGP_INTERNAL_NEIGHBORS' and possibly no 'BGP_NEIGHBOR' (ebgp) neighbors.
    nbrs_in_cfg_facts = {}
    nbrs_in_cfg_facts.update(config_facts.get('BGP_NEIGHBOR', {}))
    nbrs_in_cfg_facts.update(config_facts.get('BGP_INTERNAL_NEIGHBOR', {}))
    # In VoQ Chassis, we would have BGP_VOQ_CHASSIS_NEIGHBOR as well.
    nbrs_in_cfg_facts.update(config_facts.get('BGP_VOQ_CHASSIS_NEIGHBOR', {}))
    for k, v in list(nbrs_in_cfg_facts.items()):
        # Compare the bgp neighbors name with config db bgp neighbors name
        assert v['name'] == bgp_facts['bgp_neighbors'][k]['description'], (
            "BGP neighbor name mismatch for neighbor. "
            "Expected '{}', got '{}'."
        ).format(
            v['name'],
            bgp_facts['bgp_neighbors'][k]['description']
        )
        # Compare the bgp neighbors ASN with config db
        assert int(v['asn'].encode().decode("utf-8")) == bgp_facts['bgp_neighbors'][k]['remote AS'], (
            "BGP remote AS number mismatch for neighbor. "
            "Expected remote AS: '{}', got: '{}'."
        ).format(
            int(v['asn'].encode().decode("utf-8")),
            bgp_facts['bgp_neighbors'][k]['remote AS']
        )


class BGPNeighbor(object):

    def __init__(self, duthost, ptfhost, name,
                 neighbor_ip, neighbor_asn,
                 dut_ip, dut_asn, port, neigh_type=None,
                 namespace=None, is_multihop=False, is_passive=False, debug=False,
                 is_ipv6_only=False, router_id=None, confed_asn=None, use_vtysh=False):

        self.duthost = duthost
        self.ptfhost = ptfhost
        self.ptfip = ptfhost.mgmt_ip
        self.name = name
        self.ip = neighbor_ip
        self.asn = neighbor_asn
        self.peer_ip = dut_ip
        self.peer_asn = dut_asn
        self.port = port
        self.type = neigh_type
        self.namespace = namespace
        self.is_passive = is_passive
        self.is_multihop = not is_passive and is_multihop
        self.debug = debug
        self.is_ipv6_neighbor = is_ipv6_only
        if not self.is_ipv6_neighbor:
            self.router_id = router_id or self.ip
        else:
            # Generate router ID by combining 20.0.0.0 base with last 3 bytes of IPv6 addr
            router_id_base = ipaddress.IPv4Address("20.0.0.0")
            ipv6_addr = ipaddress.IPv6Address(self.ip)
            self.router_id = router_id or str(ipaddress.IPv4Address(int(router_id_base) | int(ipv6_addr) & 0xFFFFFF))
        self.use_vtysh = use_vtysh
        self.confed_asn = confed_asn

    def start_session(self):
        """Start the BGP session."""
        logging.debug("start bgp session %s", self.name)

        if self.use_vtysh:
            _config_bgp_neighbor_with_vtysh(
                self.duthost,
                peer_addr=self.ip,
                peer_asn=self.asn,
                dut_addr=self.peer_ip,
                dut_asn=self.peer_asn
            )
        elif not self.is_passive:
            _write_variable_from_j2_to_configdb(
                self.duthost,
                "bgp/templates/neighbor_metadata_template.j2",
                namespace=self.namespace,
                save_dest_path=NEIGHBOR_SAVE_DEST_TMPL % self.name,
                neighbor_name=self.name,
                neighbor_lo_addr=self.ip,
                neighbor_mgmt_addr=self.ip,
                neighbor_hwsku=None,
                neighbor_type=self.type
            )

            _write_variable_from_j2_to_configdb(
                self.duthost,
                "bgp/templates/bgp_template.j2",
                namespace=self.namespace,
                save_dest_path=BGP_SAVE_DEST_TMPL % self.name,
                db_table_name="BGP_NEIGHBOR",
                peer_addr=self.ip,
                asn=self.asn,
                local_addr=self.peer_ip,
                peer_name=self.name
            )

        self.ptfhost.exabgp(
            name=self.name,
            state="restarted" if self.is_ipv6_neighbor else "started",
            local_ip=self.ip,
            router_id=self.router_id,
            peer_ip=self.peer_ip,
            local_asn=self.asn,
            peer_asn=self.confed_asn if self.confed_asn is not None else self.peer_asn,
            port=self.port,
            debug=self.debug
        )
        if not wait_tcp_connection(self.ptfhost, self.ptfip, self.port, timeout_s=60):
            raise RuntimeError("Failed to start BGP neighbor %s" % self.name)

        if self.is_multihop:
            allow_ebgp_multihop_cmd = (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s ebgp-multihop'"
            )
            allow_ebgp_multihop_cmd %= (self.peer_asn, self.ip)
            self.duthost.shell(allow_ebgp_multihop_cmd)

    def stop_session(self):
        """Stop the BGP session."""
        logging.debug("stop bgp session %s", self.name)

        if self.use_vtysh:
            _remove_bgp_neighbor_with_vtysh(
                self.duthost,
                peer_addr=self.ip,
                dut_asn=self.peer_asn
            )
        elif not self.is_passive:
            for asichost in self.duthost.asics:
                asichost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_NEIGHBOR|{}'".format(self.ip))
                asichost.run_sonic_db_cli_cmd("CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{}'".format(self.name))

        self.ptfhost.exabgp(name=self.name, state="absent")

    def teardown_session(self):
        # error_subcode 3: Peer De-configured. References: RFC 4271
        msg = "neighbor {} teardown 3"
        msg = msg.format(self.peer_ip)
        logging.debug("teardown session: %s", msg)
        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": msg}, proxies={"http": None, "https": None})
        logging.debug("teardown session return: %s" % resp)
        assert resp.status_code == 200, (
            "Expected HTTP 200 from exabgp API, but got {}."
        ).format(
            resp.status_code
        )

        self.ptfhost.exabgp(name=self.name, state="stopped")

        if self.use_vtysh:
            _shutdown_bgp_neighbor_with_vtysh(
                self.duthost,
                peer_addr=self.ip,
                dut_asn=self.peer_asn
            )
        elif not self.is_passive:
            for asichost in self.duthost.asics:
                if asichost.namespace == self.namespace:
                    logging.debug("update CONFIG_DB admin_status to down on {}".format(asichost.namespace))
                    asichost.run_sonic_db_cli_cmd("CONFIG_DB hset 'BGP_NEIGHBOR|{}' admin_status down".format(self.ip))

    def announce_route(self, route):
        if "aspath" in route:
            msg = "announce route {prefix} next-hop {nexthop} as-path [ {aspath} ]"
        else:
            msg = "announce route {prefix} next-hop {nexthop}"
        msg = msg.format(**route)
        logging.debug("announce route: %s", msg)
        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": msg}, proxies={"http": None, "https": None})
        logging.debug("announce return: %s", resp)
        assert resp.status_code == 200, (
            "Expected HTTP 200 from exabgp API, but got {}."
        ).format(
            resp.status_code
        )

    def withdraw_route(self, route):
        if "aspath" in route:
            msg = "withdraw route {prefix} next-hop {nexthop} as-path [ {aspath} ]"
        else:
            msg = "withdraw route {prefix} next-hop {nexthop}"
        msg = msg.format(**route)
        logging.debug("withdraw route: %s", msg)
        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": msg}, proxies={"http": None, "https": None})
        logging.debug("withdraw return: %s", resp)
        assert resp.status_code == 200, (
            "Expected HTTP 200 from exabgp API, but got {}."
        ).format(
            resp.status_code
        )

    def announce_routes_batch(self, routes):
        commands = []
        for route in routes:
            cmd = "announce route {prefix} next-hop {nexthop}".format(
                prefix=route["prefix"],
                nexthop=route["nexthop"]
            )
            if "aspath" in route:
                cmd += " as-path [ {aspath} ]".format(
                    aspath=route["aspath"]
                )

            logging.debug(f"Queueing cmd '{cmd}' for batch announcement")
            commands.append(cmd)

        full_cmd = ";".join(commands)

        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": full_cmd}, proxies={"http": None, "https": None})
        logging.debug("announce return: %s", resp)
        assert resp.status_code == 200, (
            "Expected HTTP 200 from exabgp API, but got {}."
        ).format(
            resp.status_code
        )

    def withdraw_routes_batch(self, routes):
        commands = []
        for route in routes:
            cmd = "withdraw route {prefix} next-hop {nexthop}".format(
                prefix=route["prefix"],
                nexthop=route["nexthop"]
            )
            if "aspath" in route:
                cmd += " as-path [ {aspath} ]".format(
                    aspath=route["aspath"]
                )

            logging.debug(f"Queueing cmd '{cmd}' for batch withdraw")
            commands.append(cmd)

        full_cmd = ";".join(commands)

        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": full_cmd}, proxies={"http": None, "https": None})
        logging.debug("announce return: %s", resp)
        assert resp.status_code == 200, (
            "Expected HTTP 200 from exabgp API, but got {}."
        ).format(
            resp.status_code
        )
