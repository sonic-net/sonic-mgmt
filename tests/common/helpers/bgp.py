import jinja2
import logging
import requests

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


class BGPNeighbor(object):

    def __init__(self, duthost, ptfhost, name,
                 neighbor_ip, neighbor_asn,
                 dut_ip, dut_asn, port, neigh_type=None,
                 namespace=None, is_multihop=False, is_passive=False):
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

    def start_session(self):
        """Start the BGP session."""
        logging.debug("start bgp session %s", self.name)

        if not self.is_passive:
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
            state="started",
            local_ip=self.ip,
            router_id=self.ip,
            peer_ip=self.peer_ip,
            local_asn=self.asn,
            peer_asn=self.peer_asn,
            port=self.port
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
        if not self.is_passive:
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
        assert resp.status_code == 200

        self.ptfhost.exabgp(name=self.name, state="stopped")
        if not self.is_passive:
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
        assert resp.status_code == 200

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
        assert resp.status_code == 200
