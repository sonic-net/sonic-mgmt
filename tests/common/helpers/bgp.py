import jinja2
import logging
import requests

from tests.common.utilities import wait_tcp_connection


NEIGHBOR_SAVE_DEST_TMPL = "/tmp/neighbor_%s.j2"
BGP_SAVE_DEST_TMPL = "/tmp/bgp_%s.j2"


def _write_variable_from_j2_to_configdb(duthost, template_file, **kwargs):
    save_dest_path = kwargs.pop("save_dest_path", "/tmp/temp.j2")
    keep_dest_file = kwargs.pop("keep_dest_file", True)
    config_template = jinja2.Template(open(template_file).read())
    duthost.copy(content=config_template.render(**kwargs), dest=save_dest_path)
    duthost.shell("sonic-cfggen -j %s --write-to-db" % save_dest_path)
    if not keep_dest_file:
        duthost.file(path=save_dest_path, state="absent")


class BGPNeighbor(object):

    def __init__(self, duthost, ptfhost, name,
                 neighbor_ip, neighbor_asn,
                 dut_ip, dut_asn, port, neigh_type, is_multihop=False):
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
        self.is_multihop = is_multihop

    def start_session(self):
        """Start the BGP session."""
        logging.debug("start bgp session %s", self.name)

        _write_variable_from_j2_to_configdb(
            self.duthost,
            "bgp/templates/neighbor_metadata_template.j2",
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
        if not wait_tcp_connection(self.ptfhost, self.ptfip, self.port):
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
        self.duthost.shell("redis-cli -n 4 -c DEL 'BGP_NEIGHBOR|%s'" % self.ip)
        self.duthost.shell("redis-cli -n 4 -c DEL 'DEVICE_NEIGHBOR_METADATA|%s'" % self.name)
        self.ptfhost.exabgp(name=self.name, state="absent")

    def announce_route(self, route):
        if "aspath" in route:
            msg = "announce route {prefix} next-hop {nexthop} as-path [ {aspath} ]"
        else:
            msg = "announce route {prefix} next-hop {nexthop}"
        msg = msg.format(**route)
        logging.debug("announce route: %s", msg)
        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": msg})
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
        resp = requests.post(url, data={"commands": msg})
        logging.debug("withdraw return: %s", resp)
        assert resp.status_code == 200
