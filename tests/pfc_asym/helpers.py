import os
import pytest

from netaddr import IPAddress
from common.helpers.general import generate_ips


OS_ROOT_DIR = "/root"
TESTS_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ANSIBLE_ROOT = os.path.realpath(os.path.join(TESTS_ROOT, "../ansible"))

ARP_RESPONDER = os.path.join(TESTS_ROOT, "scripts/arp_responder.py")
ARP_RESPONDER_CONF = os.path.join(TESTS_ROOT, "scripts/arp_responder.conf.j2")
SAI_TESTS = os.path.join(ANSIBLE_ROOT, "roles/test/files/saitests")
PTF_TESTS = os.path.join(ANSIBLE_ROOT, "roles/test/files/ptftests")


class Setup(object):
    """
    Class defines functionality to fill in 'setup_params' variable defined in 'setup' fixture.
    """
    def __init__(self, duthost, ptfhost, setup_params, ansible_facts, minigraph_facts, use_port_num):
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.mg_facts = minigraph_facts
        self.ansible_facts = ansible_facts
        self.vars = setup_params
        if not 0 <= use_port_num <= len(self.mg_facts["minigraph_vlans"][self.mg_facts["minigraph_vlan_interfaces"][0]["attachto"]]["members"]):
            raise Exception("Incorrect number specificed for used server ports: {}".format(use_port_num))
        self.vlan_members = self.mg_facts["minigraph_vlans"][self.mg_facts["minigraph_vlan_interfaces"][0]["attachto"]]["members"][0:use_port_num]
        self.portchannel_member = self.mg_facts["minigraph_portchannels"][self.mg_facts["minigraph_portchannel_interfaces"][0]["attachto"]]["members"][0]

    def generate_setup(self):
        """
        Main function to compose parameters which is used in 'setup' fixture
        """
        self.generate_server_ports()
        self.generate_non_server_ports()
        self.generate_router_mac()
        self.prepare_arp_responder()
        self.copy_ptf_sai_tests()
        self.prepare_ptf_port_map()
        self.generate_priority()
        self.generate_pfc_to_dscp_map()
        self.generate_pfc_bitmask()

    def generate_server_ports(self):
        """ Generate list of port parameters which are connected to servers """
        generated_ips = generate_ips(len(self.vlan_members), "{}/{}".format(self.mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                                            self.mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']),
                                            [IPAddress(self.mg_facts['minigraph_vlan_interfaces'][0]['addr'])])

        self.vars["ptf_test_params"]["server_ports"] = []
        for index, item in enumerate(self.vlan_members):
            port_info = {"dut_name": item,
                            "ptf_name": "eth{}".format(self.mg_facts["minigraph_port_indices"][item]),
                            "index": self.mg_facts["minigraph_port_indices"][item],
                            "ptf_ip": generated_ips[index],
                            "oid": None}

            redis_oid = self.duthost.command("docker exec -i database redis-cli --raw -n 2 HMGET \
                        COUNTERS_PORT_NAME_MAP {}".format(item))["stdout"]
            self.vars["server_ports_oids"].append(redis_oid)

            sai_redis_oid = int(self.duthost.command("docker exec -i database redis-cli -n 1 hget VIDTORID {}".format(redis_oid))["stdout"].replace("oid:", ""), 16)
            port_info["oid"] = sai_redis_oid
            self.vars["ptf_test_params"]["server_ports"].append(port_info)

        self.vars["ptf_test_params"]["server"] = self.ansible_facts["ansible_hostname"]

    def generate_non_server_ports(self):
        """ Generate list of port parameters which are connected to VMs """
        redis_oid = self.duthost.command("docker exec -i database redis-cli --raw -n 2 HMGET \
                                            COUNTERS_PORT_NAME_MAP {}".format(self.portchannel_member))["stdout"]
        sai_redis_oid = int(self.duthost.command("docker exec -i database redis-cli -n 1 hget VIDTORID {}".format(redis_oid))["stdout"].replace("oid:", ""), 16)
        self.vars["ptf_test_params"]["non_server_port"] = {"ptf_name": "eth{}".format(self.mg_facts["minigraph_port_indices"][self.portchannel_member]),
                                                    "index": self.mg_facts["minigraph_port_indices"][self.portchannel_member],
                                                    "ip": self.mg_facts["minigraph_portchannel_interfaces"][0]["peer_addr"],
                                                    "dut_name": self.portchannel_member,
                                                    "oid": sai_redis_oid}

    def generate_router_mac(self):
        """ Get DUT MAC address which will be used by PTF as Ethernet destination MAC address during sending traffic """
        self.vars["ptf_test_params"]["router_mac"] = self.ansible_facts["ansible_Ethernet0"]["macaddress"]


    def prepare_arp_responder(self):
        """ Copy ARP responder to the PTF host """
        self.ptfhost.script("./scripts/change_mac.sh")
        self.ptfhost.copy(src=ARP_RESPONDER, dest="/opt")
        extra_vars = {"arp_responder_args" : "-c /tmp/arp_responder_pfc_asym.json"}
        self.ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
        self.ptfhost.template(src=ARP_RESPONDER_CONF, dest="/etc/supervisor/conf.d/arp_responder.conf", force=True)
        res1 = self.ptfhost.command('supervisorctl reread')
        res2 = self.ptfhost.command('supervisorctl update')

    def copy_ptf_sai_tests(self):
        """ Copy 'saitests' and 'ptftests' directory to the PTF host """
        self.ptfhost.copy(src=SAI_TESTS, dest=OS_ROOT_DIR)
        self.ptfhost.copy(src=PTF_TESTS, dest=OS_ROOT_DIR)

    def prepare_ptf_port_map(self):
        """ Copy 'ptf_portmap' file which is defined in inventory to the PTF host """
        ptf_portmap = None
        for item in self.duthost.host.options["inventory_manager"].groups["sonic_latest"].hosts:
            if item.name == self.duthost.hostname:
                ptf_portmap = os.path.join(ANSIBLE_ROOT, item.vars["ptf_portmap"])
                self.ptfhost.copy(src=ptf_portmap, dest=OS_ROOT_DIR)
                self.vars["ptf_test_params"]["port_map_file"] = os.path.basename(ptf_portmap)
                break
        else:
            pytest.fail("Unable to find 'ptf_portmap' variable in inventory file for {} DUT".format(self.duthost.hostname))

    def generate_priority(self):
        """ Get configuration of lossless and lossy priorities """
        lossless = []
        lossy = []
        buf_pg_keys = self.duthost.command("docker exec -i database redis-cli --raw -n 4 KEYS *BUFFER_PG*")["stdout"].split()

        get_priority_cli = "for item in {}; do docker exec -i database redis-cli -n 4 HGET $item \"profile\"; done".format(
            " ".join(["\"{}\"".format(item) for item in buf_pg_keys])
            )
        out = self.duthost.command(get_priority_cli, _uses_shell=True)["stdout"].split()
        for index, pg_key in enumerate(buf_pg_keys):
            value = pg_key.split("|")[-1].split("-")
            if "lossless" in out[index]:
                lossless.extend(value)
            elif "lossy" in out[index]:
                lossy.extend(value)
            else:
                pytest.fail("Unable to read lossless and lossy priorities. Buffer PG profile value - {}".format(var))

        self.vars["ptf_test_params"]["lossless_priorities"] = list(set(lossless))
        self.vars["ptf_test_params"]["lossy_priorities"] = list(set(lossy))

    def generate_pfc_to_dscp_map(self):
        """ Get PFC to DSCP fields mapping """
        pfc_to_dscp = {}
        dscp_to_tc_key = self.duthost.command("docker exec -i database redis-cli --raw -n 4 KEYS *DSCP_TO_TC_MAP*")["stdout"]
        dscp_to_tc_keys = self.duthost.command("docker exec -i database redis-cli --raw -n 4 HKEYS {}".format(dscp_to_tc_key))["stdout"].split()

        get_dscp_to_tc = "for item in {}; do docker exec -i database redis-cli -n 4 HGET \"{}\" $item; done".format(
                            " ".join(dscp_to_tc_keys), dscp_to_tc_key
                            )
        dscp_to_tc = self.duthost.command(get_dscp_to_tc, _uses_shell=True)["stdout"]
        self.vars["ptf_test_params"]["pfc_to_dscp"] = dict(zip(map(int, dscp_to_tc.split()),
                                                            map(int, dscp_to_tc_keys)))

    def generate_pfc_bitmask(self):
        """ Compose PFC bitmask for Rx and Tx values """
        pfc_mask = 0
        pfc_rx_mask = 0
        all_priorities = [0, 1, 2, 3, 4, 5, 6, 7] # Asymmetric PFC sets Rx bitmask for all priorities
        for item in self.vars["ptf_test_params"]["lossless_priorities"]:
            pfc_mask = pfc_mask | (1 << int(item))
        for item in all_priorities:
            pfc_rx_mask = pfc_rx_mask | (1 << item)

        self.vars["pfc_bitmask"]["pfc_mask"] = pfc_mask
        self.vars["pfc_bitmask"]["pfc_tx_mask"] = pfc_mask
        self.vars["pfc_bitmask"]["pfc_rx_mask"] = pfc_rx_mask
