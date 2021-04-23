import pytest
import os
import time

from netaddr import IPAddress
from tests.common.helpers.generators import generate_ips


PFC_GEN_FILE = "pfc_gen.py"
PFC_FRAMES_NUMBER = 50000000
PFC_QUEUE_INDEX = 0xff

ANSIBLE_ROOT = os.path.normpath((os.path.join(__file__, "../../../ansible")))
RUN_PLAYBOOK = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../scripts/exec_template.yml"))

OS_ROOT_DIR = "/root"
TESTS_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "../.."))
ANSIBLE_ROOT = os.path.realpath(os.path.join(TESTS_ROOT, "../ansible"))

ARP_RESPONDER = os.path.join(TESTS_ROOT, "scripts/arp_responder.py")
ARP_RESPONDER_CONF = os.path.join(TESTS_ROOT, "templates/arp_responder.conf.j2")


def get_fanout(fanout_graph_facts, setup):
    for fanout_host_name, value in fanout_graph_facts.items():
        for _, ports in value["device_conn"].items():
            for attr, attr_info in ports.items():
                if attr == "peerport":
                    if attr_info == setup["ptf_test_params"]["server_ports"][0]["dut_name"]:
                        return fanout_host_name
    return None


@pytest.fixture(scope="module")
def ansible_facts(duthosts, rand_one_dut_hostname):
    """ Ansible facts fixture """
    duthost = duthosts[rand_one_dut_hostname]
    yield duthost.setup()['ansible_facts']


@pytest.fixture(scope="module")
def minigraph_facts(duthosts, rand_one_dut_hostname, tbinfo):
    """ DUT minigraph facts fixture """
    duthost = duthosts[rand_one_dut_hostname]
    yield duthost.get_extended_minigraph_facts(tbinfo)


@pytest.fixture(autouse=True, scope="module")
def deploy_pfc_gen(fanouthosts, fanout_graph_facts, setup):
    """
    Fixture to deploy 'pfc_gen.py' file for specific platforms to the Fanout switch.
    """
    fanout_host_name = get_fanout(fanout_graph_facts, setup)

    if "arista" in fanout_graph_facts[fanout_host_name]["device_info"]["HwSku"].lower():
        arista_pfc_gen_dir = "/mnt/flash/"
        for host_name, fanout in fanouthosts.items():
            if host_name == fanout_host_name:
                break

        fanout.host.file(path=arista_pfc_gen_dir, state="directory")
        fanout.host.file(path=os.path.join(arista_pfc_gen_dir, PFC_GEN_FILE), state="touch")
        fanout.host.copy(src=os.path.join(ANSIBLE_ROOT, "roles/test/files/helpers/pfc_gen.py"), dest=arista_pfc_gen_dir)


@pytest.fixture(scope="function")
def pfc_storm_template(ansible_facts, fanout_graph_facts, setup):
    """
    Compose dictionary which items will be used to start/stop PFC generator on Fanout switch by 'pfc_storm_runner' fixture.
    Dictionary values depends on fanout HWSKU (MLNX-OS, Arista or others)
    """
    res = {
        "template": {
            "pfc_storm_start": None,
            "pfc_storm_stop": None
            },
        "template_params": {
            "pfc_gen_file": PFC_GEN_FILE,
            "pfc_queue_index": PFC_QUEUE_INDEX,
            "pfc_frames_number": PFC_FRAMES_NUMBER,
            "pfc_fanout_interface": "",
            "ansible_eth0_ipv4_addr": ansible_facts["ansible_eth0"]["ipv4"]["address"],
            "pfc_asym": True
            }
    }
    fanout_host_name = get_fanout(fanout_graph_facts, setup)
    if fanout_graph_facts[fanout_host_name]["device_info"]["HwSku"] == "MLNX-OS":
        res["template"]["pfc_storm_start"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_mlnx.j2")
        res["template"]["pfc_storm_stop"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_stop_mlnx.j2")
    elif "arista" in fanout_graph_facts[fanout_host_name]["device_info"]["HwSku"].lower():
        res["template"]["pfc_storm_start"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_arista.j2")
        res["template"]["pfc_storm_stop"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_stop_arista.j2")
    else:
        pytest.fail("Unsupported HWSKU. Please define Jinja templates to start/stop PFC generator on fanout")

    yield res


@pytest.fixture(scope="function")
def pfc_storm_runner(fanouthosts, fanout_graph_facts, pfc_storm_template, setup):
    """
    Start/stop PFC generator on Fanout switch
    """
    class StormRunner(object):
        def __init__(self):
            self.server_ports = False
            self.non_server_port = False
            self.used_server_ports = [item["dut_name"] for item in setup["ptf_test_params"]["server_ports"]]
            self.used_non_server_port = [setup["ptf_test_params"]["non_server_port"]["dut_name"]]

        def run(self):
            params["pfc_fanout_interface"] = ""
            dev_conn = fanout_graph_facts[fanout_host_name]["device_conn"]
            plist = []
            if self.server_ports:
                p = ",".join([iface for iface, value in dev_conn.items() if value["peerport"] in self.used_server_ports])
                if p:
                    plist.append(p)
            if self.non_server_port:
                p = ",".join([iface for iface, value in dev_conn.items() if value["peerport"] in self.used_non_server_port])
                if p:
                    plist.append(p)
            params["pfc_fanout_interface"] += ",".join([key for key in plist])
            fanout_host.exec_template(ansible_root=ANSIBLE_ROOT, ansible_playbook=RUN_PLAYBOOK, inventory=setup["fanout_inventory"], \
                **params)
            time.sleep(5)
    fanout_host_name = get_fanout(fanout_graph_facts, setup)
    for host_name, fanout_host in fanouthosts.items():
        if host_name == fanout_host_name:
            break
    params = pfc_storm_template["template_params"].copy()
    params["peer_hwsku"] = str(fanout_graph_facts[fanout_host_name]["device_info"]["HwSku"])
    params["template_path"] = pfc_storm_template["template"]["pfc_storm_start"]

    yield StormRunner()
    params["template_path"] = pfc_storm_template["template"]["pfc_storm_stop"]
    fanout_host.exec_template(ansible_root=ANSIBLE_ROOT, ansible_playbook=RUN_PLAYBOOK, inventory=setup["fanout_inventory"], \
        **params)
    time.sleep(5)


@pytest.fixture(scope="function")
def enable_pfc_asym(setup, duthosts, rand_one_dut_hostname):
    """
    Enable/disable asymmetric PFC on all server interfaces
    """
    duthost = duthosts[rand_one_dut_hostname]
    get_pfc_mode = "docker exec -i database redis-cli --raw -n 1 HGET ASIC_STATE:SAI_OBJECT_TYPE_PORT:{} SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE"
    srv_ports = " ".join([port["dut_name"] for port in setup["ptf_test_params"]["server_ports"]])
    pfc_asym_enabled = "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE"
    pfc_asym_restored = "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED"

    get_asym_pfc = "docker exec -i database redis-cli --raw -n 1 HGET ASIC_STATE:SAI_OBJECT_TYPE_PORT:{port} {sai_attr}"
    sai_asym_pfc_rx = "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_RX"
    sai_asym_pfc_tx = "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_TX"
    sai_default_asym_pfc = "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"

    try:
        # Enable asymmetric PFC on all server interfaces
        duthost.shell("for item in {}; do config interface pfc asymmetric $item on; done".format(srv_ports))
        for p_oid in setup["server_ports_oids"]:
            # Verify asymmetric PFC enabled
            assert pfc_asym_enabled == duthost.command(get_pfc_mode.format(p_oid))["stdout"]
            # Verify asymmetric PFC Rx and Tx values
            assert setup["pfc_bitmask"]["pfc_rx_mask"] == int(duthost.command(get_asym_pfc.format(port=p_oid, sai_attr=sai_asym_pfc_rx))["stdout"])
            assert setup["pfc_bitmask"]["pfc_tx_mask"] == int(duthost.command(get_asym_pfc.format(port=p_oid, sai_attr=sai_asym_pfc_tx))["stdout"])
        yield

    finally:
        # Disable asymmetric PFC on all server interfaces
        duthost.shell("for item in {}; do config interface pfc asymmetric $item off; done".format(srv_ports))
        time.sleep(5)
        for p_oid in setup["server_ports_oids"]:
            # Verify asymmetric PFC disabled
            assert pfc_asym_restored == duthost.command(get_pfc_mode.format(p_oid))["stdout"]
            # Verify PFC value is restored to default
            assert setup["pfc_bitmask"]["pfc_mask"] == int(duthost.command(get_asym_pfc.format(port=p_oid, sai_attr=sai_default_asym_pfc))["stdout"])

@pytest.fixture(scope="module")
def setup(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ansible_facts, minigraph_facts, request):
    """
    Fixture performs initial steps which is required for test case execution.
    Also it compose data which is used as input parameters for PTF test cases, and PFC - RX and TX masks which is used in test case logic.
    Collected data is returned as dictionary object and is available to use in pytest test cases.

    Setup steps:

    - Ensure topology is T0, skip tests run otherwise
    - Gather minigraph facts about the device
    - Get server ports OIDs
    - Get server ports info
    - Get non server port info
    - Set unique MACs to PTF interfaces Run on PTF host- tests/scripts/change_mac.sh
    - Set ARP responder:
        Copy ARP responder to PTF '/opt' directory
        Copy ARP responder supervisor configuration to the PTF container directory
        '/etc/supervisor/conf.d/arp_responder.conf'

        Update supervisor configuration on PTF container
        Execute CLI commands:
            supervisorctl reread
            supervisorctl update

    - Copy PTF tests to PTF host '/root' directory
    - Copy SAI tests to PTF host '/root' directory
    - Copy PTF portmap to PTF host '/root/default_interface_to_front_map.ini' directory

    Teardown steps:

    - Verify PFC value is restored to default
    - Remove PTF tests from PTF container
    - Remove SAI tests from PTF container
    - Remove portmap from PTF container
    - Remove ARP responder
    - Restore supervisor configuration in PTF container
    """
    duthost = duthosts[rand_one_dut_hostname]
    if tbinfo['topo']['name'] != "t0":
        pytest.skip('Unsupported topology')
    setup_params = {
        "pfc_bitmask": {
            "pfc_mask": 0,
            "pfc_rx_mask": 0,
            "pfc_tx_mask": 0
            },
        "ptf_test_params": {
            "port_map_file": None,
            "server": None,
            "server_ports": [],
            "non_server_port": None,
            "router_mac": None,
            "pfc_to_dscp": None,
            "lossless_priorities": None,
            "lossy_priorities": None
            },
        "server_ports_oids": [],
        "fanout_inventory": request.config.getoption("--fanout_inventory")
    }

    server_ports_num = request.config.getoption("--server_ports_num")
    setup = Setup(duthost, ptfhost, setup_params, ansible_facts, minigraph_facts, server_ports_num)
    setup.generate_setup()

    yield setup_params

    # Remove portmap
    ptfhost.file(path=os.path.join(OS_ROOT_DIR, setup_params["ptf_test_params"]["port_map_file"]), state="absent")


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
                            "ptf_name": "eth{}".format(self.mg_facts["minigraph_ptf_indices"][item]),
                            "index": self.mg_facts["minigraph_ptf_indices"][item],
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
        self.vars["ptf_test_params"]["non_server_port"] = {"ptf_name": "eth{}".format(self.mg_facts["minigraph_ptf_indices"][self.portchannel_member]),
                                                    "index": self.mg_facts["minigraph_ptf_indices"][self.portchannel_member],
                                                    "ip": self.mg_facts["minigraph_portchannel_interfaces"][0]["peer_addr"],
                                                    "dut_name": self.portchannel_member,
                                                    "oid": sai_redis_oid}

    def generate_router_mac(self):
        """ Get DUT MAC address which will be used by PTF as Ethernet destination MAC address during sending traffic """
        self.vars["ptf_test_params"]["router_mac"] = self.duthost.facts["router_mac"]


    def prepare_arp_responder(self):
        """ Copy ARP responder to the PTF host """
        self.ptfhost.script("./scripts/change_mac.sh")
        self.ptfhost.copy(src=ARP_RESPONDER, dest="/opt")
        extra_vars = {"arp_responder_args" : "-c /tmp/arp_responder_pfc_asym.json"}
        self.ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
        self.ptfhost.template(src=ARP_RESPONDER_CONF, dest="/etc/supervisor/conf.d/arp_responder.conf", force=True)
        self.ptfhost.command('supervisorctl reread')
        self.ptfhost.command('supervisorctl update')

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
