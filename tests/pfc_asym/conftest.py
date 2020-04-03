import pytest
import time
import json

from helpers import Setup, OS_ROOT_DIR, ANSIBLE_ROOT
from common.devices import Localhost


PFC_GEN_FILE = "pfc_gen.py"
PFC_FRAMES_NUMBER = 50000000
PFC_QUEUE_INDEX = 0xff
ANSIBLE_ROOT = os.path.normpath((os.path.join(__file__, "../../../ansible")))
LAB_CONNECTION_GRAPH = os.path.normpath((os.path.join(os.path.dirname(__file__),
                                        "../../ansible/files/lab_connection_graph.xml")))


class FanoutHost(Localhost):
    def __init__(self, ansible_adhoc, localhost, duthost):
        Localhost.__init__(self, ansible_adhoc)
        self.ansible_playbook = os.path.realpath(os.path.join(os.path.dirname(__file__), "../scripts/exec_template.yml"))
        self.playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i lab -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        self.localhost = localhost
        self.duthost = duthost
        self.fanout_host = None
        self.facts = {}
        self.gather_facts()

    def exec_template(self, **kwargs):
        cli_cmd = self.playbook_template.format(ansible_path=ANSIBLE_ROOT, playbook=self.ansible_playbook,
                                                fanout_host=self.fanout_host, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["stdout"]))

    def gather_facts(self):
        dut_facts = self.localhost.conn_graph_facts(host=self.duthost.hostname, filename=LAB_CONNECTION_GRAPH)["ansible_facts"]
        self.fanout_host = dut_facts["device_conn"]["Ethernet0"]["peerdevice"]
        self.facts = self.localhost.conn_graph_facts(host=self.fanout_host, filename=LAB_CONNECTION_GRAPH)["ansible_facts"]


@pytest.fixture(scope="module")
def fanout_host(ansible_adhoc, testbed_devices):
    fanout = FanoutHost(ansible_adhoc, testbed_devices["localhost"], testbed_devices["dut"])
    return fanout


@pytest.fixture(scope="module")
def ansible_facts(duthost):
    """ Ansible facts fixture """
    yield duthost.setup()['ansible_facts']


@pytest.fixture(scope="module")
def minigraph_facts(duthost):
    """ DUT minigraph facts fixture """
    yield duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']


@pytest.fixture(autouse=True)
def flush_neighbors(duthost):
    """ Clear ARP table to make sure that neighbors learning will be triggered """
    duthost.command("sonic-clear arp")


@pytest.fixture(autouse=True, scope="module")
def deploy_pfc_gen(fanout_host):
    """
    Fixture to deploy 'pfc_gen.py' file for specific platforms to the Fanout switch.
    """
    if "arista" in fanout_host.facts["device_info"]["HwSku"].lower():
        arista_pfc_gen_dir = "/mnt/flash/"
        fanout_host.file(path=arista_pfc_gen_dir, state="directory")
        fanout_host.file(path=os.path.join(arista_pfc_gen_dir, PFC_GEN_FILE), state="touch")
        fanout_host.copy(src=os.path.join(ANSIBLE_ROOT, "roles/test/files/helpers/pfc_gen.py"), dest=arista_pfc_gen_dir)


@pytest.fixture(scope="module")
def setup(testbed, duthost, ptfhost, ansible_facts, minigraph_facts, request):
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
    if testbed['topo']['name'] != "t0":
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
        "server_ports_oids": []
    }

    server_ports_num = request.config.getoption("--server_ports_num")
    setup = Setup(duthost, ptfhost, setup_params, ansible_facts, minigraph_facts, server_ports_num)
    setup.generate_setup()

    yield setup_params

    # Remove portmap
    ptfhost.file(path=os.path.join(OS_ROOT_DIR, setup_params["ptf_test_params"]["port_map_file"]), state="absent")
    # Remove SAI and PTF tests
    ptfhost.file(path=os.path.join(OS_ROOT_DIR, "saitests"), state="absent")
    ptfhost.file(path=os.path.join(OS_ROOT_DIR, "ptftests"), state="absent")


@pytest.fixture(scope="function")
def pfc_storm_template(ansible_facts, fanout_host):
    """
    Compose dictionary which items will be used to start/stop PFC generator on Fanout switch by 'pfc_storm_runner' fixture.
    Dictionary values depends on fanout HWSKU (MLNX-OS, Arista or others)
    """
    fanout_facts = fanout_host.facts

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

    if fanout_facts["device_info"]["HwSku"] == "MLNX-OS":
        res["template"]["pfc_storm_start"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_mlnx.j2")
        res["template"]["pfc_storm_stop"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_stop_mlnx.j2")
    elif "arista" in fanout_facts["device_info"]["HwSku"].lower():
        res["template"]["pfc_storm_start"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_arista.j2")
        res["template"]["pfc_storm_stop"] = os.path.join(ANSIBLE_ROOT, "roles/test/templates/pfc_storm_stop_arista.j2")
    else:
        pytest.fail("Unsupported HWSKU. Please define Jinja templates to start/stop PFC generator on fanout")

    yield res


@pytest.fixture(scope="function")
def pfc_storm_runner(fanout_host, pfc_storm_template, setup):
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
            if self.server_ports:
                params["pfc_fanout_interface"] += ",".join([key for key, value in fanout_host.facts["device_conn"].items() if value["peerport"] in self.used_server_ports])
            if self.non_server_port:
                if params["pfc_fanout_interface"]:
                    params["pfc_fanout_interface"] += ","
                params["pfc_fanout_interface"] += ",".join([key for key, value in fanout_host.facts["device_conn"].items() if value["peerport"] in self.used_non_server_port])
            fanout_host.exec_template(**params)
            time.sleep(5)

    params = pfc_storm_template["template_params"].copy()
    params["peer_hwsku"] = str(fanout_host.facts["device_info"]["HwSku"])
    params["template_path"] = pfc_storm_template["template"]["pfc_storm_start"]
    yield StormRunner()
    params["template_path"] = pfc_storm_template["template"]["pfc_storm_stop"]
    fanout_host.exec_template(**params)
    time.sleep(5)


@pytest.fixture(scope="function")
def enable_pfc_asym(setup, duthost):
    """
    Enable/disable asymmetric PFC on all server interfaces
    """
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
        for p_oid in setup["server_ports_oids"]:
            # Verify asymmetric PFC disabled
            assert pfc_asym_restored == duthost.command(get_pfc_mode.format(p_oid))["stdout"]
            # Verify PFC value is restored to default
            assert setup["pfc_bitmask"]["pfc_mask"] == int(duthost.command(get_asym_pfc.format(port=p_oid, sai_attr=sai_default_asym_pfc))["stdout"])
