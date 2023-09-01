"""
1. This script modifies the middle 8 interface
2. (Ethernet96, Ethernet104, Ethernet112, Ethernet120, Ethernet128, Ethernet136,
3. Ethernet144, Ethernet152) speed of O8C48 DUT and churchill fanout SONiC.
4. Script first takes the back up of the minigraph.xml of DUT.
5. It also copies the existing minigraph.xml to a minigraph_test.xml
6. Then the bandwidth is modified for the etp interfaces corresponding to the
7. above 8 Ethernet interfaces of the minigraph_test.xml
8. This file is copied back to minigraph.xml and config_load minigraph is done
9. Script then gets the DUT Ethernet interface corresponding to provided etp interfaces
10. It also gets the Fanout peer port of the corresponding to the DUT Ethernet interfaces
11. Script will first check if one of the modified DUT interface speed is
12. same as existing speed of its fanout peer interface
13. If it is not same then the speed is modified on the 8 fanout interfaces
14. connected to DUT by modifying config_db.json
15. Config reload is done after the fanout speed modification
16. Finally the modified config is saved for the DUT
17. Because the running config is changed, at the end of the testcase run,
18. the original golden running config was saved which overwrote the DUT speed modification.
19. To avoid this "setattr(request.config.option, "dut_clean", True)" is added in the begining of the script
20. In the end changed the dut_clean to False.
21. In tests/conftest.py added the following for core_dump_and_config_check function after yield - line number 1930
 dut_clean= getattr(request.config.option, "dut_clean", True)
    if not dut_clean:
        return
"""


import pytest
from lxml import etree
import json
import re
import time


pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture(scope="module", autouse=True)
def test_speed_change(duthosts, enum_rand_one_per_hwsku_hostname, fanouthosts, conn_graph_facts, request, tbinfo):
    """
    @summary: speed change for o8c48 DUT and churchill fanout
    """
    def convert_speed_to_string(speed):
        if speed == 100000:
            return "100G"
        elif speed == 400000:
            return "400G"
        else:
            raise ValueError("Invalid speed: {}".format(speed))

    setattr(request.config.option, "dut_clean", True)

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("show version")
    duthost.shell("sudo cp /etc/sonic/minigraph.xml /etc/sonic/minigraph_back.xml")
    duthost.shell("sudo cp /etc/sonic/minigraph.xml /etc/sonic/minigraph_test.xml")
    result = duthost.command("sudo cat /etc/sonic/minigraph_test.xml")
    input_file = result["stdout"]

# Parse the XML string into an ElementTree object
    parser = etree.XMLParser(remove_blank_text=True)
    root = etree.fromstring(input_file, parser=parser)

    namespace = {"evolution": "Microsoft.Search.Autopilot.Evolution"}
    device_links = root.findall(".//evolution:DeviceLinkBase", namespaces=namespace)

    etp_interfaces = ["etp12", "etp13", "etp14", "etp15", "etp16", "etp17", "etp18", "etp19"]

    for device_link in device_links:
        start_port_element = device_link.find("evolution:StartPort", namespaces=namespace)
        if start_port_element is not None and start_port_element.text in etp_interfaces:
            bandwidth_element = device_link.find("evolution:Bandwidth", namespaces=namespace)

            if bandwidth_element is not None:
                bandwidth = int(bandwidth_element.text)
                if bandwidth == 400000:
                    bandwidth_element.text = "100000"
                elif bandwidth == 100000:
                    bandwidth_element.text = "400000"

    modified_xml = etree.tostring(root, encoding="unicode", pretty_print=True)
    duthost.copy(content=modified_xml, dest="/etc/sonic/minigraph_test.xml", verbose=False)
    duthost.shell('sudo cp /etc/sonic/minigraph_test.xml /etc/sonic/minigraph.xml')
    print("Execute cli 'config load_minigraph -y' to apply new minigraph")
    duthost.shell("config load_minigraph -y")
    time.sleep(120)
    conn_facts = conn_graph_facts['device_conn'][duthost.hostname]
    peer_device = conn_facts['Ethernet96']['peerdevice']
    peerdev_ans = fanouthosts[peer_device]
    fanout_os = peerdev_ans.get_fanout_os()

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    etp = list(mg_facts['minigraph_ports'].values())


# Get DUT Ethernet interface names for desired aliases
    dut_interfaces = []
    for interface in etp:
        if interface['alias'] in etp_interfaces:
            dut_interfaces.append(interface['name'])

    peer_ports = []  # List to store peer ports for each interface

    for interface in dut_interfaces:
        if interface in conn_facts:
            peer_device = conn_facts[interface]['peerdevice']
            peer_port = conn_facts[interface]['peerport']
            peer_ports.append(peer_port)
            print("DUT Interface: {}, Peer Device: {}, Peer Port: {}".format(interface, peer_device, peer_port))
        else:
            print("DUT Interface {} not found in connection facts".format(interface))


# check DUT speed after speed change and compare with existing fanout interface speed
    out = duthost.show_and_parse("show interface status {}".format(dut_interfaces[0]))
    dut_speed = out[0]['speed']
#    output = peerdev_ans.host.command("show interface status Ethernet248")
    output = peerdev_ans.host.command("show interface status {}".format(peer_ports[0]))
    output = str(output)
    lines = output.splitlines()
    speed_line = lines[0]
    speed_match = re.search(r"\d+G", speed_line)
    if speed_match:
        fanout_speed = speed_match.group(0)
        print("Speed:", fanout_speed)
    else:
        print("Speed not found.")

#   check if speed of DUT after modification and the existing fanout interface speed are notsame
    if dut_speed != fanout_speed:
        if fanout_os == "sonic":
            peerdev_ans.host.command("sudo cp /etc/sonic/config_db.json /etc/sonic/config_db_work.json")
        try:

            result = peerdev_ans.host.command("sudo cat /etc/sonic/config_db.json")
            config_db_json = result["stdout"]
            config_db = json.loads(config_db_json)

            for peer_port in peer_ports:
                show_intf_output = peerdev_ans.host.command("show interface status {}".format(peer_port))
                speed_match = re.search(r"\s(\d+)G\s", show_intf_output["stdout"])
                speed = int(speed_match.group(1)) if speed_match else None

                if speed == 400:
                    config_db["PORT"][peer_port]["lanes"] = ",".join(config_db["PORT"][peer_port]["lanes"]
                                                                     .split(",")[:-4])
                    config_db["PORT"][peer_port]["speed"] = "100000"
                    config_db["PORT"][peer_port]["fec"] = "rs"
                elif speed == 100:
                    lanes = config_db["PORT"][peer_port]["lanes"].split(",")
                    new_lanes = [str(int(lane) + len(lanes)) for i, lane in enumerate(lanes)]
                    config_db["PORT"][peer_port]["lanes"] = ",".join(lanes + new_lanes)
                    config_db["PORT"][peer_port]["speed"] = "400000"
                    config_db["PORT"][peer_port]["fec"] = "rs"
            peerdev_ans.host.copy(content=json.dumps(config_db, indent=4), dest="/tmp/config_db_1.json", verbose=False)

            peerdev_ans.host.command("sudo cp {} {}".format("/tmp/config_db_1.json", "/etc/sonic/config_db.json"))
            peerdev_ans.host.command("config reload -y -f")

            time.sleep(60)
        except Exception:
            print("An exception occurred")

    duthost.shell("config save -y")
    time.sleep(60)
    setattr(request.config.option, "dut_clean", False)


def test_run():
    pass
