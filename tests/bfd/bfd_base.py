import random
import pytest
import re
import time
import logging
from tests.platform_tests.cli import util
from tests.common.plugins.sanity_check.checks import _parse_bfd_output

logger = logging.getLogger(__name__)


class BfdBase:
    def list_to_dict(self, sample_list):
        data_rows = sample_list[3:]
        for data in data_rows:
            data_dict = {}
            data = data.encode("utf-8").split()
            data_dict["Peer Addr"] = data[0]
            data_dict["Interface"] = data[1]
            data_dict["Vrf"] = data[2]
            data_dict["State"] = data[3]
            data_dict["Type"] = data[4]
            data_dict["Local Addr"] = data[5]
            data_dict["TX Interval"] = data[6]
            data_dict["RX Interval"] = data[7]
            data_dict["Multiplier"] = data[8]
            data_dict["Multihop"] = data[9]
            data_dict["Local Discriminator"] = data[10]
        return data_dict

    def selecting_route_to_delete(self, asic_routes, nexthops):
        for asic in asic_routes:
            for prefix in asic_routes[asic]:
                nexthops_in_static_route_output = asic_routes[asic][prefix]
                # If nexthops on source dut are same destination dut's interfaces, we are picking that static route
                if sorted(nexthops_in_static_route_output) == sorted(nexthops):
                    time.sleep(2)
                    logger.info("Nexthops from static route output")
                    logger.info(sorted(nexthops_in_static_route_output))
                    logger.info("Given Nexthops")
                    logger.info(sorted(nexthops))
                    logger.info("Prefix")
                    logger.info(prefix)
                    return prefix

    def modify_all_bfd_sessions(self, dut, flag):
        # Extracting asic count
        cmd = "show platform summary"
        logging.info("Verifying output of '{}' on '{}'...".format(cmd, dut.hostname))
        summary_output_lines = dut.command(cmd)["stdout_lines"]
        summary_dict = util.parse_colon_speparated_lines(summary_output_lines)
        asic_count = int(summary_dict["ASIC Count"])

        # Creating bfd.json, bfd0.json, bfd1.json, bfd2.json ...
        for i in range(asic_count):
            file_name = "config_db{}.json".format(i)
            dut.shell("cp /etc/sonic/{} /etc/sonic/{}.bak".format(file_name, file_name))
            if flag == "false":
                command = """sed -i 's/"bfd": "true"/"bfd": "false"/' {}""".format(
                    "/etc/sonic/" + file_name
                )
            elif flag == "true":
                command = """sed -i 's/"bfd": "false"/"bfd": "true"/' {}""".format(
                    "/etc/sonic/" + file_name
                )
            dut.shell(command)

    def extract_backend_portchannels(self, dut):
        output = dut.show_and_parse("show int port -d all")
        port_channel_dict = {}

        for item in output:
            if "BP" in item.get("ports", ""):
                port_channel = item.get("team dev", "")
                ports_with_status = [
                    port.strip()
                    for port in item.get("ports", "").split()
                    if "BP" in port
                ]
                ports = [
                    (
                        re.match(r"^([\w-]+)\([A-Za-z]\)", port).group(1)
                        if re.match(r"^([\w-]+)\([A-Za-z]\)", port)
                        else None
                    )
                    for port in ports_with_status
                ]
                status_match = re.search(
                    r"LACP\(A\)\((\w+)\)", item.get("protocol", "")
                )
                status = status_match.group(1) if status_match else ""
                if ports:
                    port_channel_dict[port_channel] = {
                        "members": ports,
                        "status": status,
                    }

        return port_channel_dict

    def extract_ip_addresses_for_backend_portchannels(self, dut, dut_asic, version):
        backend_port_channels = self.extract_backend_portchannels(dut)
        if version == "ipv4":
            command = "show ip int -d all"
        elif version == "ipv6":
            command = "show ipv6 int -d all"
        data = dut.show_and_parse("{} -n asic{}".format(command, dut_asic.asic_index))
        result_dict = {}
        for item in data:
            if version == "ipv4":
                ip_address = item.get("ipv4 address/mask", "").split("/")[0]
            elif version == "ipv6":
                ip_address = item.get("ipv6 address/mask", "").split("/")[0]
            interface = item.get("interface", "")

            if interface in backend_port_channels:
                result_dict[interface] = ip_address
        return result_dict

    def delete_bfd(self, asic_number, prefix, dut):
        command = "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'false'".format(
            asic_number, prefix
        ).replace(
            "\\", ""
        )
        logger.info(command)
        dut.shell(command)
        time.sleep(15)

    def add_bfd(self, asic_number, prefix, dut):
        command = "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'true'".format(
            asic_number, prefix
        ).replace(
            "\\", ""
        )
        logger.info(command)
        dut.shell(command)
        time.sleep(15)

    def extract_current_bfd_state(self, nexthop, asic_number, dut):
        bfd_peer_command = "ip netns exec asic{} show bfd peer {}".format(
            asic_number, nexthop
        )
        logger.info("Verifying BFD status on {}".format(dut))
        logger.info(bfd_peer_command)
        bfd_peer_output = (
            dut.shell(bfd_peer_command, module_ignore_errors=True)["stdout"]
            .encode("utf-8")
            .strip()
            .split("\n")
        )
        if "No BFD sessions found" in bfd_peer_output[0]:
            return "No BFD sessions found"
        else:
            entry = self.list_to_dict(bfd_peer_output)
            return entry["State"]

    def find_bfd_peers_with_given_state(self, dut, dut_asic, expected_bfd_state):
        # Expected BFD states: Up, Down, No BFD sessions found
        peer_count = []
        bfd_cmd = "ip netns exec asic{} show bfd sum"
        result = True
        bfd_peer_output = (
            dut.shell(bfd_cmd.format(dut_asic))["stdout"]
            .encode("utf-8")
            .strip()
            .split("\n")
        )
        if any(
            keyword in bfd_peer_output[0]
            for keyword in ("Total number of BFD sessions: 0", "No BFD sessions found")
        ):
            return result
        else:
            bfd_output = _parse_bfd_output(bfd_peer_output)
            for peer in bfd_output:
                if not bfd_output[peer]["State"] == expected_bfd_state:
                    peer_count.append(peer)
        if len(peer_count) > 0:
            result = False
        return result

    def verify_bfd_state(self, dut, dut_nexthops, dut_asic, expected_bfd_state):
        logger.info("Verifying BFD state on {} ".format(dut))
        for nexthop in dut_nexthops:
            current_bfd_state = self.extract_current_bfd_state(
                nexthop, dut_asic.asic_index, dut
            )
            logger.info("current_bfd_state: {}".format(current_bfd_state))
            logger.info("expected_bfd_state: {}".format(expected_bfd_state))
            if current_bfd_state != expected_bfd_state:
                return False
        return True

    def extract_routes(self, static_route_output, version):
        asic_routes = {}
        asic = None

        for line in static_route_output:
            if line.startswith("asic"):
                asic = line.split(":")[0]
                asic_routes[asic] = {}
            elif line.startswith("S>*") or line.startswith("  *"):
                parts = line.split(",")
                if line.startswith("S>*"):
                    if version == "ipv4":
                        prefix_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", parts[0])
                    elif version == "ipv6":
                        prefix_match = re.search(r"([0-9a-fA-F:.\/]+)", parts[0])
                    if prefix_match:
                        prefix = prefix_match.group(1)
                    else:
                        continue
                if version == "ipv4":
                    next_hop_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", parts[0])
                elif version == "ipv6":
                    next_hop_match = re.search(r"via\s+([0-9a-fA-F:.\/]+)", parts[0])
                if next_hop_match:
                    next_hop = next_hop_match.group(1)
                else:
                    continue

                asic_routes[asic].setdefault(prefix, []).append(next_hop)
        return asic_routes

    @pytest.fixture(
        scope="class", name="select_src_dst_dut_and_asic", params=(["multi_dut"])
    )
    def select_src_dst_dut_and_asic(self, duthosts, request, tbinfo):
        src_dut_index = 0
        dst_dut_index = 0
        src_asic_index = 0
        dst_asic_index = 0
        if (len(duthosts.frontend_nodes)) < 2:
            pytest.skip("Don't have 2 frontend nodes - so can't run multi_dut tests")
        # Random selection of dut indices based on number of front end nodes
        dut_indices = random.sample(list(range(len(duthosts.frontend_nodes))), 2)
        src_dut_index = dut_indices[0]
        dst_dut_index = dut_indices[1]

        # Random selection of source asic based on number of asics available on source dut
        src_asic_index_selection = random.choice(
            duthosts[src_dut_index].get_asic_namespace_list()
        )
        src_asic_index = src_asic_index_selection.split("asic")[1]

        # Random selection of destination asic based on number of asics available on destination dut
        dst_asic_index_selection = random.choice(
            duthosts[dst_dut_index].get_asic_namespace_list()
        )
        dst_asic_index = dst_asic_index_selection.split("asic")[1]

        yield {
            "src_dut_index": src_dut_index,
            "dst_dut_index": dst_dut_index,
            "src_asic_index": int(src_asic_index),
            "dst_asic_index": int(dst_asic_index),
        }

    @pytest.fixture(scope="class")
    def get_src_dst_asic_and_duts(self, duthosts, select_src_dst_dut_and_asic):
        logger.info("Printing select_src_dst_dut_and_asic")
        logger.info(select_src_dst_dut_and_asic)

        logger.info("Printing duthosts.frontend_nodes")
        logger.info(duthosts.frontend_nodes)
        src_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["src_dut_index"]]
        dst_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["dst_dut_index"]]

        logger.info("Printing source dut asics")
        logger.info(src_dut.asics)
        logger.info("Printing destination dut asics")
        logger.info(dst_dut.asics)
        src_asic = src_dut.asics[select_src_dst_dut_and_asic["src_asic_index"]]
        dst_asic = dst_dut.asics[select_src_dst_dut_and_asic["dst_asic_index"]]

        all_asics = [src_asic, dst_asic]
        all_duts = [src_dut, dst_dut]

        rtn_dict = {
            "src_asic": src_asic,
            "dst_asic": dst_asic,
            "src_dut": src_dut,
            "dst_dut": dst_dut,
            "all_asics": all_asics,
            "all_duts": all_duts,
        }
        rtn_dict.update(select_src_dst_dut_and_asic)
        yield rtn_dict
