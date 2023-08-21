
import random
import pytest, re
import logging
logger = logging.getLogger(__name__)


class BfdBase:
    def list_to_dict(self, sample_list):
        header = sample_list[1].split()
        data_rows = sample_list[3:]
        for data in data_rows:
            data_dict = {}
            data = data.encode("utf-8").split()
            data_dict['Peer Addr'] = data[0]
            data_dict['Interface'] = data[1]
            data_dict['Vrf'] = data[2]
            data_dict['State'] = data[3]
            data_dict['Type'] = data[4]
            data_dict['Local Addr'] = data[5]
            data_dict['TX Interval'] = data[6]
            data_dict['RX Interval'] = data[7]
            data_dict['Multiplier'] = data[8]
            data_dict['Multihop'] = data[9]
            data_dict['Local Discriminator'] = data[10]
        return data_dict
    
    def selecting_route_to_delete(self, asic_routes, nexthops):
        for asic in asic_routes:
            for prefix in asic_routes[asic]:
                nexthops_in_static_route_output = asic_routes[asic][prefix]
                #If nexthops on source dut are same destination dut's interfaces, we are picking that static route
                if sorted(nexthops_in_static_route_output) == sorted(nexthops):
                    return prefix
    
    def delete_bfd(self, asic_number, prefix, dut):
        command = 'sonic-db-cli -n asic{} CONFIG_DB HSET "STATIC_ROUTE|{}" bfd \'false\''.format(asic_number, prefix).replace('\\', '')
        dut.shell(command)
    
    def add_bfd(self, asic_number, prefix, dut):
        command = 'sonic-db-cli -n asic{} CONFIG_DB HSET "STATIC_ROUTE|{}" bfd \'true\''.format(asic_number, prefix).replace('\\', '')
        dut.shell(command)
    
    def extract_current_bfd_state(self, list_of_nexthops, asic_number, dut):
        
        for nexthop in list_of_nexthops:
            bfd_peer_command = "ip netns exec asic{} show bfd peer {}".format(asic_number, nexthop)
            logger.info("Verifying BFD status on {}".format(dut))
            logger.info(bfd_peer_command)
            bfd_peer_output = dut.shell(bfd_peer_command, module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
            if "No BFD sessions found" in bfd_peer_output[0]:
                return "No BFD sessions found"
            else:                
                entry = self.list_to_dict(bfd_peer_output)
                return entry['State']
                    
    def extract_routes(self, static_route_output):
        asic_routes = {}
        asic = None
        for line in static_route_output:
            if line.startswith("asic"):
                asic = line.split(':')[0]
                asic_routes[asic] = {}
            elif line.startswith("S>*") or line.startswith("  *"):
                parts = line.split(',')
                if line.startswith("S>*"):
                    prefix = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", parts[0]).group(1)
                next_hop = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", parts[0]).group(1)
                asic_routes[asic].setdefault(prefix, []).append(next_hop)
        return asic_routes
    
    @pytest.fixture(scope='class', name="select_src_dst_dut_and_asic",
                    params=(["multi_dut"]))
    def select_src_dst_dut_and_asic(self, duthosts, request, tbinfo):
        src_dut_index = 0
        dst_dut_index = 0
        src_asic_index = 0
        dst_asic_index = 0
        if (len(duthosts.frontend_nodes)) < 2:
            pytest.skip("Don't have 2 frontend nodes - so can't run multi_dut tests")
        dut_indices = random.sample(list(range(len(duthosts.frontend_nodes))), 2)
        src_dut_index = dut_indices[0]
        dst_dut_index = dut_indices[1]
        asic_indices = random.sample(duthosts[src_dut_index].get_asic_namespace_list(), 2)
        src_asic_index = asic_indices[0].split("asic")[1]
        dst_asic_index = asic_indices[1].split("asic")[1]
       
        yield {
        "src_dut_index": src_dut_index,
        "dst_dut_index": dst_dut_index,
        "src_asic_index": int(src_asic_index),
        "dst_asic_index": int(dst_asic_index)
        }

    @pytest.fixture(scope='class')
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
            "all_duts": all_duts
        }
        rtn_dict.update(select_src_dst_dut_and_asic)
        yield rtn_dict
