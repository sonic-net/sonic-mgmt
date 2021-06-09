import os
import inspect
import sys
import imp

CONN_GRAPH_LOG = "/tmp/conn_graph_debug.txt"

def get_conn_graph_facts(hostnames):
    """
    @summary: Load conn_graph_facts from conn_graph_facts.xml
    @param hostnames: A list of hostname
    @return: A dict, conn_graph_facts
    """
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    ansible_path = os.path.join(os.path.dirname(os.path.abspath(filename)), '../')
    if ansible_path not in sys.path:
        sys.path.append(ansible_path)

    utils = imp.load_source('conn_graph_utils', os.path.join(ansible_path, 'library/conn_graph_facts.py'))
    utils.LAB_GRAPHFILE_PATH = os.path.join(ansible_path, utils.LAB_GRAPHFILE_PATH)
    utils.debug_fname = CONN_GRAPH_LOG

    lab_graph = utils.find_graph(hostnames=hostnames, part=True)
    succeed, results = utils.build_results(lab_graph=lab_graph, hostnames=hostnames, ignore_error=True)
    if not succeed:
        print("Parse conn graph failes msg = {}".format(results))
        return {'device_pdu_info': {}, 'device_pdu_links': {}}
    return results
