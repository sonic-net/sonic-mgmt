import os
import inspect
import sys
try:
    import importlib.util
    import importlib.machinery
    use_importlib = True
except ImportError:
    import imp
    use_importlib = False

CONN_GRAPH_LOG = "/tmp/conn_graph_debug.txt"


def load_source(modname, filename):
    if use_importlib:
        loader = importlib.machinery.SourceFileLoader(modname, filename)
        spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)
        module = importlib.util.module_from_spec(spec)
        # The module is always executed and not cached in sys.modules.
        # Uncomment the following line to cache the module.
        # sys.modules[module.__name__] = module
        loader.exec_module(module)
    else:
        # For Python 2.x compatibility
        module = imp.load_source(modname, filename)
    return module


def get_conn_graph_facts(hostnames):
    """
    @summary: Load conn_graph_facts from conn_graph_facts.xml
    @param hostnames: A list of hostname
    @return: A dict, conn_graph_facts
    """
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    ansible_path = os.path.join(
        os.path.dirname(os.path.abspath(filename)), '../')
    if ansible_path not in sys.path:
        sys.path.append(ansible_path)

    utils = load_source('conn_graph_utils', os.path.join(
        ansible_path, 'library/conn_graph_facts.py'))
    utils.LAB_GRAPHFILE_PATH = os.path.join(
        ansible_path, utils.LAB_GRAPHFILE_PATH)
    utils.debug_fname = CONN_GRAPH_LOG

    lab_graph = utils.find_graph(hostnames=hostnames, part=True)
    succeed, results = lab_graph.build_results(hostnames=hostnames, ignore_error=True)
    if not succeed:
        print("Parse conn graph failes msg = {}".format(results))
        return {'device_pdu_info': {}, 'device_pdu_links': {}}
    return results
