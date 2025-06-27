import yaml
from threading import Thread

import tortuga_common_utils as t_common
from spytest import st
from utilities import parallel


def wait(seconds):
    """
    Wait for a specified number of seconds.
    Args:
        seconds (int): Number of seconds to wait.
    """
    st.wait(seconds)


def configure(config, nodes, add=True,):
    """
    param Any: configuration in YAML format
    param nodes: WorkArea nodes map
    param add: add or delete the configuration
    """
    with open(config, "r") as file:
        configuration = yaml.load(file, Loader=yaml.FullLoader)
        # Map of switch and list of their thread
        config_threads = {}
        # list of switches
        for switch, value in configuration.items():
            if add:
                config_threads[switch] = [
                    Thread(
                        target=t_common.config_node,
                        args=(nodes[switch], value["pre-sonic-bgp"]["config"], "vtysh"),
                    ),
                    Thread(
                        target=t_common.config_node,
                        args=(
                            nodes[switch],
                            configuration[switch]["sonic"]["config"],
                            "",
                        ),
                    ),
                    Thread(
                        target=t_common.config_node,
                        args=(nodes[switch], value["bgp"]["config"], "vtysh"),
                    ),
                ]
            else:
                config_threads[switch] = [
                    Thread(
                        target=t_common.config_node,
                        args=(nodes[switch], value["bgp"]["deconfig"], "vtysh"),
                    ),
                    Thread(
                        target=t_common.config_node,
                        args=(
                            nodes[switch],
                            configuration[switch]["sonic"]["deconfig"],
                            "",
                        ),
                    ),
                    Thread(
                        target=t_common.config_node,
                        args=(
                            nodes[switch],
                            value["pre-sonic-bgp"]["deconfig"],
                            "vtysh",
                        ),
                    ),
                ]

        def start_thread(thread):
            """
            Start the thread
            :param thread: Thread to be started
            """
            thread.start()
            return thread

        def wait_on_thread(thread1, thread2, thread3, thread4):
            """
            Wait for the thread to finish
            :param thread1: Thread 1
            :param thread2: Thread 2
            :param thread3: Thread 3
            :param thread4: Thread 4
            """
            st.wait(2)
            thread1.join()
            thread2.join()
            thread3.join()
            thread4.join()

        # Run config threads each stage in parallel across DUTs
        # order of execution pre-sonic-bgp -> sonic -> bgp
        while config_threads["leaf0"]:
            t1 = start_thread(config_threads["leaf0"].pop(0))
            t2 = start_thread(config_threads["leaf1"].pop(0))
            t3 = start_thread(config_threads["leaf2"].pop(0))
            t4 = start_thread(config_threads["spine0"].pop(0))
            wait_on_thread(t1, t2, t3, t4)
        st.log("Config applied successfully")


def exec_each(devices, func, *args, **kwargs):
    """
    Execute a function on each device in the list of devices.
    Args:
        devices (list): List of devices to execute the function on.
        func (function): Function to execute.
        *args: Positional arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.
    """
    parallel.exec_foreach(True, devices, func, *args, **kwargs)



def download_file(node, name, file_name, src_path, dst_path=None):
    """
    Download a file from the node.
    Args:
        node (WorkArea): Node to download the file from.
        name (str): Name of the node.
        src_path (str): Source path of the file.
        file_name (str): Name of the file to download.
    """
    if not dst_path:
        dst_path = "/tmp/{name}.{file_name}".format(name=name, file_name=file_name)
    return st.download_file_from_dut(node, src_path + "/"+ file_name, dst_path)


def upload_file(node, src_path, dst_path):
    """
    Upload a file to the node.
    Args:
        node (WorkArea): Node to upload the file to.
        src_path (str): Source path of the file.
        dst_path (str): Destination path of the file.
    """
    return st.upload_file_to_dut(node, src_path, dst_path)
