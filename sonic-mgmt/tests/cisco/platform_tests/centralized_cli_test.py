import json
import logging
import re
import time


def does_result_contain(result, match_str):
    """
    Helper function to check whether output contains specific string pattern
    """
    for line in result['stdout_lines']:
        matches = re.search(match_str, line)
        if matches != None:
            return True
    return False

def check_output_for_errors(result):
    """
    Helper function to check whether output contains any error string patterns
    """
    for line in result['stdout_lines']:
        matches = re.search(r"LC Timeout!!!", line)
        if matches != None:
            return True
        matches = re.search(r"debug shell server for .* is not running", line)
        if matches != None:
            return True
        matches = re.search(r"Traceback \(most recent call last\):", line)
        if matches != None:
            return True
        matches = re.search(r"remote socket terminated", line)
        if matches != None:
            return True
    return False

def get_platform_serial_number(duthost):
    serial_num = None
    out = duthost.command("show platform summary")
    output_lines = out["stdout"].splitlines()
    for line in output_lines:
        if line.startswith("Serial Number"):
            serial_num = line.split(":", 1)[1].strip()
    return serial_num



def find_active_lc_list(duthosts):
    """
    Function to get the list of linecards in the modular chassis
    """
    node_list = []
    output = ""
    std_output = ""
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            pass
        else:
            output = duthost.shell("pgrep -af lc_rp_cmd_client.py | grep -v pgrep", module_ignore_errors=True)
            std_output = output["stdout"].strip()
            if output["rc"] == 0 and std_output:
                logging.info(f"Process is running: {std_output} {duthost}")
                node_list.append(find_node_name_from_duthost(duthost))
            else:
                logging.info("Process is not running {std_output} {duthost}")
    return node_list

def get_namespace_list_for_lc(duthost, lc):
    """
    Function to get the list of asic-ids in a linecard
    """
    namespace_list = []
    pattern_asic_str = rf"^CHASSIS_ASIC_TABLE\|{lc}\|(asic\d+)$"

    # Iterate through CHASSIS_ASIC_TABLE of CHASSIS_STATE_DB to fetch the asic-id information
    chassis_asic_dict = json.loads(duthost.shell("sonic-db-dump -n CHASSIS_STATE_DB -k CHASSIS_ASIC_TABLE* -y")['stdout'])
    keys = chassis_asic_dict.keys()
    for key in keys:
        matches = re.search(pattern_asic_str, key)
        if matches != None:
            asic_id = matches.group(1)
            namespace_list.append(asic_id)
    return namespace_list

def find_min_namespace_count(duthosts):
    """
    Function to get the minimum number of asic-ids among all linecards and supervisor
    """
    lc_namespace_list = []
    min_namespace_count = 0
    for duthost in duthosts:
        dut_namespace_count = len(duthost.get_asic_namespace_list())
        if dut_namespace_count < min_namespace_count:
            min_namespace_count = dut_namespace_count

    return min_namespace_count

def find_node_name_from_duthost(duthost):
    """
    Function to find node name from duthost
    """
    serial_num = get_platform_serial_number(duthost)
    chassis_module_dict = json.loads(duthost.shell("sonic-db-dump -n STATE_DB -k CHASSIS_MODULE_TABLE* -y")['stdout'])
    keys = chassis_module_dict.keys()
    for key in keys:
        node_dict = chassis_module_dict[key]
        node_value_dict = node_dict['value']
        if node_value_dict['serial'] == serial_num:
            node_name = key.split("|", 1)[1]
            if node_name != None:
                return node_name

    return None

def find_duthost_from_node_name(duthosts, node):
    for duthost in duthosts:
        serial_num = get_platform_serial_number(duthost)
        if serial_num == None:
            continue
        chassis_module_dict = json.loads(duthost.shell("sonic-db-dump -n STATE_DB -k CHASSIS_MODULE_TABLE* -y")['stdout'])
        keys = chassis_module_dict.keys()
        for key in keys:
            node_dict = chassis_module_dict[key]
            node_value_dict = node_dict['value']
            if node_value_dict['serial'] == serial_num:
                return duthost

    return None

def save_memory_leak_context(duthosts):
    """
    Function to save memory utilization context. This is run before and after the test case
    Collects memory usage data for both Supervisor and Line Cards, but only Line Cards will be checked for leaks
    """
    used_mem_kb = [-1]*len(duthosts)
    
    index = 0
    for duthost in duthosts:
        temp_used_mem_kb = 0
        # Take average of 5 measurements for more stable readings
        for j in range(5):
            if duthost.is_supervisor_node():
                # For Supervisor, skip any memory checks, it gives false positives
                logging.info(f"Skipping saving memory usage contexts for Supervisor")
            else:
                # For Line Cards, get memory usage of lc_rp_cmd_client.py process
                cmd = f"ps -eo pid,comm,rss,args | grep lc_rp_cmd_client.py | grep -v grep | awk '{{print $3}}'"
                output = duthost.shell(cmd)
                if output["stdout"].strip():
                    temp_used_mem_kb += int(output["stdout"].strip())
                else:
                    # If process not found, use 0
                    temp_used_mem_kb += 0
        used_mem_kb[index] = temp_used_mem_kb/5
        index += 1
    return used_mem_kb
    
def compare_memory_usage_contexts(duthosts, saved_ctxt_used_mem_kb, current_used_mem_kb, tc_dict, results):
    """
    Function to compare memory utilization contexts that are saved before and after the test case execution
    Only checks for memory leaks on Line Cards (LC), skips Route Processor (RP/Supervisor) due to high memory consumption variations
    """
    node_name = None
    index = 0
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            # Skip memory leak checks for Supervisor/RP due to high memory consumption variations
            logging.info(f"Skipping memory leak check for Supervisor: saved={saved_ctxt_used_mem_kb[index]}, current={current_used_mem_kb[index]}")
        else:
            # Only check memory leaks for Line Cards
            node_name = find_node_name_from_duthost(duthost)
            memory_diff = current_used_mem_kb[index] - saved_ctxt_used_mem_kb[index]
            logging.info(f"Memory usage check for {node_name}: saved={saved_ctxt_used_mem_kb[index]}, current={current_used_mem_kb[index]}, diff={memory_diff}")
            if memory_diff >= 512:
                error_msg = f"Memory leak detected on linecard {node_name}: before={saved_ctxt_used_mem_kb[index]}KB, after={current_used_mem_kb[index]}KB, difference={memory_diff}KB"
                update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return False
        index += 1

    return True
        

def save_cpu_utilization_context(duthosts):
    """
    Function to save CPU utilization context. This is run before and after the test case
    Collects CPU usage data for both Supervisor and Line Cards, but only Line Cards will be checked for high usage
    """
    used_cpu_pc = [-1]*len(duthosts)

    index = 0
    for duthost in duthosts:
        if duthost.is_supervisor_node() == False:
            temp_usage_percent = 0
            # Take the average of 5 attempts for more stable readings
            for i in range(5):
                cmd = f"ps -eo %cpu=,cmd= | grep lc_rp_cmd_client.py | grep -v grep"
                output = duthost.shell(cmd, module_ignore_errors=True)
                match = re.search(r'(\d+\.\d+)', duthost.shell(cmd)["stdout"])
                if not match:
                    # If pattern doesn't match, log warning and use 0
                    logging.warning(f"Unable to parse CPU usage from: {output['stdout']}")
                    usage_percent = 0
                else:
                    usage_percent = float(match.group(1))
                temp_usage_percent += usage_percent
            used_cpu_pc[index] = temp_usage_percent/5
        index += 1
    return used_cpu_pc
    
def compare_cpu_usage_contexts(duthosts, saved_ctxt_cpu_pc, current_cpu_pc, tc_dict, results):
    """
    Function to compare CPU utilization contexts that are saved before and after the test case execution
    Only checks for high CPU usage on Line Cards (LC), skips Route Processor (RP/Supervisor) due to high CPU usage variations
    """
    node_name = None
    index = 0
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            # Skip CPU usage checks for Supervisor/RP due to high CPU usage variations
            logging.info(f"Skipping CPU usage check for Supervisor: saved={saved_ctxt_cpu_pc[index]}%, current={current_cpu_pc[index]}%")
        else:
            # Only check CPU usage for Line Cards
            node_name = find_node_name_from_duthost(duthost)
            cpu_diff = current_cpu_pc[index] - saved_ctxt_cpu_pc[index]
            logging.info(f"CPU usage check for {node_name}: saved={saved_ctxt_cpu_pc[index]}%, current={current_cpu_pc[index]}%, diff={cpu_diff}%")
            if cpu_diff >= 5:
                error_msg = f"High CPU utilization detected on linecard {node_name}: before={saved_ctxt_cpu_pc[index]}%, after={current_cpu_pc[index]}%, difference={cpu_diff}%"
                update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return False
        index += 1

    return True
        

def save_thread_context(duthosts):
    """
    Function to save thread count context for lc_rp_cmd_client.py process
    This monitors threads spawned by LC service to handle RP-LC communication
    """
    thread_counts = [-1]*len(duthosts)
    
    index = 0
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            # For Supervisor, set to 0 as we don't monitor threads here
            thread_counts[index] = 0
        else:
            # For Line Cards, get thread count for lc_rp_cmd_client.py process
            cmd = f"ps -eLf | grep lc_rp_cmd_client.py | grep -v grep | wc -l"
            output = duthost.shell(cmd)
            if output["stdout"].strip():
                thread_counts[index] = int(output["stdout"].strip())
            else:
                # If process not found, set to 0
                thread_counts[index] = 0
        index += 1
    return thread_counts

def compare_thread_contexts(duthosts, saved_ctxt_thread_count, current_thread_count, tc_dict, results):
    """
    Function to compare thread counts before and after CLI command execution
    Ensures no hanging threads remain in lc_rp_cmd_client.py process after command completion
    """
    node_name = None
    index = 0
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            # Skip thread checks for Supervisor as it doesn't run lc_rp_cmd_client.py
            logging.info(f"Skipping thread check for Supervisor")
        else:
            # Check thread cleanup for Line Cards
            node_name = find_node_name_from_duthost(duthost)
            thread_diff = current_thread_count[index] - saved_ctxt_thread_count[index]
            logging.info(f"Thread count check for {node_name}: saved={saved_ctxt_thread_count[index]}, current={current_thread_count[index]}, diff={thread_diff}")
            
            # Allow for a small increase in threads (up to 2) as some background threads might be normal
            # But ensure no significant thread leak (more than 2 additional threads)
            if thread_diff > 2:
                error_msg = f"Thread leak detected in lc_rp_cmd_client.py on linecard {node_name}: before={saved_ctxt_thread_count[index]}, after={current_thread_count[index]}, difference={thread_diff}"
                update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return False
            
            # Also warn if threads decreased significantly (might indicate process restart)
            if thread_diff < -5:
                logging.warning(f"Significant thread count decrease on {node_name}: before={saved_ctxt_thread_count[index]}, after={current_thread_count[index]}")
        index += 1

    return True


def update_results(results, tcname, status, error_msg):
    result = {}
    result["tc_name"] = tcname
    result["status"] = status
    result["error_msg"] = error_msg
    logging.info(f"*************** Test Result: {result} ****************")
    results.append(result)


def print_result_summary(results):
    logging.info("Show Platform NPU Testcases Summary: ")
    for res in results:
        logging.info(res)


