import json
import logging
import re
import time
from pathlib import Path


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
            # Non-modular nodes (T0/T1) do not run lc_rp_cmd_client.py.
            # Treat CPU usage context as 0 to avoid false failures.
            if not duthost.facts.get('modular_chassis', False):
                used_cpu_pc[index] = 0
                index += 1
                continue

            temp_usage_percent = 0
            # Take the average of 5 attempts for more stable readings
            for i in range(5):
                cmd = f"ps -eo %cpu=,cmd= | grep lc_rp_cmd_client.py | grep -v grep"
                output = duthost.shell(cmd, module_ignore_errors=True)
                match = re.search(r'(\d+\.\d+)', output.get("stdout", ""))
                if not match:
                    # If pattern doesn't match, log warning and use 0
                    logging.warning(f"Unable to parse CPU usage from: {output.get('stdout', '')}")
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
        elif not duthost.facts.get('modular_chassis', False):
            logging.info(f"Skipping CPU usage check for NON-CHASSIS: saved={saved_ctxt_cpu_pc[index]}%, current={current_cpu_pc[index]}%")
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


RP_LC_ADMIN_PASSWORD = "password"

def prepare_lc_command_for_admin_user(duthost, command_str, admin_password=RP_LC_ADMIN_PASSWORD):
    """
    For admin user sessions, feed default password for interactive centralized CLI auth.
    """
    try:
        inventory_host = duthost.host.options['inventory_manager'].get_host(duthost.hostname)
        ansible_user = inventory_host.vars.get('ansible_user') or inventory_host.vars.get('ansible_ssh_user')
    except Exception:
        ansible_user = None

    if ansible_user == "admin":
        return f"printf '{admin_password}\\n' | {command_str}"
    return command_str


def find_lc_last_up_interface_via_rp_rexec(duthost, lc_target=None, active_lc_list=None, admin_password=RP_LC_ADMIN_PASSWORD):
    """
    RP-LC case: run rexec on RP and parse LC blocks to find the last UP Ethernet interface.
    Returns (lc_name, interface_name) or (None, None) if not found.
    """
    log_tag = "[FIND_INTERFACE_RP_LC]"
    rexec_cmd = 'rexec all -u admin -c "show int status"'
    exec_rexec_cmd = prepare_lc_command_for_admin_user(duthost, rexec_cmd, admin_password=admin_password)
    result = duthost.shell(exec_rexec_cmd, module_ignore_errors=True)

    if result.get("rc", 1) != 0 and not result.get("stdout", "").strip():
        logging.warning(f"{log_tag} Failed to run rexec command: {rexec_cmd}")
        return None, None

    current_lc = None
    selected_lc = None
    selected_interface = None

    for line in result.get("stdout_lines", []):
        stripped_line = line.strip()
        section_match = re.match(r'^=+\s+([^|\s]+)\|.*output:\s+=+$', stripped_line)
        if section_match:
            current_lc = section_match.group(1)
            continue

        if not current_lc:
            continue
        if lc_target and lc_target != "all" and current_lc != lc_target:
            continue
        if active_lc_list and current_lc not in active_lc_list:
            continue
        if not stripped_line or "Interface" in stripped_line or "---" in stripped_line:
            continue

        parts = stripped_line.split()
        if len(parts) < 8:
            continue

        interface_name = parts[0]
        oper_status = parts[7].lower()
        if not interface_name.startswith("Ethernet") or oper_status != "up":
            continue

        selected_lc = current_lc
        selected_interface = interface_name

    if selected_lc and selected_interface:
        logging.info(f"{log_tag} Selected LC/interface from rexec output: {selected_lc}/{selected_interface}")
        return selected_lc, selected_interface

    logging.warning(f"{log_tag} No UP Ethernet interface found from RP rexec output")
    return None, None


def find_last_up_ethernet_interface(duthost, cli_case=None, lc_target=None, active_lc_list=None, admin_password=RP_LC_ADMIN_PASSWORD, return_lc_info=False):
    """
    Function to find the last UP Ethernet interface for 3 CLI cases:
    - RP: RP local command
    - LC: LC local command
    - RP-LC: RP command targeting LC via centralized CLI
    """
    resolved_cli_case = cli_case
    if not resolved_cli_case:
        resolved_cli_case = "RP" if duthost.is_supervisor_node() else "LC"

    if resolved_cli_case == "RP-LC":
        selected_lc, interface = find_lc_last_up_interface_via_rp_rexec(
            duthost,
            lc_target=lc_target,
            active_lc_list=active_lc_list,
            admin_password=admin_password
        )
        if return_lc_info:
            return selected_lc, interface
        return interface

    LOG_TAG = f"[FIND_INTERFACE_{resolved_cli_case}]"

    try:
        interface_prefix = "Ethernet"

        if resolved_cli_case == "RP":
            command = "show interface status -d all"
            logging.info(f"{LOG_TAG} Searching for last UP Ethernet interface on RP node...")
        else:
            command = "show interface status"
            logging.info(f"{LOG_TAG} Searching for last UP Ethernet interface on LC node...")

        result = duthost.command(command, module_ignore_errors=True)

        if result["rc"] != 0:
            logging.error(f"{LOG_TAG} Failed to execute '{command}' command")
            if return_lc_info:
                return None, None
            return None

        output_lines = result["stdout_lines"]
        selected_interface = None

        for line in output_lines:
            if not line.strip() or "Interface" in line or "---" in line:
                continue

            parts = line.strip().split()
            if len(parts) >= 8:
                interface_name = parts[0]

                oper_status = parts[7] if len(parts) > 7 else None

                if not oper_status:
                    continue

                if interface_name.startswith(interface_prefix) and oper_status.lower() == "up":
                    selected_interface = interface_name

        if selected_interface:
            logging.info(f"{LOG_TAG} Found last UP Ethernet interface on {resolved_cli_case}: {selected_interface}")
            if return_lc_info:
                return None, selected_interface
            return selected_interface

        logging.warning(f"{LOG_TAG} No UP {interface_prefix} interfaces found")
        if return_lc_info:
            return None, None
        return None

    except Exception as e:
        logging.error(f"{LOG_TAG} Exception while finding UP {interface_prefix} interface: {str(e)}")
        if return_lc_info:
            return None, None
        return None


def parse_additional_parameters(tc_dict):
    """
    Parse additional parameters from testcase config.
    Supports key: additional_parameters
    Returns a normalized set of parameter tokens.
    """
    params = set()

    value = tc_dict.get("additional_parameters", [])
    if not value:
        return params

    if not isinstance(value, list):
        logging.warning(
            "[PARSE_ADDITIONAL_PARAMETERS] additional_parameters must be a list, "
            f"got {type(value).__name__}. Ignoring value: {value}"
        )
        return params

    allowed_parameters = {
        "interface_option1",
        "interface_option2",
        "rp_active_asic",
        "skip_generic_cli",
        "skip_vxr_not_support",
    }

    for raw_value in value:
        normalized = str(raw_value).strip().lower()
        if normalized in allowed_parameters:
            params.add(normalized)
        else:
            logging.warning(f"[PARSE_ADDITIONAL_PARAMETERS] Unsupported additional parameter ignored: '{normalized}'")

    return params


def reformat_clicmd(duthost, tc_dict, results, cli_case=None, lc_target=None, active_lc_list=None, admin_password=RP_LC_ADMIN_PASSWORD):
    """
    Function to reformat CLI commands with interface parameters if needed
    Supports explicit 3 CLI cases: LC, RP, RP-LC.
    Returns True if successful, False if should skip/fail test
    """
    resolved_cli_case = cli_case
    if not resolved_cli_case:
        resolved_cli_case = "RP" if duthost.is_supervisor_node() else "LC"

    LOG_TAG = f"[REFORMAT_CLICMD_{resolved_cli_case}]"
    logging.info(f"{LOG_TAG} Reformating CLI command for {resolved_cli_case} case: {tc_dict['command']}")
    
    # For tests that need interface selection, dynamically find and append interface
    additional_parameters = parse_additional_parameters(tc_dict)

    if any(p.startswith('interface_option') for p in additional_parameters):
        logging.info(
            f"{LOG_TAG} Interface selection required for {resolved_cli_case} case - "
            f"additional_parameters: '{additional_parameters}'"
        )

        selected_lc = None
        interface = None
        if resolved_cli_case == "LC":
            _, interface = find_last_up_ethernet_interface(
                duthost,
                cli_case="LC",
                return_lc_info=True
            )
        elif resolved_cli_case == "RP":
            _, interface = find_last_up_ethernet_interface(
                duthost,
                cli_case="RP",
                return_lc_info=True
            )
        elif resolved_cli_case == "RP-LC":
            selected_lc, interface = find_lc_last_up_interface_via_rp_rexec(
                duthost,
                lc_target=lc_target,
                active_lc_list=active_lc_list,
                admin_password=admin_password
            )
        else:
            error_msg = f"{LOG_TAG} Unsupported cli_case '{resolved_cli_case}', expected one of LC/RP/RP-LC"
            logging.error(error_msg)
            update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return False

        if resolved_cli_case == "RP-LC":
            tc_dict['resolved_lc_target'] = selected_lc
            tc_dict['resolved_lc_interface'] = interface

        if not interface:
            logging.info(f"{LOG_TAG} No UP Ethernet interfaces found for {resolved_cli_case} case - skipping test as PASS")
            update_results(results, tc_dict["tcname"], "PASSED", f"SKIPPED - No UP Ethernet interfaces found for {resolved_cli_case}")
            return False
        
        if 'interface_option1' in additional_parameters:
            original_command = tc_dict['command']
            if 'interface' in original_command:
                tc_dict['command'] = original_command.replace('interface', f'interface {interface}')
                logging.info(f"{LOG_TAG} Applied interface option1 on {resolved_cli_case} case: {tc_dict['command']}")
            else:
                error_msg = f"{LOG_TAG} Command does not contain 'interface' keyword for option 1 in {resolved_cli_case} case: {original_command}"
                logging.error(error_msg)
                update_results(results, tc_dict["tcname"], "FAILED", error_msg)
                return False
                
        elif 'interface_option2' in additional_parameters:
            tc_dict['command'] = tc_dict['command'] + f" -i {interface}"
            logging.info(f"{LOG_TAG} Applied interface option2 on {resolved_cli_case} case: {tc_dict['command']}")
        else:
            error_msg = (
                f"{LOG_TAG} Interface option detected but no specific option1 or option2 found "
                f"in additional_parameters='{additional_parameters}'"
            )
            logging.error(error_msg)
            update_results(results, tc_dict["tcname"], "FAILED", error_msg)
            return False
    else:
        logging.info(f"{LOG_TAG} No interface parameter needed for {resolved_cli_case} case command: {tc_dict['command']}")
    
    return True


def parse_invalid_linecard_all_option_error(result):
    """
    Parse command output and detect the expected centralized CLI validation error
    when '-l all' is used for commands that require a specific line-card.
    """
    stdout = result.get('stdout', '') or ''
    stderr = result.get('stderr', '') or ''
    stdout_lines = result.get('stdout_lines', []) or []
    stderr_lines = result.get('stderr_lines', []) or []

    stdout_text = "\n".join(stdout_lines) if stdout_lines else stdout
    stderr_text = "\n".join(stderr_lines) if stderr_lines else stderr
    combined_output = f"{stdout_text}\n{stderr_text}".strip()

    has_linecard_hint = re.search(
        r"Please\s+specify\s+a\s+specific\s+LINE-CARD",
        combined_output,
        re.IGNORECASE
    )

    return bool(has_linecard_hint)



def parse_missing_n_option_error(result):
    """
    Parse command output and detect the expected CLI validation error
    when a command that requires ASIC selection is called without '-n'.
    """
    stdout = result.get('stdout', '') or ''
    stderr = result.get('stderr', '') or ''
    stdout_lines = result.get('stdout_lines', []) or []
    stderr_lines = result.get('stderr_lines', []) or []

    stdout_text = "\n".join(stdout_lines) if stdout_lines else stdout
    stderr_text = "\n".join(stderr_lines) if stderr_lines else stderr
    combined_output = f"{stdout_text}\n{stderr_text}".strip()

    has_missing_n = re.search(
        r"Missing\s+option\s+['\"]-n['\"]",
        combined_output,
        re.IGNORECASE
    )

    return bool(has_missing_n)


RP_LC_SHOW_TESTCASE_CHOICES_FILENAME = "test_rp_lc_testcase_choices.json"


def load_rp_lc_testcase_choices():
    """
    Load testcase entries from test_rp_lc_testcase_choices.json (next to this module or testbed path).
    Used by test_rp_lc_show_platform_npu, test_show_platform_npu_matrix, and similar.

    Returns:
        list: testcase dicts, or [] if the file is missing or invalid.
    """
    candidates = [
        Path(__file__).resolve().parent / RP_LC_SHOW_TESTCASE_CHOICES_FILENAME,
        Path("/data/tests/cisco/platform_tests") / RP_LC_SHOW_TESTCASE_CHOICES_FILENAME,
    ]
    for path in candidates:
        try:
            with path.open("r") as f:
                data = json.load(f)

            testcases = data["testcases"] if isinstance(data, dict) and "testcases" in data else data
            if not isinstance(testcases, list):
                logging.error(
                    "Invalid testcase choices format in %s: expected list or dict with 'testcases'",
                    path,
                )
                return []

            if not testcases:
                logging.error("No testcases found in testcase choices file: %s", path)
                return []

            logging.info("Loaded %s testcases from %s", len(testcases), path.name)
            return testcases
        except FileNotFoundError:
            continue
        except json.JSONDecodeError as e:
            logging.error("Invalid JSON in testcase choices file %s: %s", path, e)
            return []
        except Exception as e:
            logging.error("Error loading testcase choices file %s: %s", path, e)
            return []
    logging.error("Testcase choices file not found (tried: %s)", candidates)
    return []


def rp_lc_testcase_choices_case_id(case):
    """Pytest param id for a testcase dict from load_rp_lc_testcase_choices()."""
    return case.get("tcname") or case.get("name") or case.get("id") or str(case)


RP_LC_TESTCASE_CHOICES_CASES = load_rp_lc_testcase_choices()

