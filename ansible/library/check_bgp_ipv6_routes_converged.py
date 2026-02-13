#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import json
import time
import logging
import datetime
from ansible.module_utils.debug_utils import config_module_logging
import gzip
import base64


# Constants
CONFIG_INTERFACE_COMMAND_TEMPLATE = "sudo config interface {action} {target}"
CONFIG_BGP_SESSIONS_COMMAND_TEMPLATE = "sudo config bgp {action} {target}"


def get_bgp_ipv6_routes(module):
    cmd = "docker exec bgp vtysh -c 'show ipv6 route bgp json'"
    rc, out, err = module.run_command(cmd, executable='/bin/bash', use_unsafe_shell=True)
    if rc != 0:
        module.fail_json(msg=f"Failed to get bgp routes: {err}")
    return json.loads(out)


def _perform_action_on_connections(module, action, connection_type, targets, all_neighbors):
    """
    Perform actions (shutdown/startup) on BGP sessions or interfaces.
    """
    # Action on BGP sessions
    if connection_type == "bgp_sessions":
        if all_neighbors:
            cmd = CONFIG_BGP_SESSIONS_COMMAND_TEMPLATE.format(action=action, target="all")
            _execute_command_on_dut(module, cmd)
        else:
            for session in targets:
                target_session = "neighbor " + session
                cmd = CONFIG_BGP_SESSIONS_COMMAND_TEMPLATE.format(action=action, target=target_session)
                _execute_command_on_dut(module, cmd)
        logging.info(f"BGP sessions {action} completed.")
    # Action on Interfaces
    elif connection_type == "ports":
        ports_str = ",".join(targets)
        cmd = CONFIG_INTERFACE_COMMAND_TEMPLATE.format(action=action, target=ports_str)
        _execute_command_on_dut(module, cmd)
        logging.info(f"Interfaces {action} completed.")
    else:
        logging.info("No valid connection type provided for %s.", action)


def _execute_command_on_dut(module, cmd):
    """Helper function to execute shell commands."""
    logging.info("Running command: %s", cmd)
    rc, out, err = module.run_command(cmd, executable="/bin/bash", use_unsafe_shell=True)
    if rc != 0:
        module.fail_json(msg=f"Command failed: {err}")
    logging.info("Command completed successfully.")


def compare_routes(running_routes, expected_routes):
    expected_set = set(expected_routes.keys())
    running_set = set(running_routes.keys())
    missing = expected_set - running_set
    extra = running_set - expected_set
    if missing or extra:
        if missing:
            logging.warning(f"Missing prefixes in running_routes: {list(missing)}")
        if extra:
            logging.warning(f"Extra prefixes in running_routes: {list(extra)}")
        return False

    nh_diff_prefixes = []
    for prefix, attr in expected_routes.items():
        except_nhs = [nh['ip'] for nh in attr[0]['nexthops']]
        running_nhs = [nh['ip'] for nh in running_routes[prefix][0]['nexthops'] if "active" in nh and nh["active"]]
        if set(except_nhs) != set(running_nhs):
            nh_diff_prefixes.append((prefix, except_nhs, running_nhs))
    if nh_diff_prefixes:
        for prefix, expected, running in nh_diff_prefixes:
            logging.warning(f"Prefix {prefix} nexthops not match, expected: {expected}, running: {running}")
        return False

    return True


def main():
    module = AnsibleModule(
        argument_spec=dict(
            expected_routes=dict(required=True, type='str'),
            shutdown_connections=dict(required=True, type='list', elements='str'),
            connection_type=dict(required=False, type='str', choices=['ports', 'bgp_sessions', 'none'], default='none'),
            shutdown_all_connections=dict(required=False, type='bool', default=False),
            timeout=dict(required=False, type='int', default=300),
            interval=dict(required=False, type='int', default=1),
            log_path=dict(required=False, type='str', default='/tmp'),
            compressed=dict(required=False, type='bool', default=False),
            action=dict(required=False, type='str', choices=['shutdown', 'startup', 'no_action'], default='no_action')
        ),
        supports_check_mode=False
    )
    if module.params['log_path']:
        config_module_logging("check_bgp_ipv6_routes_converged", log_path=module.params['log_path'])

    logging.info("Start to check bgp routes converged at %s", datetime.datetime.now().strftime("%H:%M:%S"))

    # check if need to decompress
    if module.params.get('compressed', False):
        # decompress
        compressed_bytes = base64.b64decode(module.params['expected_routes'])
        json_str = gzip.decompress(compressed_bytes).decode('utf-8')
        expected_routes = json.loads(json_str)
    else:
        expected_routes = json.loads(module.params['expected_routes'])

    shutdown_connections = module.params.get('shutdown_connections', [])
    connection_type = module.params.get('connection_type', 'none')
    shutdown_all_connections = module.params['shutdown_all_connections']
    timeout = module.params['timeout']
    interval = module.params['interval']
    action = module.params.get('action', 'no_action')

    # record start time
    start_time = time.time()
    logging.info("start time: %s", datetime.datetime.fromtimestamp(start_time).strftime("%H:%M:%S"))

    if not shutdown_connections or action == 'no_action':
        logging.info("No connections or action is 'no_action', skipping interface operation.")
    else:
        # interface operation based on action
        _perform_action_on_connections(module, action, connection_type, shutdown_connections, shutdown_all_connections)

    # Sleep some time to wait routes to be converged
    time.sleep(4)

    # check routes
    check_count = 0
    while True:
        check_count += 1
        logging.info(f"BGP routes check round: {check_count}")
        # record the time before getting routes in this round
        before_get_route_time = time.time()
        logging.info(f"Before get route time: "
                     f" {datetime.datetime.fromtimestamp(before_get_route_time).strftime('%H:%M:%S')}")
        running_routes = get_bgp_ipv6_routes(module)
        logging.info("Obtained the routes")
        if compare_routes(running_routes, expected_routes):
            # Use the time before getting routes as end_time when compare routes succeed to avoid including the time
            # spent on running # "docker exec bgp vtysh -c 'show ipv6 route bgp json'", which can take 6-8 seconds
            # with a large number of BGP routes. This ensures the end_time reflects the actual convergence moment.
            end_time = before_get_route_time
            logging.info("BGP routes converged at %s", datetime.datetime.fromtimestamp(end_time).strftime("%H:%M:%S"))
            module.exit_json(
                changed=False,
                converged=True,
                start_time=start_time,
                end_time=before_get_route_time
            )
        logging.info(f"Compare done at round: {check_count}")
        if before_get_route_time - start_time > timeout:
            end_time = before_get_route_time
            logging.info("BGP routes not converged at %s",
                         datetime.datetime.fromtimestamp(end_time).strftime("%H:%M:%S"))
            module.exit_json(
                changed=False,
                converged=False,
                msg="Timeout waiting for BGP routes to converge",
                start_time=start_time,
                end_time=end_time
            )
        time.sleep(interval)


if __name__ == '__main__':
    main()
