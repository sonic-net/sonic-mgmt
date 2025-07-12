import logging


def _run_cmd_in_ssh(ssh, cmd, timeout=180):
    """
    Run a command in remote host
    """

    if isinstance(cmd, str):
        cmd_str = cmd
    elif isinstance(cmd, list):
        cmd_str = ';'.join(cmd)
    else:
        raise ValueError(f"command passed is neither list or str, cannot create command string. cmd: {cmd}, type: {type(cmd)}")

    # run command inside the container
    stdin, stdout, stderr = ssh.exec_command(cmd_str, timeout=timeout)

    # to prevent buffer blockage
    cmd_output = stdout.read().decode()
    cmd_error = stderr.read().decode()

    # get the exit status
    exit_status = stdout.channel.recv_exit_status()

    logging.info(f"Output for command '{cmd_str}': exit_status:{exit_status}\nstdout: {cmd_output}\nstderr: {cmd_error}")
    return cmd_output, cmd_error, exit_status

def _run_cmd_in_ssh_container(ssh, container_name, cmd, timeout=180):
    """
    Run a command in container
    """

    if isinstance(cmd, str):
        cmd_str = cmd
    elif isinstance(cmd, list):
        cmd_str = ';'.join(cmd)
    else:
        raise ValueError(f"command passed is neither list or str, cannot create command string. cmd: {cmd}, type: {type(cmd)}")
    # Escape internal double quotes for safe shell execution
    cmd_str = cmd_str.replace('"', '\\"')
    # run command inside the container
    docker_exec_cmd = f'docker exec {container_name} sh -c "{cmd_str}"'
    return _run_cmd_in_ssh(ssh, docker_exec_cmd, timeout)
