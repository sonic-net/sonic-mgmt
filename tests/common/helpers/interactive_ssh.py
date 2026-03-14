import logging
import re
import socket
import time

from paramiko import SSHClient, AutoAddPolicy


def exec_interactive_ssh(ssh_host, username, password, command, expect_pattern=None, response="",
                         timeout=30, read_delay=1, logger=None, host_for_error=None, debug=False):
    """Execute an interactive command over SSH and optionally handle prompt/response flows."""
    log = logger or logging.getLogger(__name__)

    ssh_client = None
    output = ""
    pattern_found = None

    try:
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        ssh_client.connect(
            ssh_host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False
        )

        shell = ssh_client.invoke_shell()
        time.sleep(read_delay)

        if shell.recv_ready():
            shell.recv(65535)

        if not command.endswith('\n'):
            command += '\n'
        shell.send(command)
        if debug:
            log.debug(f"Sent command: {command.strip()}")

        start_time = time.time()

        if expect_pattern:
            pattern_found = False
            compiled_pattern = re.compile(expect_pattern)

            while time.time() - start_time < timeout:
                time.sleep(0.5)

                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    if debug:
                        log.debug(f"Received chunk: {chunk[:100]}")

                    if compiled_pattern.search(output):
                        pattern_found = True
                        if debug:
                            log.debug(f"Pattern '{expect_pattern}' found in output")

                        if not response.endswith('\n'):
                            response += '\n'
                        shell.send(response)
                        if debug:
                            log.debug(f"Sent response: {response.strip()}")
                        time.sleep(read_delay)

                        time.sleep(read_delay)
                        while shell.recv_ready():
                            output += shell.recv(4096).decode('utf-8', errors='ignore')
                            time.sleep(0.2)
                        break

            if not pattern_found:
                log.warning(f"Pattern '{expect_pattern}' not found within {timeout}s timeout")
                while shell.recv_ready():
                    output += shell.recv(4096).decode('utf-8', errors='ignore')
                    time.sleep(0.2)
        else:
            last_data_time = time.time()
            idle_timeout = min(max(timeout * 0.2, 30), 120)

            if debug:
                log.debug(f"No pattern expected - will wait up to {idle_timeout}s of idle time or {timeout}s total")

            shell.settimeout(0.5)

            while time.time() - start_time < timeout:
                try:
                    chunk = shell.recv(4096)
                    if chunk:
                        output += chunk.decode('utf-8', errors='ignore')
                        last_data_time = time.time()
                        if debug:
                            log.debug(f"Received chunk: {chunk[:100]}")
                    elif shell.exit_status_ready():
                        if debug:
                            log.debug("Channel EOF - command completed")
                        break
                except socket.timeout:
                    idle_time = time.time() - last_data_time
                    if idle_time > idle_timeout:
                        if debug:
                            log.debug(
                                f"No data received for {idle_time:.1f}s (>{idle_timeout}s idle timeout) - "
                                "command appears complete"
                            )
                        break
                    if shell.closed:
                        if debug:
                            log.debug("Channel closed - command completed")
                        break
                except Exception as error:
                    log.warning(f"Exception while reading: {error}")
                    break

            shell.settimeout(0.2)
            for _ in range(5):
                try:
                    chunk = shell.recv(4096)
                    if chunk:
                        output += chunk.decode('utf-8', errors='ignore')
                        if debug:
                            log.debug(f"Final read: received {len(chunk)} bytes")
                except (socket.timeout, Exception):
                    pass

        shell.close()

        log.info(f"Interactive command completed. Output length: {len(output)} chars")
        if pattern_found is not None:
            log.info(f"Expected pattern found: {pattern_found}")

        return {
            'failed': False,
            'rc': 0,
            'stdout': output,
            'stderr': '',
            'pattern_found': pattern_found
        }

    except Exception as error:
        error_msg = f'Interactive command failed: {str(error)}'
        error_host = host_for_error or ssh_host
        log.error(f"exec_interactive error on {error_host}: {error_msg}")
        return {
            'failed': True,
            'rc': 1,
            'stdout': output,
            'stderr': error_msg
        }
    finally:
        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass
