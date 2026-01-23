import os
import sys
import argparse
import subprocess
import shutil
import logging
import json
import textwrap
from typing import Dict, Optional

# Standard directory name for the SONiC test workspaces
SONIC_WORKSPACES_DIR = "sonic_test_workspaces"

# Default proxy configuration for the UCS Host
UCS_PROXY_DEFAULTS = {
    "no_proxy": ".cisco.com",
}

# Default proxy configuration for the SONiC Management Container
SONIC_MGMT_CONTAINER_PROXY_DEFAULTS = {
    "no_proxy": ".cisco.com",
}

class SonicTestEnvSetup:
    """
    A comprehensive automation class for setting up SONiC test environments on UCS Linux servers.
    Handles UCS host configuration (proxies, drivers, images) and SONiC environment instantiation.
    """

    def __init__(self, args):
        """
        Initializes the SonicTestEnvSetup class.

        Args:
            args (argparse.Namespace): Parsed command-line arguments.
        """
        self.args = args
        
        # Initialize Logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger(__name__)

        # Determine context for logging
        command = getattr(args, 'command', 'unknown')
        subcommand = getattr(args, 'subcommand', '')
        self.logger.info(f"Initialized SonicTestEnvSetup. Command: {command} {subcommand}")

    # ==============================================================================
    # Shared Helper Methods
    # ==============================================================================

    def _download_file(self, url: str, dest_path: str):
        """
        Universal helper to download a file using wget.
        Assumes proxy environment variables are already set if needed.
        """
        try:
            self.logger.info(f"Downloading {url} to {dest_path}...")
            subprocess.run(
                ["wget", "-O", dest_path, url],
                check=True
            )
            self.logger.info(f"Download completed: {dest_path}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to download file from {url}: {e}")
            raise

    def _load_docker_image_from_url(self, image_url: str):
        """
        Universal helper to download and load a Docker image from a URL.
        Handles temporary file management.
        """
        filename = image_url.split('/')[-1]
        temp_path = os.path.join("/tmp", filename)

        try:
            # 1. Download
            self._download_file(image_url, temp_path)

            # 2. Load
            self.logger.info(f"Loading docker image from {temp_path}...")
            subprocess.run(
                ["docker", "load", "-i", temp_path],
                check=True
            )
            self.logger.info("Docker image loaded successfully.")

        except Exception as e:
            self.logger.error(f"Failed to load docker image from {image_url}: {e}")
            raise
        finally:
            # 3. Cleanup
            if os.path.exists(temp_path):
                os.remove(temp_path)
                self.logger.info(f"Cleaned up temporary file: {temp_path}")

    # ==============================================================================
    # UCS Setup Methods (Command: ucs)
    # ==============================================================================

    def _configure_ucs_proxies(self):
        """
        Configures proxy settings in the user's .bashrc file AND the current process environment.
        Removes ANY existing export lines for the target proxy variables in .bashrc 
        and appends a new block.
        """
        # Determine settings: Use provided JSON or fall back to defaults
        proxy_settings = self.args.proxy if self.args.proxy else UCS_PROXY_DEFAULTS

        bashrc_path = os.path.expanduser("~/.bashrc")
        start_marker = "# --- SONiC Automation Proxies ---"
        end_marker = "# ------------------------------"
        
        # Keys to explicitly remove/update (both lower and upper case)
        target_keys = ["http_proxy", "https_proxy", "ftp_proxy", "no_proxy"]
        
        self.logger.info(f"Configuring UCS proxies in {bashrc_path}...")

        try:
            # 1. Read existing content
            if os.path.exists(bashrc_path):
                with open(bashrc_path, "r") as f:
                    lines = f.readlines()
            else:
                lines = []
                self.logger.warning(f"{bashrc_path} not found. Creating new file.")

            # 2. Filter out existing proxy exports and old markers
            new_lines = []
            for line in lines:
                stripped = line.strip()
                
                # Skip old markers
                if stripped == start_marker or stripped == end_marker:
                    continue
                
                # Check if line is an export of one of our target keys
                is_target_proxy = False
                if stripped.startswith("export "):
                    # Extract variable name: "export http_proxy=..." -> "http_proxy"
                    parts = stripped.split('=')
                    if parts:
                        var_decl = parts[0] # "export http_proxy"
                        var_name = var_decl.replace("export ", "").strip()
                        
                        if var_name.lower() in target_keys:
                            is_target_proxy = True
                
                if not is_target_proxy:
                    new_lines.append(line)

            # 3. Append new proxy block
            if new_lines and not new_lines[-1].endswith('\n'):
                new_lines.append('\n')

            new_lines.append(f"{start_marker}\n")
            
            for key, value in proxy_settings.items():
                # Write to file
                new_lines.append(f"export {key.lower()}={value}\n")
                new_lines.append(f"export {key.upper()}={value}\n")
                
                # Apply to CURRENT process environment immediately
                os.environ[key.lower()] = value
                os.environ[key.upper()] = value
            
            new_lines.append(f"{end_marker}\n")

            # 4. Write back to file
            with open(bashrc_path, "w") as f:
                f.writelines(new_lines)
            
            self.logger.info(f"Successfully updated {bashrc_path}.")
            self.logger.info("Proxies have also been applied to the current script execution environment.")

        except Exception as e:
            self.logger.error(f"Failed to configure proxies in .bashrc: {e}")
            raise

    def _setup_veos_image(self):
        """
        Downloads a vEOS image from the provided URL and places it in ~/veos-vm/images.
        """
        # Define target directory relative to current user's home
        target_dir = os.path.expanduser("~/veos-vm/images")

        self.logger.info(f"Setting up vEOS image in {target_dir}...")

        # 1. Ensure directory exists
        try:
            os.makedirs(target_dir, exist_ok=True)
        except OSError as e:
            self.logger.error(f"Failed to create directory {target_dir}: {e}")
            raise

        # 2. Determine destination path
        filename = self.args.image_url.split('/')[-1]
        dest_path = os.path.join(target_dir, filename)

        # 3. Download file
        try:
            self._download_file(self.args.image_url, dest_path)
            self.logger.info(f"vEOS image successfully downloaded to {dest_path}")
        except Exception as e:
            self.logger.error(f"Failed to setup vEOS image: {e}")
            raise

    def _apply_intel_driver_workaround(self):
        """
        Applies the workaround for the Intel i40e driver bug that blocks LLDP packets.
        Executes a shell loop with sudo to write 'lldp stop' to the driver debug command files.
        Uses sudo -S to accept password from stdin.
        """
        self.logger.info("Applying Intel i40e driver LLDP workaround...")

        # Construct the shell command
        cmd = [
            "sudo", "-S", "-p", "", "sh", "-c",
            'for i in /sys/kernel/debug/i40e/*; do if [ -d "$i" ]; then echo "lldp stop" > "$i/command"; echo "Applied to $i"; fi; done'
        ]

        # Log the command safely
        safe_log_cmd = f"echo '<HIDDEN_PASSWORD>' | {' '.join(cmd)}"
        self.logger.info(f"Executing command: {safe_log_cmd}")

        try:
            # Run the command, passing the password securely via stdin
            password_input = f"{self.args.sudo_password}\n"

            result = subprocess.run(
                cmd,
                input=password_input, # Pass password here
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.logger.info("Workaround applied successfully.")
            self.logger.debug(f"Command output: {result.stdout}")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to apply Intel driver workaround: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            raise

    def _apply_cpu_softlock_workaround(self):
        """
        Applies the workaround for CPU soft lockup errors by increasing the kernel watchdog threshold.
        Writes config to /etc/sysctl.d/ and reloads sysctl.
        Uses sudo -S to accept password from stdin.
        """
        self.logger.info("Applying CPU soft lockup workaround (watchdog_thresh=20)...")

        config_file = "/etc/sysctl.d/99-watchdog_thresh.conf"
        password_input = f"{self.args.sudo_password}\n"

        try:
            # 1. Write configuration
            # We use sh -c to handle the redirection > with sudo privileges
            self.logger.info(f"Writing configuration to {config_file}...")
            write_cmd = [
                "sudo", "-S", "-p", "", "sh", "-c",
                f'echo "kernel.watchdog_thresh=20" > {config_file}'
            ]

            self.logger.info(f"Executing write command: echo '<HIDDEN_PASSWORD>' | {' '.join(write_cmd)}")

            subprocess.run(
                write_cmd,
                input=password_input,
                text=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # 2. Reload sysctl settings
            self.logger.info("Reloading sysctl settings...")
            reload_cmd = ["sudo", "-S", "-p", "", "sysctl", "-p", config_file]

            self.logger.info(f"Executing reload command: echo '<HIDDEN_PASSWORD>' | {' '.join(reload_cmd)}")

            subprocess.run(
                reload_cmd,
                input=password_input,
                text=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            self.logger.info("CPU soft lockup workaround applied successfully.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to apply CPU soft lockup workaround: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            raise

    # ==============================================================================
    # SONiC Environment Methods (Command: sonic_test_env)
    # ==============================================================================

    def _remove_workspace_resources(self):
        """
        Removes workspace resources: forcibly removes the specific Docker container
        and the specific workspace directory.
        Does NOT remove the Docker image to preserve bandwidth for other workspaces.
        """
        container_name = self.args.workspace_name
        # Target specific workspace directory: ~/sonic_test_workspaces/{workspace_name}
        workspace_dir = os.path.expanduser(f"~/{SONIC_WORKSPACES_DIR}/{self.args.workspace_name}")

        self.logger.info(f"Starting removal. Target Directory: {workspace_dir}, Target Container: {container_name}")

        # 1. Remove Docker Container
        try:
            self.logger.info(f"Attempting to remove container: {container_name}")
            # check=False allows the command to fail silently if container doesn't exist
            result = subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode == 0:
                self.logger.info(f"Successfully removed container: {container_name}")
            else:
                # Docker returns non-zero if container doesn't exist, which is fine
                self.logger.info(f"Container {container_name} not found or already removed.")
        except Exception as e:
            self.logger.error(f"Error occurred while removing container: {e}")
            raise

        # 2. Remove Specific Workspace Directory
        if os.path.exists(workspace_dir):
            try:
                self.logger.info(f"Removing directory: {workspace_dir}")
                shutil.rmtree(workspace_dir)
                self.logger.info(f"Successfully removed {workspace_dir}")
            except Exception as e:
                self.logger.error(f"Failed to remove directory {workspace_dir}: {e}")
                raise
        else:
            self.logger.info(f"Directory {workspace_dir} does not exist. No cleanup needed.")

    def _setup_git_repository(self):
        """
        Clones the Git repository into the specific workspace directory.
        Handles URL construction with authentication tokens.
        SECURITY: Immediately updates the git remote URL to remove the token after cloning.
        """
        # Target directory: ~/sonic_test_workspaces/{workspace_name}
        parent_dir = os.path.expanduser(f"~/{SONIC_WORKSPACES_DIR}/{self.args.workspace_name}")
        
        self.logger.info(f"Setting up Git repository. Target Directory: {parent_dir}")

        # 1. Create Directory Structure
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except OSError as e:
            self.logger.error(f"Failed to create directory {parent_dir}: {e}")
            raise

        # 2. Construct URLs
        # Clean the input URL: remove 'https://' or 'http://' if present
        clean_url_body = self.args.git_repo_url.replace("https://", "").replace("http://", "")
        
        # URL for Cloning (With Token)
        auth_url = f"https://{self.args.git_user}:{self.args.git_token}@{clean_url_body}"
        
        # URL for Remote Config (Clean, No Token)
        final_clean_url = f"https://{clean_url_body}"

        # Masked URL for logging
        masked_url = f"https://{self.args.git_user}:<HIDDEN_TOKEN>@{clean_url_body}"

        # 3. Clone Repository
        try:
            self.logger.info(f"Cloning branch '{self.args.git_branch}' from {masked_url}...")
            
            cmd = ["git", "clone", "-b", self.args.git_branch, auth_url]
            
            subprocess.run(
                cmd,
                cwd=parent_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.logger.info("Repository cloned successfully.")

            # 4. Redact Token from Remote URL
            # We need to find the specific folder git created to run the git config command inside it.
            # Usually it's the last part of the URL.
            repo_name = clean_url_body.split('/')[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]

            repo_path = os.path.join(parent_dir, repo_name)

            if os.path.isdir(repo_path):
                self.logger.info(f"Updating git remote to remove credentials in {repo_path}...")
                subprocess.run(
                    ["git", "remote", "set-url", "origin", final_clean_url],
                    cwd=repo_path,
                    check=True
                )
                self.logger.info("Git remote URL successfully sanitized (token removed).")
            else:
                self.logger.warning(f"Could not locate repo directory at {repo_path} to sanitize remote URL.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Git operation failed. Return code: {e.returncode}")
            self.logger.error(f"Error output: {e.stderr}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during git setup: {e}")
            raise

    def _manage_docker_image(self):
        """
        Ensures the required Docker image exists locally.
        Checks for the image based on the filename from the URL.
        If missing, uses the universal helper to download and load it.
        """
        # Extract filename from URL: "sonic-mgmt_...mix.gz"
        filename_with_ext = self.args.sonic_mgmt_image_url.split('/')[-1]
        
        # Remove extensions to get the likely image name for checking
        image_identifier = filename_with_ext.split('.')[0]
        
        self.logger.info(f"Checking for local existence of image matching identifier: '{image_identifier}'...")

        # 1. Check if image exists locally
        try:
            result = subprocess.run(
                ["docker", "images"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if image_identifier in result.stdout:
                self.logger.info(f"Image '{image_identifier}' found locally. Skipping download.")
                return  # <--- EXIT HERE if found
            else:
                self.logger.info(f"Image '{image_identifier}' not found locally. Proceeding to download.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check docker images: {e}")
            raise

        # 2. Download and Load (using helper)
        self._load_docker_image_from_url(self.args.sonic_mgmt_image_url)

    def _launch_sonic_mgmt_container(self):
        """
        Constructs and executes the docker run command to launch the SONiC management container.
        Dynamically detects the correct code mount path based on repository structure.
        """
        container_name = self.args.workspace_name
        
        # Base workspace directory: ~/sonic_test_workspaces/{workspace_name}
        workspace_dir = os.path.expanduser(f"~/{SONIC_WORKSPACES_DIR}/{self.args.workspace_name}")
        
        self.logger.info(f"Determining code mount path. Scanning directory: {workspace_dir}")

        try:
            # 1. Identify the repository directory created by git clone
            subdirs = [d for d in os.listdir(workspace_dir) if os.path.isdir(os.path.join(workspace_dir, d))]
            if not subdirs:
                raise FileNotFoundError("No directory found inside workspace folder. Git clone might have failed.")
            
            # The directory created by git clone (e.g., 'sonic-test', 'sonic-mgmt', or 'msft-sonic-mgmt')
            repo_dir_name = subdirs[0]
            repo_full_path = os.path.join(workspace_dir, repo_dir_name)
            
            # 2. Check for the 3 supported cases
            
            # Case 1: Nested sonic-mgmt (e.g., .../sonic-test/sonic-mgmt)
            # This handles the case where the repo is 'sonic-test' containing 'sonic-mgmt'
            nested_path = os.path.join(repo_full_path, "sonic-mgmt")
            
            if os.path.isdir(nested_path):
                code_mount_path = nested_path
                self.logger.info(f"Detected Case 1: Nested sonic-mgmt found at {code_mount_path}")
            
            # Case 2: Repo is sonic-mgmt (e.g., .../sonic-mgmt)
            elif repo_dir_name == "sonic-mgmt":
                code_mount_path = repo_full_path
                self.logger.info(f"Detected Case 2: Repository root is sonic-mgmt at {code_mount_path}")
                
            # Case 3: Repo is msft-sonic-mgmt (e.g., .../msft-sonic-mgmt)
            elif repo_dir_name == "msft-sonic-mgmt":
                code_mount_path = repo_full_path
                self.logger.info(f"Detected Case 3: Repository root is msft-sonic-mgmt at {code_mount_path}")
            else:
                raise FileNotFoundError(f"Could not find valid sonic-mgmt path in {repo_full_path}")

        except Exception as e:
            self.logger.error(f"Error determining mount path: {e}")
            raise

        self.logger.info(f"Launching container: {container_name}")

        # Determine Image Name
        filename_with_ext = self.args.sonic_mgmt_image_url.split('/')[-1]
        image_identifier = filename_with_ext.split('.')[0]
        
        try:
            result = subprocess.run(
                f"docker images | grep {image_identifier}",
                shell=True,
                stdout=subprocess.PIPE,
                text=True
            )
            if not result.stdout:
                raise ValueError(f"Could not find docker image matching {image_identifier}")
            
            repo_name = result.stdout.strip().split()[0]
            full_image_name = f"{repo_name}:{self.args.sonic_mgmt_image_tag}"
            self.logger.info(f"Using Docker image: {full_image_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to identify docker image: {e}")
            raise

        # Determine Log Mount Dir
        log_mount = self.args.container_log_mount_dir if self.args.container_log_mount_dir else os.path.expanduser("~/test_logs")

        # Construct Docker Run Command
        cmd = [
            "docker", "run",
            "--name", container_name,
            "--net=host",
            "--privileged",
            "-v", f"{code_mount_path}:/data",
            "-v", f"{log_mount}:/run_logs",
            "-itd"
        ]

        # Add Proxy Env Vars
        container_proxies = self.args.container_proxy if self.args.container_proxy else SONIC_MGMT_CONTAINER_PROXY_DEFAULTS

        for key, value in container_proxies.items():
            cmd.extend(["-e", f"{key}={value}"])
            cmd.extend(["-e", f"{key.upper()}={value}"])

        # Add Image and Command
        cmd.append(full_image_name)
        cmd.append("bash")

        # Execute
        try:
            self.logger.info(f"Executing command: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            self.logger.info(f"Container {container_name} launched successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to launch container: {e}")
            raise

    # ==============================================================================
    # Main Execution Logic
    # ==============================================================================

    def run(self):
        """
        Executes the logic based on the parsed command and subcommand.
        """
        if self.args.command == "ucs":
            if self.args.subcommand == "setup_proxy":
                self._configure_ucs_proxies()
            elif self.args.subcommand == "setup_veos_image":
                self._setup_veos_image()
            elif self.args.subcommand == "load_docker_image":
                self._load_docker_image_from_url(self.args.image_url)
            elif self.args.subcommand == "apply_intel_driver_workaround":
                self._apply_intel_driver_workaround()
            elif self.args.subcommand == "apply_cpu_softlock_workaround":
                self._apply_cpu_softlock_workaround()

        elif self.args.command == "sonic_test_env":
            if self.args.subcommand == "create":
                # Ensure proxies are set for current execution (only relevant for 'create')
                container_proxies = self.args.container_proxy if self.args.container_proxy else SONIC_MGMT_CONTAINER_PROXY_DEFAULTS
                for key, value in container_proxies.items():
                    os.environ[key.lower()] = value
                    os.environ[key.upper()] = value

                # Execute Setup Sequence (Clean -> Git -> Image -> Launch)
                self._remove_workspace_resources()
                self._setup_git_repository()
                self._manage_docker_image()
                self._launch_sonic_mgmt_container()

            elif self.args.subcommand == "remove":
                # Execute Removal Only
                self._remove_workspace_resources()

def parse_arguments():
    """
    Parses command line arguments with nested subcommands structure.
    """
    parser = argparse.ArgumentParser(description="SONiC Test Environment Setup Automation")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Main command")

    # ==========================================
    # Command 1: ucs (Host Configuration)
    # ==========================================
    parser_ucs = subparsers.add_parser("ucs", help="Configure UCS Host (proxies, workarounds, docker images, veos images)")
    ucs_subparsers = parser_ucs.add_subparsers(dest="subcommand", required=True, help="UCS Setup Subcommands")

    # 1.a setup_proxy
    parser_proxy = ucs_subparsers.add_parser("setup_proxy", help="Configure UCS Host Proxies (.bashrc)")
    parser_proxy.add_argument(
        "--proxy",
        required=False, 
        type=json.loads, 
        help='JSON string of proxies for the UCS Host. If omitted, uses defaults.'
    )

    # 1.b setup_veos_image
    parser_veos = ucs_subparsers.add_parser("setup_veos_image", help="Download vEOS image to UCS and put them into ~/veos-vm/images")
    parser_veos.add_argument(
        "--image_url",
        required=True, 
        help="HTTP URL to the vEOS image file"
    )

    # 1.c load_docker_image
    parser_docker = ucs_subparsers.add_parser("load_docker_image", help="Download and load an arbitrary Docker image")
    parser_docker.add_argument(
        "--image_url",
        required=True, 
        help="HTTP URL to the Docker image tarball"
    )

    # 1.d apply_intel_driver_workaround
    parser_intel = ucs_subparsers.add_parser("apply_intel_driver_workaround", help="Apply Intel i40e LLDP workaround")
    parser_intel.add_argument(
        "--sudo_password",
        required=True,
        help="Sudo password for the UCS user"
    )

    # 1.e apply_cpu_softlock_workaround
    parser_cpu = ucs_subparsers.add_parser("apply_cpu_softlock_workaround", help="Apply CPU soft lockup workaround")
    parser_cpu.add_argument(
        "--sudo_password",
        required=True,
        help="Sudo password for the UCS user"
    )

    # ==========================================
    # Command 2: sonic_test_env (Workspace Management)
    # ==========================================
    parser_env = subparsers.add_parser("sonic_test_env", help="Manage SONiC Test Workspaces (Create/Remove)")
    env_subparsers = parser_env.add_subparsers(dest="subcommand", required=True, help="Workspace Actions")

    # 2.a create (Create/Setup Workspace)
    parser_create = env_subparsers.add_parser("create", help="Create and setup a new SONiC test workspace")
    parser_create.add_argument("--workspace_name", required=True, help="Unique identifier for the workspace. Used for directory name (~/sonic_test_workspaces/{workspace_name}) and container name.")
    parser_create.add_argument("--git_repo_url", default="wwwin-github.cisco.com/whitebox/sonic-test", help="Git repo URL")
    parser_create.add_argument("--git_branch", required=True, help="Git branch to clone")
    parser_create.add_argument("--git_user", required=True, help="Git username")
    parser_create.add_argument("--git_token", required=True, help="Git access token")
    parser_create.add_argument("--sonic_mgmt_image_url", required=True, help="URL to sonic-mgmt docker image")
    parser_create.add_argument("--sonic_mgmt_image_tag", default="latest", help="sonic mgmt docker image tag")
    parser_create.add_argument("--container_log_mount_dir", help="Log mount path (defaults to ~/test_logs if not set)")
    parser_create.add_argument(
        "--container_proxy",
        required=False,
        type=json.loads,
        help='JSON string of proxies for the Docker container.'
    )

    # 2.b remove (Delete Workspace)
    parser_remove = env_subparsers.add_parser("remove", help="Remove an existing workspace (Container and Directory)")
    parser_remove.add_argument(
        "--workspace_name",
        required=True,
        help="Unique identifier for the workspace to remove."
    )

    return parser.parse_args()

def main():
    # Check if no arguments were provided
    if len(sys.argv) == 1:
        help_msg = """
            ==============================================================================
            SONiC Test Environment Setup Script
            ==============================================================================
            Usage Examples:

            1. UCS Host Setup (One-time or Maintenance):
               -----------------------------------------
               python3 do_sonic_test_env_setup.py ucs setup_proxy \\
                   --proxy '{"http_proxy": "http://proxy.esl.cisco.com:80", "no_proxy": ".cisco.com"}'
               python3 do_sonic_test_env_setup.py ucs setup_veos_image --image_url "http://172.27.147.154/IMAGES/sonic-test-env/cEOS/cEOS64-lab-4.29.5M.tar"
               python3 do_sonic_test_env_setup.py ucs load_docker_image --image_url "http://172.27.147.154/IMAGES/sonic-test-env/debian/debian-bookworm.tar.gz"
               python3 do_sonic_test_env_setup.py ucs apply_intel_driver_workaround --sudo_password "pass"
               python3 do_sonic_test_env_setup.py ucs apply_cpu_softlock_workaround --sudo_password "pass"

            2. SONiC Test Environment Management:
               ----------------------------------
               a) Create/Setup a Workspace:
               python3 do_sonic_test_env_setup.py sonic_test_env create \\
                   --workspace_name "cicd_prod_202505" \\
                   --git_branch "master" \\
                   --git_user "cicd_user" \\
                   --git_token "ghp_AbCdEf123456" \\
                   --sonic_mgmt_image_url "http://172.27.147.154/IMAGES/sonic-test-env/sonic-mgmt/sept090425-sonic-mgmt.tar.gz" \\
                   --sonic_mgmt_image_tag "latest" \\                                     # (Optional) Defaults to 'latest'
                   --git_repo_url "wwwin-github.cisco.com/whitebox/sonic-test" \\         # (Optional) Defaults to 'whitebox/sonic-test'
                   --container_log_mount_dir "/home/sonic/test_logs" \\                   # (Optional) Defaults to /home/{user}/test_logs
                   --container_proxy '{"no_proxy": ".cisco.com"}'                         # (Optional) Defaults to '{"NO_PROXY": ".cisco.com", "no_proxy": ".cisco.com"}'

               b) Remove a Workspace:
               python3 do_sonic_test_env_setup.py sonic_test_env remove \\
                   --workspace_name "cicd_prod_202505"

            For detailed help, run:
               python3 do_sonic_test_env_setup.py ucs --help
               python3 do_sonic_test_env_setup.py sonic_test_env create --help
               python3 do_sonic_test_env_setup.py sonic_test_env remove --help
            ==============================================================================
            """
        print(textwrap.dedent(help_msg))
        sys.exit(1)

    args = parse_arguments()

    # Initialize and run
    automation = SonicTestEnvSetup(args)
    automation.run()

if __name__ == "__main__":
    main()
