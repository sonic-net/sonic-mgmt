#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_container

short_description: manage Docker containers

description:
  - Manage the life cycle of Docker containers.
  - Supports check mode. Run with C(--check) and C(--diff) to view config difference and list of actions to be taken.
notes:
  - For most config changes, the container needs to be recreated. This means that the existing container has to be destroyed
    and a new one created. This can cause unexpected data loss and downtime. You can use the O(comparisons) option to prevent
    this.
  - If the module needs to recreate the container, it will only use the options provided to the module to create the new container
    (except O(image)). Therefore, always specify B(all) options relevant to the container.
  - When O(restart) is set to V(true), the module will only restart the container if no config changes are detected.
  - When specifying IPv6 addresses for networks, Docker since version 29 no longer returns the orignal address used
    when adding a container to a network, but normalizes them. The module will try to normalize IP addresses for comparison,
    but it uses the C(ipaddress) module from the Python 3 standard library for that. When using the module with Python 2,
    please install the L(ipaddress backport for Python 2.x, https://pypi.org/project/ipaddress/).
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: partial
    details:
      - When trying to pull an image, the module assumes this is never changed in check mode except when the image is not
        present on the Docker daemon.
      - This behavior can be configured with O(pull_check_mode_behavior).
  diff_mode:
    support: full
  idempotent:
    support: partial
    details:
      - If O(recreate=true) or O(restart=true) the module is not idempotent.

options:
  auto_remove:
    description:
      - Enable auto-removal of the container on daemon side when the container's process exits.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  blkio_weight:
    description:
      - Block IO (relative weight), between 10 and 1000.
    type: int
  capabilities:
    description:
      - List of capabilities to add to the container.
      - This is equivalent to C(docker run --cap-add), or the docker-compose option C(cap_add).
    type: list
    elements: str
  cap_drop:
    description:
      - List of capabilities to drop from the container.
    type: list
    elements: str
  cgroupns_mode:
    description:
      - Specify the cgroup namespace mode for the container.
      - The Docker CLI calls this simply C(cgroupns).
    type: str
    choices:
      - host
      - private
    version_added: 3.0.0
  cgroup_parent:
    description:
      - Specify the parent cgroup for the container.
    type: str
    version_added: 1.1.0
  cleanup:
    description:
      - Use with O(detach=false) to remove the container after successful execution.
    type: bool
    default: false
  command:
    description:
      - Command to execute when the container starts. A command may be either a string or a list.
      - Prior to version 2.4, strings were split on commas.
      - See O(command_handling) for differences in how strings and lists are handled.
    type: raw
  comparisons:
    description:
      - Allows to specify how properties of existing containers are compared with module options to decide whether the container
        should be recreated / updated or not.
      - Only options which correspond to the state of a container as handled by the Docker daemon can be specified, as well
        as O(networks).
      - Must be a dictionary specifying for an option one of the keys V(strict), V(ignore) and V(allow_more_present).
      - If V(strict) is specified, values are tested for equality, and changes always result in updating or restarting. If
        V(ignore) is specified, changes are ignored.
      - V(allow_more_present) is allowed only for lists, sets and dicts. If it is specified for lists or sets, the container
        will only be updated or restarted if the module option contains a value which is not present in the container's options.
        If the option is specified for a dict, the container will only be updated or restarted if the module option contains
        a key which is not present in the container's option, or if the value of a key present differs.
      - The wildcard option C(*) can be used to set one of the default values V(strict) or V(ignore) to I(all) comparisons
        which are not explicitly set to other values.
      - See the examples for details.
    type: dict
  container_default_behavior:
    description:
      - In older versions of this module, various module options used to have default values. This caused problems with containers
        which use different values for these options.
      - The default value is now V(no_defaults). To restore the old behavior, set it to V(compatibility), which will ensure
        that the default values are used when the values are not explicitly specified by the user.
      - This affects the O(auto_remove), O(detach), O(init), O(interactive), O(memory), O(paused), O(privileged), O(read_only),
        and O(tty) options.
    type: str
    choices:
      - compatibility
      - no_defaults
    default: no_defaults
  command_handling:
    description:
      - The default behavior for O(command) (when provided as a list) and O(entrypoint) is to convert them to strings without
        considering shell quoting rules. (For comparing idempotency, the resulting string is split considering shell quoting
        rules).
      - Also, setting O(command) to an empty list of string, and setting O(entrypoint) to an empty list will be handled as
        if these options are not specified. This is different from idempotency handling for other container-config related
        options.
      - When this is set to V(compatibility), which was the default until community.docker 3.0.0, the current behavior will
        be kept.
      - When this is set to V(correct), these options are kept as lists, and an empty value or empty list will be handled
        correctly for idempotency checks. This has been the default since community.docker 3.0.0.
    type: str
    choices:
      - compatibility
      - correct
    version_added: 1.9.0
    default: correct
  cpu_period:
    description:
      - Limit CPU CFS (Completely Fair Scheduler) period.
      - See O(cpus) for an easier to use alternative.
    type: int
  cpu_quota:
    description:
      - Limit CPU CFS (Completely Fair Scheduler) quota.
      - See O(cpus) for an easier to use alternative.
    type: int
  cpus:
    description:
      - Specify how much of the available CPU resources a container can use.
      - A value of V(1.5) means that at most one and a half CPU (core) will be used.
    type: float
  cpuset_cpus:
    description:
      - CPUs in which to allow execution.
      - For example V(1,3) or V(1-3).
    type: str
  cpuset_mems:
    description:
      - Memory nodes (MEMs) in which to allow execution V(0-3) or V(0,1).
    type: str
  cpu_shares:
    description:
      - CPU shares (relative weight).
    type: int
  default_host_ip:
    description:
      - Define the default host IP to use.
      - Must be an empty string, an IPv4 address, or an IPv6 address.
      - With Docker 20.10.2 or newer, this should be set to an empty string (V("")) to avoid the port bindings without an
        explicit IP address to only bind to IPv4. See U(https://github.com/ansible-collections/community.docker/issues/70)
        for details.
      - By default, the module will try to auto-detect this value from the C(bridge) network's C(com.docker.network.bridge.host_binding_ipv4)
        option. If it cannot auto-detect it, it will fall back to V(0.0.0.0).
    type: str
    version_added: 1.2.0
  detach:
    description:
      - Enable detached mode to leave the container running in background.
      - If disabled, the task will reflect the status of the container run (failed if the command failed).
      - If O(container_default_behavior=compatibility), this option has a default of V(true).
    type: bool
  devices:
    description:
      - List of host device bindings to add to the container.
      - Each binding is a mapping expressed in the format C(<path_on_host>:<path_in_container>:<cgroup_permissions>).
    type: list
    elements: str
  device_read_bps:
    description:
      - List of device path and read rate (bytes per second) from device.
    type: list
    elements: dict
    suboptions:
      path:
        description:
          - Device path in the container.
        type: str
        required: true
      rate:
        description:
          - Device read limit in format C(<number>[<unit>]).
          - Number is a positive integer. Unit can be one of V(B) (byte), V(K) (kibibyte, 1024B), V(M) (mebibyte), V(G) (gibibyte),
            V(T) (tebibyte), or V(P) (pebibyte).
          - Omitting the unit defaults to bytes.
        type: str
        required: true
  device_write_bps:
    description:
      - List of device and write rate (bytes per second) to device.
    type: list
    elements: dict
    suboptions:
      path:
        description:
          - Device path in the container.
        type: str
        required: true
      rate:
        description:
          - Device read limit in format C(<number>[<unit>]).
          - Number is a positive integer. Unit can be one of V(B) (byte), V(K) (kibibyte, 1024B), V(M) (mebibyte), V(G) (gibibyte),
            V(T) (tebibyte), or V(P) (pebibyte).
          - Omitting the unit defaults to bytes.
        type: str
        required: true
  device_read_iops:
    description:
      - List of device and read rate (IO per second) from device.
    type: list
    elements: dict
    suboptions:
      path:
        description:
          - Device path in the container.
        type: str
        required: true
      rate:
        description:
          - Device read limit.
          - Must be a positive integer.
        type: int
        required: true
  device_write_iops:
    description:
      - List of device and write rate (IO per second) to device.
    type: list
    elements: dict
    suboptions:
      path:
        description:
          - Device path in the container.
        type: str
        required: true
      rate:
        description:
          - Device read limit.
          - Must be a positive integer.
        type: int
        required: true
  device_requests:
    description:
      - Allows to request additional resources, such as GPUs.
    type: list
    elements: dict
    suboptions:
      capabilities:
        description:
          - List of lists of strings to request capabilities.
          - The top-level list entries are combined by OR, and for every list entry, the entries in the list it contains are
            combined by AND.
          - The driver tries to satisfy one of the sub-lists.
          - Available capabilities for the C(nvidia) driver can be found at U(https://github.com/NVIDIA/nvidia-container-runtime).
        type: list
        elements: list
      count:
        description:
          - Number or devices to request.
          - Set to V(-1) to request all available devices.
        type: int
      device_ids:
        description:
          - List of device IDs.
        type: list
        elements: str
      driver:
        description:
          - Which driver to use for this device.
        type: str
      options:
        description:
          - Driver-specific options.
        type: dict
    version_added: 0.1.0
  device_cgroup_rules:
    description:
      - List of cgroup rules to apply to the container.
    type: list
    elements: str
    version_added: 3.11.0
  dns_opts:
    description:
      - List of DNS options.
    type: list
    elements: str
  dns_servers:
    description:
      - List of custom DNS servers.
    type: list
    elements: str
  dns_search_domains:
    description:
      - List of custom DNS search domains.
    type: list
    elements: str
  domainname:
    description:
      - Container domainname.
    type: str
  env:
    description:
      - Dictionary of key,value pairs.
      - Values which might be parsed as numbers, booleans or other types by the YAML parser must be quoted (for example V("true"))
        in order to avoid data loss.
      - Please note that if you are passing values in with Jinja2 templates, like V("{{ value }}"), you need to add V(| string)
        to prevent Ansible to convert strings such as V("true") back to booleans. The correct way is to use V("{{ value |
        string }}").
    type: dict
  env_file:
    description:
      - Path to a file, present on the target, containing environment variables C(FOO=BAR).
      - If variable also present in O(env), then the O(env) value will override.
    type: path
  entrypoint:
    description:
      - Command that overwrites the default C(ENTRYPOINT) of the image.
      - See O(command_handling) for differences in how strings and lists are handled.
    type: list
    elements: str
  etc_hosts:
    description:
      - Dict of host-to-IP mappings, where each host name is a key in the dictionary. Each host name will be added to the
        container's C(/etc/hosts) file.
      - Instead of an IP address, the special value V(host-gateway) can also be used, which resolves to the host's gateway
        IP and allows containers to connect to services running on the host.
    type: dict
  exposed_ports:
    description:
      - List of additional container ports which informs Docker that the container listens on the specified network ports
        at runtime.
      - If the port is already exposed using C(EXPOSE) in a Dockerfile, it does not need to be exposed again.
    type: list
    elements: str
    aliases:
      - exposed
      - expose
  force_kill:
    description:
      - Use the kill command when stopping a running container.
    type: bool
    default: false
    aliases:
      - forcekill
  groups:
    description:
      - List of additional group names and/or IDs that the container process will run as.
    type: list
    elements: str
  healthcheck:
    description:
      - Configure a check that is run to determine whether or not containers for this service are "healthy".
      - See the docs for the L(HEALTHCHECK Dockerfile instruction,https://docs.docker.com/engine/reference/builder/#healthcheck)
        for details on how healthchecks work.
      - 'O(healthcheck.interval), O(healthcheck.timeout), O(healthcheck.start_period), and O(healthcheck.start_interval) are
        specified as durations. They accept duration as a string in a format that look like: V(5h34m56s), V(1m30s), and so
        on. The supported units are V(us), V(ms), V(s), V(m) and V(h).'
      - See also O(state=healthy).
    type: dict
    suboptions:
      test:
        description:
          - Command to run to check health.
          - Must be either a string or a list. If it is a list, the first item must be one of V(NONE), V(CMD) or V(CMD-SHELL).
        type: raw
      test_cli_compatible:
        description:
          - If set to V(true), omitting O(healthcheck.test) while providing O(healthcheck) does not disable healthchecks,
            but simply overwrites the image's values by the ones specified in O(healthcheck). This is the behavior used by
            the Docker CLI.
          - If set to V(false), omitting O(healthcheck.test) will disable the container's health check. This is the classical
            behavior of the module and currently the default behavior.
        default: false
        type: bool
        version_added: 3.10.0
      interval:
        description:
          - Time between running the check.
          - The default used by the Docker daemon is V(30s).
        type: str
      timeout:
        description:
          - Maximum time to allow one check to run.
          - The default used by the Docker daemon is V(30s).
        type: str
      retries:
        description:
          - Consecutive number of failures needed to report unhealthy.
          - The default used by the Docker daemon is V(3).
        type: int
      start_period:
        description:
          - Start period for the container to initialize before starting health-retries countdown.
          - The default used by the Docker daemon is V(0s).
        type: str
      start_interval:
        description:
          - Time between health checks during the start period. This option requires Docker Engine version 25.0 or later.
          - The default used by the Docker daemon is V(5s).
        type: str
        version_added: 3.10.0
  hostname:
    description:
      - The container's hostname.
    type: str
  image:
    description:
      - Repository path and tag used to create the container. If an image is not found or pull is true, the image will be
        pulled from the registry. If no tag is included, V(latest) will be used.
      - Can also be an image ID. If this is the case, the image is assumed to be available locally. The O(pull) option is
        ignored for this case.
    type: str
  image_comparison:
    description:
      - Determines which image to use for idempotency checks that depend on image parameters.
      - The default, V(desired-image), will use the image that is provided to the module with the O(image) parameter.
      - V(current-image) will use the image that the container is currently using, if the container exists. It falls back
        to the image that is provided in case the container does not yet exist.
      - This affects the O(env), O(env_file), O(exposed_ports), O(labels), and O(volumes) options.
    type: str
    choices:
      - desired-image
      - current-image
    default: desired-image
    version_added: 3.0.0
  image_label_mismatch:
    description:
      - How to handle labels inherited from the image that are not set explicitly.
      - When V(ignore), labels that are present in the image but not specified in O(labels) will be ignored. This is useful
        to avoid having to specify the image labels in O(labels) while keeping labels O(comparisons) V(strict).
      - When V(fail), if there are labels present in the image which are not set from O(labels), the module will fail. This
        prevents introducing unexpected labels from the base image.
      - 'B(Warning:) This option is ignored unless C(labels: strict) or C(*: strict) is specified in the O(comparisons) option.'
    type: str
    choices:
      - 'ignore'
      - 'fail'
    default: ignore
    version_added: 2.6.0
  image_name_mismatch:
    description:
      - Determines what the module does if the image matches, but the image name in the container's configuration does not
        match the image name provided to the module.
      - 'This is ignored if C(image: ignore) is set in O(comparisons).'
      - If set to V(recreate) (default) the container will be recreated.
      - If set to V(ignore) the container will not be recreated because of this. It might still get recreated for other reasons.
        This has been the default behavior of the module for a long time, but might not be what users expect.
      - The default changed from V(ignore) to V(recreate) in community.docker 4.0.0.
    type: str
    choices:
      - recreate
      - ignore
    default: recreate
    version_added: 3.2.0
  init:
    description:
      - Run an init inside the container that forwards signals and reaps processes.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  interactive:
    description:
      - Keep stdin open after a container is launched, even if not attached.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  ipc_mode:
    description:
      - Set the IPC mode for the container.
      - Can be one of V(container:<name|id>) to reuse another container's IPC namespace or V(host) to use the host's IPC namespace
        within the container.
    type: str
  keep_volumes:
    description:
      - Retain anonymous volumes associated with a removed container.
    type: bool
    default: true
  kill_signal:
    description:
      - Override default signal used to kill a running container.
    type: str
  kernel_memory:
    description:
      - Kernel memory limit in format C(<number>[<unit>]). Number is a positive integer. Unit can be V(B) (byte), V(K) (kibibyte,
        1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte). Minimum is V(4M).
      - Omitting the unit defaults to bytes.
    type: str
  labels:
    description:
      - Dictionary of key value pairs.
    type: dict
  links:
    description:
      - List of name aliases for linked containers in the format C(container_name:alias).
      - Setting this will force container to be restarted.
    type: list
    elements: str
  log_driver:
    description:
      - Specify the logging driver. Docker uses V(json-file) by default.
      - See L(the Docker logging configuration documentation,https://docs.docker.com/config/containers/logging/configure/)
        for possible choices.
    type: str
  log_options:
    description:
      - Dictionary of options specific to the chosen O(log_driver).
      - See U(https://docs.docker.com/engine/admin/logging/overview/) for details.
      - O(log_driver) needs to be specified for O(log_options) to take effect, even if using the default V(json-file) driver.
    type: dict
    aliases:
      - log_opt
  mac_address:
    description:
      - Container MAC address (for example, V(92:d0:c6:0a:29:33)).
      - Note that the global container-wide MAC address is deprecated and no longer used since Docker API version 1.44.
      - Use O(networks[].mac_address) instead.
    type: str
  memory:
    description:
      - Memory limit in format C(<number>[<unit>]). Number is a positive integer. Unit can be V(B) (byte), V(K) (kibibyte,
        1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
      - Omitting the unit defaults to bytes.
      - If O(container_default_behavior=compatibility), this option has a default of V("0").
    type: str
  memory_reservation:
    description:
      - Memory soft limit in format C(<number>[<unit>]). Number is a positive integer. Unit can be V(B) (byte), V(K) (kibibyte,
        1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
      - Omitting the unit defaults to bytes.
    type: str
  memory_swap:
    description:
      - Total memory limit (memory + swap) in format C(<number>[<unit>]), or the special values V(unlimited) or V(-1) for
        unlimited swap usage. Number is a positive integer. Unit can be V(B) (byte), V(K) (kibibyte, 1024B), V(M) (mebibyte),
        V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
      - Omitting the unit defaults to bytes.
    type: str
  memory_swappiness:
    description:
      - Tune a container's memory swappiness behavior. Accepts an integer between 0 and 100.
      - If not set, the value will be remain the same if container exists and will be inherited from the host machine if it
        is (re-)created.
    type: int
  mounts:
    type: list
    elements: dict
    description:
      - Specification for mounts to be added to the container. More powerful alternative to O(volumes).
    suboptions:
      target:
        description:
          - Path inside the container.
        type: str
        required: true
      source:
        description:
          - Mount source.
          - For example, this can be a volume name or a host path.
          - If not supplied when O(mounts[].type=volume) an anonymous volume will be created.
        type: str
      type:
        description:
          - The mount type.
          - Note that V(npipe) is only supported by Docker for Windows.
          - V(cluster) requires Docker API 1.42+ and has been added in community.docker 4.8.0.
          - V(image) requires Docker API 1.47+ and has been added in community.docker 4.8.0.
        type: str
        choices:
          - bind
          - npipe
          - tmpfs
          - volume
          - cluster
          - image
        default: volume
      read_only:
        description:
          - Whether the mount should be read-only.
        type: bool
      consistency:
        description:
          - The consistency requirement for the mount.
        type: str
        choices:
          - cached
          - consistent
          - default
          - delegated
      create_mountpoint:
        description:
          - Create mount point on host if missing.
          - Requires Docker API 1.42+.
          - Only valid for O(mounts[].type=bind).
        type: bool
        version_added: 4.8.0
      propagation:
        description:
          - Propagation mode. Only valid for the V(bind) type.
        type: str
        choices:
          - private
          - rprivate
          - shared
          - rshared
          - slave
          - rslave
      no_copy:
        description:
          - False if the volume should be populated with the data from the target. Only valid for the V(volume) type.
          - The default value is V(false).
        type: bool
      non_recursive:
        description:
          - Disable recursive bind mount.
          - Requires Docker API 1.40+.
          - Only valid for O(mounts[].type=bind).
        type: bool
        version_added: 4.8.0
      read_only_non_recursive:
        description:
          - Make the mount non-recursively read-only, but still leave the mount recursive (unless NonRecursive is set to true in conjunction).
          - Requires Docker API 1.44+.
          - Only valid for O(mounts[].type=bind).
        type: bool
        version_added: 4.8.0
      read_only_force_recursive:
        description:
          - Raise an error if the mount cannot be made recursively read-only.
          - Requires Docker API 1.44+.
          - Only valid for O(mounts[].type=bind).
        type: bool
        version_added: 4.8.0
      labels:
        description:
          - User-defined name and labels for the volume. Only valid for the V(volume) type.
        type: dict
      volume_driver:
        description:
          - Specify the volume driver. Only valid for the V(volume) type.
          - See L(here,https://docs.docker.com/storage/volumes/#use-a-volume-driver) for details.
        type: str
      volume_options:
        description:
          - Dictionary of options specific to the chosen volume_driver. See L(here,https://docs.docker.com/storage/volumes/#use-a-volume-driver)
            for details.
        type: dict
      subpath:
        type: str
        description:
          - Source path inside the volume/image. Must be relative without any back traversals.
          - Requires Docker API 1.45+.
          - Only valid for O(mounts[].type=volume) or O(mounts[].type=image).
        version_added: 4.8.0
      tmpfs_size:
        description:
          - The size for the tmpfs mount in bytes in format <number>[<unit>].
          - Number is a positive integer. Unit can be one of V(B) (byte), V(K) (kibibyte, 1024B), V(M) (mebibyte), V(G) (gibibyte),
            V(T) (tebibyte), or V(P) (pebibyte).
          - Omitting the unit defaults to bytes.
        type: str
      tmpfs_mode:
        description:
          - The permission mode for the tmpfs mount.
        type: str
      tmpfs_options:
        type: list
        elements: dict
        description:
          - Options to be passed to the tmpfs mount.
          - Every list element must be a dictionary with one key and a value.
            All keys must be strings, and values can be either a string or V(null)/V(none) for a flag.
          - Requires Docker API 1.46+.
          - Only valid for O(mounts[].type=tmpfs).
        version_added: 4.8.0
  name:
    description:
      - Assign a name to a new container or match an existing container.
      - When identifying an existing container name may be a name or a long or short container ID.
    type: str
    required: true
  network_mode:
    description:
      - Connect the container to a network. Choices are V(bridge), V(host), V(none), C(container:<name|id>), C(<network_name>)
        or V(default).
      - Since community.docker 2.0.0, if O(networks_cli_compatible=true) and O(networks) contains at least one network, the
        default value for O(network_mode) is the name of the first network in the O(networks) list. You can prevent this by
        explicitly specifying a value for O(network_mode), like the default value V(default) which will be used by Docker
        if O(network_mode) is not specified.
    type: str
  userns_mode:
    description:
      - Set the user namespace mode for the container. Currently, the only valid value are V(host) and the empty string (V("")).
    type: str
  networks:
    description:
      - List of networks the container belongs to.
      - For examples of the data structure and usage see EXAMPLES below.
      - 'To remove a container from one or more networks, use C(networks: strict) in the O(comparisons) option.'
      - 'If O(networks_cli_compatible=false), this will not remove the default network if O(networks) is specified. This is
        different from the behavior of C(docker run ...). You need to explicitly use C(networks: strict) in O(comparisons)
        to enforce the removal of the default network (and all other networks not explicitly mentioned in O(networks)) in
        that case.'
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - The network's name.
        type: str
        required: true
      ipv4_address:
        description:
          - The container's IPv4 address in this network.
        type: str
      ipv6_address:
        description:
          - The container's IPv6 address in this network.
        type: str
      links:
        description:
          - A list of containers to link to.
        type: list
        elements: str
      aliases:
        description:
          - List of aliases for this container in this network. These names can be used in the network to reach this container.
        type: list
        elements: str
      mac_address:
        description:
          - Endpoint MAC address (for example, V(92:d0:c6:0a:29:33)).
          - This is only available for Docker API version 1.44 and later.
          - Please note that when a container is attached to a network after creation, this is currently ignored by the Docker
            Daemon at least in some cases. When passed on creation, this seems to work better.
        type: str
        version_added: 3.6.0
  networks_cli_compatible:
    description:
      - If O(networks_cli_compatible=true) (default), this module will behave as C(docker run --network) and will B(not) add
        the default network if O(networks) is specified. If O(networks) is not specified, the default network will be attached.
      - 'When O(networks_cli_compatible=false) and networks are provided to the module with the O(networks) option, the module
        behaves differently than C(docker run --network): C(docker run --network other) will create a container with network
        C(other) attached, but the default network not attached. This module with O(networks) set to C({name: other}) will
        create a container with both C(default) and C(other) attached. If C(networks: strict) or C(*: strict) is set in O(comparisons),
        the C(default) network will be removed afterwards.'
    type: bool
    default: true
  oom_killer:
    description:
      - Whether or not to disable OOM Killer for the container.
    type: bool
  oom_score_adj:
    description:
      - An integer value containing the score given to the container in order to tune OOM killer preferences.
    type: int
  output_logs:
    description:
      - If set to true, output of the container command will be printed.
      - Only effective when O(log_driver) is set to V(json-file), V(journald), or V(local).
    type: bool
    default: false
  paused:
    description:
      - Use with the started state to pause running processes inside the container.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  pid_mode:
    description:
      - Set the PID namespace mode for the container.
    type: str
  pids_limit:
    description:
      - Set PIDs limit for the container. It accepts an integer value.
      - Set V(-1) for unlimited PIDs.
    type: int
  platform:
    description:
      - Platform for the container in the format C(os[/arch[/variant]]).
      - "Note that since community.docker 3.5.0, the module uses both the image's metadata and the Docker daemon's information
        to normalize platform strings similarly to how Docker itself is doing this. If you notice idempotency problems, please
        verify whether this is still a problem with the latest release of community.docker, and if it is,
        L(create an issue in the community.docker GitHub repository,
        https://github.com/ansible-collections/community.docker/issues/new?assignees=&labels=&projects=&template=bug_report.md).
        For older community.docker versions, you can use the O(comparisons) option with C(platform: ignore) to prevent accidental
        recreation of the container due to this."
    type: str
    version_added: 3.0.0
  privileged:
    description:
      - Give extended privileges to the container.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  publish_all_ports:
    description:
      - Publish all ports to the host.
      - Any specified port bindings from O(published_ports) will remain intact when V(true).
    type: bool
    version_added: 1.8.0
  published_ports:
    description:
      - List of ports to publish from the container to the host.
      - 'Use docker CLI syntax: V(8000), V(9000:8000), or V(0.0.0.0:9000:8000), where 8000 is a container port, 9000 is a
        host port, and 0.0.0.0 is a host interface.'
      - Port ranges can be used for source and destination ports. If two ranges with different lengths are specified, the
        shorter range will be used. Since community.general 0.2.0, if the source port range has length 1, the port will not
        be assigned to the first port of the destination range, but to a free port in that range. This is the same behavior
        as for C(docker) command line utility.
      - Bind addresses must be either IPv4 or IPv6 addresses. Hostnames are B(not) allowed. This is different from the C(docker)
        command line utility. Use the P(community.general.dig#lookup) lookup to resolve hostnames.
      - If O(networks) parameter is provided, will inspect each network to see if there exists a bridge network with optional
        parameter C(com.docker.network.bridge.host_binding_ipv4). If such a network is found, then published ports where no
        host IP address is specified will be bound to the host IP pointed to by C(com.docker.network.bridge.host_binding_ipv4).
        Note that the first bridge network with a C(com.docker.network.bridge.host_binding_ipv4) value encountered in the
        list of O(networks) is the one that will be used.
      - The value V(all) was allowed in earlier versions of this module. Support for it was removed in community.docker 3.0.0.
        Use the O(publish_all_ports) option instead.
    type: list
    elements: str
    aliases:
      - ports
  pull:
    description:
      - If set to V(never), will never try to pull an image. Will fail if the image is not available on the Docker daemon.
      - If set to V(missing) or V(false), only pull the image if it is not available on the Docker daemon. This is the default
        behavior.
      - If set to V(always) or V(true), always try to pull the latest version of the image.
      - B(Note:) images are only pulled when specified by name. If the image is specified as a image ID (hash), it cannot
        be pulled, and this option is ignored.
      - B(Note:) the values V(never), V(missing), and V(always) are only available since community.docker 3.8.0. Earlier versions
        only support V(true) and V(false).
    type: raw
    choices:
      - never
      - missing
      - always
      - true
      - false
    default: missing
  pull_check_mode_behavior:
    description:
      - Allows to adjust the behavior when O(pull=always) or O(pull=true) in check mode.
      - Since the Docker daemon does not expose any functionality to test whether a pull will result in a changed image, the
        module by default acts like O(pull=always) only results in a change when the image is not present.
      - If set to V(image_not_present) (default), only report changes in check mode when the image is not present.
      - If set to V(always), always report changes in check mode.
    type: str
    default: image_not_present
    choices:
      - image_not_present
      - always
    version_added: 3.8.0
  read_only:
    description:
      - Mount the container's root file system as read-only.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  recreate:
    description:
      - Use with present and started states to force the re-creation of an existing container.
    type: bool
    default: false
  removal_wait_timeout:
    description:
      - When removing an existing container, the docker daemon API call exists after the container is scheduled for removal.
        Removal usually is very fast, but it can happen that during high I/O load, removal can take longer. By default, the
        module will wait until the container has been removed before trying to (re-)create it, however long this takes.
      - By setting this option, the module will wait at most this many seconds for the container to be removed. If the container
        is still in the removal phase after this many seconds, the module will fail.
    type: float
  restart:
    description:
      - Use with started state to force a matching container to be stopped and restarted.
    type: bool
    default: false
  restart_policy:
    description:
      - Container restart policy.
      - Place quotes around V(no) option.
    type: str
    choices:
      - 'no'
      - 'on-failure'
      - 'always'
      - 'unless-stopped'
  restart_retries:
    description:
      - Use with restart policy to control maximum number of restart attempts.
    type: int
  runtime:
    description:
      - Runtime to use for the container.
    type: str
  shm_size:
    description:
      - Size of C(/dev/shm) in format C(<number>[<unit>]). Number is positive integer. Unit can be V(B) (byte), V(K) (kibibyte,
        1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
      - Omitting the unit defaults to bytes. If you omit the size entirely, Docker daemon uses V(64M).
    type: str
  security_opts:
    description:
      - List of security options in the form of C("label:user:User").
    type: list
    elements: str
  state:
    description:
      - V(absent) - A container matching the specified name will be stopped and removed. Use O(force_kill) to kill the container
        rather than stopping it. Use O(keep_volumes) to retain anonymous volumes associated with the removed container.
      - V(present) - Asserts the existence of a container matching the name and any provided configuration parameters. If
        no container matches the name, a container will be created. If a container matches the name but the provided configuration
        does not match, the container will be updated, if it can be. If it cannot be updated, it will be removed and re-created
        with the requested config.
      - V(started) - Asserts that the container is first V(present), and then if the container is not running moves it to
        a running state. Use O(restart) to force a matching container to be stopped and restarted.
      - V(healthy) - Asserts that the container is V(present) and V(started), and is actually healthy as well. This means
        that the conditions defined in O(healthcheck) respectively in the image's C(HEALTHCHECK) (L(Docker reference for HEALTHCHECK,
        https://docs.docker.com/reference/dockerfile/#healthcheck)) are satisfied. The time waited can be controlled with
        O(healthy_wait_timeout). This state has been added in community.docker 3.11.0.
      - V(stopped) - Asserts that the container is first V(present), and then if the container is running moves it to a stopped
        state.
      - 'To control what will be taken into account when comparing configuration, see the O(comparisons) option. To avoid
        that the image version will be taken into account, you can also use the V(image: ignore) in the O(comparisons) option.'
      - Use the O(recreate) option to always force re-creation of a matching container, even if it is running.
      - If the container should be killed instead of stopped in case it needs to be stopped for recreation, or because O(state)
        is V(stopped), please use the O(force_kill) option. Use O(keep_volumes) to retain anonymous volumes associated with
        a removed container.
      - Use O(keep_volumes) to retain anonymous volumes associated with a removed container.
    type: str
    default: started
    choices:
      - absent
      - present
      - healthy
      - stopped
      - started
  stop_signal:
    description:
      - Override default signal used to stop the container.
    type: str
  healthy_wait_timeout:
    description:
      - When waiting for the container to become healthy if O(state=healthy), this option controls how long the module waits
        until the container state becomes healthy.
      - The timeout is specified in seconds. The default, V(300), is 5 minutes.
      - Set this to 0 or a negative value to wait indefinitely. Note that depending on the container this can result in the
        module not terminating.
    default: 300
    type: float
    version_added: 3.11.0
  stop_timeout:
    description:
      - Number of seconds to wait for the container to stop before sending C(SIGKILL). When the container is created by this
        module, its C(StopTimeout) configuration will be set to this value.
      - When the container is stopped, will be used as a timeout for stopping the container. In case the container has a custom
        C(StopTimeout) configuration, the behavior depends on the version of the docker daemon. New versions of the docker
        daemon will always use the container's configured C(StopTimeout) value if it has been configured.
    type: int
  storage_opts:
    description:
      - Storage driver options for this container as a key-value mapping.
    type: dict
    version_added: 1.3.0
  tmpfs:
    description:
      - Mount a tmpfs directory.
    type: list
    elements: str
  tty:
    description:
      - Allocate a pseudo-TTY.
      - If O(container_default_behavior=compatibility), this option has a default of V(false).
    type: bool
  ulimits:
    description:
      - List of ulimit options. A ulimit is specified as V(nofile:262144:262144).
    type: list
    elements: str
  sysctls:
    description:
      - Dictionary of key,value pairs.
    type: dict
  user:
    description:
      - Sets the username or UID used and optionally the groupname or GID for the specified command.
      - Can be of the forms C(user), C(user:group), C(uid), C(uid:gid), C(user:gid) or C(uid:group).
    type: str
  uts:
    description:
      - Set the UTS namespace mode for the container.
    type: str
  volumes:
    description:
      - List of volumes to mount within the container.
      - 'Use docker CLI-style syntax: C(/host:/container[:mode]).'
      - Mount modes can be a comma-separated list of various modes such as V(ro), V(rw), V(consistent), V(delegated), V(cached),
        V(rprivate), V(private), V(rshared), V(shared), V(rslave), V(slave), and V(nocopy). Note that the docker daemon might
        not support all modes and combinations of such modes.
      - SELinux hosts can additionally use V(z) or V(Z) to use a shared or private label for the volume.
      - Note that Ansible 2.7 and earlier only supported one mode, which had to be one of V(ro), V(rw), V(z), and V(Z).
    type: list
    elements: str
  volume_driver:
    description:
      - The container volume driver.
    type: str
  volumes_from:
    description:
      - List of container names or IDs to get volumes from.
    type: list
    elements: str
  working_dir:
    description:
      - Path to the working directory.
    type: str

author:
  - "Cove Schneider (@cove)"
  - "Joshua Conner (@joshuaconner)"
  - "Pavel Antonov (@softzilla)"
  - "Thomas Steinbach (@ThomasSteinbach)"
  - "Philippe Jandot (@zfil)"
  - "Daan Oosterveld (@dusdanig)"
  - "Chris Houseknecht (@chouseknecht)"
  - "Kassian Sun (@kassiansun)"
  - "Felix Fontein (@felixfontein)"

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Create a data container
  community.docker.docker_container:
    name: mydata
    image: busybox
    volumes:
      - /data

- name: Re-create a redis container
  community.docker.docker_container:
    name: myredis
    image: redis
    command: redis-server --appendonly yes
    state: present
    recreate: true
    exposed_ports:
      - 6379
    volumes_from:
      - mydata

- name: Restart a container
  community.docker.docker_container:
    name: myapplication
    image: someuser/appimage
    state: started
    restart: true
    links:
      - "myredis:aliasedredis"
    devices:
      - "/dev/sda:/dev/xvda:rwm"
    ports:
     # Publish container port 9000 as host port 8080
      - "8080:9000"
     # Publish container UDP port 9001 as host port 8081 on interface 127.0.0.1
      - "127.0.0.1:8081:9001/udp"
     # Publish container port 9002 as a random host port
      - "9002"
     # Publish container port 9003 as a free host port in range 8000-8100
     # (the host port will be selected by the Docker daemon)
      - "8000-8100:9003"
     # Publish container ports 9010-9020 to host ports 7000-7010
      - "7000-7010:9010-9020"
    env:
      SECRET_KEY: "ssssh"
      # Values which might be parsed as numbers, booleans or other types by the YAML parser need to be quoted
      BOOLEAN_KEY: "yes"

- name: Container present
  community.docker.docker_container:
    name: mycontainer
    state: present
    image: ubuntu:14.04
    command: sleep infinity

- name: Stop a container
  community.docker.docker_container:
    name: mycontainer
    state: stopped

- name: Start 4 load-balanced containers
  community.docker.docker_container:
    name: "container{{ item }}"
    recreate: true
    image: someuser/anotherappimage
    command: sleep 1d
  with_sequence: count=4

- name: Remove container
  community.docker.docker_container:
    name: ohno
    state: absent

- name: Syslogging output
  community.docker.docker_container:
    name: myservice
    image: busybox
    log_driver: syslog
    log_options:
      syslog-address: tcp://my-syslog-server:514
      syslog-facility: daemon
      # NOTE: in Docker 1.13+ the "syslog-tag" option was renamed to "tag" for
      # older docker installs, use "syslog-tag" instead
      tag: myservice

- name: Create db container and connect to network
  community.docker.docker_container:
    name: db_test
    image: "postgres:latest"
    networks:
      - name: "{{ docker_network_name }}"

- name: Start container, connect to network and link
  community.docker.docker_container:
    name: sleeper
    image: ubuntu:14.04
    networks:
      - name: TestingNet
        ipv4_address: "172.16.1.100"
        aliases:
          - sleepyzz
        links:
          - db_test:db
      - name: TestingNet2

- name: Start a container with a command
  community.docker.docker_container:
    name: sleepy
    image: ubuntu:14.04
    command: ["sleep", "infinity"]

- name: Add container to networks
  community.docker.docker_container:
    name: sleepy
    networks:
      - name: TestingNet
        ipv4_address: 172.16.1.18
        links:
          - sleeper
      - name: TestingNet2
        ipv4_address: 172.16.10.20

- name: Update network with aliases
  community.docker.docker_container:
    name: sleepy
    networks:
      - name: TestingNet
        aliases:
          - sleepyz
          - zzzz

- name: Remove container from one network
  community.docker.docker_container:
    name: sleepy
    networks:
      - name: TestingNet2
    comparisons:
      networks: strict

- name: Remove container from all networks
  community.docker.docker_container:
    name: sleepy
    comparisons:
      networks: strict

- name: Start a container and use an env file
  community.docker.docker_container:
    name: agent
    image: jenkinsci/ssh-slave
    env_file: /var/tmp/jenkins/agent.env

- name: Create a container with limited capabilities
  community.docker.docker_container:
    name: sleepy
    image: ubuntu:16.04
    command: sleep infinity
    capabilities:
      - sys_time
    cap_drop:
      - all

- name: Finer container restart/update control
  community.docker.docker_container:
    name: test
    image: ubuntu:18.04
    env:
      arg1: "true"
      arg2: "whatever"
    volumes:
      - /tmp:/tmp
    comparisons:
      image: ignore # do not restart containers with older versions of the image
      env: strict # we want precisely this environment
      volumes: allow_more_present # if there are more volumes, that's ok, as long as `/tmp:/tmp` is there

- name: Finer container restart/update control II
  community.docker.docker_container:
    name: test
    image: ubuntu:18.04
    env:
      arg1: "true"
      arg2: "whatever"
    comparisons:
      '*': ignore # by default, ignore *all* options (including image)
      env: strict # except for environment variables; there, we want to be strict

- name: Start container with healthstatus
  community.docker.docker_container:
    name: nginx-proxy
    image: nginx:1.13
    state: started
    healthcheck:
      # Check if nginx server is healthy by curl'ing the server.
      # If this fails or timeouts, the healthcheck fails.
      test: ["CMD", "curl", "--fail", "http://nginx.host.com"]
      interval: 1m30s
      timeout: 10s
      retries: 3
      start_period: 30s
      start_interval: 10s

- name: Remove healthcheck from container
  community.docker.docker_container:
    name: nginx-proxy
    image: nginx:1.13
    state: started
    healthcheck:
      # The "NONE" check needs to be specified
      test: ["NONE"]

- name: Create a tmpfs with a size and mode
  community.docker.docker_container:
    name: tmpfs test
    image: ubuntu:22.04
    state: started
    mounts:
      - type: tmpfs
        target: /cache
        tmpfs_mode: "1700" # only readable to the owner
        tmpfs_size: "16G"

- name: Start container with block device read limit
  community.docker.docker_container:
    name: test
    image: ubuntu:18.04
    state: started
    device_read_bps:
      # Limit read rate for /dev/sda to 20 mebibytes per second
      - path: /dev/sda
        rate: 20M
    device_read_iops:
      # Limit read rate for /dev/sdb to 300 IO per second
      - path: /dev/sdb
        rate: 300

- name: Start container with GPUs
  community.docker.docker_container:
    name: test
    image: ubuntu:18.04
    state: started
    device_requests:
      # Add some specific devices to this container
      - device_ids:
          - '0'
          - 'GPU-3a23c669-1f69-c64e-cf85-44e9b07e7a2a'
      # Add nVidia GPUs to this container
      - driver: nvidia
        count: -1 # this means we want all
        capabilities:
        # We have one OR condition: 'gpu' AND 'utility'
          - - gpu
            - utility
        # See https://github.com/NVIDIA/nvidia-container-runtime#supported-driver-capabilities
        # for a list of capabilities supported by the nvidia driver

- name: Start container with storage options
  community.docker.docker_container:
    name: test
    image: ubuntu:18.04
    state: started
    storage_opts:
      # Limit root filesystem to 12 MB - note that this requires special storage backends
      # (https://fabianlee.org/2020/01/15/docker-use-overlay2-with-an-xfs-backing-filesystem-to-limit-rootfs-size/)
      size: 12m
"""

RETURN = r"""
container:
  description:
    - Facts representing the current state of the container. Matches the docker inspection output.
    - Empty if O(state=absent).
    - If O(detach=false), will include C(Output) attribute containing any output from container run.
  returned: success; or when O(state=started) and O(detach=false), and when waiting for the container result did not fail
  type: dict
  sample: '{ "AppArmorProfile": "", "Args": [], "Config": { "AttachStderr": false, "AttachStdin": false, "AttachStdout": false,
    "Cmd": [ "/usr/bin/supervisord" ], "Domainname": "", "Entrypoint": null, "Env": [ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ], "ExposedPorts": { "443/tcp": {}, "80/tcp": {} }, "Hostname": "8e47bf643eb9", "Image": "lnmp_nginx:v1", "Labels": {},
    "OnBuild": null, "OpenStdin": false, "StdinOnce": false, "Tty": false, "User": "", "Volumes": { "/tmp/lnmp/nginx-sites/logs/":
    {} }, ... }'
status:
  description:
    - In case a container is started without detaching, this contains the exit code of the process in the container.
    - Before community.docker 1.1.0, this was only returned when non-zero.
  returned: when O(state=started) and O(detach=false), and when waiting for the container result did not fail
  type: int
  sample: 0
"""

from ansible_collections.community.docker.plugins.module_utils.module_container.docker_api import (
    DockerAPIEngineDriver,
)

from ansible_collections.community.docker.plugins.module_utils.module_container.module import (
    run_module,
)


def main():
    engine_driver = DockerAPIEngineDriver()
    run_module(engine_driver)


if __name__ == '__main__':
    main()
