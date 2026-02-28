from collections import defaultdict
from multiprocessing.pool import AsyncResult
from pprint import pformat
import random
from typing import List
from natsort import natsorted
import re

from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.helpers.dut_utils import is_container_running

INVALID_ASIC_INDEX = -1


class SonicDocker:
    """
    SonicDocker container wrapper. When execute function, it will calls SonicDockerManager functions
    with pre-populated self.name (container_name) as the first argument.

    See also:
        SonicDockerManager: Manager class to manage all SonicDocker containers instances
    """
    __slots__ = ('name', 'docker_manager', 'asic_index')

    def __init__(self, manager, container_name):
        self.name = container_name
        self.docker_manager = manager

        parse_asic = re.search(r"(\d+)$", container_name)
        self.asic_index = int(parse_asic.group()) if parse_asic is not None else None

    def __str__(self):
        return f"<DockerContainer({self.name})>"

    def __getattr__(self, attr):
        if attr.startswith("_") or attr in self.__slots__:
            return object.__getattribute__(self, attr)

        func = getattr(self.docker_manager, attr)

        if callable(func):
            def _handle(*args, **kwargs):
                return func(self.name, *args, **kwargs)
            return _handle

        return object.__getattribute__(self, attr)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, SonicDocker):
            return self.name == other.name
        return False

    def __repr__(self):
        return self.__str__()


class SonicDockerManager:
    """
    Manager docker containers instance for multi-asic and single asics.

    Usage:
        duthost.containers().<container_name>().<method>()

    See: https://github.com/sonic-net/sonic-mgmt/pull/20513 for detail examples

    Common usage:
        1. Execute command on `syncd` for single-asic and `syncd0` for multi asic

            duthost.containers().syncd()[0].exec("echo hello-world")

            # Or randomly pick one syncd container for multi-asic

            duthost.containers().syncd().random().exec("echo hello-world")

        2. Execute command on `syncd` for single-asic and `syncd0`, `syncd1`, ...`syncdN` for multi asic
        in PARALLEL

            duthost.containers().syncd().exec("echo hello-world")

        3. Execute command only on `syncd1`

            duthost.containers().syncd(1).exec("echo hello-world")
            # or
            duthost.containers().syncd(namespace="asic1").exec("echo hello-world")
            # or
            duthost.containers().syncd(asic_index=1).exec("echo hello-world")

        4. Get list of all container name for syncd

            [docker.name for docker in duthost.containers().syncd()]


    See also:
        duthost: an instance of MultiAsicSonicHost
        containers: Return the list of containers organise by group.

    """

    __slots__ = ('duthost', 'containers')

    class ContainerList(list):
        """
        SonicDockerManager.ContainerList is internal class to store and execute command SonicDocker in parallel
        """
        def __init__(self, manager, *args):
            super().__init__(*args)
            self.manager = manager

        def __str__(self):
            return f"<SonicDockerManager.ContainerList({[docker.name for docker in self]})>"

        def __getattr__(self, attr):
            try:
                value = object.__getattribute__(self, attr)
                return value

            except AttributeError as e:
                func = object.__getattribute__(self.manager, attr)

                if not callable(func):
                    raise e

                def _handle(*args, **kwargs):
                    result: List[AsyncResult] = [None] * len(self)

                    with SafeThreadPoolExecutor(max_workers=max(1, min(len(self), 8))) as executor:
                        for i, docker in enumerate(self):
                            result[i] = executor.submit(
                                getattr(docker, attr), *args, **kwargs
                            )

                    for i, res in enumerate(result):
                        result[i] = res.get()

                    return result

                return _handle

        def get_by_asic_index(self, asic_index=None):
            """
            Return instance of filtered SonicDockerManager.ContainerList for index

            :param asic_index: Asic index
            """
            if asic_index is None:
                return self

            return self.__class__(self.manager,
                                  filter(lambda docker: docker.asic_index == asic_index, self))

        def random(self):
            if not self:
                raise ValueError("Cannot select a random container from an empty ContainerList.")
            return random.choice(self)

    def __init__(self, duthost):
        self.duthost = duthost
        self.__init_containers()

    def __init_containers(self):
        """
        Initialize the containers inventory to self.containers

        :param self: SonicDockerManager instance
        """
        container_names = natsorted(self.duthost.get_all_containers())
        self.containers = defaultdict(
            lambda: SonicDockerManager.ContainerList(self)
        )

        for name in container_names:
            container_group_name = name.rstrip("0123456789")
            self.containers[container_group_name].append(SonicDocker(self, name))

    def __getattr__(self, attr):
        if attr.startswith("_") or attr in self.__slots__:
            return object.__getattribute__(self, attr)

        if attr in object.__getattribute__(self, "containers"):
            def _handle(asic_index=None, namespace=None):
                if asic_index is None and namespace is None:
                    return self.containers[attr]
                if namespace:
                    match = re.search(r"(\d+)$", string=namespace)
                    asic_index = int(match.group()) if match else INVALID_ASIC_INDEX
                return self.containers[attr].get_by_asic_index(asic_index)
            return _handle

    def __str__(self):
        container_infos = {
            group: [docker.name for docker in self.containers[group]] for group in natsorted(self.containers)
        }

        return f"<SonicDockerManager [{pformat(container_infos, width=120)}]>"

    def __repr__(self):
        return self.__str__()

    def refresh(self):
        """
        Update to get the latest container info. By default it's cached first run for performance.
        """
        self.__init_containers()

    """
    Functions that will inherit from SonicDockerManager.ContainerList and SonicDocker.

    NOTE: Call to this functions performed by SonicDockerManager.ContainerList or SonicDocker will pass container_name
    as the first argument.
    """
    def exec(self, container_name, cmd, shell=False, **kwargs):
        exec_cmd = self.duthost.shell if shell else self.duthost.command
        return exec_cmd(f'sudo docker exec {container_name} {cmd}', **kwargs)

    def is_running(self, container_name):
        return is_container_running(self.duthost, container_name)
