import traceback
from typing import Optional

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_text
from ansible_collections.kubernetes.core.plugins.module_utils.version import (
    LooseVersion,
)


class AnsibleK8SModule:
    """A base module class for K8S modules.

    This class should be used instead of directly using AnsibleModule. If there
    is a need for other methods or attributes to be proxied, they can be added
    here.
    """

    default_settings = {
        "check_k8s": True,
        "check_pyyaml": True,
        "module_class": AnsibleModule,
    }

    def __init__(self, **kwargs) -> None:
        local_settings = {}
        for key in AnsibleK8SModule.default_settings:
            try:
                local_settings[key] = kwargs.pop(key)
            except KeyError:
                local_settings[key] = AnsibleK8SModule.default_settings[key]
        self.settings = local_settings

        self._module = self.settings["module_class"](**kwargs)

        if self.settings["check_k8s"]:
            self.requires("kubernetes")
            self.has_at_least("kubernetes", "24.2.0", warn=True)

        if self.settings["check_pyyaml"]:
            self.requires("pyyaml")

    @property
    def check_mode(self):
        return self._module.check_mode

    @property
    def server_side_dry_run(self):
        return self.check_mode and self.has_at_least("kubernetes", "18.20.0")

    @property
    def _diff(self):
        return self._module._diff

    @property
    def _name(self):
        return self._module._name

    @property
    def params(self):
        return self._module.params

    def warn(self, *args, **kwargs):
        return self._module.warn(*args, **kwargs)

    def deprecate(self, *args, **kwargs):
        return self._module.deprecate(*args, **kwargs)

    def debug(self, *args, **kwargs):
        return self._module.debug(*args, **kwargs)

    def exit_json(self, *args, **kwargs):
        return self._module.exit_json(*args, **kwargs)

    def fail_json(self, *args, **kwargs):
        return self._module.fail_json(*args, **kwargs)

    def fail_from_exception(self, exception):
        msg = to_text(exception)
        tb = "".join(
            traceback.format_exception(None, exception, exception.__traceback__)
        )
        return self.fail_json(msg=msg, exception=tb)

    def has_at_least(
        self, dependency: str, minimum: Optional[str] = None, warn: bool = False
    ) -> bool:
        supported = has_at_least(dependency, minimum)
        if not supported and warn:
            self.warn(
                "{0}<{1} is not supported or tested. Some features may not work.".format(
                    dependency, minimum
                )
            )
        return supported

    def requires(
        self,
        dependency: str,
        minimum: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        try:
            requires(dependency, minimum, reason=reason)
        except Exception as e:
            self.fail_json(msg=to_text(e))


def gather_versions() -> dict:
    versions = {}
    try:
        import jsonpatch

        versions["jsonpatch"] = jsonpatch.__version__
    except ImportError:
        pass

    try:
        import kubernetes

        versions["kubernetes"] = kubernetes.__version__
    except ImportError:
        pass

    try:
        import kubernetes_validate

        versions["kubernetes-validate"] = kubernetes_validate.__version__
    except ImportError:
        pass

    try:
        import yaml

        versions["pyyaml"] = yaml.__version__
    except ImportError:
        pass

    return versions


def has_at_least(dependency: str, minimum: Optional[str] = None) -> bool:
    """Check if a specific dependency is present at a minimum version.

    If a minimum version is not specified it will check only that the
    dependency is present.
    """
    dependencies = gather_versions()
    current = dependencies.get(dependency)
    if current is not None:
        if minimum is None:
            return True
        supported = LooseVersion(current) >= LooseVersion(minimum)
        return supported
    return False


def requires(
    dependency: str, minimum: Optional[str] = None, reason: Optional[str] = None
) -> None:
    """Fail if a specific dependency is not present at a minimum version.

    If a minimum version is not specified it will require only that the
    dependency is present. This function raises an exception when the
    dependency is not found at the required version.
    """
    if not has_at_least(dependency, minimum):
        if minimum is not None:
            lib = "{0}>={1}".format(dependency, minimum)
        else:
            lib = dependency
        raise Exception(missing_required_lib(lib, reason=reason))
