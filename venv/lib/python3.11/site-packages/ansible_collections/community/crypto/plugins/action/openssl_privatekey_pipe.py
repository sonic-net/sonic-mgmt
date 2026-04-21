# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import typing as t

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey import (
    get_privatekey_argument_spec,
    select_backend,
)
from ansible_collections.community.crypto.plugins.plugin_utils._action_module import (
    ActionModuleBase,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._argspec import (  # pragma: no cover
        ArgumentSpec,
    )
    from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.privatekey import (  # pragma: no cover
        PrivateKeyBackend,
    )
    from ansible_collections.community.crypto.plugins.plugin_utils._action_module import (  # pragma: no cover
        AnsibleActionModule,
    )


class PrivateKeyModule:
    def __init__(
        self, module: AnsibleActionModule, module_backend: PrivateKeyBackend
    ) -> None:
        self.module = module
        self.module_backend = module_backend
        self.check_mode = module.check_mode
        self.changed = False
        self.return_current_key: bool = module.params["return_current_key"]

        content: str | None = module.params["content"]
        content_base64: bool = module.params["content_base64"]
        if content is not None:
            if content_base64:
                try:
                    data = base64.b64decode(content)
                except Exception as e:
                    module.fail_json(msg=f"Cannot decode Base64 encoded data: {e}")
            else:
                data = to_bytes(content)
            module_backend.set_existing(privatekey_bytes=data)

    def generate(self, module: AnsibleActionModule) -> None:
        """Generate a keypair."""

        if self.module_backend.needs_regeneration():
            # Regenerate
            self.module_backend.generate_private_key()
            # Call get_private_key_data() to make sure that exceptions are raised now:
            self.module_backend.get_private_key_data()
            self.changed = True
        elif self.module_backend.needs_conversion():
            # Convert
            self.module_backend.convert_private_key()
            # Call get_private_key_data() to make sure that exceptions are raised now:
            self.module_backend.get_private_key_data()
            self.changed = True

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""
        result = self.module_backend.dump(
            include_key=self.changed or self.return_current_key
        )
        result["changed"] = self.changed
        return result


class ActionModule(ActionModuleBase):
    def setup_module(self) -> tuple[ArgumentSpec, dict[str, t.Any]]:
        argument_spec = get_privatekey_argument_spec()
        argument_spec.argument_spec.update(
            {
                "content": {"type": "str", "no_log": True},
                "content_base64": {"type": "bool", "default": False},
                "return_current_key": {"type": "bool", "default": False},
            }
        )
        return argument_spec, {
            "supports_check_mode": True,
        }

    def run_module(self, module: AnsibleActionModule) -> None:
        module_backend = select_backend(module=module)

        try:
            private_key = PrivateKeyModule(module, module_backend)
            private_key.generate(module)
            result = private_key.dump()
            if private_key.return_current_key:
                # In case the module's input (`content`) is returned as `privatekey`:
                # Since `content` is no_log=True, `privatekey`'s value will get replaced by
                # VALUE_SPECIFIED_IN_NO_LOG_PARAMETER. To avoid this, we remove the value of
                # `content` from module.no_log_values. Since we explicitly set
                # `module.no_log = True`, this should be safe.
                module.no_log = True
                try:
                    module.no_log_values.remove(module.params["content"])
                except KeyError:
                    pass
                module.params["content"] = "ANSIBLE_NO_LOG_VALUE"
            module.exit_json(**result)
        except OpenSSLObjectError as exc:
            module.fail_json(msg=str(exc))
