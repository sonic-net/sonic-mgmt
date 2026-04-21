from __future__ import annotations

import warnings
from datetime import datetime, timezone

from ansible.module_utils.basic import AnsibleModule

from .vendor.hcloud.locations import BoundLocation
from .vendor.hcloud.server_types import BoundServerType, ServerTypeLocation

DEPRECATED_EXISTING_SERVERS = """
Existing servers of that type will continue to work as before and no action is \
required on your part.
""".strip()


def deprecated_server_type_warning(
    module: AnsibleModule,
    server_type: BoundServerType,
    location: BoundLocation | None = None,
) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if server_type.deprecation is not None:
            if server_type.deprecation.unavailable_after < datetime.now(timezone.utc):
                module.warn(
                    str.format(
                        "Server type {server_type} is unavailable in all locations and can no longer be ordered. ",
                        server_type=server_type.name,
                    )
                    + DEPRECATED_EXISTING_SERVERS,
                )
            else:
                module.warn(
                    str.format(
                        "Server type {server_type} is deprecated in all locations and will no longer be available "
                        "for order as of {unavailable_after}. ",
                        server_type=server_type.name,
                        unavailable_after=server_type.deprecation.unavailable_after.strftime("%Y-%m-%d"),
                    )
                    + DEPRECATED_EXISTING_SERVERS,
                )
            return True

    deprecated_locations: list[ServerTypeLocation] = []
    unavailable_locations: list[ServerTypeLocation] = []

    for o in server_type.locations or []:
        if o.deprecation is not None:
            deprecated_locations.append(o)
            if o.deprecation.unavailable_after < datetime.now(timezone.utc):
                unavailable_locations.append(o)

    if not deprecated_locations:
        return False

    # Warn when the server type is deprecated in the given location
    if location:
        found = [o for o in deprecated_locations if location.name == o.location.name]
        if not found:
            return False

        deprecated_location = found[0]

        if deprecated_location in unavailable_locations:
            module.warn(
                str.format(
                    "Server type {server_type} is unavailable in {location} and can no longer be ordered. ",
                    server_type=server_type.name,
                    location=deprecated_location.location.name,
                )
                + DEPRECATED_EXISTING_SERVERS,
            )
        else:
            module.warn(
                str.format(
                    "Server type {server_type} is deprecated in {location} and will no longer be available "
                    "for order as of {unavailable_after}. ",
                    server_type=server_type.name,
                    location=deprecated_location.location.name,
                    unavailable_after=deprecated_location.deprecation.unavailable_after.strftime("%Y-%m-%d"),
                )
                + DEPRECATED_EXISTING_SERVERS,
            )

        return True

    # No location given, only warn when all locations are deprecated
    if len(server_type.locations) != len(deprecated_locations):
        return False

    if unavailable_locations:

        if len(deprecated_locations) != len(unavailable_locations):
            module.warn(
                str.format(
                    "Server type {server_type} is deprecated in all locations ({deprecated_locations}) and can no "
                    "longer be ordered in some locations ({unavailable_locations}). ",
                    server_type=server_type.name,
                    deprecated_locations=",".join(o.location.name for o in deprecated_locations),
                    unavailable_locations=",".join(o.location.name for o in unavailable_locations),
                )
                + DEPRECATED_EXISTING_SERVERS,
            )
        else:
            module.warn(
                str.format(
                    "Server type {server_type} is unavailable in all locations ({unavailable_locations}) and can no "
                    "longer be ordered. ",
                    server_type=server_type.name,
                    unavailable_locations=",".join(o.location.name for o in unavailable_locations),
                )
                + DEPRECATED_EXISTING_SERVERS,
            )
    else:
        module.warn(
            str.format(
                "Server type {server_type} is deprecated in all locations ({deprecated_locations}) and will no "
                "longer be available for order. ",
                server_type=server_type.name,
                deprecated_locations=",".join(o.location.name for o in deprecated_locations),
            )
            + DEPRECATED_EXISTING_SERVERS,
        )

    return True
