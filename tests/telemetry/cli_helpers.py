# Compatibility shim: cli_helpers moved to tests/gnmi/cli_helpers.py as part of
# the telemetry -> gnmi test migration. Re-export from the new location so
# downstream consumers still importing it from tests/telemetry keep working.
from tests.gnmi.cli_helpers import *  # noqa: F401,F403
