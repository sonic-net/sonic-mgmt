"""
Common QoS test utilities for PFC / congestion tests.

Shared helpers used across test_pfc_vxlan.py, test_pfc_l2vni.py, and other
QoS test files in a 2-spine + 2-leaf CLOS topology.

Functions:
    Topology:
        get_nodes()                          - Node name to DUT object mapping
        shutdown_leaf_to_leaf_links()         - Shut D3D4/D4D3 direct links
        startup_leaf_to_leaf_links()          - Bring them back up
        get_leaf_to_leaf_interfaces()         - Get leaf-to-leaf interface names

    Pre-flight checks:
        verify_pfc_priority_on_interfaces()  - Check PFC enabled on target TC
        verify_link_states()                 - Verify expected UP/DOWN states
        dump_qos_maps()                      - Dump DSCP-to-TC / TC-to-Queue maps

    PFC counters:
        get_raw_pfc_counters()               - Run 'show pfc counters' once
        parse_pfc_counters_all()             - Parse PFC counters for N interfaces
        capture_pfc_counters()               - Capture PFC counters across DUTs
        print_pfc_counter_deltas()           - Print before/after PFC deltas

    Drop counters:
        get_drop_count()                     - Get TX/RX drop count for one interface
        capture_drop_counters()              - Capture drop counters across DUTs
        print_drop_counter_deltas()          - Print before/after drop deltas

    Traffic cleanup:
        remove_traffic_streams()             - Remove IXIA traffic configs

    Speed query:
        get_link_speeds()                    - Query actual interface speeds from DUTs
"""

import re
import time
import os
import json

from spytest import st, tgapi
from utilities.parallel import exec_foreach
from collections import OrderedDict

# NOTE: PFC_TC_TABLE and create_pfc_xoff_stream() were moved to
# traffic_stream_ixia_api.py (the canonical home for IXIA stream helpers).
# Callers should import them from `traffic_stream_ixia_api` directly.

# Module-level cache for nodes dict
_nodes_cache = None



def get_nodes():
    """
    Get node name to DUT object mapping for 2-spine + 2-leaf topology.
    Caches the result to avoid repeated testbed var lookups.

    Returns:
        dict: {'spine0': D1, 'spine1': D2, 'leaf0': D3, 'leaf1': D4}
    """
    global _nodes_cache
    if _nodes_cache is None:
        vars = st.get_testbed_vars()
        _nodes_cache = {
            'spine0': vars.D1,
            'spine1': vars.D2,
            'leaf0': vars.D3,
            'leaf1': vars.D4
        }
    return _nodes_cache


# ---------------------------------------------------------------------------
# Per-DUT ConfigDb cache
# ---------------------------------------------------------------------------
_config_db_cache = {}

def load_config_db(dut):
    """Load (or reload) ConfigDb for a DUT. Call after 'config qos reload'."""
    from config_db import ConfigDb
    _config_db_cache[dut] = ConfigDb(dut)
    st.log(f"ConfigDb loaded for {dut}")

def get_config_db(dut):
    """Get cached ConfigDb for a DUT. Loads on first access if not cached."""
    if dut not in _config_db_cache:
        load_config_db(dut)
    return _config_db_cache[dut]


def get_dut_platform(dut):
    """
    Query and return the DUT platform string (e.g. 'x86_64-n9164e_ns4_o-r0').

    Args:
        dut: DUT object

    Returns:
        Platform string if found, None otherwise.
    """
    try:
        output = st.show(dut, "show platform summary", skip_tmpl=True, skip_error_check=True)
        for line in (output or "").splitlines():
            if line.startswith("Platform:"):
                return line.split(":", 1)[1].strip()
    except Exception as e:
        st.log(f"Failed to query platform on {dut}: {e}")
    return None


# ---------------------------------------------------------------------------
# Switchport mode utilities
# ---------------------------------------------------------------------------

def get_switchport_mode(dut, port):
    """Return current switchport mode ('access', 'trunk', 'routed', or '')
    for ``port`` by querying CONFIG_DB PORT|<port> 'mode' field. Empty
    string means the field is unset (SONiC default == routed).

    The raw ``st.config()`` output includes the shell prompt
    (``admin@sonic:~$``) and may include the command echo, so naive
    ``splitlines()[-1]`` parsing returns the prompt instead of the mode.
    Scan all lines and return the first one matching a known mode token.
    """
    _KNOWN_MODES = {'access', 'trunk', 'routed'}
    out = st.config(
        dut,
        f"sonic-db-cli CONFIG_DB HGET 'PORT|{port}' mode",
        skip_error_check=True,
        skip_tmpl=True,
    )
    for line in (out or '').splitlines():
        token = line.strip().lower()
        if token in _KNOWN_MODES:
            return token
    return ''


def set_switchport_mode(dut, port, desired):
    """Set ``port`` to ``desired`` switchport mode ('access' or 'routed').

    Robust against image-specific CLI variants:
      * Idempotent: no-op if port is already in the desired mode.
      * Tries the primary command form, then one fallback form.
      * Verifies via CONFIG_DB that the mode actually changed.

    Raises RuntimeError if neither form works -- silent failures here
    cascade into mysterious traffic-phase failures later in CI (e.g.
    VLAN add or IP add silently no-ops on a port stuck in the wrong
    mode).
    """
    if desired not in ('access', 'routed'):
        raise ValueError(f"unsupported switchport mode: {desired}")
    current = get_switchport_mode(dut, port)
    # Treat empty CONFIG_DB mode as 'routed' (SONiC default).
    if current == desired or (desired == 'routed' and current == ''):
        st.log(f"set_switchport_mode: {port} already in '{desired}' mode")
        return
    forms = [
        f"sudo config switchport mode {desired} {port}",
        f"sudo config interface switchport mode {desired} {port}",
    ]
    last_out = ''
    for cmd in forms:
        out = st.config(dut, cmd, skip_tmpl=True, skip_error_check=True) or ''
        last_out = out
        if 'Usage:' not in out and 'Error:' not in out and 'invalid' not in out.lower():
            new_mode = get_switchport_mode(dut, port)
            if new_mode == desired or (desired == 'routed' and new_mode == ''):
                return
    raise RuntimeError(
        f"Failed to set {port} switchport mode to '{desired}' on {dut}. "
        f"Last CLI output: {last_out!r}. CI/CD risk: silent failure here "
        f"causes VLAN add or IP add to no-op and traffic phases to fail."
    )


# ---------------------------------------------------------------------------
# PFC Headroom Buffer Utilities
# ---------------------------------------------------------------------------

def get_buffer_pg_profile(dut, port, tc=3):
    """
    Get the BUFFER_PG profile name for a port and traffic class.

    Looks up BUFFER_PG|<port>|<tc_range> where tc_range contains the given TC.
    For lossless traffic, TC 3-4 typically share a profile like 'pg_lossless_800000_5m_profile'.

    Args:
        dut: DUT handle
        port: Interface name (e.g., 'Ethernet1_60')
        tc: Traffic class (default 3)

    Returns:
        str: Profile name (e.g., 'pg_lossless_800000_5m_profile'), or None if not found

    Example:
        >>> get_buffer_pg_profile(dut, 'Ethernet1_60', tc=3)
        'pg_lossless_800000_5m_profile'
    """
    config = get_config_db(dut)
    buffer_pg = config.get("BUFFER_PG", {})

    # Look for entries matching this port
    for key in buffer_pg.keys():
        # Key format: "Ethernet1_60|3-4" or "Ethernet1_60|0-2"
        if not key.startswith(port + "|"):
            continue

        # Parse TC range from key (e.g., "3-4" -> [3, 4])
        tc_part = key.split("|")[-1]
        if "-" in tc_part:
            try:
                tc_start, tc_end = map(int, tc_part.split("-"))
                if tc_start <= tc <= tc_end:
                    profile = buffer_pg[key].get("profile")
                    st.log(f"get_buffer_pg_profile: {port} TC{tc} -> {profile}")
                    return profile
            except ValueError:
                continue
        else:
            # Single TC entry (e.g., "3")
            try:
                if int(tc_part) == tc:
                    profile = buffer_pg[key].get("profile")
                    st.log(f"get_buffer_pg_profile: {port} TC{tc} -> {profile}")
                    return profile
            except ValueError:
                continue

    st.log(f"get_buffer_pg_profile: No profile found for {port} TC{tc}")
    return None


def get_buffer_profile_xoff(dut, profile_name):
    """
    Get the xoff value from a BUFFER_PROFILE entry.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_800000_5m_profile')

    Returns:
        str: xoff value as string, or None if not found

    Example:
        >>> get_buffer_profile_xoff(dut, 'pg_lossless_800000_5m_profile')
        '1966080'
    """
    config = get_config_db(dut)
    buffer_profile = config.get("BUFFER_PROFILE", {})

    if profile_name not in buffer_profile:
        st.log(f"get_buffer_profile_xoff: Profile '{profile_name}' not found")
        return None

    xoff = buffer_profile[profile_name].get("xoff")
    st.log(f"get_buffer_profile_xoff: {profile_name} -> xoff={xoff}")
    return xoff


def set_buffer_profile_xoff(dut, profile_name, xoff_value):
    """
    Set the xoff value in a BUFFER_PROFILE entry via redis-cli.

    This directly modifies CONFIG_DB without requiring config reload.
    The change takes effect immediately for buffer management.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_800000_5m_profile')
        xoff_value: New xoff value (string or int, will be converted to string)

    Returns:
        bool: True on success, False on failure

    Example:
        >>> set_buffer_profile_xoff(dut, 'pg_lossless_800000_5m_profile', '0')
        True
    """
    xoff_str = str(xoff_value)
    redis_key = f"BUFFER_PROFILE|{profile_name}"
    cmd = f'redis-cli -n 4 HSET "{redis_key}" "xoff" "{xoff_str}"'

    st.log(f"set_buffer_profile_xoff: Setting {profile_name} xoff={xoff_str}")
    try:
        result = st.config(dut, cmd, skip_tmpl=True)
        # redis-cli HSET returns 0 (field existed) or 1 (new field)
        st.log(f"set_buffer_profile_xoff: redis-cli returned: {result}")
        return True
    except Exception as e:
        st.log(f"set_buffer_profile_xoff: Failed to set xoff: {e}")
        return False


def get_buffer_profile_xon(dut, profile_name):
    """
    Get the xon value from a BUFFER_PROFILE entry.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_800000_5m_profile')

    Returns:
        str: xon value as string, or None if not found

    Example:
        >>> get_buffer_profile_xon(dut, 'pg_lossless_800000_5m_profile')
        '1966080'
    """
    config = get_config_db(dut)
    buffer_profile = config.get("BUFFER_PROFILE", {})

    if profile_name not in buffer_profile:
        st.log(f"get_buffer_profile_xon: Profile '{profile_name}' not found")
        return None

    xon = buffer_profile[profile_name].get("xon")
    st.log(f"get_buffer_profile_xon: {profile_name} -> xon={xon}")
    return xon


def set_buffer_profile_xon(dut, profile_name, xon_value):
    """
    Set the xon value in a BUFFER_PROFILE entry via redis-cli.

    This directly modifies CONFIG_DB without requiring config reload.
    The change takes effect immediately for buffer management.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_800000_5m_profile')
        xon_value: New xon value (string or int, will be converted to string)

    Returns:
        bool: True on success, False on failure

    Example:
        >>> set_buffer_profile_xon(dut, 'pg_lossless_800000_5m_profile', '0')
        True
    """
    xon_str = str(xon_value)
    redis_key = f"BUFFER_PROFILE|{profile_name}"
    cmd = f'redis-cli -n 4 HSET "{redis_key}" "xon" "{xon_str}"'

    st.log(f"set_buffer_profile_xon: Setting {profile_name} xon={xon_str}")
    try:
        result = st.config(dut, cmd, skip_tmpl=True)
        # redis-cli HSET returns 0 (field existed) or 1 (new field)
        st.log(f"set_buffer_profile_xon: redis-cli returned: {result}")
        return True
    except Exception as e:
        st.log(f"set_buffer_profile_xon: Failed to set xon: {e}")
        return False


def get_buffer_profile_size(dut, profile_name):
    """
    Get the size value from a BUFFER_PROFILE entry.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_800000_5m_profile')

    Returns:
        str: Size value (e.g., '296384') or None if not found

    Example:
        >>> get_buffer_profile_size(dut, 'pg_lossless_800000_5m_profile')
        '296384'
    """
    config = get_config_db(dut)
    buffer_profile = config.get("BUFFER_PROFILE", {})

    if profile_name not in buffer_profile:
        st.log(f"get_buffer_profile_size: Profile '{profile_name}' not found")
        return None

    size = buffer_profile[profile_name].get("size")
    st.log(f"get_buffer_profile_size: {profile_name} -> size={size}")
    return size


def set_buffer_profile_size(dut, profile_name, size_value):
    """
    Set the size value in a BUFFER_PROFILE entry via redis-cli.

    This directly modifies CONFIG_DB without requiring config reload.
    The change takes effect immediately for buffer management.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_800000_5m_profile')
        size_value: New size value (string or int, will be converted to string)

    Returns:
        bool: True on success, False on failure

    Example:
        >>> set_buffer_profile_size(dut, 'pg_lossless_800000_5m_profile', '39360')
        True
    """
    size_str = str(size_value)
    redis_key = f"BUFFER_PROFILE|{profile_name}"
    cmd = f'redis-cli -n 4 HSET "{redis_key}" "size" "{size_str}"'

    st.log(f"set_buffer_profile_size: Setting {profile_name} size={size_str}")
    try:
        result = st.config(dut, cmd, skip_tmpl=True)
        # redis-cli HSET returns 0 (field existed) or 1 (new field)
        st.log(f"set_buffer_profile_size: redis-cli returned: {result}")
        return True
    except Exception as e:
        st.log(f"set_buffer_profile_size: Failed to set size: {e}")
        return False


def get_buffer_profile_dynamic_th(dut, profile_name):
    """
    Get the dynamic_th (alpha) value from a BUFFER_PROFILE entry.

    Reads CONFIG_DB directly:
        redis-cli -n 4 HGET "BUFFER_PROFILE|<profile_name>" "dynamic_th"

    Returns:
        str: dynamic_th value (e.g., '0', '-3', '-7') as stored in CONFIG_DB,
             or None if not found.
    """
    config = get_config_db(dut)
    buffer_profile = config.get("BUFFER_PROFILE", {})

    if profile_name not in buffer_profile:
        st.log(f"get_buffer_profile_dynamic_th: Profile '{profile_name}' not found")
        return None

    dyn_th = buffer_profile[profile_name].get("dynamic_th")
    st.log(f"get_buffer_profile_dynamic_th: {profile_name} -> dynamic_th={dyn_th}")
    return dyn_th


def set_buffer_profile_dynamic_th(dut, profile_name, value):
    """
    Set dynamic_th (alpha) on a BUFFER_PROFILE via `mmuconfig -p <profile> -a <value>`.

    `mmuconfig` is the supported SONiC CLI for changing the dynamic threshold
    (alpha) of a buffer profile and is preferred over a raw redis-cli HSET
    because it goes through the buffer manager and propagates the change to
    the SAI/SDK layer.

    Args:
        dut: DUT handle
        profile_name: Profile name (e.g., 'pg_lossless_400000_300m_profile')
        value: New dynamic_th value (int or str), e.g. -7

    Returns:
        bool: True on success, False on failure.
    """
    cmd = f"mmuconfig -p {profile_name} -a {value}"
    st.log(f"set_buffer_profile_dynamic_th: {profile_name} -> dynamic_th={value} via mmuconfig")
    try:
        result = st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
        st.log(f"set_buffer_profile_dynamic_th: mmuconfig output: {result}")
        return True
    except Exception as e:
        st.log(f"set_buffer_profile_dynamic_th: Failed: {e}")
        return False


def show_mmuconfig(dut, profile_name=None):
    """
    Display MMU buffer configuration using 'mmuconfig -l'.

    If profile_name is specified, filter output to show that profile.
    Logs the output for debugging buffer settings.

    Args:
        dut: DUT handle
        profile_name: Optional profile name to filter (e.g., 'pg_lossless_800000_5m_profile')

    Returns:
        str: Raw output from mmuconfig -l
    """
    st.log("=" * 70)
    st.log(f"MMU CONFIG (mmuconfig -l) on {dut}:")
    st.log("=" * 70)

    try:
        output = st.show(dut, "mmuconfig -l", skip_tmpl=True, skip_error_check=True)
        if output:
            if profile_name:
                # Filter to show the specific profile section
                st.log(f"Filtering for profile: {profile_name}")
                lines = output.splitlines()
                in_profile = False
                for line in lines:
                    if profile_name in line:
                        in_profile = True
                    if in_profile:
                        st.log(f"  {line}")
                        # Stop at next profile (starts with non-whitespace)
                        if in_profile and line and not line.startswith(' ') and profile_name not in line:
                            break
            else:
                # Show full output
                for line in output.splitlines():
                    st.log(f"  {line}")
        st.log("=" * 70)
        return output
    except Exception as e:
        st.log(f"show_mmuconfig: Failed to run mmuconfig -l: {e}")
        return None


class HeadroomZeroContext:
    """
    Context manager to temporarily set PFC headroom (xoff) to 0 and restore.

    Used by headroom sizing tests to measure actual headroom demand by
    counting drops when headroom=0.

    For Gamut platform (n9164e), also sets size=xon to ensure proper
    buffer configuration for PFC generation.

    Usage:
        with HeadroomZeroContext(dut, 'Ethernet1_60', tc=3) as ctx:
            # headroom is now 0 - packets will drop during PFC backpressure
            run_headroom_measurement()
            print(f"Original xoff was: {ctx.original_xoff}")
        # original values automatically restored

    Attributes:
        dut: DUT handle
        port: Interface name
        tc: Traffic class
        profile_name: Discovered BUFFER_PROFILE name
        original_xoff: Original xoff value (for restoration)
        original_size: Original size value (for restoration, Gamut only)
        is_gamut: True if platform is Gamut (n9164e)
    """

    def __init__(self, dut, port, tc=3):
        """
        Initialize the context manager.

        Args:
            dut: DUT handle
            port: Interface name (e.g., 'Ethernet1_60')
            tc: Traffic class (default 3)
        """
        self.dut = dut
        self.port = port
        self.tc = tc
        self.profile_name = None
        self.original_xoff = None
        self.original_size = None
        self.original_xon = None
        self.original_dynamic_th = None
        # Forced dynamic_th (alpha) applied to the BUFFER_PROFILE for the
        # duration of the headroom test. -7 (the minimum) forces every PG
        # to claim essentially zero of the shared pool, so the only buffer
        # available is the dedicated headroom (xoff). Combined with xoff=0
        # this makes any backpressure event drop immediately and lets us
        # measure (drops/pfc_tx)*frame as the real headroom demand.
        self.forced_dynamic_th = -7
        self.is_gamut = False

    def __enter__(self):
        """
        Cache current xoff value and set to 0.

        Returns:
            self: Context manager instance (access original_xoff, profile_name)

        Raises:
            ValueError: If profile or xoff cannot be found
        """
        # Get the profile name for this port/TC
        self.profile_name = get_buffer_pg_profile(self.dut, self.port, self.tc)
        if not self.profile_name:
            raise ValueError(
                f"HeadroomZeroContext: No BUFFER_PG profile found for "
                f"{self.port} TC{self.tc}"
            )

        # Detect if this is Gamut platform
        platform = detect_platform(self.dut)
        self.is_gamut = (platform == 'n9164e')
        st.log(f"HeadroomZeroContext: Platform={platform}, is_gamut={self.is_gamut}")

        # Cache the original xoff value
        self.original_xoff = get_buffer_profile_xoff(self.dut, self.profile_name)
        if self.original_xoff is None:
            raise ValueError(
                f"HeadroomZeroContext: No xoff value found for profile "
                f"'{self.profile_name}'"
            )

        # For Gamut, also cache original xon and size values
        # Gamut requires: xoff=0, size=xon (original xon value)
        if self.is_gamut:
            self.original_xon = get_buffer_profile_xon(self.dut, self.profile_name)
            self.original_size = get_buffer_profile_size(self.dut, self.profile_name)
            st.log(f"HeadroomZeroContext: Gamut platform - will set xoff=0, size={self.original_xon} "
                   f"(was xoff={self.original_xoff}, size={self.original_size}, xon={self.original_xon})")

        # Cache original dynamic_th (alpha) so we can restore it on exit.
        # Not fatal if absent (some platforms may not set it explicitly);
        # we still try to apply the forced value.
        self.original_dynamic_th = get_buffer_profile_dynamic_th(
            self.dut, self.profile_name)
        st.log(f"HeadroomZeroContext: Original dynamic_th={self.original_dynamic_th} "
               f"on {self.profile_name}")

        # Set xoff to 0 for all platforms
        st.banner(f"HeadroomZeroContext: Setting {self.profile_name} xoff=0 "
                  f"(was {self.original_xoff})")

        success = set_buffer_profile_xoff(self.dut, self.profile_name, "0")
        if not success:
            raise RuntimeError(
                f"HeadroomZeroContext: Failed to set xoff=0 on {self.profile_name}"
            )

        # Force dynamic_th to the minimum (-7) on this profile so the PG
        # cannot draw from the shared pool. See note on forced_dynamic_th
        # in __init__ for rationale.
        st.banner(f"HeadroomZeroContext: Setting {self.profile_name} "
                  f"dynamic_th={self.forced_dynamic_th} "
                  f"(was {self.original_dynamic_th}) via mmuconfig")
        if not set_buffer_profile_dynamic_th(
                self.dut, self.profile_name, self.forced_dynamic_th):
            # Best-effort restore of xoff before failing
            set_buffer_profile_xoff(
                self.dut, self.profile_name, self.original_xoff)
            raise RuntimeError(
                f"HeadroomZeroContext: Failed to set dynamic_th="
                f"{self.forced_dynamic_th} on {self.profile_name}"
            )

        # For Gamut, also set size = original xon value
        if self.is_gamut and self.original_xon is not None:
            st.log(f"HeadroomZeroContext: Setting {self.profile_name} size={self.original_xon} (Gamut)")
            success_size = set_buffer_profile_size(self.dut, self.profile_name, self.original_xon)
            if not success_size:
                st.error(f"HeadroomZeroContext: Failed to set size={self.original_xon} on {self.profile_name}")
                # Restore xoff since we failed partway through
                set_buffer_profile_xoff(self.dut, self.profile_name, self.original_xoff)
                raise RuntimeError(
                    f"HeadroomZeroContext: Failed to set size={self.original_xon} on {self.profile_name}"
                )

        # Show mmuconfig to verify the buffer profile settings
        st.log(f"HeadroomZeroContext: Gamut={self.is_gamut}, xoff set to 0")
        show_mmuconfig(self.dut, self.profile_name)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Restore the original xoff value (and size for Gamut).

        Always attempts restoration, even if an exception occurred.
        Logs but does not re-raise restoration failures.
        """
        if self.profile_name and self.original_xoff is not None:
            # Restore dynamic_th first (mmuconfig change) before touching
            # xoff/size via redis-cli, so the profile is returned to its
            # original alpha before we hand control back to the test.
            if self.original_dynamic_th is not None:
                st.log(f"HeadroomZeroContext: Restoring {self.profile_name} "
                       f"dynamic_th={self.original_dynamic_th} via mmuconfig")
                if not set_buffer_profile_dynamic_th(
                        self.dut, self.profile_name, self.original_dynamic_th):
                    st.error(
                        f"HeadroomZeroContext: FAILED to restore dynamic_th="
                        f"{self.original_dynamic_th} on {self.profile_name} - "
                        f"manual restoration may be needed!"
                    )
            else:
                st.log(f"HeadroomZeroContext: No original dynamic_th cached "
                       f"for {self.profile_name}, skipping alpha restore")

            # For Gamut, restore size first
            if self.is_gamut and self.original_size is not None:
                st.log(f"HeadroomZeroContext: Restoring {self.profile_name} "
                       f"size={self.original_size} (Gamut)")
                success_size = set_buffer_profile_size(
                    self.dut, self.profile_name, self.original_size
                )
                if not success_size:
                    st.error(
                        f"HeadroomZeroContext: FAILED to restore size={self.original_size} "
                        f"on {self.profile_name} - manual restoration may be needed!"
                    )

            st.banner(f"HeadroomZeroContext: Restoring {self.profile_name} "
                      f"xoff={self.original_xoff}")
            success = set_buffer_profile_xoff(
                self.dut, self.profile_name, self.original_xoff
            )
            if not success:
                st.error(
                    f"HeadroomZeroContext: FAILED to restore xoff={self.original_xoff} "
                    f"on {self.profile_name} - manual restoration may be needed!"
                )
        else:
            st.log("HeadroomZeroContext: No restoration needed (profile/xoff not set)")

        # Don't suppress exceptions
        return False


def capture_headroom_counters(dut, port, tc=3):
    """
    Capture all counters relevant to headroom sizing tests.

    Collects PG drops, PFC counters, port counters, watermarks in one call.

    Args:
        dut: DUT handle
        port: Interface name
        tc: Traffic class (default 3)

    Returns:
        dict: {
            'pg_drop': int,           # Priority group drop count for TC
            'pfc_rx': int,            # PFC frames received for TC
            'pfc_tx': int,            # PFC frames transmitted for TC
            'rx_packets': int,        # Total RX packets on port
            'tx_packets': int,        # Total TX packets on port
            'pg_watermark': int,      # PG watermark (shared) for TC
            'buffer_pool_watermark': dict,  # {pool_name: value}
        }

    Example:
        >>> counters = capture_headroom_counters(dut, 'Ethernet1_60', tc=3)
        >>> print(f"PG drops: {counters['pg_drop']}")
    """
    result = {
        'pg_drop': 0,
        'pfc_rx': 0,
        'pfc_tx': 0,
        'rx_packets': 0,
        'tx_packets': 0,
        'pg_watermark': 0,
        'buffer_pool_watermark': {},
    }

    try:
        # PG drop counters
        pg_drops = _get_pg_drop_counters_simple(dut, port)
        result['pg_drop'] = pg_drops.get(tc, 0)

        # PFC counters
        result['pfc_rx'] = get_pfc_rx_count(dut, port, tc)
        result['pfc_tx'] = get_pfc_tx_count(dut, port, tc)

        # Port counters
        port_counters = _get_port_counters_simple(dut, port)
        result['rx_packets'] = port_counters.get('rx_ok', 0)
        result['tx_packets'] = port_counters.get('tx_ok', 0)

        # PG watermark (shared)
        pg_wm = _get_pg_watermark_simple(dut, port)
        result['pg_watermark'] = pg_wm.get(tc, 0)

        # Buffer pool watermark
        try:
            raw = get_buffer_pool_watermark(dut)
            if raw:
                parsed = parse_buffer_pool_watermark(raw)
                for k, v in parsed.items():
                    try:
                        result['buffer_pool_watermark'][k] = int(str(v).replace(',', ''))
                    except (ValueError, AttributeError):
                        result['buffer_pool_watermark'][k] = v
        except Exception as e:
            st.log(f"capture_headroom_counters: buffer pool watermark failed: {e}")

    except Exception as e:
        st.log(f"capture_headroom_counters: Error capturing counters: {e}")

    st.log(f"capture_headroom_counters({port}, TC{tc}): {result}")
    return result


def get_queue_drops_for_port(dut, port, tc=3):
    """
    Get queue drop counter (unicast) for a specific port and TC.

    Uses 'show queue counters <port>' to get Drop/pkts for UC<tc>.

    Args:
        dut: DUT handle
        port: Port name (e.g., 'Ethernet1_45')
        tc: Traffic class (default 3)

    Returns:
        int: Queue drop packets for UC<tc>
    """
    cmd = f"show queue counters {port}"
    output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)

    if not output:
        st.log(f"No queue counters output for {port}")
        return 0

    queue_name = f"UC{tc}"
    for line in output.splitlines():
        line = line.strip()
        if port in line and queue_name in line:
            parts = line.split()
            # Format: Port TxQ Counter/pkts Counter/bytes Drop/pkts Drop/bytes
            # Example: Ethernet1_45  UC3  12345  1234567  100  N/A
            if len(parts) >= 5:
                try:
                    drop_pkts = int(parts[4].replace(',', ''))
                    st.log(f"Queue drops {port} {queue_name}: {drop_pkts} pkts")
                    return drop_pkts
                except ValueError:
                    if parts[4] == 'N/A':
                        st.log(f"Queue drops {port} {queue_name}: N/A (0)")
                        return 0

    st.log(f"Could not parse queue drops for {port} {queue_name}")
    return 0


def get_queue_watermark_for_port(dut, port, tc=3):
    """
    Get queue watermark (unicast) for a specific port and TC.

    Args:
        dut: DUT handle
        port: Port name (e.g., 'Ethernet1_45')
        tc: Traffic class (default TC=3)

    Returns:
        int: Queue watermark in bytes for UC<tc>
    """
    cmd = f"show queue watermark unicast | grep -w {port}"
    output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)

    if not output:
        st.log(f"No queue watermark output for {port}")
        return 0

    for line in output.splitlines():
        line = line.strip()
        if port in line:
            parts = line.split()
            # Format: Port UC0 UC1 UC2 UC3 UC4 ...
            # UC<tc> is at index tc+1
            if len(parts) > tc + 1:
                try:
                    watermark = int(parts[tc + 1])
                    st.log(f"Queue watermark {port} UC{tc}: {watermark} bytes")
                    return watermark
                except ValueError:
                    pass

    st.log(f"Could not parse queue watermark for {port} UC{tc}")
    return 0


def collect_pfc_debug_info(dut, port, tc=3):
    """
    Collect comprehensive PFC debug information when we see unexpected behavior.

    Called when pg_drop > 0 but pfc_tx == 0 to diagnose why PFC wasn't generated.

    Args:
        dut: DUT handle
        port: Interface name
        tc: Traffic class

    Returns:
        dict: Debug information collected
    """
    debug_info = {}

    st.banner(f"COLLECTING PFC DEBUG INFO FOR {port} TC{tc}")

    # 1. Check BUFFER_PG profile applied to the port
    st.log("=== BUFFER_PG Configuration ===")
    try:
        profile_name = get_buffer_pg_profile(dut, port, tc)
        debug_info['buffer_pg_profile'] = profile_name
        st.log(f"BUFFER_PG profile for {port} TC{tc}: {profile_name}")

        if profile_name:
            # Get full profile details
            xoff = get_buffer_profile_xoff(dut, profile_name)
            debug_info['xoff_value'] = xoff
            st.log(f"Profile {profile_name} xoff value: {xoff}")
    except Exception as e:
        st.log(f"Error getting buffer profile: {e}")
        debug_info['buffer_pg_error'] = str(e)
        profile_name = None

    # 2. Show buffer configuration from redis
    st.log("=== BUFFER_PROFILE from Redis ===")
    try:
        cmd = f"redis-cli -n 4 HGETALL 'BUFFER_PROFILE|{profile_name}'" if profile_name else "echo 'No profile'"
        output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        debug_info['buffer_profile_redis'] = output
        st.log(f"Redis BUFFER_PROFILE:\n{output}")
    except Exception as e:
        st.log(f"Error getting redis buffer profile: {e}")

    # 3. Show PFC priority configuration
    st.log("=== PFC Priority Configuration ===")
    try:
        output = st.show(dut, f"show pfc priority | grep -E 'Interface|{port}'", skip_tmpl=True, skip_error_check=True)
        debug_info['pfc_priority'] = output
        st.log(f"PFC priority:\n{output}")
    except Exception as e:
        st.log(f"Error getting PFC priority: {e}")

    # 4. Show PFC counters (all TCs)
    st.log("=== PFC Counters (All TCs) ===")
    try:
        output = st.show(dut, f"show pfc counters | grep -E 'Port|{port}'", skip_tmpl=True, skip_error_check=True)
        debug_info['pfc_counters'] = output
        st.log(f"PFC counters:\n{output}")
    except Exception as e:
        st.log(f"Error getting PFC counters: {e}")

    # 5. Show priority-group drop counters (all PGs)
    st.log("=== Priority Group Drop Counters ===")
    try:
        output = st.show(dut, f"show priority-group drop counters | grep -E 'Port|{port}'", skip_tmpl=True, skip_error_check=True)
        debug_info['pg_drop_counters'] = output
        st.log(f"PG drop counters:\n{output}")
    except Exception as e:
        st.log(f"Error getting PG drop counters: {e}")

    # 6. Show priority-group watermark
    st.log("=== Priority Group Watermark ===")
    try:
        output = st.show(dut, f"show priority-group watermark shared | grep -E 'Port|{port}'", skip_tmpl=True, skip_error_check=True)
        debug_info['pg_watermark'] = output
        st.log(f"PG watermark:\n{output}")
    except Exception as e:
        st.log(f"Error getting PG watermark: {e}")

    # 7. Show interface status
    st.log("=== Interface Status ===")
    try:
        output = st.show(dut, f"show interface status | grep {port}", skip_tmpl=True, skip_error_check=True)
        debug_info['interface_status'] = output
        st.log(f"Interface status:\n{output}")
    except Exception as e:
        st.log(f"Error getting interface status: {e}")

    # 8. Check if PFC is enabled via lldp or interface config
    st.log("=== PFC Asymmetric Setting ===")
    try:
        output = st.show(dut, f"redis-cli -n 4 HGETALL 'PORT_QOS_MAP|{port}'", skip_tmpl=True, skip_error_check=True)
        debug_info['port_qos_map'] = output
        st.log(f"PORT_QOS_MAP:\n{output}")
    except Exception as e:
        st.log(f"Error getting PORT_QOS_MAP: {e}")

    # 9. Check PFC watchdog status
    st.log("=== PFC Watchdog Status ===")
    try:
        output = st.show(dut, "show pfcwd stats", skip_tmpl=True, skip_error_check=True)
        debug_info['pfcwd_stats'] = output
        st.log(f"PFC watchdog stats:\n{output}")
    except Exception as e:
        st.log(f"Error getting PFCWD stats: {e}")

    st.banner("END PFC DEBUG INFO")
    return debug_info


# ---------------------------------------------------------------------------
# DSCP / TC mapping
# ---------------------------------------------------------------------------

def convert_tc_to_dscp(dut, tc):
    """Return the first DSCP value that maps to the given TC on *dut*.

    Uses the cached ConfigDb instance to read DSCP_TO_TC_MAP.
    Call load_config_db(dut) after 'config qos reload' to pick up changes.
    """
    config = get_config_db(dut)
    dscp_map = config["DSCP_TO_TC_MAP"]
    map_name = next(iter(dscp_map))
    mapping = dscp_map[map_name]
    tc_str = str(tc)
    for dscp_val, mapped_tc in mapping.items():
        if mapped_tc == tc_str:
            return dscp_val
    return None


# ---------------------------------------------------------------------------
# Leaf-to-leaf link management
# ---------------------------------------------------------------------------

def shutdown_leaf_to_leaf_links(nodes):
    """
    Shutdown direct Leaf0<->Leaf1 links (D3D4P1/D4D3P1) if they exist.

    In some testbeds, Leaf0 and Leaf1 have a direct back-to-back link.
    If left up, traffic can bypass the spine entirely, defeating congestion
    tests that rely on spine-link oversubscription to trigger PFC.

    Args:
        nodes: Dict mapping node names to DUT objects
    """
    vars = st.get_testbed_vars()

    shut_count = 0
    for var_name, node_name in [('D3D4P1', 'leaf0'), ('D4D3P1', 'leaf1')]:
        if hasattr(vars, var_name):
            intf = getattr(vars, var_name)
            peer = 'Leaf1' if node_name == 'leaf0' else 'Leaf0'
            st.log(f"Shutting down {intf} on {node_name} (direct link to {peer})")
            st.config(nodes[node_name], f"sudo config interface shutdown {intf}")
            shut_count += 1

    if shut_count > 0:
        st.log(f"Shut {shut_count} leaf-to-leaf link(s)")
        st.wait(2)
    else:
        st.log("No leaf-to-leaf links found in testbed (D3D4P1/D4D3P1) - skipping")


def startup_leaf_to_leaf_links(nodes):
    """
    Bring back up direct Leaf0<->Leaf1 links (D3D4P1/D4D3P1) if they exist.

    Args:
        nodes: Dict mapping node names to DUT objects
    """
    vars = st.get_testbed_vars()

    for var_name, node_name in [('D3D4P1', 'leaf0'), ('D4D3P1', 'leaf1')]:
        if hasattr(vars, var_name):
            intf = getattr(vars, var_name)
            peer = 'Leaf1' if node_name == 'leaf0' else 'Leaf0'
            st.log(f"Starting up {intf} on {node_name} (direct link to {peer})")
            st.config(nodes[node_name], f"sudo config interface startup {intf}")

    st.wait(2)


def get_leaf_to_leaf_interfaces():
    """
    Return leaf-to-leaf interface names if they exist in the testbed.

    Returns:
        dict: {'leaf0': [intf_list], 'leaf1': [intf_list]}
              Empty lists if no leaf-to-leaf links exist.
    """
    vars = st.get_testbed_vars()

    result = {'leaf0': [], 'leaf1': []}
    if hasattr(vars, 'D3D4P1'):
        result['leaf0'].append(vars.D3D4P1)
    if hasattr(vars, 'D4D3P1'):
        result['leaf1'].append(vars.D4D3P1)
    return result


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def verify_pfc_priority_on_interfaces(nodes, interfaces_map, tc):
    """
    Pre-flight check: verify PFC is enabled on the target TC for all interfaces
    in the traffic path. Parses 'show pfc priority' output.

    Output format:
        Interface       Lossless priorities
        --------------  ---------------------
        Ethernet1_1     3,4
        Ethernet1_57    3,4

    Args:
        nodes: Dict mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class to check (e.g. 3)

    Returns:
        bool: True if all interfaces have PFC enabled on the target TC
    """
    st.banner(f"PRE-FLIGHT: Verifying PFC priority enabled on TC {tc} for all traffic-path interfaces")
    all_ok = True
    tc_str = str(tc)

    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        dut = nodes[node_name]

        grep_pattern = '|'.join(interfaces)
        output = st.show(dut, f"show pfc priority | egrep '{grep_pattern}'", skip_tmpl=True)
        st.log(f"=== {node_name.upper()} show pfc priority (filtered) ===")
        st.log(output)

        for intf in interfaces:
            found = False
            for line in output.splitlines():
                if intf in line:
                    found = True
                    parts = line.split()
                    if len(parts) >= 2:
                        lossless_str = parts[1]
                        lossless_tcs = [x.strip() for x in lossless_str.split(',')]
                        if tc_str in lossless_tcs:
                            st.log(f"  {node_name} {intf}: lossless priorities = {lossless_str} (TC {tc} present - good)")
                        else:
                            st.error(f"  {node_name} {intf}: lossless priorities = {lossless_str} (TC {tc} NOT in list)")
                            all_ok = False
                    else:
                        st.error(f"  {node_name} {intf}: no lossless priorities found (line: {line.strip()})")
                        all_ok = False
                    break
            if not found:
                st.error(f"  {node_name} {intf}: NOT FOUND in 'show pfc priority' output")
                all_ok = False

    if all_ok:
        st.log("PRE-FLIGHT PASSED: PFC priority enabled on all traffic-path interfaces")
    else:
        st.error("PRE-FLIGHT FAILED: PFC priority NOT enabled on one or more interfaces")
    return all_ok


def verify_link_states(nodes, expected_up, expected_down):
    """
    Verify interface oper states match expectations after link shutdown.

    Args:
        nodes: Dict mapping node names to DUT objects
        expected_up: Dict {node_name: [interfaces that should be UP]}
        expected_down: Dict {node_name: [interfaces that should be DOWN]}

    Returns:
        bool: True if all states match expectations
    """
    st.banner("Verifying interface oper states after link shutdown")
    all_ok = True

    for node_name, interfaces in expected_up.items():
        if node_name not in nodes:
            continue
        for intf in interfaces:
            output = st.show(nodes[node_name], f"show interfaces status {intf}", skip_tmpl=True)
            if 'up' in output.lower():
                st.log(f"  {node_name} {intf}: UP (expected)")
            else:
                st.error(f"  {node_name} {intf}: NOT UP (expected UP) - output: {output.strip()[:200]}")
                all_ok = False

    for node_name, interfaces in expected_down.items():
        if node_name not in nodes:
            continue
        for intf in interfaces:
            output = st.show(nodes[node_name], f"show interfaces status {intf}", skip_tmpl=True)
            if 'down' in output.lower() or 'disabled' in output.lower():
                st.log(f"  {node_name} {intf}: DOWN (expected)")
            else:
                st.error(f"  {node_name} {intf}: NOT DOWN (expected DOWN) - output: {output.strip()[:200]}")
                all_ok = False

    if all_ok:
        st.log("All interface states match expectations")
    else:
        st.error("WARNING: Some interface states do not match expectations")
    return all_ok


def dump_qos_maps(nodes, node_names):
    """
    Dump QoS DSCP-to-TC and TC-to-queue maps on specified nodes.
    Useful to confirm the DSCP used by IXIA actually maps to TC 3.
    """
    st.banner("PRE-FLIGHT: Dumping QoS maps on traffic-path DUTs")
    for name in node_names:
        if name not in nodes:
            continue
        dut = nodes[name]
        st.log(f"=== {name.upper()} QoS Maps ===")
        st.show(dut, "show dscp-to-tc-map", skip_tmpl=True)
        st.show(dut, "show tc-to-queue-map", skip_tmpl=True)


# ---------------------------------------------------------------------------
# PFC counter capture and reporting
# ---------------------------------------------------------------------------

def get_raw_pfc_counters(dut):
    """
    Run 'show pfc counters' once and return the raw output.
    Uses st.config to avoid verbose auto-logging of full counter table.

    Returns:
        str: Raw output from 'show pfc counters'
    """
    return st.config(dut, "show pfc counters", skip_error_check=True)


def parse_pfc_counters_all(raw_output, interfaces, tc):
    """
    Parse PFC TX and RX counts for multiple interfaces from raw 'show pfc counters' output.
    Scans the raw output only ONCE to extract counters for all requested interfaces.

    Args:
        raw_output: Raw string output from 'show pfc counters'
        interfaces: List of interface names like ['Ethernet1_48', 'Ethernet1_57']
        tc: Traffic class (queue number) for PFC counters (0-7)

    Returns:
        dict: {interface: {'tx': tx_count, 'rx': rx_count}}
    """
    counters = {intf: {'tx': 0, 'rx': 0} for intf in interfaces}
    interfaces_set = set(interfaces)

    current_direction = None

    for line in raw_output.splitlines():
        if 'Port Rx' in line:
            current_direction = 'rx'
            continue
        elif 'Port Tx' in line:
            current_direction = 'tx'
            continue

        if current_direction is None:
            continue
        if line.strip().startswith('-') or not line.strip():
            continue

        tokens = line.split()
        if len(tokens) < tc + 2:
            continue

        intf_name = tokens[0]
        if intf_name not in interfaces_set:
            continue

        try:
            count = int(tokens[1 + tc].replace(',', ''))
            counters[intf_name][current_direction] = count
        except (ValueError, IndexError):
            continue

    return counters


def capture_pfc_counters(nodes, interfaces_map, tc):
    """
    Capture PFC TX and RX counters for specified interfaces on each node.
    Runs 'show pfc counters' only ONCE per DUT, then parses all interfaces in one pass.

    Args:
        nodes: Dictionary mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class for PFC counters

    Returns:
        dict: Nested dict {node: {interface: {'tx': val, 'rx': val}}}
    """
    counters = {}
    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        raw_output = get_raw_pfc_counters(nodes[node_name])
        counters[node_name] = parse_pfc_counters_all(raw_output, interfaces, tc)

    return counters


def print_pfc_counter_deltas(before, after, label="PFC Counter Deltas"):
    """
    Calculate and print PFC TX and RX counter deltas between before and after snapshots.
    Only prints interfaces where there is a non-zero delta.
    """
    st.banner(label)
    has_deltas = False

    for node_name in sorted(after.keys()):
        node_deltas = []
        for intf in sorted(after[node_name].keys()):
            before_tx = before.get(node_name, {}).get(intf, {}).get('tx', 0)
            before_rx = before.get(node_name, {}).get(intf, {}).get('rx', 0)
            after_tx = after[node_name][intf]['tx']
            after_rx = after[node_name][intf]['rx']

            delta_tx = after_tx - before_tx
            delta_rx = after_rx - before_rx

            if delta_tx != 0 or delta_rx != 0:
                node_deltas.append({
                    'intf': intf,
                    'delta_tx': delta_tx,
                    'delta_rx': delta_rx,
                    'before_tx': before_tx,
                    'after_tx': after_tx,
                    'before_rx': before_rx,
                    'after_rx': after_rx
                })

        if node_deltas:
            has_deltas = True
            st.log(f"=== {node_name.upper()} ===")
            for d in node_deltas:
                parts = []
                if d['delta_tx'] != 0:
                    parts.append(f"TX {d['before_tx']} -> {d['after_tx']} (delta: +{d['delta_tx']})")
                if d['delta_rx'] != 0:
                    parts.append(f"RX {d['before_rx']} -> {d['after_rx']} (delta: +{d['delta_rx']})")
                st.log(f"  {d['intf']}: PFC {', '.join(parts)}")

    if not has_deltas:
        st.log("No PFC counter changes detected on any interface.")


# ---------------------------------------------------------------------------
# Drop counter capture and reporting
# ---------------------------------------------------------------------------

def get_drop_count(dut, interface_name, direction):
    """
    Get drop count for an interface in specified direction.

    Args:
        dut: DUT object to run command on
        interface_name: Interface name like 'Ethernet1_48'
        direction: 'tx' or 'rx'

    Returns:
        int: Drop count for the specified direction
    """
    result = st.show(dut, f"show int count -i {interface_name}", skip_tmpl=True)
    # Output format (note: RX_BPS/TX_BPS like "0.00 B/s" splits into 2 tokens):
    #          IFACE    STATE    RX_OK  RX_BPS    RX_UTIL  RX_ERR  RX_DRP  RX_OVR
    #                                                                TX_OK  TX_BPS    TX_UTIL  TX_ERR  TX_DRP  TX_OVR
    # After split(): 0=IFACE, 1=STATE, 2=RX_OK, 3=0.00, 4=B/s, 5=RX_UTIL,
    #                6=RX_ERR, 7=RX_DRP, 8=RX_OVR,
    #                9=TX_OK, 10=0.00, 11=B/s, 12=TX_UTIL, 13=TX_ERR, 14=TX_DRP, 15=TX_OVR
    lines = result.strip().splitlines()
    for line in lines:
        if interface_name in line:
            tokens = line.split()
            if direction.lower() == 'rx':
                return int(tokens[7].replace(',', ''))
            else:  # tx
                return int(tokens[14].replace(',', ''))
    return 0


def capture_drop_counters(nodes, interfaces_map):
    """
    Capture TX and RX drop counts for specified interfaces on each node.

    Args:
        nodes: Dictionary mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces

    Returns:
        dict: Nested dict {node: {interface: {'tx_drop': val, 'rx_drop': val}}}
    """
    counters = {}
    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        counters[node_name] = {}
        for intf in interfaces:
            tx_drop = get_drop_count(nodes[node_name], intf, 'tx')
            rx_drop = get_drop_count(nodes[node_name], intf, 'rx')
            counters[node_name][intf] = {'tx_drop': tx_drop, 'rx_drop': rx_drop}
    return counters


def print_drop_counter_deltas(before, after, label="Drop Counter Deltas"):
    """
    Calculate and print drop counter deltas between before and after snapshots.
    Only prints interfaces where there is a non-zero delta.
    """
    st.banner(label)
    has_deltas = False

    for node_name in sorted(after.keys()):
        node_deltas = []
        for intf in sorted(after[node_name].keys()):
            before_tx = before.get(node_name, {}).get(intf, {}).get('tx_drop', 0)
            before_rx = before.get(node_name, {}).get(intf, {}).get('rx_drop', 0)
            after_tx = after[node_name][intf]['tx_drop']
            after_rx = after[node_name][intf]['rx_drop']

            delta_tx = after_tx - before_tx
            delta_rx = after_rx - before_rx

            if delta_tx != 0 or delta_rx != 0:
                node_deltas.append({
                    'intf': intf,
                    'delta_tx': delta_tx,
                    'delta_rx': delta_rx,
                    'before_tx': before_tx,
                    'after_tx': after_tx,
                    'before_rx': before_rx,
                    'after_rx': after_rx
                })

        if node_deltas:
            has_deltas = True
            st.log(f"=== {node_name.upper()} ===")
            for d in node_deltas:
                parts = []
                if d['delta_tx'] != 0:
                    parts.append(f"TX_DRP {d['before_tx']} -> {d['after_tx']} (delta: +{d['delta_tx']})")
                if d['delta_rx'] != 0:
                    parts.append(f"RX_DRP {d['before_rx']} -> {d['after_rx']} (delta: +{d['delta_rx']})")
                st.log(f"  {d['intf']}: {', '.join(parts)}")

    if not has_deltas:
        st.log("No drop counter changes detected on any interface.")


# ---------------------------------------------------------------------------
# Traffic cleanup
# ---------------------------------------------------------------------------

def remove_traffic_streams(streams_dict):
    """
    Remove traffic item configurations from IXIA.
    Properly cleans up traffic configs using tg_traffic_config(mode='remove').

    Args:
        streams_dict: Dictionary of traffic streams from traffic setup
    """
    if not streams_dict:
        return
    st.banner("Removing traffic streams from IXIA")
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        st.log(f"Removing traffic config: {traffic_item} -> {stream_id}")
        tg.tg_traffic_config(mode='remove', stream_id=stream_id)


def get_link_speeds(nodes, interfaces_by_node):
    """
    Query actual interface speeds (in Gbps) from DUTs.

    Args:
        nodes: dict mapping node names to DUT objects
        interfaces_by_node: dict mapping node name to list of interface names
            e.g. {'leaf0': ['Ethernet1_1_1', 'Ethernet1_2_1'], 'spine0': ['Ethernet1_3_1']}

    Returns:
        dict: {node_name: {interface: speed_gbps}} e.g. {'leaf0': {'Ethernet1_1_1': 400}}
    """
    speeds = {}
    for node_name, intf_list in interfaces_by_node.items():
        dut = nodes[node_name]
        speeds[node_name] = {}
        for intf in intf_list:
            speed = get_if_speed(dut, intf)
            speeds[node_name][intf] = speed
            st.log(f"  {node_name} {intf} speed: {speed}G")
    return speeds


def format_speed(gbps):
    """Format a speed in Gbps to a human-readable string (e.g. 400G, 1.6Tbps)."""
    if gbps >= 1000:
        return f"{gbps / 1000:.1f}Tbps"
    return f"{gbps}G"


def dump_counters(dut, interfaces, msg=""):
    """
    Dump debug info while traffic is running.
    Shows PFC counters, queue counters, PG watermarks, and buffer PG config.
    All output goes to the log as-is -- no parsing.

    Args:
        dut: DUT handle (the leaf under test)
        interfaces: list of interface names to check (e.g. ingress + egress ports)
    """
    st.log("=== Interface counters ===")
    st.show(dut, "show interface counters", skip_tmpl=True)

    st.log(f"=== Queue counters: {interfaces} ===")
    if 'all' in interfaces:
        st.show(dut, "show queue counters", skip_tmpl=True)
    else:
        for intf in interfaces:
            st.show(dut, f"show queue counters {intf}", skip_tmpl=True)

    st.log("=== Queue watermarks ===")
    st.show(dut, "show queue watermark unicast", skip_tmpl=True)

    st.log("=== Drop counters ===")
    st.show(dut, "show dropcounters count", skip_tmpl=True)

    st.log("=== PFC counters ===")
    st.show(dut, "show pfc counters", skip_tmpl=True)

    st.log("=== Priority-group watermark (shared) ===")
    st.show(dut, "show priority-group watermark shared", skip_tmpl=True)

    st.log("=== Priority-group watermark (headroom) ===")
    st.show(dut, "show priority-group watermark headroom", skip_tmpl=True)

    st.log("=== Priority-group drop counters ===")
    st.show(dut, "show priority-group drop counters", skip_tmpl=True)

    st.log("=== Buffer pool usage ===")
    st.show(dut, "show buffer_pool watermark", skip_tmpl=True,
            skip_error_check=True)

    # TODO when enabled add queue wredcounters

# ===========================================================================
# ECN / WRED Test Utilities (merged from ecn_test_utils.py)
# ===========================================================================

# ECN/ECT bit values (lower 2 bits of TOS/Traffic Class byte)
ECN_NOT_ECT = 0b00  # Not-ECT: packet not participating in ECN
ECN_ECT_1 = 0b01    # ECT(1): ECN-Capable Transport
ECN_ECT_0 = 0b10    # ECT(0): ECN-Capable Transport (default for ECN-capable)
ECN_CE = 0b11       # Congestion Experienced

# Platform detection cache: {dut_id: 'laguna' | 'carib' | 'n9164e' | 'generic'}
_platform_cache = {}


# ---------------------------------------------------------------------------
# IP TOS / Traffic Class utilities
# ---------------------------------------------------------------------------

def compute_ip_tos(dscp, ect=ECN_ECT_0):
    """
    Combine DSCP and ECT values into a single ip_tos byte.

    The TOS byte (IPv4) / Traffic Class byte (IPv6) format:
        Bits 7-2 (6 bits): DSCP (Differentiated Services Code Point)
        Bits 1-0 (2 bits): ECN (Explicit Congestion Notification)

    Args:
        dscp: DSCP value (0-63)
        ect: ECN codepoint (ECN_NOT_ECT, ECN_ECT_1, ECN_ECT_0, or ECN_CE)

    Returns:
        int: Combined ip_tos value (0-255)

    Example:
        DSCP 24 (TC 3) with ECT(0): compute_ip_tos(24, ECN_ECT_0) = 98 (0x62)
    """
    if not 0 <= dscp <= 63:
        raise ValueError(f"DSCP must be 0-63, got {dscp}")
    if not 0 <= ect <= 3:
        raise ValueError(f"ECT must be 0-3, got {ect}")
    return (dscp << 2) | ect


def extract_ecn_from_tos(ip_tos):
    """
    Extract ECN bits from ip_tos byte.

    Args:
        ip_tos: Full TOS/Traffic Class byte value

    Returns:
        int: ECN value (0-3)
    """
    return ip_tos & 0x03


def is_ecn_ce_marked(ip_tos):
    """
    Check if a packet's TOS byte indicates CE (Congestion Experienced).

    Args:
        ip_tos: Full TOS/Traffic Class byte value

    Returns:
        bool: True if ECN bits are 11 (CE)
    """
    return (ip_tos & 0x03) == ECN_CE


# ---------------------------------------------------------------------------
# Topology Validation
# ---------------------------------------------------------------------------

def validate_ecn_testbed_topology():
    """
    Pre-flight check that MUST pass before ECN test proceeds.

    Validates:
        1. Required port counts (XOFF-based congestion methodology):
           - Ingress leaf (D3): 1 TGEN connection (D3T1P1)
           - Egress leaf (D4): 1 TGEN connection (D4T1P1)
           - Ingress leaf to spine0: 1 uplink (D3D1P1)
           - Egress leaf to spine0: 1 uplink (D4D1P1)
           - Optional: spine1 links (D3D2P1, D4D2P1)

        2. Leaf-to-TGEN links must have the same speed

    Returns:
        dict: {
            'valid': bool,
            'ingress_tgen_ports': [D3T1P1],
            'egress_tgen_ports': [D4T1P1],
            'ingress_uplinks': [D3D1P1, D3D2P1],
            'egress_uplinks': [D4D1P1, D4D2P1],
            'tgen_port_speed': int (in Gbps),
            'error': str (if validation fails)
        }
    """
    st.banner("PRE-FLIGHT: Validating ECN testbed topology")
    vars = st.get_testbed_vars()
    nodes = get_nodes()

    result = {
        'valid': False,
        'ingress_tgen_ports': [],
        'egress_tgen_ports': [],
        'ingress_uplinks': [],
        'egress_uplinks': [],
        'tgen_port_speed': 0,
        'error': None
    }

    # Check required ports exist (1 TGEN per leaf + 1 uplink per leaf to spine0)
    required_ports = {
        'ingress_tgen': ['D3T1P1'],
        'egress_tgen': ['D4T1P1'],
        'ingress_uplinks': ['D3D1P1'],
        'egress_uplinks': ['D4D1P1']
    }

    # Optional spine1 links
    optional_ports = {
        'ingress_uplinks': ['D3D2P1'],
        'egress_uplinks': ['D4D2P1']
    }

    missing_ports = []
    for category, port_names in required_ports.items():
        for port_name in port_names:
            if not hasattr(vars, port_name):
                missing_ports.append(port_name)

    if missing_ports:
        result['error'] = f"Missing required ports: {', '.join(missing_ports)}"
        st.error(f"PRE-FLIGHT FAILED: {result['error']}")
        return result

    # Collect port interface names
    result['ingress_tgen_ports'] = [getattr(vars, p) for p in required_ports['ingress_tgen']]
    result['egress_tgen_ports'] = [getattr(vars, p) for p in required_ports['egress_tgen']]
    result['ingress_uplinks'] = [getattr(vars, p) for p in required_ports['ingress_uplinks']]
    result['egress_uplinks'] = [getattr(vars, p) for p in required_ports['egress_uplinks']]

    # Add optional spine1 links if available
    for category, port_names in optional_ports.items():
        for port_name in port_names:
            if hasattr(vars, port_name):
                result[category].append(getattr(vars, port_name))

    # Check leaf-to-TGEN link speeds match
    tgen_ports_to_check = [
        (nodes['leaf0'], result['ingress_tgen_ports'][0], 'D3T1P1'),
        (nodes['leaf1'], result['egress_tgen_ports'][0], 'D4T1P1'),
    ]

    st.log("Querying TGEN port speeds...")
    tgen_speeds = {}
    for dut, intf, desc in tgen_ports_to_check:
        speed = get_if_speed(dut, intf)
        tgen_speeds[desc] = speed
        st.log(f"  {desc} ({intf}): {speed}G")

    tgen_speed_values = list(tgen_speeds.values())
    if len(set(tgen_speed_values)) > 1:
        result['error'] = f"TGEN port speed mismatch - leaf-to-TGEN links must have same speed. Found: {tgen_speeds}"
        st.error(f"PRE-FLIGHT FAILED: {result['error']}")
        return result

    result['tgen_port_speed'] = tgen_speed_values[0]
    result['valid'] = True

    st.log(f"PRE-FLIGHT PASSED: TGEN ports at {result['tgen_port_speed']}G")
    st.log(f"  Ingress TGEN: {result['ingress_tgen_ports']}")
    st.log(f"  Egress TGEN: {result['egress_tgen_ports']}")
    st.log(f"  Ingress uplinks: {result['ingress_uplinks']}")
    st.log(f"  Egress uplinks: {result['egress_uplinks']}")

    return result


def build_node_topology(vars=None):
    """
    Build a role-aware per-node descriptor for the 2-spine + 2-leaf VXLAN ECN testbed.

    Each node entry describes its role and which physical ports are used as
    ingress (where traffic enters this node) and egress (where traffic leaves
    this node toward the next hop). For our linear path:

        T1D3P1 -> leaf0 -> spine0/spine1 -> leaf1 -> T1D4P1
                  ^^^^^                     ^^^^^
                  ingress=tgen              ingress=uplinks
                  egress=uplinks            egress=tgen

    Args:
        vars: Optional st.get_testbed_vars() result. Fetched if not provided.

    Returns:
        dict: {
            <node_name>: {
                'role':           'ingress_leaf' | 'spine' | 'egress_leaf',
                'tgen_port':      str | None,           # facing TGEN, if any
                'ingress_ports':  [str, ...],           # where traffic enters
                'egress_ports':   [str, ...],           # where traffic leaves
                'all_ports':      [str, ...],           # union, deduped
            }
        }

    Notes:
        - Spine1 ports are optional (single-spine deployments still work).
        - Returns only entries for nodes whose required ports are present;
          missing optional links are silently skipped.
    """
    if vars is None:
        vars = st.get_testbed_vars()

    def _g(name):
        """Return getattr(vars, name) or None when missing."""
        return getattr(vars, name, None)

    # leaf0 = ingress leaf (D3): TGEN ingress, uplinks toward spine0/spine1 are egress
    leaf0_uplinks = [p for p in [_g('D3D1P1'), _g('D3D2P1')] if p]
    leaf0_tgen    = _g('D3T1P1')

    # leaf1 = egress leaf (D4): uplinks from spine0/spine1 are ingress, TGEN is egress
    leaf1_uplinks = [p for p in [_g('D4D1P1'), _g('D4D2P1')] if p]
    leaf1_tgen    = _g('D4T1P1')

    # spine0 (D1): ingress = link from leaf0, egress = link to leaf1
    spine0_ingress = [p for p in [_g('D1D3P1')] if p]
    spine0_egress  = [p for p in [_g('D1D4P1')] if p]

    # spine1 (D2): ingress = link from leaf0, egress = link to leaf1
    spine1_ingress = [p for p in [_g('D2D3P1')] if p]
    spine1_egress  = [p for p in [_g('D2D4P1')] if p]

    topology = {}

    if leaf0_tgen and leaf0_uplinks:
        topology['leaf0'] = {
            'role':          'ingress_leaf',
            'tgen_port':     leaf0_tgen,
            'ingress_ports': [leaf0_tgen],
            'egress_ports':  list(leaf0_uplinks),
        }

    if spine0_ingress or spine0_egress:
        topology['spine0'] = {
            'role':          'spine',
            'tgen_port':     None,
            'ingress_ports': list(spine0_ingress),
            'egress_ports':  list(spine0_egress),
        }

    if spine1_ingress or spine1_egress:
        topology['spine1'] = {
            'role':          'spine',
            'tgen_port':     None,
            'ingress_ports': list(spine1_ingress),
            'egress_ports':  list(spine1_egress),
        }

    if leaf1_tgen and leaf1_uplinks:
        topology['leaf1'] = {
            'role':          'egress_leaf',
            'tgen_port':     leaf1_tgen,
            'ingress_ports': list(leaf1_uplinks),
            'egress_ports':  [leaf1_tgen],
        }

    # Compute deduped all_ports (preserving order: ingress then egress)
    for entry in topology.values():
        seen = set()
        all_ports = []
        for p in entry['ingress_ports'] + entry['egress_ports']:
            if p not in seen:
                seen.add(p)
                all_ports.append(p)
        entry['all_ports'] = all_ports

    return topology


def nodes_by_role(topology, role):
    """
    Return list of node names from a topology that match the given role.

    Args:
        topology: dict from build_node_topology()
        role:     'ingress_leaf' | 'spine' | 'egress_leaf'

    Returns:
        list[str]: node names with matching role, in insertion order.
    """
    return [n for n, e in (topology or {}).items() if e.get('role') == role]


def populate_topology_speeds(topology, nodes):
    """
    Stamp per-port link speeds (Gbps) onto an existing topology dict.

    For every node in `topology`, queries each port in `all_ports` and
    sets ``topology[node]['port_speeds'] = {port: speed_gbps}``. Speeds
    that fail to query are stored as 0.

    This is idempotent and safe to call repeatedly. It must be called
    after build_node_topology() and before snapshot rendering if you want
    speed annotations like "Ethernet1_64_1 (400G)" in the snapshot logs
    or speeds available to validators.

    Args:
        topology: dict from build_node_topology()
        nodes:    dict mapping node names to DUT handles (from get_nodes())

    Returns:
        dict: topology (same object), with 'port_speeds' populated per node.
    """
    if not topology:
        return topology
    for node_name, entry in topology.items():
        dut = nodes.get(node_name) if isinstance(nodes, dict) else None
        ports = entry.get('all_ports', []) or []
        speeds = {}
        if dut and ports:
            for p in ports:
                try:
                    sp = get_if_speed(dut, p)
                    speeds[p] = int(sp) if sp else 0
                except Exception as e:
                    st.log("populate_topology_speeds: {} {} failed: {}".format(
                        node_name, p, e))
                    speeds[p] = 0
        entry['port_speeds'] = speeds
        st.log("Speeds {}: {}".format(node_name, speeds))
    return topology


def _get_port_counters_simple(dut, port):
    """
    Lightweight scrape of `show interface counters` for a single port.

    Column layout (click CLI):
        IFACE STATE RX_OK RX_BPS_VAL RX_BPS_UNIT RX_UTIL RX_ERR RX_DRP RX_OVR
              TX_OK TX_BPS_VAL TX_BPS_UNIT TX_UTIL TX_ERR TX_DRP TX_OVR

    Returns:
        dict: {'rx_ok': int, 'rx_drp': int, 'tx_ok': int, 'tx_drp': int}
              All zeros on parse failure.
    """
    result = {'rx_ok': 0, 'rx_drp': 0, 'tx_ok': 0, 'tx_drp': 0}
    try:
        out = st.show(dut, f"show interface counters | grep -w {port}",
                      skip_tmpl=True, skip_error_check=True)
        if not out:
            return result
        line = next((ln for ln in out.splitlines() if port in ln.split()), None)
        if not line:
            return result
        parts = line.split()
        # Need at least 16 tokens for full row
        if len(parts) >= 15:
            def _ival(s):
                try:
                    return int(s.replace(',', ''))
                except (ValueError, AttributeError):
                    return 0
            result['rx_ok']  = _ival(parts[2])
            result['rx_drp'] = _ival(parts[7])
            result['tx_ok']  = _ival(parts[9])
            result['tx_drp'] = _ival(parts[14])
    except Exception as e:
        st.log(f"_get_port_counters_simple({dut},{port}) failed: {e}")
    return result


def _get_pg_watermark_simple(dut, port):
    """
    Scrape `show priority-group watermark shared` for one port.

    Expected row: <Port> PG0 PG1 PG2 PG3 PG4 PG5 PG6 PG7

    Returns:
        dict: {0: int, 1: int, ..., 7: int}  (zeros on parse failure)
    """
    result = {i: 0 for i in range(8)}
    try:
        out = st.show(dut, f"show priority-group watermark shared | grep -w {port}",
                      skip_tmpl=True, skip_error_check=True)
        if not out:
            return result
        line = next((ln for ln in out.splitlines() if port in ln.split()), None)
        if not line:
            return result
        parts = line.split()
        # Expect: port PG0..PG7  -> 9 tokens
        if len(parts) >= 9:
            for i in range(8):
                tok = parts[1 + i]
                try:
                    result[i] = int(tok.replace(',', ''))
                except (ValueError, AttributeError):
                    result[i] = 0
    except Exception as e:
        st.log(f"_get_pg_watermark_simple({dut},{port}) failed: {e}")
    return result


def _get_pg_drop_counters_simple(dut, port):
    """
    Scrape `show priority-group drop counters` for one port.

    Expected row: <Port> PG0 PG1 PG2 PG3 PG4 PG5 PG6 PG7

    Returns:
        dict: {0: int, 1: int, ..., 7: int}  (zeros on parse failure)
    """
    result = {i: 0 for i in range(8)}
    try:
        out = st.show(dut, f"show priority-group drop counters | grep -w {port}",
                      skip_tmpl=True, skip_error_check=True)
        if not out:
            return result
        line = next((ln for ln in out.splitlines() if port in ln.split()), None)
        if not line:
            return result
        parts = line.split()
        if len(parts) >= 9:
            for i in range(8):
                tok = parts[1 + i]
                try:
                    result[i] = int(tok.replace(',', ''))
                except (ValueError, AttributeError):
                    result[i] = 0
    except Exception as e:
        st.log(f"_get_pg_drop_counters_simple({dut},{port}) failed: {e}")
    return result


def capture_node_snapshot(nodes, topology, tc=3):
    """
    Capture a unified per-node, per-port snapshot of QoS-relevant counters.

    Wraps existing helpers so callers can do a single 'before' / 'after'
    capture instead of orchestrating multiple sources.

    Args:
        nodes:    Dict {node_name: dut} from get_nodes()
        topology: Dict from build_node_topology()
        tc:       Traffic class (default 3) -- drives PFC priority lookups
                  and identifies the "primary" queue (UC<tc>) for tests.
                  All queues found in WRED output are still included.

    Returns:
        dict: {
            <node_name>: {
                'role': str,
                'buffer_pool_watermark': {pool_name: int|str},
                'ports': {
                    <port>: {
                        'rx_packets': int,    # show interface counters RX_OK
                        'tx_packets': int,    # show interface counters TX_OK
                        'rx_drops':   int,    # RX_DRP
                        'tx_drops':   int,    # TX_DRP
                        'pfc_rx':     {tc: int},
                        'pfc_tx':     {tc: int},
                        'pg_watermark': {0..7: int},
                        'queues': {
                            'UC<n>': {
                                'packets':         int,
                                'drop_pkts':       int,
                                'ecn_marked_pkts': int,
                                'watermark':       int|str,  # only for UC<tc>
                            }, ...
                        }
                    }
                }
            }
        }

    Notes:
        - Tolerant of missing data: any failed lookup produces 0/empty
          rather than raising.
        - Watermark per queue is only populated for the UC<tc> entry
          (existing capture_queue_watermark_values returns a single value
          per port for the requested TC).
    """
    primary_queue = f"UC{tc}"

    # Build interfaces_map from topology for the bulk helpers
    interfaces_map = {
        node_name: list(entry.get('all_ports', []))
        for node_name, entry in topology.items()
        if node_name in nodes
    }

    # Bulk captures -- these helpers already loop internally and now also
    # parallelize across DUTs.
    wred = {}
    watermarks = {}
    try:
        wred = capture_wred_counters(nodes, interfaces_map, tc=tc)
    except Exception as e:
        st.log(f"capture_node_snapshot: capture_wred_counters failed: {e}")
    try:
        watermarks = capture_queue_watermark_values(nodes, interfaces_map, tc=tc)
    except Exception as e:
        st.log(f"capture_node_snapshot: capture_queue_watermark_values failed: {e}")

    # Per-node worker -- runs sequential per-port show commands on a single
    # DUT (one SSH session). Multiple DUTs are dispatched in parallel below.
    def _snapshot_one_node(item):
        node_name, entry = item
        dut = nodes[node_name]

        # Per-node buffer pool watermark
        pool_data = {}
        try:
            raw = get_buffer_pool_watermark(dut)
            if raw:
                parsed = parse_buffer_pool_watermark(raw)
                # parse_buffer_pool_watermark returns string values; coerce
                for k, v in parsed.items():
                    try:
                        pool_data[k] = int(str(v).replace(',', ''))
                    except (ValueError, AttributeError):
                        pool_data[k] = v
        except Exception as e:
            st.log(f"capture_node_snapshot: buffer pool capture failed on {node_name}: {e}")

        ports_data = {}
        for port in entry.get('all_ports', []):
            # Per-port basic counters
            pc = _get_port_counters_simple(dut, port)

            # PFC per-priority (just tc for now)
            try:
                pfc_rx = get_pfc_rx_count(dut, port, tc)
            except Exception:
                pfc_rx = 0
            try:
                pfc_tx = get_pfc_tx_count(dut, port, tc)
            except Exception:
                pfc_tx = 0

            # Priority-group watermark (PG0..PG7)
            pg_wm = _get_pg_watermark_simple(dut, port)

            # Priority-group drop counters (PG0..PG7) -- non-zero indicates
            # ingress drops at the PG (e.g. headroom exhausted).
            pg_drop = _get_pg_drop_counters_simple(dut, port)

            # All queues from wred capture (UC0..UC7)
            queues_dict = {}
            port_wred = wred.get(node_name, {}).get(port, {})
            wm_val = watermarks.get(node_name, {}).get(port, 'N/A')
            for q_name, q_entry in port_wred.items():
                queues_dict[q_name] = {
                    'packets':         q_entry.get('packets', 0),
                    'drop_pkts':       q_entry.get('wred_drop_pkts', 0),
                    'ecn_marked_pkts': q_entry.get('ecn_marked_pkts', 0),
                    'watermark':       wm_val if q_name == primary_queue else None,
                }
            # Ensure primary_queue always present even if WRED capture missed it
            if primary_queue not in queues_dict:
                queues_dict[primary_queue] = {
                    'packets':         0,
                    'drop_pkts':       0,
                    'ecn_marked_pkts': 0,
                    'watermark':       wm_val,
                }

            ports_data[port] = {
                'rx_packets':   pc['rx_ok'],
                'tx_packets':   pc['tx_ok'],
                'rx_drops':     pc['rx_drp'],
                'tx_drops':     pc['tx_drp'],
                'pfc_rx':       {tc: pfc_rx},
                'pfc_tx':       {tc: pfc_tx},
                'pg_watermark': pg_wm,
                'pg_drop':      pg_drop,
                'queues':       queues_dict,
            }

        return (node_name, {
            'role':                  entry.get('role', ''),
            'buffer_pool_watermark': pool_data,
            'ports':                 ports_data,
        })

    items = [(node_name, entry) for node_name, entry in topology.items()
             if node_name in nodes]
    retvals, _ = exec_foreach(True, items, _snapshot_one_node)

    snapshot = {}
    for rv in retvals:
        if rv:
            name, node_dict = rv
            snapshot[name] = node_dict

    return snapshot


def clear_node_snapshot_counters(nodes, topology, tc=3, wait_after=3):
    """
    Clear all counters/watermarks needed for a clean snapshot 'before' baseline.

    Iterates topology nodes (skipping any not present in `nodes`) and for each
    DUT clears: interface counters, queue counters, PFC, queue watermarks,
    priority-group watermarks, buffer-pool watermarks, drop counters and WRED
    counters. Delegates to existing per-DUT helpers; no new CLI surface.

    Args:
        nodes:       Dict {node_name: dut} from get_nodes()
        topology:    Dict from build_node_topology()
        tc:          Traffic class (passed through to clear_all_wred_counters)
        wait_after:  Seconds to wait after clearing (default 3) so counters
                     settle before the 'before' snapshot is taken.

    Returns:
        list: Node names that were successfully cleared.
    """
    cleared = []
    interfaces_map = {
        node_name: list(entry.get('all_ports', []))
        for node_name, entry in topology.items()
        if node_name in nodes
    }

    # Per-DUT clear_all_counters in parallel (one thread per DUT)
    items = [(node_name, nodes[node_name])
             for node_name in topology if node_name in nodes]

    def _clear_one(item):
        node_name, dut = item
        try:
            clear_all_counters(dut, wait_time=0)
            return node_name
        except Exception as e:
            st.log(f"clear_node_snapshot_counters: clear_all_counters failed on "
                   f"{node_name}: {e}")
            return None

    retvals, _ = exec_foreach(True, items, _clear_one)
    cleared = [n for n in retvals if n]

    # Bulk WRED clear (matches existing test pattern: per-port wredcounters)
    try:
        clear_all_wred_counters(nodes, interfaces_map, tc=tc)
    except Exception as e:
        st.log(f"clear_node_snapshot_counters: clear_all_wred_counters failed: {e}")

    # Bulk queue-watermark clear (idempotent with per-DUT clears above, but
    # ensures the dedicated path is exercised; cheap)
    try:
        clear_all_queue_watermarks(nodes, wait_after=0)
    except Exception as e:
        st.log(f"clear_node_snapshot_counters: clear_all_queue_watermarks failed: {e}")

    if wait_after:
        st.wait(wait_after)
    return cleared


def print_node_snapshot_deltas(before, after, topology, tc=3,
                                label="Per-Node Snapshot Deltas",
                                port_speed_gbps=None,
                                traffic_duration=None,
                                frame_size=None):
    """
    Compute, log, and return per-node deltas between two snapshots produced
    by capture_node_snapshot().

    For each node and each port in `topology`, computes deltas for:
      - Port: rx_packets, tx_packets, rx_drops, tx_drops
      - PFC : pfc_rx[tc], pfc_tx[tc]
      - PG  : pg_watermark[0..7]   (watermarks are reported as 'after' value;
                                    deltas don't make sense for high-water marks)
      - Queue UC<n>: packets, drop_pkts, ecn_marked_pkts (delta);
                    watermark for primary UC<tc> reported as after value.

    Buffer pool watermarks are reported as 'after' values (high-water marks).

    Args:
        before, after: snapshots from capture_node_snapshot()
        topology:      from build_node_topology() -- used to drive iteration
                       order (ingress_leaf -> spine -> egress_leaf) and to
                       pick up `role` for the summary.
        tc:            primary traffic class (used for queue/PFC summary keys)
        label:         banner label for the log block
        port_speed_gbps: Per-port line speed in Gbps. When provided together
                       with `traffic_duration` and `frame_size`, the deltas
                       output includes a `tx_util%` column estimating each
                       port's TX utilization as a percent of line rate.
                       Values <= 0.1%% are reported as 0.
        traffic_duration: Traffic duration in seconds (typically 60).
        frame_size:    L2 frame size in bytes (excluding preamble + IPG).
                       The on-wire size used for utilization is
                       (frame_size + 20) bytes.

    Returns:
        dict: {
            <node_name>: {
                'role': str,
                'buffer_pool_watermark': {pool: int|str},   # after values
                'totals': {                                 # node-aggregated
                    'rx_packets': int, 'tx_packets': int,
                    'rx_drops':   int, 'tx_drops':   int,
                    'pfc_rx':     int, 'pfc_tx':     int,
                    'queue_packets':       int,    # UC<tc> across ports
                    'queue_drop_pkts':     int,    # UC<tc> across ports
                    'ecn_marked_pkts':     int,    # UC<tc> across ports
                },
                'ports': {
                    <port>: {
                        'rx_packets': int, 'tx_packets': int,
                        'rx_drops':   int, 'tx_drops':   int,
                        'pfc_rx':     int, 'pfc_tx':     int,
                        'pg_watermark': {0..7: int|str},   # after
                        'queues': {
                            'UC<n>': {
                                'packets':         int,
                                'drop_pkts':       int,
                                'ecn_marked_pkts': int,
                                'watermark':       int|str|None,  # after
                            }, ...
                        }
                    }
                }
            }
        }
    """
    st.banner(label)
    primary_queue = f"UC{tc}"
    summary = {}

    # ---- Line-rate setup for tx utilization ----
    line_rate_bps = 0.0
    on_wire_bytes = 0
    util_enabled = False
    try:
        if traffic_duration and frame_size:
            if port_speed_gbps:
                line_rate_bps = float(port_speed_gbps) * 1e9
            # Add 20B (8B preamble/SFD + 12B IPG) to L2 frame for on-wire size
            on_wire_bytes = int(frame_size) + 20
            # Per-port speeds in topology can also drive utilization; we
            # enable display whenever frame/duration are valid.
            util_enabled = (on_wire_bytes > 0 and float(traffic_duration) > 0)
    except (TypeError, ValueError):
        util_enabled = False

    def _util_pct(pkts, speed_gbps=None):
        """Return utilization % of line rate; 0 when <= 0.1% or disabled.

        If speed_gbps is provided and > 0, it overrides the default
        port_speed_gbps from the function args (used for per-port
        utilization in mixed-speed topologies).
        """
        if pkts <= 0 or on_wire_bytes <= 0 or float(traffic_duration or 0) <= 0:
            return 0.0
        rate_bps = float(speed_gbps) * 1e9 if speed_gbps else line_rate_bps
        if rate_bps <= 0:
            return 0.0
        bits = pkts * on_wire_bytes * 8.0
        pct = (bits / (rate_bps * float(traffic_duration))) * 100.0
        return pct if pct > 0.1 else 0.0

    def _tx_util_pct(tx_pkts, speed_gbps=None):
        return _util_pct(tx_pkts, speed_gbps)

    def _rx_util_pct(rx_pkts, speed_gbps=None):
        return _util_pct(rx_pkts, speed_gbps)

    def _d(a, b):
        try:
            return int(a) - int(b)
        except (TypeError, ValueError):
            return 0

    # Iterate in topology order so logs read ingress -> egress
    for node_name in topology.keys():
        b_node = before.get(node_name, {}) if isinstance(before, dict) else {}
        a_node = after.get(node_name, {})  if isinstance(after,  dict) else {}
        if not a_node:
            continue

        b_ports = b_node.get('ports', {}) or {}
        a_ports = a_node.get('ports', {}) or {}

        node_summary = {
            'role':                  a_node.get('role', topology[node_name].get('role', '')),
            'buffer_pool_watermark': a_node.get('buffer_pool_watermark', {}),
            'totals': {
                'rx_packets': 0, 'tx_packets': 0,
                'rx_drops':   0, 'tx_drops':   0,
                'pfc_rx':     0, 'pfc_tx':     0,
                'queue_packets':   0,
                'queue_drop_pkts': 0,
                'ecn_marked_pkts': 0,
                'pg_drop':         0,    # sum of all PG drop deltas
                'pg_drop_per_pg':  {i: 0 for i in range(8)},
            },
            'ports': {},
        }

        st.log(f"--- {node_name} (role={node_summary['role']}) ---")
        if node_summary['buffer_pool_watermark']:
            st.log(f"  buffer_pool_watermark (after): {node_summary['buffer_pool_watermark']}")

        for port in topology[node_name].get('all_ports', []):
            b_p = b_ports.get(port, {})
            a_p = a_ports.get(port, {})
            if not a_p:
                continue

            # Port-level deltas
            rx_d  = _d(a_p.get('rx_packets', 0), b_p.get('rx_packets', 0))
            tx_d  = _d(a_p.get('tx_packets', 0), b_p.get('tx_packets', 0))
            rxdr  = _d(a_p.get('rx_drops',   0), b_p.get('rx_drops',   0))
            txdr  = _d(a_p.get('tx_drops',   0), b_p.get('tx_drops',   0))

            # PFC per primary tc
            pfc_rx_d = _d(a_p.get('pfc_rx', {}).get(tc, 0),
                          b_p.get('pfc_rx', {}).get(tc, 0))
            pfc_tx_d = _d(a_p.get('pfc_tx', {}).get(tc, 0),
                          b_p.get('pfc_tx', {}).get(tc, 0))

            # PG watermarks (after values)
            pg_after = a_p.get('pg_watermark', {}) or {}

            # PG drop counters -- delta per PG (non-zero indicates ingress
            # drops, e.g. headroom exhausted).
            a_pg_drop = a_p.get('pg_drop', {}) or {}
            b_pg_drop = b_p.get('pg_drop', {}) or {}
            pg_drop_delta = {
                i: _d(a_pg_drop.get(i, 0), b_pg_drop.get(i, 0))
                for i in range(8)
            }

            # Queue deltas -- iterate union of queues seen in either snapshot
            queues_summary = {}
            queue_names = set((a_p.get('queues') or {}).keys()) | \
                          set((b_p.get('queues') or {}).keys())
            for q in queue_names:
                a_q = (a_p.get('queues') or {}).get(q, {}) or {}
                b_q = (b_p.get('queues') or {}).get(q, {}) or {}
                queues_summary[q] = {
                    'packets':         _d(a_q.get('packets', 0),
                                          b_q.get('packets', 0)),
                    'drop_pkts':       _d(a_q.get('drop_pkts', 0),
                                          b_q.get('drop_pkts', 0)),
                    'ecn_marked_pkts': _d(a_q.get('ecn_marked_pkts', 0),
                                          b_q.get('ecn_marked_pkts', 0)),
                    'watermark':       a_q.get('watermark'),
                }

            # Per-port speed (Gbps) from topology -- used for accurate
            # utilization in mixed-speed (e.g. 400G TGEN + 800G fabric)
            # topologies. Falls back to 0 (-> uses global port_speed_gbps).
            _port_speed = (topology[node_name].get('port_speeds') or {}).get(port, 0)

            node_summary['ports'][port] = {
                'rx_packets':   rx_d,
                'tx_packets':   tx_d,
                'rx_drops':     rxdr,
                'tx_drops':     txdr,
                'pfc_rx':       pfc_rx_d,
                'pfc_tx':       pfc_tx_d,
                'pg_watermark': pg_after,
                'pg_drop':      pg_drop_delta,
                'rx_util_pct':  _rx_util_pct(rx_d, _port_speed),
                'tx_util_pct':  _tx_util_pct(tx_d, _port_speed),
                'speed_gbps':   _port_speed,
                'queues':       queues_summary,
            }

            # Aggregate node totals (use primary queue for queue/ecn totals)
            node_summary['totals']['rx_packets'] += rx_d
            node_summary['totals']['tx_packets'] += tx_d
            node_summary['totals']['rx_drops']   += rxdr
            node_summary['totals']['tx_drops']   += txdr
            node_summary['totals']['pfc_rx']     += pfc_rx_d
            node_summary['totals']['pfc_tx']     += pfc_tx_d
            pq = queues_summary.get(primary_queue, {})
            node_summary['totals']['queue_packets']   += pq.get('packets', 0)
            node_summary['totals']['queue_drop_pkts'] += pq.get('drop_pkts', 0)
            node_summary['totals']['ecn_marked_pkts'] += pq.get('ecn_marked_pkts', 0)
            for pg_idx, pg_v in pg_drop_delta.items():
                node_summary['totals']['pg_drop'] += pg_v
                node_summary['totals']['pg_drop_per_pg'][pg_idx] += pg_v

            # Per-port log line -- keep tight
            # Drop% is computed against the offered load on that direction:
            #   tx_drp%  = txdr / (tx_d + txdr)   (egress queue/buffer drops)
            #   rx_drp%  = rxdr / (rx_d + rxdr)   (ingress drops)
            #   <queue>_drop% = drop_pkts / (packets + drop_pkts)
            def _pct(num, denom):
                try:
                    return (float(num) / float(denom)) * 100.0 if denom > 0 else 0.0
                except (TypeError, ValueError, ZeroDivisionError):
                    return 0.0
            tx_drp_pct = _pct(txdr, tx_d + txdr)
            rx_drp_pct = _pct(rxdr, rx_d + rxdr)
            pq_pkts = pq.get('packets', 0)
            pq_drop = pq.get('drop_pkts', 0)
            pq_drop_pct = _pct(pq_drop, pq_pkts + pq_drop)
            pq_drop_str = f"{pq_drop}" + (f"({pq_drop_pct:.2f}%)" if pq_drop > 0 else "")
            pq_str = (
                f"{primary_queue}[pkts={pq_pkts}, "
                f"drop={pq_drop_str}, "
                f"ecn={pq.get('ecn_marked_pkts', 0)}, "
                f"wm={pq.get('watermark')}]"
            )
            rxdr_str = f"{rxdr}" + (f"({rx_drp_pct:.2f}%)" if rxdr > 0 else "")
            txdr_str = f"{txdr}" + (f"({tx_drp_pct:.2f}%)" if txdr > 0 else "")
            tx_util = node_summary['ports'][port]['tx_util_pct']
            rx_util = node_summary['ports'][port]['rx_util_pct']
            rx_util_str = (f" rx_util={rx_util:.2f}%" if util_enabled else "")
            tx_util_str = (f" tx_util={tx_util:.2f}%" if util_enabled else "")
            # Look up per-port speed (Gbps) from the topology, if populated.
            port_speed = (topology[node_name].get('port_speeds') or {}).get(port, 0)
            if port_speed:
                speed_str = " ({})".format(format_speed(port_speed))
            else:
                speed_str = ""
            port_label = "{}{}".format(port, speed_str)
            st.log(
                f"  {port_label:<22} rx={rx_d}{rx_util_str} tx={tx_d}{tx_util_str} "
                f"rx_drp={rxdr_str} tx_drp={txdr_str} "
                f"pfc_rx={pfc_rx_d} pfc_tx={pfc_tx_d} "
                f"{pq_str}"
            )
            # Log other queues only if non-zero, to avoid noise
            for q, qd in sorted(queues_summary.items()):
                if q == primary_queue:
                    continue
                if qd['packets'] or qd['drop_pkts'] or qd['ecn_marked_pkts']:
                    st.log(
                        f"      {q}: pkts={qd['packets']} "
                        f"drop={qd['drop_pkts']} ecn={qd['ecn_marked_pkts']}"
                    )
            if any(pg_after.values()):
                st.log(f"      pg_wm(after)={pg_after}")
            # Log only non-zero PG drop deltas (headroom-exhausted, etc.)
            nz_pg_drops = {pg: v for pg, v in pg_drop_delta.items() if v}
            if nz_pg_drops:
                st.log(f"      pg_drop(delta)={nz_pg_drops}")

        # Node-total log line
        t = node_summary['totals']
        nz_node_pg_drops = {pg: v for pg, v in t['pg_drop_per_pg'].items() if v}
        # Average tx/rx utilization across ports that actually moved traffic.
        # (Summing pkts vs single-port line rate would be misleading.)
        per_port_tx_utils = [
            p['tx_util_pct'] for p in node_summary['ports'].values()
            if p.get('tx_util_pct', 0) > 0
        ]
        per_port_rx_utils = [
            p['rx_util_pct'] for p in node_summary['ports'].values()
            if p.get('rx_util_pct', 0) > 0
        ]
        if util_enabled and per_port_tx_utils:
            avg_tx_util = sum(per_port_tx_utils) / len(per_port_tx_utils)
            t['tx_util_pct_avg'] = avg_tx_util
            tx_util_total_str = f" tx_util_avg={avg_tx_util:.2f}%"
        else:
            t['tx_util_pct_avg'] = 0.0
            tx_util_total_str = ""
        if util_enabled and per_port_rx_utils:
            avg_rx_util = sum(per_port_rx_utils) / len(per_port_rx_utils)
            t['rx_util_pct_avg'] = avg_rx_util
            rx_util_total_str = f" rx_util_avg={avg_rx_util:.2f}%"
        else:
            t['rx_util_pct_avg'] = 0.0
            rx_util_total_str = ""
        # Node-aggregate drop% against the offered load on that direction
        def _pct_n(num, denom):
            try:
                return (float(num) / float(denom)) * 100.0 if denom > 0 else 0.0
            except (TypeError, ValueError, ZeroDivisionError):
                return 0.0
        node_tx_drp_pct = _pct_n(t['tx_drops'], t['tx_packets'] + t['tx_drops'])
        node_rx_drp_pct = _pct_n(t['rx_drops'], t['rx_packets'] + t['rx_drops'])
        node_q_drop_pct = _pct_n(t['queue_drop_pkts'],
                                 t['queue_packets'] + t['queue_drop_pkts'])
        node_pg_drop_pct = _pct_n(t['pg_drop'], t['rx_packets'] + t['pg_drop'])
        t['tx_drop_pct'] = node_tx_drp_pct
        t['rx_drop_pct'] = node_rx_drp_pct
        t['queue_drop_pct'] = node_q_drop_pct
        t['pg_drop_pct'] = node_pg_drop_pct
        rx_drp_total_str = f"{t['rx_drops']}" + (f"({node_rx_drp_pct:.2f}%)" if t['rx_drops'] > 0 else "")
        tx_drp_total_str = f"{t['tx_drops']}" + (f"({node_tx_drp_pct:.2f}%)" if t['tx_drops'] > 0 else "")
        q_drop_total_str = f"{t['queue_drop_pkts']}" + (f"({node_q_drop_pct:.2f}%)" if t['queue_drop_pkts'] > 0 else "")
        pg_drop_total_str = f"{t['pg_drop']}" + (f"({node_pg_drop_pct:.2f}%)" if t['pg_drop'] > 0 else "")
        st.log(
            f"  TOTAL  rx={t['rx_packets']}{rx_util_total_str} "
            f"tx={t['tx_packets']}{tx_util_total_str} "
            f"rx_drp={rx_drp_total_str} tx_drp={tx_drp_total_str} "
            f"pfc_rx={t['pfc_rx']} pfc_tx={t['pfc_tx']} "
            f"{primary_queue}_pkts={t['queue_packets']} "
            f"{primary_queue}_drop={q_drop_total_str} "
            f"ecn_marked={t['ecn_marked_pkts']} "
            f"pg_drop={pg_drop_total_str}{(' ' + str(nz_node_pg_drops)) if nz_node_pg_drops else ''}"
        )
        summary[node_name] = node_summary

    return summary


# ---------------------------------------------------------------------------
# PFC Control
# ---------------------------------------------------------------------------

def get_pfc_enabled_tcs(dut):
    """
    Get list of traffic classes with PFC enabled on a DUT.

    Parses 'show pfc priority' output to find lossless priorities.

    Args:
        dut: DUT object

    Returns:
        list: List of TC numbers with PFC enabled (e.g., [3, 4])
    """
    output = st.show(dut, "show pfc priority", skip_tmpl=True)
    tcs = set()

    for line in output.splitlines():
        # Skip header lines
        if 'Interface' in line or '----' in line or not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 2:
            # Second column is comma-separated TC list like "3,4"
            tc_str = parts[1]
            for tc in tc_str.split(','):
                tc = tc.strip()
                if tc.isdigit():
                    tcs.add(int(tc))

    return sorted(list(tcs))


def disable_pfc_on_interface(dut, interface, tcs):
    """
    Disable PFC on specific TCs for an interface.

    Args:
        dut: DUT object
        interface: Interface name (e.g., 'Ethernet1_1')
        tcs: List of traffic classes to disable PFC for
    """
    for tc in tcs:
        cmd = f"pfc config priority off {interface} {tc}"
        st.log(f"Disabling PFC: {cmd}")
        st.config(dut, cmd, skip_error_check=True)


def enable_pfc_on_interface(dut, interface, tcs):
    """
    Enable PFC on specific TCs for an interface.

    Args:
        dut: DUT object
        interface: Interface name (e.g., 'Ethernet1_1')
        tcs: List of traffic classes to enable PFC for
    """
    for tc in tcs:
        cmd = f"pfc config priority on {interface} {tc}"
        st.log(f"Enabling PFC: {cmd}")
        st.config(dut, cmd, skip_error_check=True)


def disable_pfc_on_fabric(nodes, tcs=None):
    """
    Disable PFC on all leaf<->spine links for all PFC-enabled TCs.

    This prevents PFC XOFF from propagating congestion when testing ECN marking
    at a specific point. Without this, PFC would pause upstream traffic before
    ECN marking can occur.

    Args:
        nodes: Dict mapping node names to DUT objects
        tcs: List of TCs to disable PFC for. If None, auto-detect from 'show pfc priority'.

    Returns:
        dict: State info for later restoration {node: {interface: [tcs]}}
    """
    st.banner("Disabling PFC on all leaf - spine links to isolate ECN marking")
    vars = st.get_testbed_vars()

    # Auto-detect TCs if not provided
    if tcs is None:
        tcs = get_pfc_enabled_tcs(nodes['leaf0'])
        if not tcs:
            st.log("No PFC-enabled TCs found, skipping PFC disable")
            return {}
        st.log(f"Auto-detected PFC-enabled TCs: {tcs}")

    # Interfaces to disable PFC on (leaf<->spine links + TGEN-facing ports)
    interfaces_map = {
        'leaf0': [vars.D3D1P1, vars.D3D1P2],
        'leaf1': [vars.D4D1P1, vars.D4D1P2],
        'spine0': [vars.D1D3P1, vars.D1D3P2, vars.D1D4P1, vars.D1D4P2],
    }

    # Add Spine1 interfaces if they exist and are used
    if hasattr(vars, 'D3D2P1'):
        interfaces_map['leaf0'].append(vars.D3D2P1)
    if hasattr(vars, 'D3D2P2'):
        interfaces_map['leaf0'].append(vars.D3D2P2)
    if hasattr(vars, 'D4D2P1'):
        interfaces_map['leaf1'].append(vars.D4D2P1)
    if hasattr(vars, 'D4D2P2'):
        interfaces_map['leaf1'].append(vars.D4D2P2)
    if 'spine1' in nodes:
        spine1_intfs = []
        for attr in ['D2D3P1', 'D2D3P2', 'D2D4P1', 'D2D4P2']:
            if hasattr(vars, attr):
                spine1_intfs.append(getattr(vars, attr))
        if spine1_intfs:
            interfaces_map['spine1'] = spine1_intfs

    # Add TGEN-facing ports on both leaves to prevent PFC XOFF toward TGEN
    for attr in ['D3T1P1', 'D3T1P2', 'D3T1P3']:
        if hasattr(vars, attr):
            interfaces_map['leaf0'].append(getattr(vars, attr))
    for attr in ['D4T1P1', 'D4T1P2']:
        if hasattr(vars, attr):
            interfaces_map['leaf1'].append(getattr(vars, attr))

    # Save state and disable PFC
    saved_state = {}
    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        saved_state[node_name] = {}
        for intf in interfaces:
            disable_pfc_on_interface(nodes[node_name], intf, tcs)
            saved_state[node_name][intf] = tcs

    st.wait(2)  # Allow config to take effect
    st.log("PFC disabled on fabric links")

    # Show PFC priority after disabling to confirm
    for node_name in saved_state:
        if node_name in nodes:
            st.log(f"=== PFC priority on {node_name} after disable ===")
            st.show(nodes[node_name], "show pfc priority", skip_tmpl=True)

    return saved_state


def enable_pfc_on_fabric(nodes, saved_state):
    """
    Restore PFC on all leaf<->spine links.

    Args:
        nodes: Dict mapping node names to DUT objects
        saved_state: State dict from disable_pfc_on_fabric()
    """
    st.banner("Restoring PFC on leaf<->spine links")

    if not saved_state:
        st.log("No saved PFC state to restore")
        return

    for node_name, interfaces in saved_state.items():
        if node_name not in nodes:
            continue
        for intf, tcs in interfaces.items():
            enable_pfc_on_interface(nodes[node_name], intf, tcs)

    st.wait(2)
    st.log("PFC restored on fabric links")

    # Show PFC priority after restoring to confirm
    for node_name in saved_state:
        if node_name in nodes:
            st.log(f"=== PFC priority on {node_name} after restore ===")
            st.show(nodes[node_name], "show pfc priority", skip_tmpl=True)


# ---------------------------------------------------------------------------
# ECN Configuration Verification
# ---------------------------------------------------------------------------

def verify_ecn_config(nodes, node_names=None):
    """
    Pre-flight check: verify ECN is enabled on the DUTs.

    Runs 'ecnconfig -l' on specified nodes and logs the output.

    Args:
        nodes: Dict mapping node names to DUT objects
        node_names: List of node names to check. If None, checks all nodes.

    Returns:
        bool: True if ECN appears to be configured on all nodes
    """
    if node_names is None:
        node_names = list(nodes.keys())

    all_ok = True
    for name in node_names:
        if name not in nodes:
            continue
        dut = nodes[name]
        st.log(f"=== {name.upper()} ECN Configuration ===")
        output = st.show(dut, "ecnconfig -l", skip_tmpl=True)
        st.log(output)

        # Check for common ECN profile names
        if 'AZURE_LOSSLESS' in output or 'wredprofile' in output.lower() or 'ecn' in output.lower():
            st.log(f"  {name}: ECN configuration found")
        else:
            st.log(f"  {name}: WARNING - ECN configuration may not be present")
            # Don't fail, just warn - some configs use different naming

    return all_ok


# ---------------------------------------------------------------------------
# ECN Sandboxing -- disable/restore ECN on non-target nodes
# ---------------------------------------------------------------------------

def disable_ecn_on_nodes(nodes, node_names, enabled_nodes=None):
    """
    Disable ECN marking on specified nodes by setting ecn=ecn_none on all WRED profiles.

    Args:
        nodes: Dict mapping node names to DUT objects
        node_names: List of node names to disable ECN on
        enabled_nodes: Optional list of congestion point nodes (for logging only)

    Returns:
        dict: {node_name: [profile_names]} for restore
    """
    st.banner(f"Disabling ECN marking on: {node_names}")
    saved_state = {}

    for name in node_names:
        if name not in nodes:
            continue
        dut = nodes[name]
        config = get_config_db(dut)

        if "WRED_PROFILE" not in config:
            continue

        profiles_disabled = []
        for profile_name, profile in config["WRED_PROFILE"].items():
            if profile.get("ecn", "ecn_none") != "ecn_none":
                config["WRED_PROFILE"][profile_name]["ecn"] = "ecn_none"
                profiles_disabled.append(profile_name)

        if profiles_disabled:
            saved_state[name] = profiles_disabled
            st.log(f"  {name}: ECN disabled on {profiles_disabled}")

    # Dump ecnconfig on all nodes after disabling
    for name in nodes:
        st.log(f"  {name}: ecnconfig -l")
        st.show(nodes[name], "ecnconfig -l", skip_tmpl=True)

    # Also show ecnconfig on enabled/congestion point nodes
    if enabled_nodes:
        st.log(f"ECN remains ENABLED on congestion point nodes: {enabled_nodes}")
        for name in enabled_nodes:
            if name in nodes and name not in node_names:
                st.log(f"  {name}: ecnconfig -l (ECN enabled - congestion point)")
                st.show(nodes[name], "ecnconfig -l", skip_tmpl=True)

    return saved_state


def restore_ecn_on_nodes(nodes, saved_ecn_state):
    """
    Restore ECN marking (ecn=ecn_green) on nodes disabled by disable_ecn_on_nodes().

    Args:
        nodes: Dict mapping node names to DUT objects
        saved_ecn_state: Dict from disable_ecn_on_nodes()
    """
    if not saved_ecn_state:
        return

    st.banner(f"Restoring ECN marking on: {list(saved_ecn_state.keys())}")

    for name, profile_names in saved_ecn_state.items():
        if name not in nodes:
            continue
        dut = nodes[name]
        config = get_config_db(dut)

        for profile_name in profile_names:
            if "WRED_PROFILE" in config and profile_name in config["WRED_PROFILE"]:
                config["WRED_PROFILE"][profile_name]["ecn"] = "ecn_green"

        st.log(f"  {name}: ECN restored to ecn_green on {profile_names}")

    # Dump ecnconfig on all nodes after restoring
    for name in nodes:
        st.log(f"  {name}: ecnconfig -l")
        st.show(nodes[name], "ecnconfig -l", skip_tmpl=True)


# Map each congestion scenario to the nodes where ECN should be DISABLED
# (i.e., the non-target congestion points)
# Both spines are included since traffic can traverse either spine in a 2x2 CLOS
ECN_DISABLE_MAP = {
    'ingress_leaf_egress': ['spine0', 'spine1', 'leaf1'],   # A: disable B and C (both spines + egress leaf)
    'spine_egress':        ['leaf0', 'leaf1'],               # B: disable A and C (both leaves)
    'egress_leaf_tgen':    ['leaf0', 'spine0', 'spine1'],    # C: disable A and B (ingress leaf + both spines)
}


# ---------------------------------------------------------------------------
# ECN Counter Utilities (Platform-specific)
# ---------------------------------------------------------------------------

def get_ecn_counters_on_port(dut, port, tc, clear=False):
    """
    Get ECN counters for a specific port and traffic class using platform NPU command.

    Uses: show platform npu voq queue_counters -i <interface> -t <tc>

    Sample output:
        Port Ethernet1_57_1 port oid 0x80000000000054 queue oid 0xa80000005400003
            SAI_QUEUE_STAT_PACKETS :  0
            SAI_QUEUE_STAT_DROPPED_PACKETS :  0
            SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES :  0
            SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS :  0
            SAI_QUEUE_STAT_WRED_DROPPED_PACKETS :  0
            SAI_QUEUE_STAT_WATERMARK_BYTES :  0
            SAI_QUEUE_STAT_DELAY_WATERMARK :  0

    Args:
        dut: DUT object (node name like nodes['leaf0'] or direct DUT)
        port: Interface name (e.g., 'Ethernet1_57_1')
        tc: Traffic class number (0-7, typically 3 for lossless)
        clear: If True, clear the counters after reading (-c flag)

    Returns:
        dict: Parsed counter values:
            {
                'packets': int,
                'dropped_packets': int,
                'curr_occupancy_bytes': int,
                'ecn_marked_packets': int,
                'wred_dropped_packets': int,
                'watermark_bytes': int,
                'delay_watermark': int
            }
            Returns empty dict if command fails.
    """
    clear_flag = " -c" if clear else ""
    cmd = f"show platform npu voq queue_counters -i {port} -t {tc}{clear_flag}"

    st.log(f"Getting ECN counters: {cmd}")
    # Must use st.config() not st.show() -- this command needs sudo to access
    # the NPU debug shell socket ("cannot connect to debug shell socket asic 0")
    output = st.config(dut, cmd, skip_error_check=True)

    counters = {
        'packets': 0,
        'dropped_packets': 0,
        'curr_occupancy_bytes': 0,
        'ecn_marked_packets': 0,
        'wred_dropped_packets': 0,
        'watermark_bytes': 0,
        'delay_watermark': 0
    }

    # Mapping from SAI names to our dict keys
    mapping = {
        'SAI_QUEUE_STAT_PACKETS': 'packets',
        'SAI_QUEUE_STAT_DROPPED_PACKETS': 'dropped_packets',
        'SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES': 'curr_occupancy_bytes',
        'SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS': 'ecn_marked_packets',
        'SAI_QUEUE_STAT_WRED_DROPPED_PACKETS': 'wred_dropped_packets',
        'SAI_QUEUE_STAT_WATERMARK_BYTES': 'watermark_bytes',
        'SAI_QUEUE_STAT_DELAY_WATERMARK': 'delay_watermark'
    }

    for line in output.splitlines():
        line = line.strip()
        for sai_name, key in mapping.items():
            if sai_name in line:
                # Parse "SAI_QUEUE_STAT_xxx :  <value>"
                parts = line.split(':')
                if len(parts) >= 2:
                    try:
                        counters[key] = int(parts[1].strip())
                    except ValueError:
                        counters[key] = 0
                break

    st.log(f"  Port {port} TC {tc}: ECN_marked={counters['ecn_marked_packets']}, "
           f"WRED_dropped={counters['wred_dropped_packets']}, "
           f"packets={counters['packets']}")

    return counters


def clear_ecn_counters_on_port(dut, port, tc):
    """
    Clear ECN counters for a specific port and traffic class.

    Uses: show platform npu voq queue_counters -i <interface> -t <tc> -c

    Args:
        dut: DUT object
        port: Interface name (e.g., 'Ethernet1_57_1')
        tc: Traffic class number (0-7)
    """
    cmd = f"show platform npu voq queue_counters -i {port} -t {tc} -c"
    st.log(f"Clearing ECN counters: {cmd}")
    st.config(dut, cmd, skip_error_check=True)


def clear_all_ecn_counters(nodes, interfaces_map, tc=3):
    """
    Clear ECN counters on all specified interfaces.

    Args:
        nodes: Dictionary mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class to clear (default 3)
    """
    st.banner(f"Clearing ECN counters (TC {tc}) on all interfaces")
    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        dut = nodes[node_name]
        for intf in interfaces:
            clear_ecn_counters_on_port(dut, intf, tc)


def print_ecn_counter_deltas(before, after, label="ECN Counter Deltas"):
    """
    Calculate and print ECN counter deltas between before and after snapshots.

    Args:
        before: Counters dict from capture_ecn_counters()
        after: Counters dict from capture_ecn_counters()
        label: Banner label for output

    Returns:
        dict: Summary of ECN marked packet counts by node/interface
    """
    st.banner(label)
    summary = {}

    for node_name in after.keys():
        if node_name not in before:
            continue
        summary[node_name] = {}

        for intf in after[node_name].keys():
            if intf not in before[node_name]:
                continue

            before_c = before[node_name].get(intf, {})
            after_c = after[node_name].get(intf, {})

            ecn_delta = after_c.get('ecn_marked_packets', 0) - before_c.get('ecn_marked_packets', 0)
            wred_delta = after_c.get('wred_dropped_packets', 0) - before_c.get('wred_dropped_packets', 0)
            pkt_delta = after_c.get('packets', 0) - before_c.get('packets', 0)
            drop_delta = after_c.get('dropped_packets', 0) - before_c.get('dropped_packets', 0)

            st.log(f"  {node_name} {intf}: "
                   f"ECN_marked={ecn_delta}, WRED_drop={wred_delta}, "
                   f"Q_pkts={pkt_delta}, Q_drop={drop_delta}")
            summary[node_name][intf] = {
                'ecn_marked_packets': ecn_delta,
                'wred_dropped_packets': wred_delta,
                'packets': pkt_delta,
                'dropped_packets': drop_delta
            }

    return summary


# ---------------------------------------------------------------------------
# Platform Detection
# ---------------------------------------------------------------------------

def detect_platform(dut):
    """
    Detect DUT platform type by running 'show version' and caching the result.

    Recognized platform tags:
        'laguna'  -- 'x86_64-hf6100_64ed' (G200 NPU)
        'carib'   -- 'x86_64-hf6100_32d'  (Q200 NPU)
        'n9164e'  -- 'x86_64-n9164e'       (Gamut)
        'generic' -- anything else

    Returns:
        str: one of the platform tags above.
    """
    dut_key = str(dut)
    if dut_key in _platform_cache:
        return _platform_cache[dut_key]

    output = st.show(dut, "show version", skip_tmpl=True, skip_error_check=True)
    platform = 'generic'
    for line in (output or '').splitlines():
        if 'Platform:' in line:
            if 'x86_64-hf6100_64ed' in line:
                platform = 'laguna'
                break
            elif 'x86_64-hf6100_32d' in line:
                platform = 'carib'
                break
            elif 'x86_64-n9164e' in line:
                platform = 'n9164e'
                break

    _platform_cache[dut_key] = platform
    st.log("Detected platform for {}: {}".format(dut_key, platform))
    return platform


# ---------------------------------------------------------------------------
# WRED/ECN Counter Utilities (auto-selects legacy or NPU based on platform)
# ---------------------------------------------------------------------------

def clear_wred_counters(dut, interfaces=None, tc=3):
    """
    Clear WRED/ECN counters on a DUT.

    Uses 'sonic-clear queue wredcounters' for all platforms.

    Note: On Gamut (N9164E), WRED queue counters may not update properly
    even after clearing. Use interface TX_DROPS as a workaround.

    Args:
        dut: DUT object
        interfaces: Unused (kept for API compatibility)
        tc: Unused (kept for API compatibility)
    """
    st.log("Clearing WRED counters")
    st.config(dut, "sonic-clear queue wredcounters", skip_error_check=True, trace_log=1)


def clear_all_wred_counters(nodes, interfaces_map=None, tc=3):
    """
    Clear WRED/ECN counters on all nodes.

    Runs per-node clears in parallel (one thread per DUT) since each DUT
    has its own SSH session.

    Args:
        nodes: Dict mapping node names to DUT objects
        interfaces_map: Optional dict mapping node names to list of interfaces
                        (needed for laguna/carib per-port clear)
        tc: Traffic class (default 3)
    """
    items = list(nodes.items())  # [(name, dut), ...]

    def _clear_one(item):
        name, dut = item
        intfs = (interfaces_map or {}).get(name)
        clear_wred_counters(dut, interfaces=intfs, tc=tc)

    exec_foreach(True, items, _clear_one)


def parse_queue_counters(raw_output, interfaces):
    """
    Parse 'show queue counters <interface>' output.

    Output format:
        Port    TxQ    Counter/pkts    Counter/bytes    Drop/pkts    Drop/bytes
        -----  -----  --------------  ---------------  -----------  ------------
        Ethernet1_59_1    UC0         181,821      245,458,350       18,179           N/A
        Ethernet1_59_1    UC3               0                0      100,000           N/A

    Args:
        raw_output: Raw string output from 'show queue counters <interface>'
        interfaces: List of interface names to parse

    Returns:
        dict: {interface: {queue: {'counter_pkts': int, 'counter_bytes': int,
                                   'drop_pkts': int, 'drop_bytes': int}}}
    """
    counters = {intf: {} for intf in interfaces}
    interfaces_set = set(interfaces)

    def parse_value(val):
        if val == 'N/A':
            return 0
        try:
            return int(val.replace(',', ''))
        except ValueError:
            return 0

    for line in raw_output.splitlines():
        # Skip header lines and empty lines
        if 'Port' in line or '----' in line or not line.strip():
            continue
        # Skip "Last cached time" lines
        if 'cached' in line.lower():
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        intf_name = parts[0]
        if intf_name not in interfaces_set:
            continue

        queue = parts[1]  # e.g., UC0, UC3

        counters[intf_name][queue] = {
            'counter_pkts': parse_value(parts[2]),
            'counter_bytes': parse_value(parts[3]),
            'drop_pkts': parse_value(parts[4]),
            'drop_bytes': parse_value(parts[5]) if len(parts) > 5 else 0
        }

    return counters


def parse_wred_counters(raw_output, interfaces):
    """
    Parse 'show queue wredcounters <interface>' output.

    Output format:
        Port    TxQ    WredDrp/pkts    WredDrp/bytes    EcnMarked/pkts    EcnMarked/bytes
        -----  -----  --------------  ---------------  ----------------  -----------------
        Ethernet1_66    UC0             N/A              N/A               N/A                N/A
        Ethernet1_66    UC3             100              1000              500                5000

    Args:
        raw_output: Raw string output from 'show queue wredcounters'
        interfaces: List of interface names to parse

    Returns:
        dict: {interface: {queue: {'wred_drop_pkts': int, 'wred_drop_bytes': int,
                                   'ecn_marked_pkts': int, 'ecn_marked_bytes': int}}}
    """
    counters = {intf: {} for intf in interfaces}
    interfaces_set = set(interfaces)

    def parse_value(val):
        if val == 'N/A':
            return 0
        try:
            return int(val.replace(',', ''))
        except ValueError:
            return 0

    for line in raw_output.splitlines():
        # Skip header lines
        if 'Port' in line or '----' in line or not line.strip():
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        intf_name = parts[0]
        if intf_name not in interfaces_set:
            continue

        queue = parts[1]  # e.g., UC3

        counters[intf_name][queue] = {
            'wred_drop_pkts': parse_value(parts[2]),
            'wred_drop_bytes': parse_value(parts[3]),
            'ecn_marked_pkts': parse_value(parts[4]),
            'ecn_marked_bytes': parse_value(parts[5]) if len(parts) > 5 else 0
        }

    return counters


def capture_wred_counters(nodes, interfaces_map, tc=3):
    """
    Capture WRED/ECN counters for specified interfaces on each node.

    Auto-detects platform:
      - laguna/carib: uses 'show platform npu voq queue_counters -t <tc> -i <intf>'
      - N9164E (Gamut) and Generic: uses 'show queue wredcounters <intf>'
        for ECN marked counters, and BOTH 'show queue counters <intf>' and
        'show queue wredcounters <intf>' for WRED drops.

    IMPORTANT: For WRED drops, we check BOTH:
      - 'show queue counters' Drop/pkts
      - 'show queue wredcounters' WredDrp/pkts
    And use the GREATER of the two values. This ensures we get accurate
    drop counts regardless of which counter works on the platform.
    (e.g., Gamut shows 0 for WredDrp but accurate Drop/pkts)

    Both paths return data in the same format so callers don't need to change.

    Args:
        nodes: Dictionary mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class (default 3, used for laguna/carib NPU command and
            legacy queue name UC<tc>)

    Returns:
        dict: Nested dict {node: {interface: {queue: {...}}}}
              where queue dict contains keys:
                'ecn_marked_pkts'   - ECN marked packets (from wredcounters)
                'wred_drop_pkts'    - Max of queue counters Drop/pkts and wredcounters WredDrp/pkts
                'ecn_marked_bytes'  - ECN marked bytes (0 for most platforms)
                'wred_drop_bytes'   - Drop bytes (0 for most platforms)
                'packets'           - Transmitted packets (from queue counters Counter/pkts)
                'dropped_packets'   - Same as wred_drop_pkts for compatibility
    """
    counters = {}
    queue_name = f"UC{tc}"

    # Process each node in a worker thread so 4 DUTs run concurrently.
    items = [(node_name, interfaces)
             for node_name, interfaces in interfaces_map.items()
             if node_name in nodes]

    def _capture_one(item):
        node_name, interfaces = item
        dut = nodes[node_name]
        node_counters = {}
        platform = detect_platform(dut)

        for intf in interfaces:
            if platform in ('laguna', 'carib'):
                npu = get_ecn_counters_on_port(dut, intf, tc)
                # Wrap in queue-keyed dict matching legacy format
                node_counters[intf] = {
                    queue_name: {
                        'ecn_marked_pkts': npu.get('ecn_marked_packets', 0),
                        'wred_drop_pkts': npu.get('wred_dropped_packets', 0),
                        'ecn_marked_bytes': 0,
                        'wred_drop_bytes': 0,
                        'packets': npu.get('packets', 0),
                        'dropped_packets': npu.get('dropped_packets', 0),
                    }
                }
            else:
                # All other platforms (n9164e, generic):
                # 1. Get ECN marked and WredDrp from 'show queue wredcounters'
                wred_output = st.show(dut, f"show queue wredcounters {intf}",
                                      skip_tmpl=True, skip_error_check=True)
                wred_parsed = parse_wred_counters(wred_output, [intf])

                # 2. Get queue counters for drops and transmitted packets
                q_output = st.show(dut, f"show queue counters {intf}",
                                   skip_tmpl=True, skip_error_check=True)
                q_parsed = parse_queue_counters(q_output, [intf])

                # 3. Merge: ECN from wredcounters, drops = max(queue drops, wred drops)
                if intf not in node_counters:
                    node_counters[intf] = {}

                # Get all queues from both sources
                all_queues = set()
                if intf in wred_parsed:
                    all_queues.update(wred_parsed[intf].keys())
                if intf in q_parsed:
                    all_queues.update(q_parsed[intf].keys())

                for queue in all_queues:
                    wred_data = wred_parsed.get(intf, {}).get(queue, {})
                    q_data = q_parsed.get(intf, {}).get(queue, {})

                    # Get drops from both sources
                    queue_drop_pkts = q_data.get('drop_pkts', 0)
                    wred_drop_pkts = wred_data.get('wred_drop_pkts', 0)

                    # Use the GREATER of the two drop counters
                    # This ensures we get accurate drops regardless of which
                    # counter works on the platform
                    drop_pkts = max(queue_drop_pkts, wred_drop_pkts)

                    counter_pkts = q_data.get('counter_pkts', 0)

                    node_counters[intf][queue] = {
                        'ecn_marked_pkts': wred_data.get('ecn_marked_pkts', 0),
                        'ecn_marked_bytes': wred_data.get('ecn_marked_bytes', 0),
                        'wred_drop_pkts': drop_pkts,  # Max of both counters
                        'wred_drop_bytes': max(q_data.get('drop_bytes', 0),
                                               wred_data.get('wred_drop_bytes', 0)),
                        'packets': counter_pkts,  # Transmitted packets
                        'dropped_packets': drop_pkts,  # Alias for compatibility
                    }

        return (node_name, node_counters)

    retvals, _ = exec_foreach(True, items, _capture_one)
    for rv in retvals:
        if rv:
            name, nc = rv
            counters[name] = nc

    return counters


def print_wred_counter_deltas(before, after, tc=3, label="WRED/ECN Counter Deltas",
                              watermarks=None, pfc_info=None):
    """
    Calculate and print WRED/ECN counter deltas between before and after snapshots.
    Focuses on the specified TC queue.

    Args:
        before: Counters dict from capture_wred_counters()
        after: Counters dict from capture_wred_counters()
        tc: Traffic class (queue number) to report
        label: Banner label for output
        watermarks: Optional dict from capture_queue_watermark_values()
                    {node_name: {interface: watermark_bytes}}
        pfc_info: Optional dict or list of dicts with PFC RX counter info:
                  Single: {'node': str, 'interface': str, 'before': int, 'after': int}
                  Multi: {node_name: {interface: {'before': int, 'after': int}}}

    Returns:
        dict: Summary of ECN marked packet counts by node/interface
    """
    st.banner(label)
    queue_name = f"UC{tc}"
    summary = {}

    for node_name in after.keys():
        if node_name not in before:
            continue
        summary[node_name] = {}

        for intf in after[node_name].keys():
            if intf not in before[node_name]:
                continue

            before_q = before[node_name].get(intf, {}).get(queue_name, {})
            after_q = after[node_name].get(intf, {}).get(queue_name, {})

            ecn_delta = after_q.get('ecn_marked_pkts', 0) - before_q.get('ecn_marked_pkts', 0)
            wred_delta = after_q.get('wred_drop_pkts', 0) - before_q.get('wred_drop_pkts', 0)
            pkt_delta = after_q.get('packets', 0) - before_q.get('packets', 0)
            drop_delta = after_q.get('dropped_packets', 0) - before_q.get('dropped_packets', 0)
            watermark = 0
            if watermarks and node_name in watermarks:
                watermark = watermarks[node_name].get(intf, 0)

            # Get PFC RX delta for this interface if available
            pfc_delta = 0
            if pfc_info and isinstance(pfc_info, dict):
                if node_name in pfc_info and intf in pfc_info[node_name]:
                    pfc_entry = pfc_info[node_name][intf]
                    pfc_delta = pfc_entry.get('after', 0) - pfc_entry.get('before', 0)

            st.log(f"  {node_name} {intf} {queue_name}: "
                   f"ECN_marked={ecn_delta}, WRED_drop={wred_delta}, "
                   f"Q_pkts={pkt_delta}, Q_drop={drop_delta}, "
                   f"Q_wm={watermark}B, PFC_RX={pfc_delta}")
            summary[node_name][intf] = {
                'ecn_marked_pkts': ecn_delta,
                'wred_drop_pkts': wred_delta,
                'packets': pkt_delta,
                'dropped_packets': drop_delta,
                'watermark_bytes': watermark,
                'pfc_rx_delta': pfc_delta
            }

    return summary


# ---------------------------------------------------------------------------
# TGEN UDS (User Defined Statistics) - ECN CE Packet Counter
# ---------------------------------------------------------------------------

def setup_ecn_uds_counters(tg, port_handle):
    """
    Configure IXIA capture filters to count ECN CE-marked IPv6 packets.

    Uses the capture pipeline with pattern filters which are proven to work
    in the existing tg_custom_filter_config implementation.

    Sets up capture to count:
      - Filtered: ECN CE-marked packets (ECN field = 0b11 in IPv6 Traffic Class)
      - Total: All received packets

    Must be called BEFORE starting traffic. Counters accumulate while
    traffic runs and are read after traffic stops via get_ecn_uds_counters().

    IPv6 header layout (after 14-byte Ethernet header):
      byte14: version(4) | TC[7:4]   -> 0x6X
      byte15: TC[3:0] | FL[19:16]    -> 0xYZ
      TC = (byte14 & 0x0F) << 4 | (byte15 >> 4)
      ECN = TC[1:0] -> byte15 bits [5:4]
      ECN CE (0b11) -> byte15 & 0x30 == 0x30

    For pattern filter, we need 16-bit (2-byte) patterns:
      pattern1 @ offset 14: 0x6030 with mask 0xF030
        - Checks IPv6 version (6) AND ECN CE bits (0x30)
      pattern2 @ offset 12: 0x86DD with mask 0xFFFF  
        - Checks IPv6 EtherType

    Args:
        tg: TGEN handle object (TGIxia instance)
        port_handle: IXIA port handle string (e.g. '1/1/4')
    """
    # Use tg_custom_filter_config which sets up the full capture pipeline
    # Pattern must be 16-bit (4 hex chars) per the API requirement
    # 
    # Pattern1: ECN CE detection - bytes 14-15 of IPv6 header
    #   0x6030 = Version 6 (0x6X) + ECN CE (bits 5:4 = 0b11 = 0x30)
    #   Mask 0xF030 = check version nibble + ECN bits
    #
    # Pattern2: IPv6 EtherType at bytes 12-13
    #   0x86DD = IPv6 EtherType
    #   Mask 0xFFFF = exact match
    #
    result = tg.tg_custom_filter_config(
        mode='create',
        port_handle=port_handle,
        pattern_offset1='14',
        pattern1='6030',        # IPv6 version + ECN CE
        pattern_offset2='12', 
        pattern2='86DD',        # IPv6 EtherType
    )

    if result.get('status') != '1':
        st.error(f"Failed to configure ECN UDS counters on {port_handle}")
    else:
        st.log(f"ECN capture filter configured on {port_handle}: "
               f"pattern1=0x6030 (ECN CE) @ offset 14, pattern2=0x86DD (IPv6) @ offset 12")


def get_ecn_uds_counters(tg, port_handle):
    """
    Read ECN filtered packet counts from TGEN port after traffic has stopped.

    Requires setup_ecn_uds_counters() to have been called before traffic.

    Uses tg_custom_filter_config(mode='getstats') which internally calls
    tg_packet_stats() and extracts uds4_frame_count (filtered) and 
    uds3_frame_count (total).

    Args:
        tg: TGEN handle object (TGIxia instance)
        port_handle: IXIA port handle string

    Returns:
        dict: {
            'ecn_ce_marked': int,   # packets matching ECN CE filter
            'total_ipv6': int,      # total packets received  
            'marking_rate': float,  # CE / total as percentage
        }
    """
    result = tg.tg_custom_filter_config(
        mode='getstats',
        port_handle=port_handle,
    )

    ecn_ce = 0
    total = 0

    if result.get('status') == '1':
        custom_filter = result.get(port_handle, {}).get('custom_filter', {})
        ecn_ce = int(custom_filter.get('filtered_frame_count', 0))
        total = int(custom_filter.get('total_rx_count', 0))
        st.log(f"DEBUG: custom_filter result: {custom_filter}")

    rate = (ecn_ce / total * 100.0) if total > 0 else 0.0

    st.log(f"UDS ECN counters on {port_handle}: "
           f"CE_marked={ecn_ce}, total_IPv6={total}, marking_rate={rate:.2f}%")

    return {
        'ecn_ce_marked': ecn_ce,
        'total_ipv6': total,
        'marking_rate': rate,
    }


# ---------------------------------------------------------------------------
# Packet Capture
# ---------------------------------------------------------------------------

def start_packet_capture(tg, port_handle, port_name='egress', capture_mode='continuous'):
    """
    Start unfiltered packet capture on a TGEN port.

    Uses the SpyTest wrapper's tg_packet_control(action='start') which
    internally calls traffic_control(action='apply') to push config to
    hardware, then enables data plane capture.  The wrapper does NOT
    override capture_mode  --  it only adds apply + enable steps.

    Args:
        tg: TGEN handle object
        port_handle: IXIA port handle for capture
        port_name: Port name for logging (default 'egress')
        capture_mode: 'continuous' (rolling buffer) or 'trigger' (first N)

    Returns:
        bool: True if capture started successfully, False otherwise
    """
    try:
        st.banner(f"Starting packet capture on {port_name}")

        # Reset any existing capture state
        tg.tg_packet_control(port_handle=port_handle, action='reset')

        # Configure capture buffers with desired mode
        # Only enable data plane capture  --  control plane capture is not needed
        # and causes "Control capture is not selected" errors when the wrapper's
        # get_capture_stats_state checks -controlCaptureState on repeated iterations.
        tg.tg_packet_config_buffers(
            port_handle=port_handle,
            capture_mode=capture_mode,
            control_plane_capture_enable=0,
            data_plane_capture_enable=1
        )

        # Start capture via wrapper  --  its pre_proc does:
        #   1. traffic_control(action='apply')  --  pushes config to HW
        #   2. packet_config_buffers(data_plane_capture_enable='1')
        #      (no capture_mode  --  doesn't override our setting)
        #   3. packet_control(action='start')
        tg.tg_packet_control(port_handle=port_handle, action='start')

        st.log(f"Packet capture started on {port_name} (mode={capture_mode}, no filter)")
        return True

    except Exception as e:
        st.log(f"WARNING: Failed to start packet capture on {port_name}: {e}")
        import traceback
        st.log(traceback.format_exc())
        return False


def stop_packet_capture(tg, port_handle, port_name='egress', max_frames=10000):
    """
    Stop packet capture and return the raw capture dictionary.

    The caller is responsible for analyzing the captured packets
    (e.g. via extract_ecn_from_capture() or custom analysis).

    Args:
        tg: TGEN handle object
        port_handle: IXIA port handle for capture
        port_name: Port name for logging (default 'egress')
        max_frames: Maximum frames to retrieve

    Returns:
        dict: Raw capture dictionary from tg_packet_stats(), or None on failure
    """
    try:
        st.banner(f"Stopping packet capture on {port_name} port")
        tg.tg_packet_control(port_handle=port_handle, action='stop')
        st.wait(5)

        st.banner(f"Retrieving captured packets from {port_name}")
        pkt_dict = tg.tg_packet_stats(
            port_handle=port_handle,
            format='var',
            output_type='hex',
            var_num_frames=max_frames
        )
        return pkt_dict

    except Exception as e:
        st.log(f"WARNING: Failed to stop/retrieve capture on {port_name}: {e}")
        import traceback
        st.log(traceback.format_exc())
        return None


def start_ecn_ce_capture(tg, port_handle, port_name='egress', capture_mode='continuous', protocol='ipv6'):
    """
    Start packet capture, optionally with filter for ECN CE (11) marked packets.

    For IPv6: Configures IXIA capture to filter only packets with ECN=11 (CE)
    in the Traffic Class field. This is useful for verifying ECN marking at
    congestion points.

    For IPv4: Captures all packets without filtering (ECN extraction is done
    post-capture in extract_ecn_from_capture()).

    IPv6 Traffic Class Layout:
        Byte 0: Version (4 bits) + TC high (4 bits)
        Byte 1: TC low (4 bits) + Flow Label high (4 bits)
        TC = DSCP (6 bits) + ECN (2 bits)
        ECN bits are at positions 5-4 of byte 1

    For ECN=11 (CE):
        pattern='30' (0b0011_0000) - ECN=11 in bits 5-4
        mask='CF' (0b1100_1111) - only check bits 5-4 (mask bit 0 = check)

    Frame structure (untagged IPv6):
        Ethernet header: 14 bytes
        IPv6 byte 1: offset 14 + 1 = 15

    Args:
        tg: TGEN handle object
        port_handle: IXIA port handle for capture
        port_name: Port name for logging (default 'egress')
        capture_mode: 'continuous' (last N packets) or 'trigger' (first N packets)
        protocol: 'ipv6' to filter ECN CE packets, 'ipv4' to capture all packets

    Returns:
        bool: True if capture started successfully, False otherwise
    """
    try:
        st.banner(f"Starting ECN CE packet capture on {port_name} port (protocol={protocol})")

        # Reset any existing capture state
        tg.tg_packet_control(port_handle=port_handle, action='reset')

        # Configure capture filter for ECN CE (11) packets - IPv6 only
        # For IPv4, we capture all packets and analyze ECN post-capture
        if protocol == 'ipv6':
            # Using 'startOfFrame' instead of 'startOfIp' because IXIA's
            # startOfIp doesn't reliably work with IPv6 (designed for IPv4).
            st.log("Configuring capture filter for ECN CE (11) packets (IPv6)")
            tg.tg_packet_config_filter(
                port_handle=port_handle,
                mode='create',
                pattern1='30',                      # ECN=11 at bits 5-4 of byte 1
                pattern_mask1='CF',                 # Mask=0 at bits 5-4 means check those bits
                pattern_offset1=15,                 # Byte 15 = IPv6 byte 1 (after Eth header)
                pattern_offset_type1='startOfFrame' # Absolute offset from frame start
            )

            # Enable the capture filter using pattern1
            tg.tg_packet_config_triggers(
                port_handle=port_handle,
                capture_filter=1,
                capture_filter_pattern='pattern1'
            )
        else:
            # IPv4 or other: capture all packets without filtering
            st.log(f"Capture without filter (protocol={protocol})")

        # Configure capture buffers
        # capture_mode='continuous' - captures the last N packets (rolling buffer)
        # capture_mode='trigger' - captures first N packets then stops
        tg.tg_packet_config_buffers(
            port_handle=port_handle,
            capture_mode=capture_mode,
            control_plane_capture_enable=1,
            data_plane_capture_enable=1
        )

        # Start capture using low-level IXIA API directly to avoid SpyTest wrapper
        # interference. The wrapper's tg_packet_control(action='start') calls
        # packet_config_buffers internally WITHOUT capture_mode, resetting to
        # 'trigger' mode. Using ixia_eval bypasses this.
        tg.ixia_eval('packet_control', port_handle=port_handle, action='start')

        st.log(f"ECN CE capture started on {port_name} (mode={capture_mode}, protocol={protocol})")
        return True

    except Exception as e:
        st.log(f"WARNING: Failed to start ECN CE capture on {port_name}: {e}")
        import traceback
        st.log(traceback.format_exc())
        return False


def extract_ecn_from_capture(pkt_dict, port_handle, max_frames=20):
    """
    Extract ECN bits from captured packets on an egress TGEN port.

    For IPv6 packets (EtherType 0x86DD), the Traffic Class field spans
    bytes 14-15 of the Ethernet frame:
      byte[14] = 0x6T  (version=6, T=high nibble of TC)
      byte[15] = 0xTF  (T=low nibble of TC, F=high nibble of flow label)
      Traffic Class = (byte[14] & 0x0F) << 4 | (byte[15] >> 4)
      ECN = TC & 0x03

    For VLAN-tagged frames (EtherType 0x8100 at offset 12-13), the IPv6
    header starts at byte 18 instead of 14.

    Returns:
        dict with keys:
            'total_frames': int - number of frames examined
            'ecn_counts': dict - {ecn_value: count}  e.g. {0: 5, 2: 10, 3: 85}
            'ecn_labels': dict - {ecn_value: label}
            'frames': list of dicts with per-frame details (first max_frames)
    """
    ecn_labels = {0: 'Not-ECT', 1: 'ECT(1)', 2: 'ECT(0)', 3: 'CE'}
    result = {
        'total_frames': 0,
        'analyzed_frames': 0,
        'ecn_counts': {0: 0, 1: 0, 2: 0, 3: 0},
        'ecn_labels': ecn_labels,
        'frames': []
    }

    if not pkt_dict or port_handle not in pkt_dict:
        st.log("No capture data for port_handle")
        return result

    port_data = pkt_dict[port_handle]
    num_frames = int(port_data.get('aggregate', {}).get('num_frames', 0))
    if num_frames == 0:
        st.log("No frames captured")
        return result

    examine_count = min(num_frames, max_frames)
    result['total_frames'] = num_frames
    result['analyzed_frames'] = examine_count

    for i in range(examine_count):
        frame_data = port_data.get('frame', {}).get(str(i), {})
        pylist = frame_data.get('frame_pylist', [])
        if len(pylist) < 16:
            continue

        # Detect VLAN tag: EtherType at offset 12-13
        ethertype_hi = int(pylist[12], 16)
        ethertype_lo = int(pylist[13], 16)
        ethertype = (ethertype_hi << 8) | ethertype_lo

        ip_offset = 14
        if ethertype == 0x8100:
            # VLAN-tagged: real EtherType at offset 16-17
            if len(pylist) < 20:
                continue
            ethertype = (int(pylist[16], 16) << 8) | int(pylist[17], 16)
            ip_offset = 18

        if ethertype == 0x86DD:
            # IPv6: Traffic Class in bytes 0-1 of IPv6 header
            if len(pylist) < ip_offset + 2:
                continue
            byte0 = int(pylist[ip_offset], 16)
            byte1 = int(pylist[ip_offset + 1], 16)
            tc = ((byte0 & 0x0F) << 4) | (byte1 >> 4)
        elif ethertype == 0x0800:
            # IPv4: TOS byte is byte 1 of IPv4 header
            if len(pylist) < ip_offset + 2:
                continue
            tc = int(pylist[ip_offset + 1], 16)
        else:
            # Not IP -- skip
            continue

        dscp = tc >> 2
        ecn = tc & 0x03

        result['ecn_counts'][ecn] += 1
        if i < 10:
            result['frames'].append({
                'frame': i, 'tc': tc, 'dscp': dscp,
                'ecn': ecn, 'ecn_label': ecn_labels[ecn]
            })

    return result


def print_capture_ecn_summary(capture_results, label="Packet Capture ECN Summary"):
    """
    Print a summary of ECN bits extracted from packet capture.

    Args:
        capture_results: dict mapping port_alias to extract_ecn_from_capture() result
        label: Banner label
    """
    st.banner(label)
    ecn_labels = {0: 'Not-ECT', 1: 'ECT(1)', 2: 'ECT(0)', 3: 'CE'}

    for port_alias, res in capture_results.items():
        total = res['total_frames']
        analyzed = res.get('analyzed_frames', 0)
        counts = res['ecn_counts']
        st.log(f"  {port_alias}: captured={total}, analyzed={analyzed}  "
               f"Not-ECT={counts[0]}, ECT(1)={counts[1]}, "
               f"ECT(0)={counts[2]}, CE={counts[3]}")
        # Show first few frame details
        for f in res.get('frames', []):
            st.log(f"    frame[{f['frame']}]: DSCP={f['dscp']}, "
                   f"ECN={f['ecn']}({f['ecn_label']})")


def find_first_ce_packet(pkt_dict, port_handle):
    """
    Walk captured packets and return the 0-based index of the first packet
    whose ECN bits are 11 (CE).  Only IPv6 (EtherType 0x86DD) frames are
    examined; VLAN-tagged frames are handled transparently.

    Args:
        pkt_dict: Raw capture dict from stop_packet_capture()
        port_handle: IXIA port handle key in pkt_dict

    Returns:
        int or None: 0-based packet index of first CE packet, or None if
                     no CE packet was found.
    """
    if not pkt_dict or port_handle not in pkt_dict:
        return None

    port_data = pkt_dict[port_handle]
    num_frames = int(port_data.get('aggregate', {}).get('num_frames', 0))
    st.log(f"find_first_ce_packet: analyzing {num_frames} captured frames")
    for i in range(num_frames):
        frame_data = port_data.get('frame', {}).get(str(i), {})
        pylist = frame_data.get('frame_pylist', [])
        if len(pylist) < 16:
            continue

        # Detect VLAN tag
        ethertype = (int(pylist[12], 16) << 8) | int(pylist[13], 16)
        ip_offset = 14
        if ethertype == 0x8100:
            if len(pylist) < 20:
                continue
            ethertype = (int(pylist[16], 16) << 8) | int(pylist[17], 16)
            ip_offset = 18

        if ethertype != 0x86DD:
            continue
        if len(pylist) < ip_offset + 2:
            continue

        byte0 = int(pylist[ip_offset], 16)
        byte1 = int(pylist[ip_offset + 1], 16)
        tc = ((byte0 & 0x0F) << 4) | (byte1 >> 4)
        ecn = tc & 0x03

        if ecn == 3:  # CE
            return i

    return None


# ---------------------------------------------------------------------------
# Queue Watermark Utilities
# ---------------------------------------------------------------------------

def parse_queue_watermark_unicast(output, interfaces, tc=3):
    """
    Parse 'show queue watermark unicast' output and extract the watermark
    value for the given interfaces and TC queue.

    Expected output format:
        Egress shared pool occupancy per unicast queue:
                  Port    UC0    UC1    UC2        UC3    UC4  ...
        --------------  -----  -----  -----  ---------  -----  ...
        Ethernet1_57_1   1024      0      0  209640960      0  ...
        Ethernet1_57_2   1024      0      0  208926720      0  ...

    Args:
        output: Raw text from 'show queue watermark unicast'
        interfaces: List of interface names to extract
        tc: Traffic class (0-9), used to pick UC<tc> column

    Returns:
        dict: {interface_name: watermark_bytes} e.g.
              {'Ethernet1_57_1': 209640960, 'Ethernet1_57_2': 208926720}
    """
    result = {intf: 0 for intf in interfaces}
    if not output:
        return result

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('---') or line.startswith('Port') or line.startswith('Egress'):
            continue
        parts = line.split()
        if len(parts) < tc + 2:
            continue
        port_name = parts[0]
        if port_name in interfaces:
            try:
                result[port_name] = int(parts[tc + 1])
            except ValueError:
                result[port_name] = 0

    return result


DEFAULT_QUEUE_WATERMARK_INTERVAL_MS = 60000


def set_queue_watermark_poll_interval(dut, interval_ms):
    """
    Set the queue watermark counterpoll interval on a DUT.

    Uses 'counterpoll queue watermark interval <ms>' CLI, which updates
    FLEX_COUNTER_TABLE|QUEUE_WATERMARK POLL_INTERVAL in CONFIG_DB.

    Args:
        dut: DUT object
        interval_ms: Poll interval in milliseconds (e.g. 1000 for 1s)

    Returns:
        None
    """
    st.log(f"Setting queue watermark counterpoll interval to {interval_ms}ms")
    st.config(dut, f"sudo counterpoll watermark interval {interval_ms}",
              skip_error_check=True)


def restore_queue_watermark_poll_interval(dut):
    """
    Restore queue watermark counterpoll interval to the default (60s).

    Args:
        dut: DUT object
    """
    set_queue_watermark_poll_interval(dut, DEFAULT_QUEUE_WATERMARK_INTERVAL_MS)


def capture_queue_watermark_values(nodes, interfaces_map, tc=3):
    """
    Capture queue watermark values for specific interfaces on each node.

    Runs 'show queue watermark unicast' and parses the UC<tc> column.

    Args:
        nodes: Dict mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class (default 3)

    Returns:
        dict: {node_name: {interface: watermark_bytes}}
    """
    watermarks = {}
    items = [(node_name, interfaces)
             for node_name, interfaces in interfaces_map.items()
             if node_name in nodes]

    def _capture_one(item):
        node_name, interfaces = item
        dut = nodes[node_name]
        output = st.show(dut, "show queue watermark unicast", skip_tmpl=True)
        return (node_name, parse_queue_watermark_unicast(output, interfaces, tc))

    retvals, _ = exec_foreach(True, items, _capture_one)
    for rv in retvals:
        if rv:
            name, parsed = rv
            watermarks[name] = parsed
    return watermarks


def capture_queue_watermarks(dut, label=""):
    """
    Capture queue watermarks on a DUT.

    Args:
        dut: DUT object
        label: Optional label for logging

    Returns:
        str: Raw output from 'show queue watermark unicast'
    """
    st.log(f"Capturing queue watermarks{' - ' + label if label else ''}")
    output = st.show(dut, "show queue watermark unicast", skip_tmpl=True)
    return output


def capture_all_queue_watermarks(nodes, label=""):
    """
    Capture queue watermarks on all nodes.

    Args:
        nodes: Dict mapping node names to DUT objects
        label: Optional label for logging

    Returns:
        dict: {node_name: raw_output}
    """
    st.banner(f"Queue Watermarks{' - ' + label if label else ''}")
    watermarks = {}
    for name, dut in nodes.items():
        watermarks[name] = capture_queue_watermarks(dut, f"{name}")
        st.log(f"=== {name.upper()} ===")
        st.log(watermarks[name])
    return watermarks


# ---------------------------------------------------------------------------
# ECN Result Analysis
# ---------------------------------------------------------------------------

def _parse_redis_key(line, table_prefix):
    """Parse a redis-cli key line, stripping numbering and quotes.

    Returns the portion after the table prefix, split by '|', or None
    if the line does not match.
    """
    line = line.strip()
    if not line or table_prefix not in line:
        return None
    if ')' in line:
        line = line.split(')', 1)[1].strip()
    line = line.strip('"')
    return line.replace(table_prefix, '').split('|')


def _cleanup_static_routes(dut):
    """Remove all static routes from CONFIG_DB.

    Must run before removing interface IPs so the nexthops are still
    reachable during deletion.
    """
    result = st.show(dut, "redis-cli -n 4 keys 'STATIC_ROUTE|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'STATIC_ROUTE|')
        if parts is None or len(parts) != 2:
            continue
        vrf, prefix = parts
        if vrf == 'default':
            st.config(dut, "sudo config route del prefix {}".format(prefix),
                     skip_tmpl=True, skip_error_check=True)
        else:
            st.config(dut, "sudo config route del prefix {} vrf {}".format(prefix, vrf),
                     skip_tmpl=True, skip_error_check=True)


def _cleanup_l3_interfaces(dut):
    """Remove IPs and VRF bindings from physical L3 interfaces (INTERFACE table)."""
    skip_interfaces = ['eth0', 'lo', 'docker0', 'Loopback', 'Management']
    result = st.show(dut, "redis-cli -n 4 keys 'INTERFACE|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'INTERFACE|')
        if parts is None:
            continue
        intf = parts[0]
        if any(skip in intf for skip in skip_interfaces):
            continue
        if len(parts) > 1:
            st.config(dut, "sudo config interface ip remove {} {}".format(intf, parts[1]),
                     skip_tmpl=True, skip_error_check=True)
        else:
            st.config(dut, "sudo config interface vrf unbind {}".format(intf),
                     skip_tmpl=True, skip_error_check=True)


def _cleanup_vlan_interfaces(dut):
    """Remove IPs and VRF bindings from VLAN SVIs (VLAN_INTERFACE table)."""
    result = st.show(dut, "redis-cli -n 4 keys 'VLAN_INTERFACE|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VLAN_INTERFACE|')
        if parts is None:
            continue
        intf = parts[0]
        if len(parts) > 1:
            st.config(dut, "sudo config interface ip remove {} {}".format(intf, parts[1]),
                     skip_tmpl=True, skip_error_check=True)
        else:
            st.config(dut, "sudo config interface vrf unbind {}".format(intf),
                     skip_tmpl=True, skip_error_check=True)


def _cleanup_vxlan_mappings(dut):
    """Remove all VxLAN tunnel mappings.

    Must run before removing VLANs, since VxLAN maps reference VLANs.
    Key format: VXLAN_TUNNEL_MAP|<tunnel>|map_<vni>_Vlan<vid>
    CLI syntax: config vxlan map del <tunnel> <vid> <vni>
    """
    # Remove VRF-VNI maps first — VXLAN tunnel maps cannot be deleted while
    # their VNI is still referenced by a VRF-VNI mapping.
    result = st.show(dut, "redis-cli -n 4 keys 'VRF|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VRF|')
        if parts is None or len(parts) != 1:
            continue
        vrf_name = parts[0]
        if vrf_name in ('default', 'mgmt'):
            continue
        st.config(dut, "sudo config vrf del_vrf_vni_map {}".format(vrf_name),
                 skip_tmpl=True, skip_error_check=True)

    result = st.show(dut, "redis-cli -n 4 keys 'VXLAN_TUNNEL_MAP|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VXLAN_TUNNEL_MAP|')
        if parts is None or len(parts) != 2:
            continue
        tunnel_name, map_name = parts
        # Parse map_name like "map_5502_Vlan502" -> vni=5502, vid=502
        m = re.match(r'map_(\d+)_Vlan(\d+)', map_name)
        if not m:
            st.log("Skipping unrecognized vxlan map: {}".format(map_name))
            continue
        vni, vid = m.group(1), m.group(2)
        st.config(dut, "sudo config vxlan map del {} {} {}".format(tunnel_name, vid, vni),
                 skip_tmpl=True, skip_error_check=True)

    # Remove EVPN NVO entries (must happen before tunnel deletion)
    result = st.show(dut, "redis-cli -n 4 keys 'VXLAN_EVPN_NVO|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VXLAN_EVPN_NVO|')
        if parts is None or len(parts) != 1:
            continue
        nvo_name = parts[0]
        st.config(dut, "sudo config vxlan evpn_nvo del {}".format(nvo_name),
                 skip_tmpl=True, skip_error_check=True)

    # Remove the tunnel itself
    result = st.show(dut, "redis-cli -n 4 keys 'VXLAN_TUNNEL|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VXLAN_TUNNEL|')
        if parts is None or len(parts) != 1:
            continue
        tunnel_name = parts[0]
        st.config(dut, "sudo config vxlan del {}".format(tunnel_name),
                 skip_tmpl=True, skip_error_check=True)


def _cleanup_vlans(dut):
    """Remove all VLAN members and then the VLANs themselves."""
    # Members first
    result = st.show(dut, "redis-cli -n 4 keys 'VLAN_MEMBER|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VLAN_MEMBER|')
        if parts is None or len(parts) != 2:
            continue
        vlan_name, member_intf = parts
        vlan_id = vlan_name.replace('Vlan', '')
        if vlan_id.isdigit():
            st.config(dut, "sudo config vlan member del {} {}".format(vlan_id, member_intf),
                     skip_tmpl=True, skip_error_check=True)

    # VLANs
    result = st.show(dut, "redis-cli -n 4 keys 'VLAN|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VLAN|')
        if parts is None or len(parts) != 1:
            continue
        vlan_id = parts[0].replace('Vlan', '')
        if vlan_id.isdigit():
            st.config(dut, "sudo config vlan del {}".format(vlan_id),
                     skip_tmpl=True, skip_error_check=True)


def _cleanup_portchannels(dut):
    """Remove all PortChannel members and then the PortChannels themselves."""
    # Members first
    result = st.show(dut, "redis-cli -n 4 keys 'PORTCHANNEL_MEMBER|*'", skip_tmpl=True)
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'PORTCHANNEL_MEMBER|')
        if parts is None or len(parts) != 2:
            continue
        pc_name, member_intf = parts
        st.config(dut, "sudo config portchannel member del {} {}".format(pc_name, member_intf),
                 skip_tmpl=True, skip_error_check=True)

    # PortChannels
    result = st.show(dut, "redis-cli -n 4 keys 'PORTCHANNEL|*'", skip_tmpl=True)
    for line in result.splitlines():
        line = line.strip()
        if not line or 'PORTCHANNEL|' not in line or 'PORTCHANNEL_MEMBER|' in line:
            continue
        if ')' in line:
            line = line.split(')', 1)[1].strip()
        line = line.strip('"')
        pc_name = line.replace('PORTCHANNEL|', '')
        if pc_name.startswith('PortChannel'):
            st.config(dut, "sudo config portchannel del {}".format(pc_name),
                     skip_tmpl=True, skip_error_check=True)


def _cleanup_vrfs(dut):
    """Remove all non-default VRFs from CONFIG_DB.

    Must run after interfaces are unbound and VxLAN mappings are removed.
    BGP VRF instances are removed first since SONiC refuses to delete a VRF
    that is still referenced by 'router bgp <ASN> vrf <name>'.
    """
    result = st.show(dut, "redis-cli -n 4 keys 'VRF|*'", skip_tmpl=True)
    vrfs_to_delete = []
    for line in result.splitlines():
        parts = _parse_redis_key(line, 'VRF|')
        if parts is None or len(parts) != 1:
            continue
        vrf_name = parts[0]
        if vrf_name in ('default', 'mgmt'):
            continue
        vrfs_to_delete.append(vrf_name)

    if not vrfs_to_delete:
        return

    # Remove BGP VRF instances first (look up ASN from CONFIG_DB)
    for vrf_name in vrfs_to_delete:
        asn_result = st.show(dut,
            "redis-cli -n 4 hget 'BGP_GLOBALS|{}' local_asn".format(vrf_name),
            skip_tmpl=True)
        asn = None
        for aline in asn_result.splitlines():
            aline = aline.strip()
            if aline.isdigit():
                asn = aline
                break
        if asn:
            st.config(dut,
                "vtysh -c 'configure terminal' -c 'no router bgp {} vrf {}'".format(asn, vrf_name),
                skip_tmpl=True, skip_error_check=True)

    # Now delete the VRFs
    for vrf_name in vrfs_to_delete:
        st.config(dut, "sudo config vrf del {}".format(vrf_name),
                 skip_tmpl=True, skip_error_check=True)



def cleanup_config(dut):
    """Clean up IP interfaces and memberships.

    Removes static routes, L3 config, VLAN members, PortChannel members,
    VLANs, and PortChannels from CONFIG_DB.  Also clears hardware counters.
    """
    _cleanup_static_routes(dut)
    _cleanup_l3_interfaces(dut)
    _cleanup_vlan_interfaces(dut)
    _cleanup_vxlan_mappings(dut)
    _cleanup_vrfs(dut)
    _cleanup_vlans(dut)
    _cleanup_portchannels(dut)

def get_if_speed(dut, if_str):
    # First few tokens in sample output of show int status <if_name> 
    # Ethernet1_48_1  3080,3081,3082,3083     400G   9100
    result = st.show(dut, "show int status {}".format(if_str), skip_tmpl=True)
    for line in result.splitlines():
        if if_str in line:
            # Trim the trailing G and return integer value
            speed_str = line.split()[2]
            return int(speed_str[:-1])
    return 10

def cleanup_leftover_vrf_bgp(nodes):
    """Remove any leftover VRF BGP instances and VXLAN config so test can configure cleanly."""
    for leaf in ['leaf0', 'leaf1']:
        if leaf not in nodes:
            continue
        dut = nodes[leaf]

        # Step 1: Remove L3VNI binding from VRF context (must be done before BGP VRF removal)
        output = st.config(dut, "vtysh -c 'show running-config' | grep -A5 'vrf '",
                           skip_error_check=True)
        for line in output.splitlines():
            m = re.match(r'\s*vni\s+(\d+)', line.strip())
            if m:
                vni = m.group(1)
                vrf_output = st.config(dut, "vtysh -c 'show running-config' | grep -B3 'vni " + vni + "'",
                                       skip_error_check=True)
                for vrf_line in vrf_output.splitlines():
                    vm = re.match(r'vrf\s+(\S+)', vrf_line.strip())
                    if vm:
                        vrf_name = vm.group(1)
                        st.log(f"{leaf}: Removing vni {vni} from vrf {vrf_name}")
                        st.config(dut,
                                  f"vtysh -c 'configure terminal' -c 'vrf {vrf_name}' -c 'no vni {vni}' -c 'exit-vrf'",
                                  skip_error_check=True)

        # Step 2: Remove VRF BGP instances
        output = st.config(dut, "vtysh -c 'show running-config' | grep 'router bgp.*vrf'",
                           skip_error_check=True)
        for line in output.splitlines():
            m = re.match(r'(router bgp \d+ vrf \S+)', line.strip())
            if m:
                vrf_bgp = m.group(1)
                st.log(f"{leaf}: Removing leftover {vrf_bgp}")
                st.config(dut, f"vtysh -c 'configure terminal' -c 'no {vrf_bgp}'",
                          skip_error_check=True)

        # Step 3: Remove leftover vni blocks from global/EVPN context
        output2 = st.config(dut, "vtysh -c 'show running-config' | grep '^ *vni '",
                            skip_error_check=True)
        for line in output2.splitlines():
            m = re.match(r'\s*vni\s+(\d+)', line.strip())
            if m:
                st.log(f"{leaf}: Removing leftover vni {m.group(1)} binding (global)")
                st.config(dut, f"vtysh -c 'configure terminal' -c 'no vni {m.group(1)}'",
                          skip_error_check=True)

        # Step 4: Remove SONiC VRF config
        for vrf in ['Vrf01', 'Vrf02', 'Vrf03', 'Vrf04']:
            st.config(dut, f"sudo config vrf del_vrf_vni_map {vrf} || true", skip_error_check=True)
            st.config(dut, f"sudo config vrf del {vrf} || true", skip_error_check=True)

        # Step 5: Remove any leftover VXLAN tunnel from other tests
        vxlan_output = st.config(dut, "show vxlan tunnel", skip_error_check=True)
        has_vtep = 'Vtep' in vxlan_output
        has_vxlan = 'VXLAN' in vxlan_output and '2001:db8' in vxlan_output
        if has_vtep or has_vxlan:
            st.log(f"{leaf}: Removing leftover VXLAN tunnel config (Vtep={has_vtep}, VXLAN={has_vxlan})")
            # Parse mapped VLANs from the output (e.g. "1000 -> Vlan2", "10100 -> Vlan100")
            mapped_vlans = set()
            for line in vxlan_output.splitlines():
                vm = re.search(r'-> Vlan(\d+)', line)
                if vm:
                    mapped_vlans.add(vm.group(1))
            st.log(f"{leaf}: Found mapped VLANs: {mapped_vlans}")
            # Must delete ALL maps on ALL tunnels before NVO can be deleted
            st.config(dut, "sudo config vrf del_vrf_vni_map Vrf01 || true", skip_error_check=True)
            if has_vtep:
                st.config(dut, "sudo config vxlan map del Vtep 100 2727 || true", skip_error_check=True)
            if has_vxlan:
                for vlan_vni in [('2', '1000'), ('3', '1000'), ('100', '10100')]:
                    st.config(dut, f"sudo config vxlan map del VXLAN {vlan_vni[0]} {vlan_vni[1]} || true",
                              skip_error_check=True)
            st.config(dut, "sudo config vxlan evpn_nvo del NVO || true", skip_error_check=True)
            if has_vtep:
                st.config(dut, "sudo config vxlan del Vtep || true", skip_error_check=True)
            if has_vxlan:
                st.config(dut, "sudo config vxlan del VXLAN || true", skip_error_check=True)
            # Clean up leftover VLANs - must remove members, VRF binding before deletion
            for vlan_id in mapped_vlans:
                # Query CONFIG_DB for VLAN members
                member_output = st.config(dut,
                    f"redis-cli -n 4 KEYS 'VLAN_MEMBER|Vlan{vlan_id}|*'",
                    skip_error_check=True)
                for mline in member_output.splitlines():
                    mm = re.search(r'VLAN_MEMBER\|Vlan\d+\|([^"\s]+)', mline)
                    if mm:
                        member = mm.group(1)
                        st.log(f"{leaf}: Removing Vlan{vlan_id} member {member}")
                        st.config(dut, f"sudo config vlan member del {vlan_id} {member} || true",
                                  skip_error_check=True)
                # Remove VRF binding
                st.config(dut, f"sudo config interface vrf unbind Vlan{vlan_id} || true",
                          skip_error_check=True)
                st.config(dut, f"sudo config vlan del {vlan_id} || true", skip_error_check=True)
            if has_vxlan:
                for ip in ['2001:db8:1::2/128', '2001:db8:1::3/128']:
                    st.config(dut, f"sudo config interface ip rem Loopback27 {ip} || true",
                              skip_error_check=True)
            # Also remove L2VNI loopback IPs
            if has_vtep:
                for ip in ['fd27::280:10f1:25f/128', 'fd27::22d:b87f:214b/128']:
                    st.config(dut, f"sudo config interface ip rem Loopback27 {ip} || true",
                              skip_error_check=True)

        # Step 6: Unconditionally remove leftover VLANs from L2VNI (Vlan100) and L3VNI (Vlan2, Vlan3)
        # These can survive even after the VXLAN tunnels are gone.
        # A port can only be untagged in ONE VLAN -- leftover VLAN memberships
        # prevent new VLAN member adds from working.
        for vlan_id in ['2', '3', '100']:
            member_output = st.config(dut,
                f"redis-cli -n 4 KEYS 'VLAN_MEMBER|Vlan{vlan_id}|*'",
                skip_error_check=True)
            for mline in member_output.splitlines():
                mm = re.search(r'VLAN_MEMBER\|Vlan\d+\|([^"\s]+)', mline)
                if mm:
                    member = mm.group(1)
                    st.log(f"{leaf}: Removing leftover Vlan{vlan_id} member {member}")
                    st.config(dut, f"sudo config vlan member del {vlan_id} {member} || true",
                              skip_error_check=True)
            st.config(dut, f"sudo config interface vrf unbind Vlan{vlan_id} || true",
                      skip_error_check=True)
            st.config(dut, f"sudo config vlan del {vlan_id} || true", skip_error_check=True)
        # Also remove loopback IPs unconditionally
        for ip in ['2001:db8:1::2/128', '2001:db8:1::3/128',
                    'fd27::280:10f1:25f/128', 'fd27::22d:b87f:214b/128']:
            st.config(dut, f"sudo config interface ip rem Loopback27 {ip} || true",
                      skip_error_check=True)

        # Step 7: Flush stale VXLAN entries from ALL databases
        # Prior tests (L2VNI uses 'Vtep', L3VNI uses 'VXLAN') leave entries
        # in CONFIG_DB, APP_DB, and STATE_DB.  vxlanmgrd watches CONFIG_DB and
        # gets stuck in an infinite retry loop if it sees tunnels it can't
        # delete (e.g. "Vtep" with NVO still referencing it).  This blocks
        # processing of the new tunnel.
        st.log(f"{leaf}: Flushing stale VXLAN entries from CONFIG_DB/APP_DB/STATE_DB")
        # CONFIG_DB (db 4): Remove stale VXLAN_TUNNEL, VXLAN_TUNNEL_MAP, VXLAN_EVPN_NVO
        for pattern in ['VXLAN_TUNNEL|*', 'VXLAN_TUNNEL_MAP|*', 'VXLAN_EVPN_NVO|*']:
            st.config(dut,
                f"redis-cli -n 4 EVAL \"local k=redis.call('keys',ARGV[1]); if #k>0 then return redis.call('del',unpack(k)) else return 0 end\" 0 '{pattern}'",
                skip_error_check=True)
        # APP_DB (db 0): Remove stale tunnel/map/remote-vni entries
        for pattern in ['VXLAN_TUNNEL_TABLE:*', 'VXLAN_TUNNEL_MAP_TABLE:*',
                        'VXLAN_REMOTE_VNI_TABLE:*', 'VXLAN_FDB_TABLE:*']:
            st.config(dut,
                f"redis-cli -n 0 EVAL \"local k=redis.call('keys',ARGV[1]); if #k>0 then return redis.call('del',unpack(k)) else return 0 end\" 0 '{pattern}'",
                skip_error_check=True)
        # STATE_DB (db 6): Remove stale tunnel state
        st.config(dut,
            "redis-cli -n 6 EVAL \"local k=redis.call('keys',ARGV[1]); if #k>0 then return redis.call('del',unpack(k)) else return 0 end\" 0 'VXLAN_TUNNEL_TABLE|*'",
            skip_error_check=True)

        # Step 8: Restart vxlanmgrd to clear stuck in-memory delete tasks
        # Even after flushing all DBs, vxlanmgrd may have a pending delete
        # task for a tunnel (e.g. "Vtep") stuck in its internal retry loop.
        # The retry fires every second and blocks processing of new tunnels.
        # Restarting vxlanmgrd is lightweight (no cascade to orchagent/syncd)
        # and forces it to re-read the current (clean) CONFIG_DB state.
        st.log(f"{leaf}: Restarting vxlanmgrd to clear stuck delete tasks")
        st.config(dut, "sudo docker exec swss supervisorctl restart vxlanmgrd",
                  skip_error_check=True)
        time.sleep(2)  # Give vxlanmgrd time to re-initialize


def ensure_bgp_container_running(dut, node_name, max_wait=240):
    """Wait for the bgp container AND FRR daemons to be ready before issuing vtysh commands."""
    inspect_cmd = 'sudo docker inspect -f "{{.State.Running}}" bgp'
    status_cmd = 'sudo docker ps -a --filter name=bgp --format "{{.Names}} {{.Status}}"'
    # Use bash-level vtysh check (not spytest vtysh mode) to avoid prompt detection crash
    frr_check_cmd = "sudo vtysh -c 'show version' 2>&1 | head -5"

    # Phase 1: Wait for container to be running
    container_up = False
    for attempt in range(max(1, max_wait // 5)):
        output = st.config(dut, inspect_cmd, skip_error_check=True, timeout=30)
        if 'true' in output.lower():
            st.log(f"{node_name}: BGP container is running")
            container_up = True
            break
        st.log(f"{node_name}: BGP container not running yet... attempt {attempt + 1}")
        st.config(dut, 'sudo docker start bgp', skip_error_check=True, timeout=120)
        st.wait(5)

    if not container_up:
        st.log(f"ERROR: {node_name}: BGP container failed to reach running state")
        st.log(st.config(dut, status_cmd, skip_error_check=True, timeout=30))
        st.log(st.config(dut, 'sudo docker logs --tail 50 bgp', skip_error_check=True, timeout=60))
        return False

    # Phase 2: Wait for FRR daemons inside the container to be responsive
    st.log(f"{node_name}: Waiting for FRR daemons to accept connections...")
    for attempt in range(24):  # 24 x 5s = 120s max
        output = st.config(dut, frr_check_cmd, skip_error_check=True, timeout=30)
        if 'FRRouting' in output or 'frr' in output.lower():
            st.log(f"{node_name}: FRR daemons are ready after {(attempt + 1) * 5}s")
            return True
        if 'failed to connect' in output.lower():
            st.log(f"{node_name}: FRR daemons not ready yet... attempt {attempt + 1}/24")
        else:
            st.log(f"{node_name}: vtysh check output: {output[:200]}")
        st.wait(5)

    st.log(f"ERROR: {node_name}: FRR daemons never became responsive")
    st.log(st.config(dut, 'sudo docker logs --tail 50 bgp', skip_error_check=True, timeout=60))
    return False


def dump_vxlan_debug_info(nodes, context=""):
    """
    Dump comprehensive debug info for BGP and VXLAN troubleshooting.

    Args:
        nodes: Dict mapping node names to DUT objects
        context: Description of when this debug dump is being called
    """
    st.banner(f"DEBUG DUMP: {context}")

    debug_commands = [
        # BGP neighbor status
        ("show ipv6 bgp summary", "BGP IPv6 Summary"),
        ("show ip bgp summary", "BGP IPv4 Summary"),
        ("vtysh -c 'show run'", "FRR Running Config"),
        ("vtysh -c 'show bgp summary'", "BGP Summary"),
        # EVPN/L2VPN status - use vtysh for FRR commands
        ("vtysh -c 'show bgp l2vpn evpn summary'", "BGP L2VPN EVPN Summary"),
        ("vtysh -c 'show bgp l2vpn evpn'", "BGP L2VPN EVPN Routes"),
        ("vtysh -c 'show evpn vni'", "EVPN VNI Status"),
        # VXLAN status
        ("show vxlan remotevtep", "VXLAN Remote VTEPs"),
        ("show vxlan tunnel", "VXLAN Tunnels"),
        ("show vxlan interface", "VXLAN Interface"),
        ("show vxlan vlanvnimap", "VXLAN VLAN-VNI Map"),
        # Interface and IP status - both IPv4 and IPv6
        ("show ip interface", "IP Interfaces (IPv4)"),
        ("show ipv6 interface", "IP Interfaces (IPv6)"),
        ("show interface status", "Interface Status"),
        # VLAN membership for debugging
        ("show vlan brief", "VLAN Brief"),
    ]

    # Kernel-level and APP_DB/ASIC_DB diagnostics
    kernel_commands = [
        ("ip -d link show type vxlan", "Kernel VXLAN devices"),
        ("bridge fdb show | grep 00:00:00:00:00:00 | head -20", "Kernel BUM FDB entries"),
        ("bridge fdb show dev VXLAN-100 2>/dev/null || echo 'no VXLAN-100 device'", "Kernel FDB on VXLAN-100"),
        ("redis-cli -n 0 keys '*REMOTE*' 2>/dev/null || echo 'redis not accessible'", "APP_DB REMOTE keys"),
        ("redis-cli -n 0 keys '*VXLAN_TUNNEL*' 2>/dev/null || echo 'redis not accessible'", "APP_DB VXLAN_TUNNEL keys"),
        ("redis-cli -n 0 HGETALL 'VXLAN_TUNNEL_TABLE:VXLAN' 2>/dev/null || echo 'no entry'", "APP_DB VXLAN_TUNNEL_TABLE:VXLAN"),
        ("redis-cli -n 0 HGETALL 'VXLAN_TUNNEL_TABLE:Vtep' 2>/dev/null || echo 'no entry'", "APP_DB VXLAN_TUNNEL_TABLE:Vtep"),
        ("redis-cli -n 0 keys '*VNI*' 2>/dev/null || echo 'redis not accessible'", "APP_DB VNI keys"),
        ("redis-cli -n 4 keys '*VXLAN*' 2>/dev/null || echo 'redis not accessible'", "CONFIG_DB VXLAN keys"),
        ("redis-cli -n 6 keys '*TUNNEL*' 2>/dev/null || echo 'redis not accessible'", "STATE_DB TUNNEL keys"),
        ("redis-cli -n 6 keys '*VXLAN*' 2>/dev/null || echo 'no keys'", "STATE_DB VXLAN keys"),
        ("redis-cli -n 1 keys '*SAI_OBJECT_TYPE_TUNNEL*' 2>/dev/null | head -20 || echo 'no tunnel SAI objects'", "ASIC_DB Tunnel SAI objects"),
        ("redis-cli -n 1 keys '*SAI_OBJECT_TYPE_TUNNEL_MAP*' 2>/dev/null | head -20 || echo 'no tunnel map SAI objects'", "ASIC_DB Tunnel Map SAI objects"),
        ("redis-cli -n 1 keys '*SAI_OBJECT_TYPE_TUNNEL_TERM*' 2>/dev/null | head -20 || echo 'no tunnel term SAI objects'", "ASIC_DB Tunnel Term SAI objects"),
        ("sudo docker exec swss supervisorctl status 2>/dev/null || echo 'swss not running'", "SWSS service status"),
        ("sudo grep -i 'vxlan\\|tunnel' /var/log/syslog 2>/dev/null | grep -i 'err\\|fail\\|warn' | tail -20 || echo 'no vxlan errors'", "Syslog VXLAN errors"),
        ("vtysh -c 'show evpn vni 2727'", "EVPN VNI 2727 Detail"),
        ("vtysh -c 'show evpn vni 10100'", "EVPN VNI 10100 Detail"),
        ("vtysh -c 'show evpn vni 1000'", "EVPN VNI 1000 Detail"),
    ]

    for leaf in ['leaf0', 'leaf1']:
        if leaf not in nodes:
            continue
        st.banner(f"DEBUG: {leaf.upper()}")
        remote_vtep_ip = None

        for cmd, desc in debug_commands:
            st.log(f"=== {desc} ===")
            output = st.show(nodes[leaf], cmd, skip_tmpl=True, skip_error_check=True)
            # Truncate very long output
            if output and len(output) > 2000:
                st.log(f"{output[:2000]}... [truncated]")
            else:
                st.log(output if output else "(no output)")

            # Parse remote VTEP IP from 'show vxlan remotevtep' output
            if cmd == "show vxlan remotevtep" and output:
                match = re.search(r'\|\s*([0-9a-f:]+)\s*\|\s*([0-9a-f:.]+)\s*\|\s*EVPN\s*\|', output, re.IGNORECASE)
                if match:
                    remote_vtep_ip = match.group(2).strip()
                    st.log(f"Parsed remote VTEP IP: {remote_vtep_ip}")

        # Query remote MAC table if we have remote VTEP
        if remote_vtep_ip:
            st.log(f"=== VXLAN Remote MACs for {remote_vtep_ip} ===")
            remotemac_output = st.show(nodes[leaf], f"show vxlan remotemac {remote_vtep_ip}",
                                       skip_tmpl=True, skip_error_check=True)
            if remotemac_output and len(remotemac_output) > 2000:
                st.log(f"{remotemac_output[:2000]}... [truncated]")
            else:
                st.log(remotemac_output if remotemac_output else "(no output)")

        # Run kernel/APP_DB/ASIC_DB diagnostics
        st.banner(f"DEBUG: {leaf.upper()} - Kernel/APP_DB/ASIC_DB diagnostics")
        for cmd, desc in kernel_commands:
            st.log(f"=== {desc} ===")
            output = st.config(nodes[leaf], cmd, skip_error_check=True)
            st.log(f"{desc}: {output}" if output else f"{desc}: (no output)")


# =============================================================================
# Watermark Collection Utilities
# =============================================================================

def clear_queue_watermark(dut):
    """Clear queue watermark unicast on specified DUT.
    
    On some platforms (like laguna/carib), watermarks may not be cleared immediately.
    This function clears and then does a read to ensure the clear takes effect.
    """
    st.log(f"Clearing queue watermark unicast on DUT={dut}")
    st.config(dut, 'sonic-clear queue watermark unicast', skip_tmpl=True, trace_log=1)
    st.wait(2)


def clear_all_queue_watermarks(nodes, wait_after=3):
    """
    Clear queue watermarks on all nodes with robust verification.

    Per-node clears run in parallel (one thread per DUT).
    
    Args:
        nodes: Dict mapping node names to DUT objects
        wait_after: Additional wait time after all clears (seconds)
    """
    st.log("Clearing queue watermarks on all nodes...")

    def _clear_one(item):
        node_name, dut = item
        st.log(f"  Clearing queue watermark unicast on {node_name}")
        st.config(dut, 'sonic-clear queue watermark unicast', skip_tmpl=True, trace_log=1)

    exec_foreach(True, list(nodes.items()), _clear_one)

    st.wait(wait_after)
    st.log("Queue watermarks cleared on all nodes")


def get_queue_watermark(dut, port):
    """
    Get queue watermark unicast for a specific port.
    
    Args:
        dut: DUT handle
        port: Interface name (e.g., 'Ethernet296')
        
    Returns:
        Queue watermark output string
    """
    cmd = f"show queue watermark unicast | grep -A 20 '{port}'"
    st.log(f"Getting queue watermark: DUT={dut}, port={port}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Queue watermark output for {port}:\n{output}")
        return output
    except Exception as e:
        st.log(f"Error getting queue watermark: {e}")
        return None


def clear_buffer_pool_watermark(dut):
    """Clear buffer pool watermark on specified DUT."""
    st.log(f"Clearing buffer pool watermark on DUT={dut}")
    st.config(dut, 'watermarkstat -t buffer_pool -c', skip_tmpl=True, trace_log=1)
    st.wait(1)


def get_buffer_pool_watermark(dut):
    """
    Get buffer pool watermark.
    
    Args:
        dut: DUT handle
        
    Returns:
        Buffer pool watermark output string
    """
    cmd = "show buffer_pool watermark"
    st.log(f"Getting buffer pool watermark: DUT={dut}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Buffer pool watermark output:\n{output}")
        return output
    except Exception as e:
        st.log(f"Error getting buffer pool watermark: {e}")
        return None


def clear_priority_group_watermark(dut):
    """Clear priority group watermark shared on specified DUT."""
    st.log(f"Clearing priority group watermark shared on DUT={dut}")
    st.config(dut, 'sonic-clear priority-group watermark shared', skip_tmpl=True, trace_log=1)
    st.wait(1)


def get_priority_group_watermark(dut, port):
    """
    Get priority group watermark shared for a specific port.
    
    Args:
        dut: DUT handle
        port: Interface name (e.g., 'Ethernet292')
        
    Returns:
        Priority group watermark output string
    """
    cmd = f"show priority-group watermark shared | grep -A 10 '{port}'"
    st.log(f"Getting priority group watermark: DUT={dut}, port={port}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Priority group watermark output for {port}:\n{output}")
        return output
    except Exception as e:
        st.log(f"Error getting priority group watermark: {e}")
        return None


def parse_queue_watermark(raw_output, interface=None):
    """
    Parse queue watermark CLI output to extract UC0 and UC1 values.
    
    Supports two formats:
    1. Grep output (no header): Ethernet292  88089600  14688768  0  0  0  0  0  512
       Columns: Interface UC0 UC1 UC2 UC3 UC4 UC5 UC6 UC7
       
    2. Full output with header:
       Egress shared pool occupancy per unicast queue:
              Port        UC0      UC1    UC2    UC3    UC4    UC5    UC6    UC7
       -----------  ---------  -------  -----  -----  -----  -----  -----  -----
         Ethernet0          0        0      0      0      0      0      0      0
    
    Args:
        raw_output: Raw CLI output string from 'show queue watermark unicast'
        interface: Optional interface name to find in the output
        
    Returns:
        dict with UC0 and UC1 values, e.g. {'UC0': '12345', 'UC1': '67890'}
    """
    if not raw_output or not isinstance(raw_output, str):
        return {'UC0': 'N/A', 'UC1': 'N/A'}
    
    result = {'UC0': 'N/A', 'UC1': 'N/A'}
    
    try:
        lines = raw_output.strip().split('\n')
        
        # First, try to find a line starting with "Ethernet" (grep output format)
        # Format: Ethernet292  88089600  14688768  0  0  0  0  0  512
        # Columns: Interface UC0 UC1 UC2 UC3 UC4 UC5 UC6 UC7
        for line in lines:
            line = line.strip()
            if line.startswith('Ethernet'):
                parts = line.split()
                if len(parts) >= 3:
                    # If interface specified, match it; otherwise use first Ethernet line
                    if interface is None or parts[0] == interface:
                        result['UC0'] = parts[1]
                        result['UC1'] = parts[2]
                        return result
        
        # If no Ethernet line found, try the header-based format
        # Find the header line with UC0, UC1, etc.
        header_idx = -1
        for i, line in enumerate(lines):
            if 'UC0' in line and 'UC1' in line:
                header_idx = i
                break
        
        if header_idx == -1:
            return result
        
        # Parse header to get column positions
        header_line = lines[header_idx]
        
        # Find the data line (usually 2 lines after header - skip the dashes)
        data_idx = header_idx + 2
        if data_idx >= len(lines):
            return result
        
        data_line = lines[data_idx]
        
        # Split both lines by whitespace and extract values
        header_parts = header_line.split()
        data_parts = data_line.split()
        
        # Find UC0 and UC1 positions in header
        for i, part in enumerate(header_parts):
            if part == 'UC0' and i < len(data_parts):
                result['UC0'] = data_parts[i]
            elif part == 'UC1' and i < len(data_parts):
                result['UC1'] = data_parts[i]
        
        # Handle case where data line starts with "Mem:" or similar label
        if data_parts and data_parts[0].endswith(':'):
            # Shift indices by 1
            for i, part in enumerate(header_parts):
                if part == 'UC0' and (i + 1) < len(data_parts):
                    result['UC0'] = data_parts[i + 1]
                elif part == 'UC1' and (i + 1) < len(data_parts):
                    result['UC1'] = data_parts[i + 1]
                    
    except Exception as e:
        st.log(f"Error parsing queue watermark: {e}")
    
    return result


def parse_buffer_pool_watermark(raw_output):
    """
    Parse buffer pool watermark CLI output to extract pool names and bytes.
    
    The CLI output format is typically:
    Shared pool maximum occupancy:
                Pool      Bytes
    --------------------  --------
    ingress_lossless_pool  1234567
    egress_lossless_pool   2345678
    egress_lossy_pool      3456789
    
    Args:
        raw_output: Raw CLI output string from 'show buffer_pool watermark'
        
    Returns:
        dict with pool names and bytes, e.g. {'ing_lossless': '1234567', 'egr_lossless': '2345678', 'egr_lossy': '3456789'}
    """
    if not raw_output or not isinstance(raw_output, str):
        return {}
    
    result = {}
    
    try:
        lines = raw_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            # Skip header lines and dashes
            if not line or line.startswith('-') or 'Pool' in line or 'occupancy' in line.lower():
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                pool_name = parts[0]
                bytes_val = parts[-1]  # Last value is typically the bytes
                
                # Shorten pool names for display
                if 'ingress_lossless' in pool_name:
                    result['ing_lossless'] = bytes_val
                elif 'egress_lossless' in pool_name:
                    result['egr_lossless'] = bytes_val
                elif 'egress_lossy' in pool_name:
                    result['egr_lossy'] = bytes_val
                else:
                    # Use shortened name
                    short_name = pool_name[:15] if len(pool_name) > 15 else pool_name
                    result[short_name] = bytes_val
                    
    except Exception as e:
        st.log(f"Error parsing buffer pool watermark: {e}")
    
    return result


# only sonic commands to be used across all platforms
def clear_all_counters(dut, wait_time=3):
    """
    Clear all QoS-related counters and watermarks on a DUT
    
    - Interface counters (sonic-clear counters)
    - Queue counters (sonic-clear queuecounters)
    - PFC counters (sonic-clear pfccounters)
    - Queue watermark unicast (sonic-clear queue watermark unicast)
    - Priority group watermark shared (sonic-clear priority-group watermark shared)
    - Buffer pool watermark (watermarkstat -t buffer_pool -c)
    - Drop counters
    - likely to fail: WRED counters (sonic-clear queue wredcounters)
    - NO: oq-debug and npu counters
    
    Args:
        dut: DUT handle
        wait_time: Seconds to wait after clearing all counters (default: 2)
    """
    st.log("="*60)
    st.log(f"CLEARING ALL COUNTERS AND WATERMARKS ON DUT={dut}")
    st.log("="*60)
    
    st.log("Clearing interface counters...")
    st.config(dut, 'sonic-clear counters', skip_tmpl=True, trace_log=1)
    
    st.log("Clearing queue counters...")
    st.config(dut, 'sonic-clear queuecounters', skip_tmpl=True, trace_log=1)
    
    st.log("Clearing PFC counters...")
    st.config(dut, 'sonic-clear pfccounters', skip_tmpl=True, trace_log=1)
    
    st.log("Clearing queue watermark unicast...")
    st.config(dut, 'sonic-clear queue watermark unicast', skip_tmpl=True, trace_log=1)
    
    st.log("Clearing priority-group watermark shared...")
    st.config(dut, 'sonic-clear priority-group watermark shared', skip_tmpl=True, trace_log=1)

    st.log("Clearing priority-group drop counters...")
    st.config(dut, 'sonic-clear priority-group drop counters', skip_tmpl=True, skip_error_check=True, trace_log=1)
    
    st.log("Clearing buffer pool watermark...")
    st.config(dut, 'watermarkstat -t buffer_pool -c', skip_tmpl=True, trace_log=1)

    st.log("Clearing dropcounters ...")
    st.config(dut, 'sonic-clear dropcounters', skip_tmpl=True, trace_log=1)
   
    st.log("Clearing queue ECN/WRED counters...")
    st.config(dut, 'sonic-clear queue wredcounters', skip_tmpl=True, skip_error_check=True, trace_log=1)
    
    #st.log("Clearing npu counters ...")
    #get_npu_counters(dut)

    #st.log("Clearing oq-debug counters ...")
    #get_npu_oq_debug(dut)

    st.wait(wait_time, "Waiting for counters to clear")
    st.log(f"All counters cleared on DUT={dut}")


# =============================================================================
# PFC Counter Utilities
# =============================================================================

def get_pfc_tx_count(dut, port, priority):
    """
    Get PFC Tx frame count for given port and priority.
    
    Args:
        dut: DUT handle
        port: Interface name (e.g., 'Ethernet16')
        priority: Priority/TC value (0-7)
        
    Returns:
        Integer count of PFC frames transmitted
    """
    priority = int(priority)  # Ensure priority is an integer
    cmd = f"show pfc counters | sed -n '/Port Tx/,/^$/p' | grep {port}"
    st.log(f"Reading PFC Tx counters: DUT={dut}, port={port}, priority={priority}")
    st.log(f"Command: {cmd}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Raw PFC Tx output: {output}")
        # Output can be a string or list; normalize to get the line with port data
        if isinstance(output, list):
            # Find the line containing the port name
            line = next((l for l in output if port in l), None)
        else:
            # String output - find the line with port name
            lines = output.strip().split('\n')
            line = next((l for l in lines if port in l), None)
        
        if line:
            parts = line.split()
            st.log(f"Parsed parts: {parts}")
            # Format: PortName  PFC0  PFC1  PFC2  PFC3  PFC4  PFC5  PFC6  PFC7
            if len(parts) > priority + 1:
                count = int(parts[priority + 1].replace(',', ''))
                st.log(f"PFC Tx count for port={port}, priority={priority}: {count}")
                return count
    except Exception as e:
        st.log(f"Error reading PFC Tx counters: {e}")
    st.log(f"PFC Tx count for port={port}, priority={priority}: 0 (default)")
    return 0


def get_pfc_rx_count(dut, port, priority):
    """
    Get PFC Rx frame count for given port and priority.
    
    Args:
        dut: DUT handle
        port: Interface name
        priority: Priority/TC value (0-7)
        
    Returns:
        Integer count of PFC frames received
    """
    priority = int(priority)  # Ensure priority is an integer
    cmd = f"show pfc counters | sed -n '/Port Rx/,/^$/p' | grep {port}"
    st.log(f"Reading PFC Rx counters: DUT={dut}, port={port}, priority={priority}")
    st.log(f"Command: {cmd}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Raw PFC Rx output: {output}")
        # Output can be a string or list; normalize to get the line with port data
        if isinstance(output, list):
            # Find the line containing the port name
            line = next((l for l in output if port in l), None)
        else:
            # String output - find the line with port name
            lines = output.strip().split('\n')
            line = next((l for l in lines if port in l), None)
        
        if line:
            parts = line.split()
            st.log(f"Parsed parts: {parts}")
            # Format: PortName  PFC0  PFC1  PFC2  PFC3  PFC4  PFC5  PFC6  PFC7
            if len(parts) > priority + 1:
                count = int(parts[priority + 1].replace(',', ''))
                st.log(f"PFC Rx count for port={port}, priority={priority}: {count}")
                return count
    except Exception as e:
        st.log(f"Error reading PFC Rx counters: {e}")
    st.log(f"PFC Rx count for port={port}, priority={priority}: 0 (default)")
    return 0


def get_pfc_counters(dut):
    """
    Get the full PFC counters output for a DUT.
    
    Args:
        dut: DUT handle
        
    Returns:
        PFC counters output string
    """
    cmd = "show pfc counters"
    st.log(f"Getting PFC counters: DUT={dut}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"PFC counters output:\n{output}")
        return output
    except Exception as e:
        st.log(f"Error getting PFC counters: {e}")
        return None


# =============================================================================
# Traffic Statistics Utilities
# =============================================================================

def calculate_loss_percent(tx_pkts, rx_pkts):
    """
    Calculate packet loss percentage.
    
    Args:
        tx_pkts: Number of transmitted packets
        rx_pkts: Number of received packets
        
    Returns:
        Loss percentage as float
    """
    if tx_pkts == 0:
        return 0.0
    return 100.0 * (tx_pkts - rx_pkts) / tx_pkts


def get_pfc_tx_counters_all_tc(dut, port):
    """
    Get PFC Tx counters for all Traffic Classes (0-7) on a port.
    
    Args:
        dut: DUT handle
        port: Interface name (e.g., 'Ethernet1_1')
        
    Returns:
        Dictionary mapping TC (int) -> PFC Tx count (int)
        e.g., {0: 100, 1: 0, 2: 50, 3: 0, 4: 0, 5: 0, 6: 0, 7: 200}
    """
    # Use awk to match exact port name (as first field) in Port Tx section
    cmd = f"show pfc counters | awk '/Port Tx/,/^$/{{if($1==\"{port}\")print}}'"
    st.log(f"Reading PFC Tx counters for all TCs: DUT={dut}, port={port}")
    st.log(f"Command: {cmd}")
    
    result = {tc: 0 for tc in range(8)}  # Initialize all TCs to 0
    
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Raw PFC Tx output: {output}")
        
        # Output can be a string or list; normalize to get the line with port data
        if isinstance(output, list):
            line = next((l for l in output if l.split() and l.split()[0] == port), None)
        else:
            lines = output.strip().split('\n')
            line = next((l for l in lines if l.split() and l.split()[0] == port), None)
        
        if line:
            parts = line.split()
            st.log(f"Parsed parts: {parts}")
            # Format: PortName  PFC0  PFC1  PFC2  PFC3  PFC4  PFC5  PFC6  PFC7
            for tc in range(8):
                if len(parts) > tc + 1:
                    result[tc] = int(parts[tc + 1].replace(',', ''))
    except Exception as e:
        st.log(f"Error reading PFC Tx counters: {e}")
    
    st.log(f"PFC Tx counters for port={port}: {result}")
    return result


def print_pfc_tx_counter_deltas(before, after):
    """
    Print non-zero deltas between two sets of PFC Tx counters.
    
    Args:
        before: Dictionary mapping TC (int) -> PFC Tx count (int) - baseline counters
        after: Dictionary mapping TC (int) -> PFC Tx count (int) - counters after traffic
        
    Returns:
        Dictionary of non-zero deltas mapping TC (int) -> delta (int)
    """
    st.log("Calculating PFC Tx counter deltas...")
    
    non_zero_deltas = {}
    
    for tc in range(8):
        before_count = before.get(tc, 0)
        after_count = after.get(tc, 0)
        delta = after_count - before_count
        
        if delta != 0:
            non_zero_deltas[tc] = delta
            st.log(f"  TC{tc}: delta={delta} (after={after_count} - before={before_count})")
    
    if non_zero_deltas:
        st.log(f"Non-zero PFC Tx deltas: {non_zero_deltas}")
    else:
        st.log("No non-zero PFC Tx deltas detected")
    
    return non_zero_deltas
    
def get_stream_loss_percent(stats, stream_handle):
    """
    Extract loss percentage for a specific stream from stats.
    
    Args:
        stats: Statistics dictionary from get_stream_stats()
        stream_handle: Stream handle returned by create_stream()
        
    Returns:
        Tuple of (tx_pkts, rx_pkts, loss_percent)
    """
    st.log(f"Extracting stats for stream handle: {stream_handle}")
    stream_stats = stats.get(stream_handle, {})
    st.log(f"Raw stream stats for {stream_handle}:\n{json.dumps(stream_stats, indent=2)}")
    tx_pkts = int(stream_stats.get('tx', {}).get('total_pkts', 0))
    rx_pkts = int(stream_stats.get('rx', {}).get('total_pkts', 0))
    loss_pct = calculate_loss_percent(tx_pkts, rx_pkts)
    st.log(f"Stream {stream_handle}: tx_pkts={tx_pkts}, rx_pkts={rx_pkts}, loss_pct={loss_pct:.4f}%")
    return tx_pkts, rx_pkts, loss_pct


# =============================================================================
# Additional Debug Utilities
# =============================================================================

def get_mac_table(dut):
    """
    Get MAC address table (FDB) from a DUT.
    
    Args:
        dut: DUT handle
        
    Returns:
        MAC table output string
    """
    cmd = "show mac"
    st.log(f"Getting MAC table: DUT={dut}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"MAC table on {dut}:\n{output}")
        return output
    except Exception as e:
        st.log(f"Error getting MAC table: {e}")
        return None


def get_interface_link_status(dut, interfaces=None):
    """
    Get interface link status from a DUT.
    
    Args:
        dut: DUT handle
        interfaces: Optional list of interfaces to check
        
    Returns:
        Interface status output string
    """
    cmd = "show interfaces status"
    st.log(f"Getting interface status: DUT={dut}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        if interfaces:
            # Filter output to show only requested interfaces
            lines = output.split('\n')
            filtered = [l for l in lines if any(iface in l for iface in interfaces) or 'Interface' in l or '---' in l]
            output = '\n'.join(filtered)
        st.log(f"Interface status on {dut}:\n{output}")
        return output
    except Exception as e:
        st.log(f"Error getting interface status: {e}")
        return None


def collect_pre_traffic_debug(api, iteration_info=""):
    """
    Collect comprehensive debug information before starting traffic.
    
    This function collects:
    - Interface link status on leaves
    - MAC table on leaves
    - BGP summary on leaves
    - IPv6 routes on leaves
    - TGEN port statistics (via api.get_port_stats())
    - TGEN protocol session status (via api.get_protocol_session_status())
    
    Args:
        api: IxiaIPv6Api instance with dut_d mapping
        iteration_info: Optional string describing the iteration (e.g., "Q0=0, Q1=-2")
    """
    st.banner(f"PRE-TRAFFIC DEBUG COLLECTION {iteration_info}")
    
    # Get leaf DUTs
    leaf_devices = {
        'D3': ('Leaf0', ['Ethernet292', 'Ethernet296']),  # L1P1, L1P2
        'D4': ('Leaf1', ['Ethernet292', 'Ethernet300']),  # L2P1, L2P2
    }
    
    for device_id, (role, interfaces) in leaf_devices.items():
        dut = api.dut_d.get(device_id)
        if not dut:
            st.log(f"Device {device_id} ({role}) not found, skipping")
            continue
        
        st.log(f"{'='*60}")
        st.log(f"DEBUG: {device_id} ({role})")
        st.log(f"{'='*60}")
        
        # Interface link status
        st.log(f"--- {device_id}: Interface Link Status ---")
        get_interface_link_status(dut, interfaces)
        
        # MAC table
        st.log(f"--- {device_id}: MAC Table (FDB) ---")
        get_mac_table(dut)
        
        # BGP summary
        st.log(f"--- {device_id}: BGP IPv6 Summary ---")
        get_ipv6_bgp_summary(dut)
        
        # IPv6 routes (brief - just show key routes)
        st.log(f"--- {device_id}: IPv6 Routes ---")
        st.show(dut, "show ipv6 route summary", skip_tmpl=True)
    
    # Note: TGEN traffic_stats calls are intentionally omitted here.
    # Calling tg_traffic_stats before traffic is started/applied causes
    # a fatal TGenFail abort in IxNetwork ("matched_str" / "unapplied" errors).
    
    st.log(f"{'='*60}")
    st.log("PRE-TRAFFIC DEBUG COLLECTION COMPLETE")
    st.log(f"{'='*60}")


def wait_for_bgp_underlay_established(nodes, max_wait=180):
    """
    Wait for BGP sessions to establish between leaves.

    Polls 'show ipv6 bgp summary' on leaves until OVERLAY neighbors
    show Established state.

    Args:
        nodes: Dict mapping node names to DUT objects
        max_wait: Maximum seconds to wait (default 180)

    Returns:
        bool: True if sessions established, False if timeout
    """
    start_time = time.time()
    poll_interval = 10

    st.log(f"Waiting for BGP sessions to establish (max {max_wait}s)...")

    while time.time() - start_time < max_wait:
        # Check both leaves
        all_established = True

        for leaf in ['leaf0', 'leaf1']:
            if leaf not in nodes:
                continue
            # Use 'show ipv6 bgp summary' for IPv6 underlay
            output = st.show(nodes[leaf], "show ipv6 bgp summary", skip_tmpl=True, skip_error_check=True)
            st.log(f"{leaf} BGP summary: {output[:500] if output else 'empty'}...")

            # Check for NOT established states - FRR shows prefix count when established
            # NOT established states: Connect, Active, Idle, OpenSent, OpenConfirm
            # Established: shows numeric prefix count like "1", "2", "7" etc.
            not_established_states = ['Connect', 'Active', 'Idle', 'OpenSent', 'OpenConfirm', 'NoNeg']
            if output and not any(state in output for state in not_established_states):
                # Also verify there's at least one neighbor with data
                if 'Total number of neighbors' in output and 'neighbors 0' not in output:
                    st.log(f"{leaf}: BGP sessions established")
                else:
                    all_established = False
            else:
                all_established = False

        if all_established:
            elapsed = time.time() - start_time
            st.log(f"BGP sessions established after {elapsed:.1f}s")
            st.wait(5)
            return True

        #st.log(f"BGP EVPN not yet established, waiting {poll_interval}s...")
        st.log(f"BGP underlay is not yet established, waiting {poll_interval}s...")
        st.wait(poll_interval)

    st.log(f"BGP underlay sessions did not establish within {max_wait}s")
    # Dump debug info on failure
    dump_vxlan_debug_info(nodes, "BGP underlay establishment timeout")
    return False


def discover_ecn_queue_config(dut, egress_intf):
    """
    Walk CONFIG_DB to discover ECN/WRED configuration for *egress_intf*.

    Lookup chain:
        PORT_QOS_MAP[egress_intf].pfc_enable -> first lossless TC
        DSCP_TO_TC_MAP -> first DSCP that maps to that TC
        TC_TO_QUEUE_MAP -> queue number
        QUEUE[intf|queue].wred_profile -> WRED_PROFILE.ecn

    Returns:
        dict with keys: tc, dscp, queue, wred_profile, port_speed
    Raises RuntimeError on misconfiguration.
    """
    config = get_config_db(dut)

    # --- lossless TC ---
    port_qos = config["PORT_QOS_MAP"].get(egress_intf)
    if not port_qos:
        raise RuntimeError(f"PORT_QOS_MAP has no entry for {egress_intf}")
    pfc_enable = port_qos.get("pfc_enable", "")
    tc_list = [int(x) for x in pfc_enable.split(",") if x.strip()]
    if not tc_list:
        raise RuntimeError(f"No PFC-enabled TCs on {egress_intf}")
    tc = tc_list[0]
    st.log(f"discover: egress_intf={egress_intf} pfc_enable={pfc_enable} -> TC {tc}")

    # --- DSCP ---
    dscp_map_ref = port_qos.get("dscp_to_tc_map")
    if not dscp_map_ref:
        raise RuntimeError(f"PORT_QOS_MAP[{egress_intf}] missing dscp_to_tc_map")
    map_name = dscp_map_ref.split("|")[-1].rstrip("]") if "|" in dscp_map_ref else dscp_map_ref
    dscp_table = config["DSCP_TO_TC_MAP"].get(map_name, {})
    dscp = None
    tc_str = str(tc)
    for dscp_val, mapped_tc in dscp_table.items():
        if str(mapped_tc) == tc_str:
            dscp = int(dscp_val)
            break
    if dscp is None:
        raise RuntimeError(f"No DSCP maps to TC {tc} in DSCP_TO_TC_MAP[{map_name}]")
    st.log(f"discover: DSCP_TO_TC_MAP[{map_name}] -> DSCP {dscp} for TC {tc}")

    # --- Queue ---
    tc_q_map_ref = port_qos.get("tc_to_queue_map")
    if not tc_q_map_ref:
        raise RuntimeError(f"PORT_QOS_MAP[{egress_intf}] missing tc_to_queue_map")
    q_map_name = tc_q_map_ref.split("|")[-1].rstrip("]") if "|" in tc_q_map_ref else tc_q_map_ref
    q_table = config["TC_TO_QUEUE_MAP"].get(q_map_name, {})
    queue = q_table.get(tc_str)
    if queue is None:
        raise RuntimeError(f"TC_TO_QUEUE_MAP[{q_map_name}] has no entry for TC {tc}")
    queue = int(queue)
    st.log(f"discover: TC_TO_QUEUE_MAP[{q_map_name}] -> queue {queue}")

    # --- WRED profile ---
    queue_key = f"{egress_intf}|{queue}"
    queue_entry = config["QUEUE"].get(queue_key, {})
    wred_profile_ref = queue_entry.get("wred_profile")
    if not wred_profile_ref:
        raise RuntimeError(f"QUEUE[{queue_key}] has no wred_profile")
    profile_name = wred_profile_ref.split("|")[-1].rstrip("]") if "|" in wred_profile_ref else wred_profile_ref
    profile = config["WRED_PROFILE"].get(profile_name, {})
    ecn_mode = profile.get("ecn", "ecn_none")
    if ecn_mode == "ecn_none":
        raise RuntimeError(f"WRED_PROFILE[{profile_name}].ecn is '{ecn_mode}'  --  ECN not enabled")
    st.log(f"discover: WRED_PROFILE[{profile_name}] ecn={ecn_mode}")

    speed = get_if_speed(dut, egress_intf)

    result = {
        'tc': tc,
        'dscp': dscp,
        'queue': queue,
        'wred_profile': profile_name,
        'port_speed': speed,
    }
    st.banner(f"ECN Queue Config Discovery: {result}")
    return result


def discover_lossy_wred_queue_config(dut, egress_intf):
    """
    Walk CONFIG_DB to discover a lossy queue with WRED drop (ecn=ecn_none)
    on *egress_intf*.

    Lookup chain:
        PORT_QOS_MAP[egress_intf].pfc_enable -> set of lossless TCs to avoid
        QUEUE[egress_intf|*] -> find entries with wred_profile
        WRED_PROFILE[name].ecn == 'ecn_none' -> pure WRED drop profile
        TC_TO_QUEUE_MAP -> reverse-map queue number to TC
        DSCP_TO_TC_MAP -> first DSCP that maps to that TC

    Returns:
        dict with keys: tc, dscp, queue, wred_profile, port_speed
    Raises RuntimeError on misconfiguration.
    """
    config = get_config_db(dut)

    # --- lossless TCs to avoid ---
    port_qos = config["PORT_QOS_MAP"].get(egress_intf)
    if not port_qos:
        raise RuntimeError(f"PORT_QOS_MAP has no entry for {egress_intf}")
    pfc_enable = port_qos.get("pfc_enable", "")
    lossless_tcs = set(int(x) for x in pfc_enable.split(",") if x.strip())
    st.log(f"discover: egress_intf={egress_intf} lossless TCs={lossless_tcs}")

    # --- TC_TO_QUEUE_MAP (for reverse lookup) ---
    tc_q_map_ref = port_qos.get("tc_to_queue_map")
    if not tc_q_map_ref:
        raise RuntimeError(f"PORT_QOS_MAP[{egress_intf}] missing tc_to_queue_map")
    q_map_name = tc_q_map_ref.split("|")[-1].rstrip("]") if "|" in tc_q_map_ref else tc_q_map_ref
    tc_to_q = config["TC_TO_QUEUE_MAP"].get(q_map_name, {})

    # Build reverse map: queue_number -> TC
    q_to_tc = {}
    for tc_str, q_str in tc_to_q.items():
        q_to_tc[int(q_str)] = int(tc_str)

    # --- Walk QUEUE entries for egress_intf, find lossy + WRED ---
    queue_table = config["QUEUE"]
    found_queue = None
    found_profile_name = None

    for queue_key, queue_entry in queue_table.items():
        if not queue_key.startswith(f"{egress_intf}|"):
            continue
        wred_ref = queue_entry.get("wred_profile")
        if not wred_ref:
            continue

        queue_num = int(queue_key.split("|")[1])
        profile_name = wred_ref.split("|")[-1].rstrip("]") if "|" in wred_ref else wred_ref
        profile = config["WRED_PROFILE"].get(profile_name, {})
        ecn_mode = profile.get("ecn", "ecn_none")

        # We want ecn_none (pure WRED drop) on a lossy (non-PFC) queue
        if ecn_mode != "ecn_none":
            st.log(f"  skip queue {queue_num}: profile={profile_name} ecn={ecn_mode} (not lossy drop)")
            continue

        tc_for_queue = q_to_tc.get(queue_num)
        if tc_for_queue is None:
            st.log(f"  skip queue {queue_num}: no TC mapping found")
            continue

        if tc_for_queue in lossless_tcs:
            st.log(f"  skip queue {queue_num}: TC {tc_for_queue} is lossless (PFC-enabled)")
            continue

        found_queue = queue_num
        found_profile_name = profile_name
        st.log(f"  found lossy WRED queue {queue_num}: TC={tc_for_queue} profile={profile_name}")
        break

    if found_queue is None:
        st.log(f"No lossy queue with WRED drop profile found on {egress_intf} "
               f"(queues use tail-drop). Returning None.")
        return None

    tc = q_to_tc[found_queue]

    # --- DSCP for this TC ---
    dscp_map_ref = port_qos.get("dscp_to_tc_map")
    if not dscp_map_ref:
        raise RuntimeError(f"PORT_QOS_MAP[{egress_intf}] missing dscp_to_tc_map")
    map_name = dscp_map_ref.split("|")[-1].rstrip("]") if "|" in dscp_map_ref else dscp_map_ref
    dscp_table = config["DSCP_TO_TC_MAP"].get(map_name, {})
    dscp = None
    tc_str = str(tc)
    for dscp_val, mapped_tc in dscp_table.items():
        if str(mapped_tc) == tc_str:
            dscp = int(dscp_val)
            break
    if dscp is None:
        raise RuntimeError(f"No DSCP maps to TC {tc} in DSCP_TO_TC_MAP[{map_name}]")
    st.log(f"discover: DSCP_TO_TC_MAP[{map_name}] -> DSCP {dscp} for TC {tc}")

    speed = get_if_speed(dut, egress_intf)

    result = {
        'tc': tc,
        'dscp': dscp,
        'queue': found_queue,
        'wred_profile': found_profile_name,
        'port_speed': speed,
    }
    st.banner(f"Lossy WRED Queue Config Discovery: {result}")
    return result
    

_qos_reloaded = set()

def perform_qos_reload(dut, force=False):
    # We keep track of which DUTs have already undergone a qos reload.
    # However if function is invoked with force option, we will disregard
    # a prior qos reload
    if dut in _qos_reloaded and not force:
        st.log(f"QoS already reloaded on {dut}, skipping")
        return
    if find_platform_str(dut) == 'gamut':
        st.config(dut,
          'redis-cli -n 4 hset "DEVICE_METADATA|localhost" cfg_profile hyperfabric',
          skip_tmpl=True, skip_error_check=True)
        st.config(dut,
          'config qos clear',
          skip_tmpl=True, skip_error_check=True)
        st.wait(10)
        st.config(dut,
          'config qos reload --no-dynamic-buffer',
          skip_tmpl=True, skip_error_check=True)
        st.wait(30)
    else:
        st.config(dut, 'config qos reload', skip_error_check=True)
    if not force:
        _qos_reloaded.add(dut)

def validate_value(actual, expected, tolerance_percent):
    """Check if actual is within tolerance_percent of expected."""
    if expected == 0:
        return actual <= tolerance_percent
    delta = abs(actual - expected) * 100.0 / expected
    return delta <= tolerance_percent

def show_cmd_to_dict(dut, cmd, add_j=True):
    """
    Helper to run a show command and parse its JSON output.
    Returns parsed dictionary or None if output is malformed.
    """
    if add_j:
        out_str = st.show(dut, 'show ' + cmd + ' -j', skip_tmpl=True)
    else:
        out_str = st.show(dut, 'show ' + cmd, skip_tmpl=True)
    idx = out_str.rfind('}')
    if idx == -1:
        st.error("show cmd {} returned malformed string {}".format(cmd, out_str))
        return None

    # This is to handle cli inconsistency. 'config scheduler' expects 
    # meter-type but 'show schedule -j' returns meter_type
    out_str = out_str[:idx + 1].replace('meter_type', 'meter-type')
    return json.loads(out_str)

def get_if_mac(dut, if_name):
    mac_str = st.config(dut,\
                  "ifconfig {} | grep ether | awk '{{print $2}}'".format(if_name),\
                  skip_tmpl = True)

    i = 0
    ctr = 0
    for c in mac_str:
        if c == ':':
            ctr += 1
            if ctr == 5:
                return mac_str[:i + 3]
        i += 1
    return None

# json2 is a json file with optional comment lines starting with hash
# The function will strip the comment lines and return a dictionary
def json2_file_to_dict(json2_file, ordered):
    result = ''
    with open(json2_file, 'r') as file_obj:
        for line in file_obj:
            temp = line.lstrip()
            # skip lines with leading hash
            if temp.startswith('#'):
                continue
            result += line
        return json.loads(result, object_pairs_hook=OrderedDict) if ordered \
               else json.loads(result)
    return None

def find_platform_str(dut):
    '''
    Get the platform string and map it to a name like siren
    '''
    platform_dict = {'x86_64-hf6100_32d-r0' : 'carib',
                    'x86_64-hf6100_60l4d-r0' : 'siren',
                    'x86_64-hf6100_64ed-r0' : 'laguna',
                    'x86_64-n9164e_ns4_o-r0' : 'gamut'}

    result = st.show(dut,
                 "show platform summary | grep Platform: | awk '{print $2}'",
                 skip_tmpl=True)
    # Make sure we trim any linefeed or trailing content
    platform_str = result.split('\n')[0]
    return platform_dict.get(platform_str, None)

def is_q200(plat_str):
    return plat_str == 'carib' or plat_str == 'siren'

def is_g200(plat_str):
    return plat_str == 'laguna'

def is_gamut(plat_str):
    return plat_str == 'gamut'

def get_qos_test_dict(fname, key, ordered=False):
    input_file = os.path.join(os.path.dirname(__file__), fname)
    if not os.path.exists(input_file):
        return None
    input_dict = json2_file_to_dict(input_file, ordered)
    if input_dict != None and key in input_dict:
        return input_dict[key]
    return None

