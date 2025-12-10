import logging
import pytest


logger = logging.getLogger(__name__)


def _read_appl_db_field(duthost, key, field):
    try:
        cmd = f"redis-cli -n 0 hget '{key}' '{field}'"
        res = duthost.shell(cmd, module_ignore_errors=True)
        return (res.get('stdout') or '').strip()
    except Exception as e:
        logger.debug(f"Failed to read APP_DB field {key}.{field}: {str(e)}")
        return ''


def _should_use_pipe_for_dscp(duthost):
    # Prefer the live default from APP_DB if present
    dscp_mode = _read_appl_db_field(duthost, 'TUNNEL_DECAP_TABLE:IPINIP_TUNNEL', 'dscp_mode')
    if dscp_mode in ('pipe', 'uniform'):
        return dscp_mode == 'pipe'

    asic_type = (duthost.facts.get('asic_type') or '').lower()
    os_version = duthost.os_version if hasattr(duthost, 'os_version') else ''

    if asic_type in ('mellanox', 'innovium'):
        return True
    if asic_type == 'broadcom':
        return '201911' in os_version
    # Default to uniform for others unless explicitly detected as pipe
    return False


def _get_default_ttl_mode(duthost):
    ttl_mode = _read_appl_db_field(duthost, 'TUNNEL_DECAP_TABLE:IPINIP_TUNNEL', 'ttl_mode')
    return ttl_mode if ttl_mode in ('pipe', 'uniform') else 'pipe'


@pytest.fixture(scope='module')
def supported_ttl_dscp_params(rand_selected_dut):
    """
    Determine supported TTL/DSCP modes based on DUT ASIC/platform defaults and
    pass a single configuration downstream.

    - DSCP mode: prefer live APP_DB value; fallback by ASIC heuristics.
    - TTL mode: prefer live APP_DB value; fallback to 'pipe'.
    - VXLAN: default to 'disable' (no set/unset sequence) for decap tests.
    """
    duthost = rand_selected_dut
    use_pipe_for_dscp = _should_use_pipe_for_dscp(duthost)
    ttl_mode = _get_default_ttl_mode(duthost)

    params = {
        'ttl': ttl_mode,
        'dscp': 'pipe' if use_pipe_for_dscp else 'uniform',
        'vxlan': 'disable',
    }
    logger.info(f"supported_ttl_dscp_params resolved to {params}")
    return params
