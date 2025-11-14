import os


def load_lossless_info_from_pg_profile_lookup(duthost, dut_asic):
    """
    Load pg_profile_lookup.ini into a dictionary of default lossless profiles.

    Args:
        duthost: the DUT host object
        dut_asic: the ASIC instance

    Returns:
        dict: mapping (speed, cable_length) -> profile_info
    """
    threshold_mode = dut_asic.run_redis_cmd(
        argv=['redis-cli', '-n', 4, 'hget', 'BUFFER_POOL|ingress_lossless_pool', 'mode']
    )[0]
    threshold_field_name = 'dynamic_th' if threshold_mode == 'dynamic' else 'static_th'

    dut_hwsku = duthost.facts["hwsku"]
    dut_platform = duthost.facts["platform"]
    skudir = f"/usr/share/sonic/device/{dut_platform}/{dut_hwsku}/"
    if dut_asic.namespace is not None:
        skudir = skudir + dut_asic.namespace.split('asic')[-1] + '/'

    pg_profile_lookup_file = os.path.join(skudir, 'pg_profile_lookup.ini')
    duthost.file(path=pg_profile_lookup_file, state="file")
    lines = duthost.shell(f'cat {pg_profile_lookup_file}')["stdout_lines"]

    profiles = {}
    for line in lines:
        if line.startswith('#'):
            continue
        tokens = line.split()
        speed, cable_length, size, xon, xoff, threshold = tokens[:6]
        profile_info = {
            'pool': '[BUFFER_POOL|ingress_lossless_pool]',
            'size': size,
            'xon': xon,
            'xoff': xoff,
            threshold_field_name: threshold
        }
        if len(tokens) > 6:
            profile_info['xon_offset'] = tokens[6]
        profiles[(speed, cable_length)] = profile_info

    return profiles
