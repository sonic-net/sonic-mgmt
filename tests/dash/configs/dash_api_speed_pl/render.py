#!/usr/bin/env python3
# Jinja2 generator for DASH Private-Link config (same JSON as dpugen/dash.py). CLI: python render.py [-o out] [-p params]; templates in templates/.

import argparse
import hashlib
import ipaddress
import os
import socket
import struct
import sys
import uuid
from multiprocessing import Pool, cpu_count

from jinja2 import Environment, FileSystemLoader


# ============================================================================
#  Default parameters  (mirrors dpugen/dflt_params.py)
# ============================================================================
DEFAULTS = {
    'LOOPBACK':          '221.0.0.1',
    'PAL':               '221.1.0.0',
    'PAR':               '221.2.0.0',
    'GATEWAY':           '222.0.0.1',
    'DPUS':               8,
    'VM_VNI':             1000,
    'ENI_START':          1000,
    'ENI_COUNT':          256,
    'ENI_STEP':           1,
    'ENI_L2R_STEP':       1000,
    'ACL_NSG_COUNT':      5,
    'ACL_RULES_NSG':      12800,
    'IP_PER_ACL_RULE':    1,
    'ACL_MAPPED_PER_NSG': 12800,
    'MAC_L_START':        '00:1A:C5:00:00:01',
    'MAC_R_START':        '00:1B:6E:00:00:01',
    'MAC_STEP_ENI':       '00:00:00:18:00:00',
    'IP_L_START':         '1.1.0.1',
    'IP_R_START':         '1.4.0.1',
    'IP_STEP1':           '0.0.0.1',
    'IP_STEP_ENI':        '0.64.0.0',
    'IP_STEP_NSG':        '0.2.0.0',
    'TOTAL_OUTBOUND_ROUTES': 128000,
    # Minimal mode: 1 outbound route + MINIMAL_MAPPINGS VNet mappings per ENI (vs full scale).
    'MINIMAL_SINGLE_ENTRY': False,
    'MINIMAL_MAPPINGS': 1,
}


# ============================================================================
#  Conversion helpers
# ============================================================================
def ip2int(s):
    # IPv4 string -> 32-bit integer.
    return int(ipaddress.ip_address(s))


def mac2int(s):
    # MAC string -> 48-bit integer.
    return int(s.replace(':', ''), 16)


# ============================================================================
#  Jinja2 custom filters
# ============================================================================
def filt_ipv4(n):
    # Integer -> IPv4 string: 0x01040001 -> '1.4.0.1'
    return socket.inet_ntoa(struct.pack('>I', int(n)))


def filt_hex_hi16(n):
    # Upper 2 bytes as 4-hex-digit string: 0x01040001 -> '0104'
    return f'{(int(n) >> 16) & 0xFFFF:04x}'  # noqa: E231


def filt_hex_lo16(n):
    # Lower 2 bytes as 4-hex-digit string: 0x01040001 -> '0001'
    return f'{int(n) & 0xFFFF:04x}'  # noqa: E231


def vni_lehex(vni):
    # VNI -> little-endian hex string: 2000 -> 'd007'
    h = f'{vni:04x}'  # noqa: E231  # '07d0'
    return h[2:4] + h[0:2]                      # 'd007'


def guid(s):
    # Deterministic UUID from string (MD5-based, matches dpugen).
    return str(uuid.UUID(hex=hashlib.md5(s.encode('UTF-8')).hexdigest()))


def mac_str(n):
    # Integer -> 'XX:XX:XX:XX:XX:XX' MAC string.
    h = f'{int(n):012X}'  # noqa: E231
    return ':'.join(h[i:i + 2] for i in range(0, 12, 2))


# ============================================================================
#  Outbound-route computation (port of dpugen/dashgen/dash_route_table.py)
# ============================================================================
def _pick_block_mix(ips, target):
    # Return [(block_bits, count), ...] tiling `ips` into blocks summing to `target` routes.
    for bb in range(1, 17):
        bs = 1 << bb
        if bs > ips:
            break
        if ips % bs == 0 and (ips // bs) * bb == target:
            return [(bb, ips // bs)]
    for gap in range(1, 17):
        for k1 in range(1, 17 - gap):
            k2 = k1 + gap
            bs1, bs2 = 1 << k1, 1 << k2
            if bs2 > ips:
                break
            det = bs1 * k2 - bs2 * k1
            if det == 0:
                continue
            x_num = ips * k2 - target * bs2
            y_num = target * bs1 - ips * k1
            if x_num % det or y_num % det:
                continue
            X, Y = x_num // det, y_num // det
            if X >= 0 and Y >= 0:
                return [(k1, X), (k2, Y)]
    best_bb, best_r = 1, 0
    for bb in range(1, 17):
        bs = 1 << bb
        if bs > ips:
            break
        r = (ips // bs) * bb
        if r <= target and r > best_r:
            best_bb, best_r = bb, r
    return [(best_bb, ips // (1 << best_bb))]


def _decompose_block(base_ip, block_bits):
    # Non-summarizable decomposition of a 2^block_bits-IP block (gap at base+0; /32 at base+1, /31 at base+2, ...).
    return [{'ip': base_ip + (1 << i), 'mask': 32 - i} for i in range(block_bits)]


def compute_outbound_routes(ip_r_start_eni, eni_index, params, total_outbound_routes):
    # Yield outbound route dicts for one ENI: {ip, mask, routing_type, [overlay_ip]}.
    p = params
    if p.get('MINIMAL_SINGLE_ENTRY'):
        # Exactly one outbound route: dest /32 (IP_R_START) via the single VNet mapping.
        yield {'ip': filt_ipv4(ip_r_start_eni), 'mask': 32, 'routing_type': 'vnet'}
        return
    num_nsg_groups = p['ACL_NSG_COUNT'] * 2
    ips_per_nsg = p['ACL_RULES_NSG'] * p['IP_PER_ACL_RULE']
    ip_step_nsg = ip2int(p['IP_STEP_NSG'])
    ip_step1 = ip2int(p['IP_STEP1'])
    mapped_ips_per_nsg = p['ACL_MAPPED_PER_NSG'] * p['IP_PER_ACL_RULE']

    target_per_nsg = total_outbound_routes // num_nsg_groups if num_nsg_groups else 0
    block_mix = (_pick_block_mix(ips_per_nsg, target_per_nsg)
                 if (ips_per_nsg and target_per_nsg) else [])

    if p['ACL_MAPPED_PER_NSG'] > 0:
        gateway_ip = filt_ipv4(ip_r_start_eni)
    elif p['ACL_MAPPED_PER_NSG'] == 0:
        gateway_ip = filt_ipv4(ip2int(p['GATEWAY']) + ip_step1 * eni_index)
    else:
        raise ValueError(
            f'ACL_MAPPED_PER_NSG <{p["ACL_MAPPED_PER_NSG"]}> cannot be < 0')

    added = 0
    for table_index in range(num_nsg_groups):
        # IP_R_START ends in .1 by convention; -1 shifts to a power-of-2 boundary.
        nsg_base = ip_r_start_eni + ip_step_nsg * table_index - 1
        offset = 0
        for bb, count in block_mix:
            bs = 1 << bb
            for _ in range(count):
                is_mapped = offset < mapped_ips_per_nsg
                base_ip = nsg_base + offset
                for r in _decompose_block(base_ip, bb):
                    entry = {
                        'ip': filt_ipv4(r['ip']),
                        'mask': r['mask'],
                        'routing_type': 'vnet' if is_mapped else 'vnet_direct',
                    }
                    if not is_mapped:
                        entry['overlay_ip'] = gateway_ip
                    yield entry
                added += bb
                offset += bs

    if added == 0:
        network = ipaddress.IPv4Network(
            f'{filt_ipv4(ip_r_start_eni)}/10', strict=False)
        entry = {
            'ip': str(network.network_address),
            'mask': network.prefixlen,
            'routing_type': 'vnet' if p['ACL_MAPPED_PER_NSG'] > 0 else 'vnet_direct',
        }
        if p['ACL_MAPPED_PER_NSG'] == 0:
            entry['overlay_ip'] = gateway_ip
        yield entry


# ============================================================================
#  Template environment
# ============================================================================
def make_env():
    tpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    env = Environment(
        loader=FileSystemLoader(tpl_dir),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters['ipv4'] = filt_ipv4
    env.filters['hex_hi16'] = filt_hex_hi16
    env.filters['hex_lo16'] = filt_hex_lo16
    return env


# ============================================================================
#  File-generation workers  (picklable for multiprocessing)
# ============================================================================
def _postprocess(content):
    # Match compact_json formatting: trailing space after line-ending commas, CRLF.
    lines = content.split('\n')
    lines = [line + ' ' if line.endswith(',') else line for line in lines]
    return '\r\n'.join(lines)


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(_postprocess(content).encode('utf-8'))


def _render_apl(args):
    # Render one APL file.
    output_dir, prefix, dpu_id, ctx = args
    env = make_env()
    tmpl = env.get_template('apl.json.j2')
    path = os.path.join(output_dir, f'dpu{dpu_id}',
                        f'{prefix}.dpu{dpu_id}.000apl.json')
    _write(path, tmpl.render(**ctx))
    return path


def _render_grp(args):
    # Render one route-group file (one per ENI, pushed before the eni/routes file).
    output_dir, prefix, dpu_id, eni_global, ctx = args
    env = make_env()
    tmpl = env.get_template('grp.json.j2')
    path = os.path.join(output_dir, f'dpu{dpu_id}',
                        f'{prefix}.dpu{dpu_id}.{eni_global:03d}grp.json')  # noqa: E231
    _write(path, tmpl.render(**ctx))
    return path


def _render_eni(args):
    # Render one ENI file.
    output_dir, prefix, dpu_id, eni_global, ctx = args
    env = make_env()
    tmpl = env.get_template('eni.json.j2')
    path = os.path.join(output_dir, f'dpu{dpu_id}',
                        f'{prefix}.dpu{dpu_id}.{eni_global:03d}eni.json')  # noqa: E231
    _write(path, tmpl.render(**ctx))
    return path


def _render_map(args):
    # Render one MAP file (the big one: ~64 000 entries).
    output_dir, prefix, dpu_id, eni_global, ctx = args
    env = make_env()
    tmpl = env.get_template('map.json.j2')
    path = os.path.join(output_dir, f'dpu{dpu_id}',
                        f'{prefix}.dpu{dpu_id}.{eni_global:03d}map.json')  # noqa: E231
    # Render fully then postprocess (stream would need line-buffered postprocessing)
    _write(path, tmpl.render(**ctx))
    return path


# ============================================================================
#  Main orchestrator
# ============================================================================
def generate(params, output_dir, prefix='pl_100'):
    p = params
    dpus = p['DPUS']
    enis_per_dpu = p['ENI_COUNT'] // dpus

    # Pre-convert address strings to integers for fast arithmetic
    IP1 = ip2int(p['IP_STEP1'])
    IP_ENI = ip2int(p['IP_STEP_ENI'])
    IP_NSG = ip2int(p['IP_STEP_NSG'])
    MAC_ENI = mac2int(p['MAC_STEP_ENI'])

    # Per-ENI route split (matches dash.py: conf_total // ENI_COUNT).
    per_eni_total_routes = p['TOTAL_OUTBOUND_ROUTES'] // p['ENI_COUNT']

    apl_jobs = []
    grp_jobs = []
    eni_jobs = []
    map_jobs = []

    for dpu in range(dpus):
        # ── Per-DPU base values ─────────────────────────────────────────
        dpu_eni_start = p['ENI_START'] + dpu * enis_per_dpu * p['ENI_STEP']
        dpu_loopback = str(ipaddress.ip_address(p['LOOPBACK']) + dpu * IP1)
        dpu_pal = ip2int(p['PAL']) + dpu * enis_per_dpu * IP1
        dpu_par = ip2int(p['PAR']) + dpu * enis_per_dpu * IP1
        dpu_ip_l = ip2int(p['IP_L_START']) + dpu * enis_per_dpu * IP_ENI
        dpu_ip_r = ip2int(p['IP_R_START']) + dpu * enis_per_dpu * IP_ENI
        dpu_mac_l = mac2int(p['MAC_L_START']) + dpu * enis_per_dpu * MAC_ENI
        dpu_vm_vni = p['VM_VNI'] + dpu * enis_per_dpu

        # APL context
        apl_jobs.append((output_dir, prefix, dpu, {
            'eni_start': dpu_eni_start,
            'loopback': dpu_loopback,
        }))

        # ── Per-ENI values ──────────────────────────────────────────────
        for ei in range(enis_per_dpu):
            eni_global = dpu * enis_per_dpu + ei   # 0..255  (for filename)
            eni = dpu_eni_start + ei * p['ENI_STEP']  # 1000..1255
            r_vni = eni + p['ENI_L2R_STEP']           # 2000..2255
            eni_pal = dpu_pal + ei * IP1
            eni_par = dpu_par + ei * IP1
            eni_ip_l = dpu_ip_l + ei * IP_ENI
            eni_ip_r = dpu_ip_r + ei * IP_ENI
            eni_mac_l = dpu_mac_l + ei * MAC_ENI
            eni_hex = hex(eni)[2:]

            # GRP: per-ENI route group, pushed before its routes (order grp -> eni -> map).
            grp_jobs.append((output_dir, prefix, dpu, eni_global, {
                'eni':              eni,
                'route_group_guid': guid(f'route-group-{eni}'),
            }))

            # ENI context — routes materialized as a list of dicts
            routes = list(compute_outbound_routes(
                eni_ip_r, eni_global, p, per_eni_total_routes))
            eni_jobs.append((output_dir, prefix, dpu, eni_global, {
                'eni':              eni,
                'r_vni_id':         r_vni,
                'vnet_guid':        guid(f'DASH_VNET_TABLE:vnet-{r_vni}'),  # noqa: E231
                'mac_address':      mac_str(eni_mac_l),
                'underlay_ip':      filt_ipv4(eni_pal),
                'pl_underlay_sip':  dpu_loopback,
                # Bluefield needs the encoding hi-group set (fd40/mask fffe); zeroed -> ENI dropped (sonic-mgmt#23765).
                'pl_sip_encoding':  f'fd40::{vni_lehex(r_vni)}:64:ff71:0:0'  # noqa: E231
                                    f'/fffe:0:0:ffff:ffff:ffff::',  # noqa: E231,E131
                'vm_vni':           dpu_vm_vni,
                'route_group_guid': guid(f'route-group-{eni}'),
                'routes':           routes,
                'local_ip':         filt_ipv4(eni_ip_l),
                'vtep_remote':      filt_ipv4(eni_par),
                'include_route_rule': dpus <= 4,
            }))

            # MAP context
            map_jobs.append((output_dir, prefix, dpu, eni_global, {
                'eni':                eni,
                'r_vni_id':           r_vni,
                'vtep_remote':        filt_ipv4(eni_par),
                'eni_hex':            eni_hex,
                # Bluefield: CA2PA overlay SIP mask must be bits 80-112 (wide /96 rejected); use 1:ffff:ffff:: (sonic-mgmt#23765).
                'overlay_sip_prefix': f'1:100:{eni_hex}::'  # noqa: E231
                                      f'/1:ffff:ffff::',  # noqa: E231,E131
                'ip_r_start':         eni_ip_r,
                # Minimal mode -> 1 nsg group / 1 mapping; else full nsg_count.
                'nsg_count':          1 if p.get('MINIMAL_SINGLE_ENTRY') else p['ACL_NSG_COUNT'] * 2,
                # Minimal mode -> MINIMAL_MAPPINGS mappings; else ACL_RULES_NSG.
                'acl_rules_nsg':      (2 * p.get('MINIMAL_MAPPINGS', 1)
                                       if p.get('MINIMAL_SINGLE_ENTRY') else p['ACL_RULES_NSG']),
                'ip_step_nsg':        IP_NSG,
            }))

    # ── Render in parallel ──────────────────────────────────────────────
    workers = min(cpu_count(), dpus)
    print(f'Generating {len(apl_jobs)} APL + {len(grp_jobs)} GRP + {len(eni_jobs)} ENI '
          f'+ {len(map_jobs)} MAP files  ({workers} workers) ...',
          file=sys.stderr)

    with Pool(workers) as pool:
        for path in pool.imap_unordered(_render_apl, apl_jobs):
            print(f'  {path}', file=sys.stderr)
        for path in pool.imap_unordered(_render_grp, grp_jobs):
            print(f'  {path}', file=sys.stderr)
        for path in pool.imap_unordered(_render_eni, eni_jobs):
            print(f'  {path}', file=sys.stderr)
        for path in pool.imap_unordered(_render_map, map_jobs):
            print(f'  {path}', file=sys.stderr)

    print('Done.', file=sys.stderr)


# ============================================================================
#  CLI
# ============================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate DASH Private-Link configs via Jinja2 templates')
    parser.add_argument('-o', '--output', default='output',
                        help='Output directory (default: ./output/)')
    parser.add_argument('-p', '--params',
                        help='Params file (Python dict, e.g. dflt_params.py)')
    parser.add_argument('--prefix', default='pl_100',
                        help='Filename prefix (default: pl_100)')
    args = parser.parse_args()

    params = dict(DEFAULTS)
    if args.params:
        with open(args.params) as f:
            content = f.read()
            # Support both bare dict and 'dflt_params = {...}' format
            if 'dflt_params' in content:
                ns = {}
                exec(content, ns)
                params.update(ns['dflt_params'])
            else:
                params.update(eval(content))

    generate(params, args.output, args.prefix)
