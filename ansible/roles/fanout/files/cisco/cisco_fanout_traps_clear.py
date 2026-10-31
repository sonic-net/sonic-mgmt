#!/usr/bin/python3
"""Clear the Silicon One SDK default packet traps on a Cisco SONiC fanout leaf.

A fanout leaf must forward the DUT's control-plane frames (LACP, LLDP, ARP, DHCP, ...)
transparently instead of punting them to its CPU. This script waits until syncd, its
dshell_client and orchagent's CoPP setup are ready, clears the traps through the SDK debug
shell, reads every trap back to verify it is gone, and retries until that is true.

Fixes over the first version:
- Leaba SDK exceptions (e.g. Leaba.NotFoundException) do not derive from Exception, so
  'except Exception' did not catch them. On older SDKs (202205) clear_trap_configuration()
  raises NotFound for a trap that is already cleared, so any re-run (service restart, fanout
  re-deploy, the legacy cisco.service having cleared the traps first) aborted the payload at
  the first trap, never printed the success marker and failed at its deadline. Any other SDK
  error had the same effect and left the remaining traps armed.
- Every trap is now read back with get_trap_configuration(); success means all are gone.
- It waits for CoPP (STATE_DB COPP_TRAP_TABLE|lacp state ok), so orchagent cannot
  re-install the LACP trap after it was cleared.
- dshell_client start is retried instead of exiting on the first failure, the retry deadline is
  configurable (TRAPS_CLEAR_TIMEOUT, default 30 min instead of 10), and output is logged line
  by line (it used to appear only when the script exited).
"""
import json
import os
import subprocess
import sys
import time

TIMEOUT = int(os.environ.get('TRAPS_CLEAR_TIMEOUT', '1800'))
RETRY = int(os.environ.get('TRAPS_CLEAR_RETRY', '30'))
COPP_GRACE = int(os.environ.get('TRAPS_CLEAR_COPP_GRACE', '600'))
MARKER_OK = '--- TRAP CLEAR COMPLETE ---'

# Default traps to clear. SDK < 1.66 names the events LA_EVENT_<name>, SDK >= 1.66 la_event_e_<name>.
TRAP_EVENTS = [
    "ETHERNET_L2CP0", "ETHERNET_LACP", "ETHERNET_ARP", "ETHERNET_L2CP2",
    "ETHERNET_DHCPV4_SERVER", "ETHERNET_DHCPV4_CLIENT", "ETHERNET_DHCPV6_SERVER", "ETHERNET_DHCPV6_CLIENT",
    "ETHERNET_CISCO_PROTOCOLS", "L3_ISIS_OVER_L3",
]

# Runs inside the syncd debug shell. Rules for that console: no empty lines inside the block,
# catch BaseException (Leaba SDK exceptions are not Exception subclasses), never sys.exit().
DSHELL_PAYLOAD = """
import sdk
try:
    d0 = sdk.la_get_device(0)
    names = __TRAP_EVENTS__
    bad = []
    for n in names:
        ev = getattr(sdk, "la_event_e_" + n, getattr(sdk, "LA_EVENT_" + n, None))
        if ev is None:
            print("TRAPCLR SKIP " + n + " (no such event in this SDK)")
            continue
        try:
            d0.clear_trap_configuration(ev)
            print("TRAPCLR CLEARED " + n)
        except BaseException as x:
            if "NotFound" in type(x).__name__ or "not found" in str(x).lower():
                print("TRAPCLR ABSENT " + n)
            else:
                print("TRAPCLR ERROR " + n + " " + type(x).__name__ + ": " + str(x)[:160])
                bad.append(n)
        try:
            d0.get_trap_configuration(ev)
            print("TRAPCLR STILL-SET " + n)
            bad.append(n)
        except BaseException as x:
            if not ("NotFound" in type(x).__name__ or "not found" in str(x).lower()):
                print("TRAPCLR VERIFY-ERROR " + n + " " + type(x).__name__ + ": " + str(x)[:160])
                bad.append(n)
    if bad:
        print("--- TRAP CLEAR INCOMPLETE: " + ",".join(sorted(set(bad))) + " ---")
    else:
        print("--- TRAP CLEAR COMPLETE ---")
except BaseException as x:
    print("FATAL SDK ERROR: " + type(x).__name__ + ": " + str(x)[:200])
""".replace("__TRAP_EVENTS__", repr(TRAP_EVENTS))


def log(msg):
    print(msg, flush=True)


def run(cmd, timeout=60, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except Exception as e:  # docker CLI hung or missing
        return subprocess.CompletedProcess(cmd, 255, '', str(e))


def syncd_running():
    r = run(['docker', 'inspect', '-f', '{{.State.Running}}', 'syncd'], timeout=30)
    return r.returncode == 0 and r.stdout.strip() == 'true'


def dshell_client_running():
    r = run(['docker', 'exec', 'syncd', 'supervisorctl', 'status', 'dshell_client'], timeout=30)
    if 'RUNNING' in r.stdout:
        return True, ''
    r = run(['docker', 'exec', 'syncd', 'supervisorctl', 'start', 'dshell_client'], timeout=60)
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0 or 'already started' in out:
        return True, ''
    return False, f'dshell_client not started yet (rc={r.returncode}): {out[:200]}'


def lacp_copp_expected():
    """True if CoPP (copp_cfg.json) installs a LACP trap that orchagent reports in STATE_DB."""
    try:
        with open('/etc/sonic/copp_cfg.json') as f:
            traps = json.load(f).get('COPP_TRAP', {})
        return any('lacp' in [t.strip() for t in str(v.get('trap_ids', '')).split(',')] for v in traps.values())
    except Exception:
        return True  # unknown: wait for the CoPP state, with the grace fallback


def copp_ready(started):
    if not lacp_copp_expected():
        return True, 'CoPP config has no LACP trap; not waiting for CoPP'
    r = run(['sonic-db-cli', 'STATE_DB', 'HGET', 'COPP_TRAP_TABLE|lacp', 'state'], timeout=30)
    if r.stdout.strip() == 'ok':
        return True, ''
    if time.time() - started > COPP_GRACE:
        return True, f'CoPP state for lacp not reported after {COPP_GRACE}s; proceeding anyway'
    return False, 'waiting for orchagent CoPP (STATE_DB COPP_TRAP_TABLE|lacp state ok)'


def attempt():
    lines = [line for line in DSHELL_PAYLOAD.splitlines() if line.strip()]
    payload = '\n'.join(lines) + '\n\nquit()\n\n'
    r = run(['docker', 'exec', '-i', 'syncd', 'sh', '-c', '/usr/bin/dshell_client.py -i'],
            timeout=120, input=payload)
    results = [ln.strip().lstrip('>').strip() for ln in r.stdout.splitlines()
               if 'TRAPCLR' in ln or '--- TRAP' in ln or 'FATAL SDK' in ln]
    if MARKER_OK in r.stdout:
        log('; '.join(x for x in results if x.startswith('TRAPCLR')))
        return True
    tail = [ln for ln in (r.stdout + '\n' + r.stderr).splitlines() if ln.strip()][-4:]
    log('Attempt failed: ' + ' | '.join(results[-6:] or tail)[:900])
    return False


def main():
    log('Starting Cisco fanout trap clear: waiting for syncd, dshell_client and CoPP...')
    started = time.time()
    last_wait = None
    while True:
        ok, why = syncd_running(), 'syncd container is not running yet'
        if ok:
            ok, why = dshell_client_running()
        if ok:
            ok, why = copp_ready(started)
            if ok and why:
                log(why)
                why = ''
        if ok:
            if attempt():
                log('Success: Traps cleared.')
                return 0
        elif why != last_wait:
            log(why)
            last_wait = why
        if time.time() - started > TIMEOUT:
            log(f'Timeout: Failed to clear traps after {TIMEOUT}s.')
            return 1
        time.sleep(RETRY)


if __name__ == '__main__':
    sys.exit(main())
