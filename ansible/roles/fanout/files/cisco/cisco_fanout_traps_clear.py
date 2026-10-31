#!/usr/bin/python3
"""Clear the Silicon One SDK default packet traps on a Cisco SONiC fanout leaf.

A fanout leaf must forward the DUT's control-plane frames (LACP, LLDP, ARP, DHCP, ...)
transparently instead of punting them to its CPU. The SDK arms these traps when syncd creates
the switch, and orchagent's CoPP can arm the LACP trap again when it programs its hostif traps.

The script waits until syncd, its dshell_client and orchagent's hostif traps are in place,
clears the traps through the SDK debug shell and reads every trap back. It reads them again
TRAPS_CLEAR_SETTLE seconds later and reports success only if they all stayed cleared;
otherwise it clears them again, until TRAPS_CLEAR_TIMEOUT. Works on SONiC 202205 to 202511.
"""
import json
import os
import subprocess
import sys
import time

TIMEOUT = int(os.environ.get('TRAPS_CLEAR_TIMEOUT', '1800'))
RETRY = int(os.environ.get('TRAPS_CLEAR_RETRY', '30'))
SETTLE = int(os.environ.get('TRAPS_CLEAR_SETTLE', '60'))
COPP_GRACE = int(os.environ.get('TRAPS_CLEAR_COPP_GRACE', '600'))
COPP_CFG = '/etc/sonic/copp_cfg.json'
MARKER_OK = '--- TRAP CLEAR COMPLETE ---'
RESULT_TAGS = ('TRAPCLR ', '--- TRAP CLEAR', 'FATAL SDK ERROR')

deadline = time.time() + TIMEOUT

# Default traps to clear. SDK < 1.66 names the events LA_EVENT_<name>, SDK >= 1.66 la_event_e_<name>.
TRAP_EVENTS = [
    "ETHERNET_L2CP0", "ETHERNET_LACP", "ETHERNET_ARP", "ETHERNET_L2CP2",
    "ETHERNET_DHCPV4_SERVER", "ETHERNET_DHCPV4_CLIENT", "ETHERNET_DHCPV6_SERVER", "ETHERNET_DHCPV6_CLIENT",
    "ETHERNET_CISCO_PROTOCOLS", "L3_ISIS_OVER_L3",
]
# Events that must exist in the SDK: while LACP is trapped, no DUT PortChannel comes up.
REQUIRED_EVENTS = ["ETHERNET_LACP"]

# Runs inside the syncd debug shell. Rules for that console: no empty lines inside the block,
# catch BaseException (Leaba SDK exceptions are not Exception subclasses), never sys.exit().
# On 202205 SDKs clear_trap_configuration() raises NotFound for a trap that is already clear.
# With __CLEAR__ False the payload only reads the traps back.
DSHELL_PAYLOAD = """
import sdk
try:
    d0 = sdk.la_get_device(0)
    bad = []
    found = 0
    for n in __TRAP_EVENTS__:
        ev = getattr(sdk, "la_event_e_" + n, getattr(sdk, "LA_EVENT_" + n, None))
        if ev is None:
            print("TRAPCLR SKIP " + n + " (no such event in this SDK)")
            if n in __REQUIRED_EVENTS__:
                bad.append(n)
            continue
        found += 1
        if __CLEAR__:
            try:
                d0.clear_trap_configuration(ev)
                print("TRAPCLR CLEARED " + n)
            except BaseException as x:
                if "NotFound" in type(x).__name__:
                    print("TRAPCLR ABSENT " + n)
                else:
                    print("TRAPCLR ERROR " + n + " " + type(x).__name__ + ": " + str(x)[:160])
                    bad.append(n)
        try:
            d0.get_trap_configuration(ev)
            print("TRAPCLR STILL-SET " + n)
            bad.append(n)
        except BaseException as x:
            if "NotFound" not in type(x).__name__:
                print("TRAPCLR VERIFY-ERROR " + n + " " + type(x).__name__ + ": " + str(x)[:160])
                bad.append(n)
    if not found:
        bad.append("no-known-trap-event")
    if bad:
        print("--- TRAP CLEAR INCOMPLETE: " + ",".join(sorted(set(bad))) + " ---")
    else:
        print("--- TRAP CLEAR COMPLETE ---")
except BaseException as x:
    print("FATAL SDK ERROR: " + type(x).__name__ + ": " + str(x)[:200])
"""


def payload(clear):
    code = (DSHELL_PAYLOAD.replace('__TRAP_EVENTS__', repr(TRAP_EVENTS))
            .replace('__REQUIRED_EVENTS__', repr(REQUIRED_EVENTS))
            .replace('__CLEAR__', repr(bool(clear))))
    lines = [line for line in code.splitlines() if line.strip()]
    return '\n'.join(lines) + '\n\nquit()\n\n'


def log(msg):
    print(msg, flush=True)


def remaining():
    return deadline - time.time()


def pause(seconds):
    time.sleep(max(0, min(seconds, remaining())))


def run(cmd, timeout=30, **kw):
    # Never block past the script's deadline, so the unit's TimeoutStartSec is never reached.
    timeout = max(1, min(timeout, remaining()))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except Exception as e:  # docker CLI hung or missing
        return subprocess.CompletedProcess(cmd, 255, '', str(e))


def db(*args):
    return run(['sonic-db-cli'] + list(args)).stdout.strip()


def syncd_running():
    r = run(['docker', 'inspect', '-f', '{{.State.Running}}', 'syncd'])
    return r.returncode == 0 and r.stdout.strip() == 'true'


def dshell_client_running():
    r = run(['docker', 'exec', 'syncd', 'supervisorctl', 'status', 'dshell_client'])
    if 'RUNNING' in r.stdout:
        return True, ''
    r = run(['docker', 'exec', 'syncd', 'supervisorctl', 'start', 'dshell_client'], timeout=60)
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0 or 'already started' in out:
        return True, ''
    return False, f'dshell_client not started yet (rc={r.returncode}): {out[:200]}'


def lacp_copp_expected():
    """True if CoPP traps LACP: coppmgrd has enabled the trap, or copp_cfg.json lists it."""
    if db('STATE_DB', 'HGET', 'COPP_TRAP_TABLE|lacp', 'state') == 'ok':
        return True
    try:
        with open(COPP_CFG) as f:
            traps = json.load(f).get('COPP_TRAP', {})
        return any('lacp' in [t.strip() for t in str(v.get('trap_ids', '')).split(',')] for v in traps.values())
    except Exception:
        return True  # unknown: wait for the CoPP LACP trap, with the grace fallback


def orchagent_traps(want_lacp):
    """Return (switch created, CoPP LACP trap programmed), from the hostif traps in ASIC_DB.

    STATE_DB COPP_TRAP_TABLE does not tell: coppmgrd writes 'state ok' from the config before
    orchagent has created the switch, and orchagent's 'hw_status' (202505+) survives a swss
    restart, while swss.sh flushes ASIC_DB on every cold start.
    """
    # CoppOrch creates its default trap right after the switch, so any trap means that orchagent
    # has created the switch.
    keys = db('ASIC_DB', 'KEYS', 'ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF_TRAP:*').split()
    if want_lacp:
        for key in keys:
            if db('ASIC_DB', 'HGET', key, 'SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE') == 'SAI_HOSTIF_TRAP_TYPE_LACP':
                return True, True
    return bool(keys), False


def copp_ready(since):
    """Return (ready, message). Ready once orchagent has created the switch and, if CoPP traps
    LACP, has programmed that trap, so that it cannot re-arm LACP after the clear."""
    want_lacp = lacp_copp_expected()
    switch_created, lacp_programmed = orchagent_traps(want_lacp)
    if lacp_programmed:
        return True, 'orchagent has programmed its CoPP LACP trap'
    if switch_created and not want_lacp:
        return True, 'orchagent has created the switch; CoPP does not trap LACP'
    if time.time() - since > COPP_GRACE:
        return True, f'orchagent CoPP not seen after {COPP_GRACE}s; clearing anyway'
    if want_lacp:
        return False, 'waiting for orchagent to program its CoPP LACP trap'
    return False, 'waiting for orchagent to create the switch'


def dshell(clear):
    """Run the payload in the SDK debug shell. Return (all traps cleared, summary)."""
    r = run(['docker', 'exec', '-i', 'syncd', 'sh', '-c', '/usr/bin/dshell_client.py -i'],
            timeout=120, input=payload(clear))
    results = []
    for ln in r.stdout.splitlines():
        # The console's '>>> ' and '... ' prompts can precede a result on the same line.
        hits = [ln.find(tag) for tag in RESULT_TAGS if tag in ln]
        if hits:
            results.append(ln[min(hits):].strip())
    if MARKER_OK in results:
        return True, '; '.join(x for x in results if x.startswith('TRAPCLR'))
    tail = [ln.strip() for ln in (r.stdout + '\n' + r.stderr).splitlines() if ln.strip()][-4:]
    return False, ' | '.join(results[-6:] or tail)[:900]


def clear_and_verify():
    ok, summary = dshell(clear=True)
    if not ok:
        log('Attempt failed: ' + summary)
        return False
    log(summary)
    # Read the traps again after a while, in case something re-armed one after the clear.
    pause(SETTLE)
    ok, summary = dshell(clear=False)
    if not ok:
        log(f'Traps not clear {SETTLE}s later, clearing again: ' + summary)
        return False
    return True


def main():
    global deadline
    deadline = time.time() + TIMEOUT
    log('Starting Cisco fanout trap clear: waiting for syncd, dshell_client and orchagent...')
    copp_since = None
    copp_done = False
    last_wait = None
    while True:
        wait = None
        if not syncd_running():
            wait = 'syncd container is not running yet'
        else:
            ok, why = dshell_client_running()
            if not ok:
                wait = why
            elif not copp_done:
                copp_since = copp_since or time.time()
                copp_done, why = copp_ready(copp_since)
                if copp_done:
                    log(why)
                else:
                    wait = why
        if wait is None:
            last_wait = None
            if clear_and_verify():
                log(f'Success: Traps cleared and still cleared {SETTLE}s later.')
                return 0
        elif wait != last_wait:
            log(wait)
            last_wait = wait
        if remaining() <= 0:
            log(f'Timeout: Failed to clear traps after {TIMEOUT}s.')
            return 1
        pause(RETRY)


if __name__ == '__main__':
    sys.exit(main())
