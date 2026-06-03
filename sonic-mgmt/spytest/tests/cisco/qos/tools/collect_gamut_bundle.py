#!/usr/bin/env python3
"""
Collect a Mellanox/Gamut bug-report bundle from a SONiC DUT.

Captures (per the Gamut "how to" wiki):
    1. SDK debug dump            (syncd: sx_api_dbg_generate_dump.py)
    2. SDK port counters         (syncd: sx_api_port_counter_dump_all.py)
    3. `show version` (head 20)
    4. `dmesg`
    5. `show techsupport` tarball (/var/dump/sonic_dump_*.tar.gz)
    6. /var/log/syslog
    7. /var/log/syslog.1         (if present)
    8. /var/log/swss/sairedis.rec

All files are staged into a single sudo-owned directory on the DUT
(/tmp/gamut_stage_<ts>) so root-only logs become readable; then SFTPed
back and packaged into:

    gamut_bundle_<hostname>_[<label>_]<YYYYMMDD_HHMMSS>.tar.gz

By default the bundle is written to /nobackup/$USER.

Reference:
    https://ciscoteams.atlassian.net/wiki/spaces/WHITEBOX/pages/1102381122/Gamut+-+how+to

Usage:
    python3 collect_gamut_bundle.py --host <ip> [--label pre|post|...] \
        [--user admin] [--password password] [--outdir <dir>]

Run once before a test and once after to compare DUT state across the
test boundary. Timestamps in filenames give natural pre/post ordering.
"""

import argparse
import getpass
import os
import sys
from datetime import datetime

import paramiko


# Per-source collection plan. Each entry produces one file in the remote
# staging dir on the DUT.
#
#   kind == "syncd_file"  : run inside syncd; cmd writes to an inner path; docker cp out
#   kind == "syncd_stdout": run inside syncd; capture stdout on host into stage
#   kind == "host_cmd"    : run on host as sudo, redirect stdout into stage
#   kind == "host_copy"   : copy an existing host path into stage (cp -a)
#   kind == "techsupport" : special-case `show techsupport`
PLAN = [
    {
        "kind":  "syncd_file",
        "name":  "sdkdump.log",
        "desc":  "SDK debug dump",
        "cmd":   "/opt/mlx/bin/sx_api_dbg_generate_dump.py /tmp/sdkdump.log",
        # Newer SDKs ignore the argument and always write to /var/log/sdk_dbg/sdkdump.
        # The collector tries each path in order until one is found.
        "inner_candidates": ["/tmp/sdkdump.log", "/var/log/sdk_dbg/sdkdump"],
    },
    {
        "kind":  "syncd_stdout",
        "name":  "port_counter.log",
        "desc":  "SDK port counters",
        "cmd":   "/opt/mlx/bin/sx_api_port_counter_dump_all.py -a",
    },
    {
        "kind": "host_cmd",
        "name": "version.out",
        "desc": "show version (head 20)",
        "cmd":  "show version | head -20",
    },
    {
        "kind": "host_cmd",
        "name": "dmesg.out",
        "desc": "dmesg",
        "cmd":  "dmesg",
    },
    {
        "kind": "techsupport",
        "name": "techsupport",
        "desc": "show techsupport",
    },
    {
        "kind":     "host_copy",
        "name":     "syslog",
        "desc":     "/var/log/syslog",
        "src":      "/var/log/syslog",
        "required": True,
    },
    {
        "kind":     "host_copy",
        "name":     "syslog.1",
        "desc":     "/var/log/syslog.1",
        "src":      "/var/log/syslog.1",
        "required": False,
    },
    {
        "kind":     "host_copy",
        "name":     "sairedis.rec",
        "desc":     "/var/log/swss/sairedis.rec",
        "src":      "/var/log/swss/sairedis.rec",
        "required": True,
    },
]


def log(msg):
    print("[{}] {}".format(datetime.now().strftime("%H:%M:%S"), msg), flush=True)


def ssh_connect(host, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password,
                   look_for_keys=False, allow_agent=False, timeout=30)
    return client


def run(ssh, cmd, timeout=600):
    """Run a shell command on the DUT. Returns (rc, stdout, stderr)."""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def sudo_sh(cmd):
    """Wrap a command for `sudo sh -c` so redirections run as root."""
    return "sudo sh -c {!r}".format(cmd)


def collect_syncd_file(ssh, stage, item):
    """Run a command inside syncd that writes to a fixed inner path; docker cp out.

    Supports either a single 'inner' path or an 'inner_candidates' list of
    paths to try in order (for SDK versions that write to different defaults).
    """
    log("Collecting: {}".format(item["desc"]))
    rc, _, err = run(ssh, sudo_sh("docker exec syncd {}".format(item["cmd"])),
                     timeout=600)
    if rc != 0:
        log("  WARN: producer rc={} {}".format(rc, err.strip()[:200]))
        return False
    candidates = item.get("inner_candidates") or [item.get("inner")]
    dst = "{}/{}".format(stage, item["name"])
    last_err = ""
    for inner in candidates:
        if not inner:
            continue
        # Probe inside container first to avoid noisy docker cp errors
        rc, _, _ = run(ssh, sudo_sh(
            "docker exec syncd test -e {}".format(inner)))
        if rc != 0:
            continue
        rc, _, err = run(ssh, sudo_sh(
            "docker cp syncd:{} {}".format(inner, dst)))
        if rc == 0:
            log("  fetched from {}".format(inner))
            return True
        last_err = err.strip()[:200]
    log("  WARN: no candidate file found in syncd (tried {}){}".format(
        candidates, " last_err=" + last_err if last_err else ""))
    return False


def collect_syncd_stdout(ssh, stage, item):
    """Run a command inside syncd and capture its stdout into <stage>/<name>.

    The redirection happens on the host (outside docker), so it does not
    depend on the script's exit code or container fs writability.
    """
    log("Collecting: {}".format(item["desc"]))
    dst = "{}/{}".format(stage, item["name"])
    full = "docker exec syncd {} > {} 2>&1".format(item["cmd"], dst)
    rc, _, err = run(ssh, sudo_sh(full), timeout=600)
    if rc != 0:
        log("  WARN: rc={} {}".format(rc, err.strip()[:200]))
    # Sanity: verify file is non-empty
    rc2, out, _ = run(ssh, sudo_sh("stat -c %s {}".format(dst)))
    size = int(out.strip() or 0) if rc2 == 0 else 0
    if size == 0:
        log("  WARN: {} is empty".format(dst))
        return False
    return True


def collect_host_cmd(ssh, stage, item):
    log("Collecting: {}".format(item["desc"]))
    dst = "{}/{}".format(stage, item["name"])
    full = "{} > {} 2>&1".format(item["cmd"], dst)
    rc, _, err = run(ssh, sudo_sh(full), timeout=600)
    if rc != 0:
        log("  WARN: rc={} {}".format(rc, err.strip()[:200]))
    return rc == 0


def collect_host_copy(ssh, stage, item):
    log("Collecting: {}".format(item["desc"]))
    src = item["src"]
    rc, _, _ = run(ssh, sudo_sh("test -e {}".format(src)))
    if rc != 0:
        level = "WARN" if item.get("required") else "INFO"
        log("  {}: {} not present".format(level, src))
        return False
    dst = "{}/{}".format(stage, item["name"])
    rc, _, err = run(ssh, sudo_sh("cp -a {} {}".format(src, dst)))
    if rc != 0:
        log("  WARN: cp failed rc={} {}".format(rc, err.strip()[:200]))
        return False
    return True


def collect_techsupport(ssh, stage):
    log("Collecting: show techsupport (this may take a few minutes)...")
    run(ssh, sudo_sh("rm -rf /var/dump/*"))
    rc, _, err = run(ssh, sudo_sh("show techsupport"), timeout=1800)
    if rc != 0:
        log("  WARN: show techsupport rc={} {}".format(rc, err.strip()[:200]))
    rc, out, _ = run(ssh, sudo_sh("ls -1 /var/dump/sonic_dump_*.tar.gz"))
    paths = [p.strip() for p in out.splitlines() if p.strip()]
    if not paths:
        log("  WARN: no techsupport tarball found in /var/dump")
        return False
    src = paths[-1]
    dst = "{}/{}".format(stage, os.path.basename(src))
    rc, _, err = run(ssh, sudo_sh("cp {} {}".format(src, dst)))
    if rc != 0:
        log("  WARN: copy techsupport failed rc={} {}".format(rc, err.strip()[:200]))
        return False
    return True


def fetch_stage(ssh, sftp, stage, workdir):
    """Make stage readable by login user, then SFTP everything back."""
    run(ssh, sudo_sh("chmod -R a+rX {}".format(stage)))
    rc, out, _ = run(ssh, "ls -1 {}".format(stage))
    names = [n.strip() for n in out.splitlines() if n.strip()]
    if not names:
        log("  WARN: stage dir empty: {}".format(stage))
        return []
    fetched = []
    for n in names:
        remote = "{}/{}".format(stage, n)
        local = os.path.join(workdir, n)
        try:
            sftp.get(remote, local)
            fetched.append(local)
        except IOError as e:
            log("  WARN: fetch {} failed: {}".format(remote, e))
    return fetched


def make_tarball(workdir, outdir, hostname, label):
    import tarfile
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    parts = ["gamut_bundle", hostname]
    if label:
        parts.append(label)
    parts.append(ts)
    tarname = "_".join(parts) + ".tar.gz"
    tarpath = os.path.join(outdir, tarname)
    log("Creating tarball: {}".format(tarpath))
    inner_top = os.path.splitext(os.path.splitext(tarname)[0])[0]
    with tarfile.open(tarpath, "w:gz") as tf:
        for entry in sorted(os.listdir(workdir)):
            full = os.path.join(workdir, entry)
            tf.add(full, arcname=os.path.join(inner_top, entry))
    log("Bundle ready: {} ({:,} bytes)".format(tarpath, os.path.getsize(tarpath)))
    return tarpath


def default_outdir():
    user = os.environ.get("USER") or getpass.getuser()
    return "/nobackup/{}".format(user)


def main():
    parser = argparse.ArgumentParser(
        description="Collect Gamut/Mellanox bug-report bundle from a SONiC DUT")
    parser.add_argument("--host", required=True, help="DUT mgmt IP or hostname")
    parser.add_argument("--user", default="admin",
                        help="SSH username (default: admin)")
    parser.add_argument("--password", default="password",
                        help="SSH password (default: password)")
    parser.add_argument("--label", default="",
                        help="Optional label (e.g. 'pre' or 'post') in filename")
    parser.add_argument("--outdir", default=default_outdir(),
                        help="Output directory for tarball (default: /nobackup/$USER)")
    parser.add_argument("--keep-stage", action="store_true",
                        help="Leave /tmp/gamut_stage_* on the DUT (default: delete)")
    parser.add_argument("--keep-workdir", action="store_true",
                        help="Keep the local staging directory (default: delete)")
    args = parser.parse_args()

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    workdir = os.path.join(outdir, ".gamut_stage_{}_{}".format(args.host, ts))
    os.makedirs(workdir, exist_ok=True)
    log("Local staging dir:  {}".format(workdir))
    log("Output directory:   {}".format(outdir))

    log("Connecting to {} as {}".format(args.host, args.user))
    ssh = ssh_connect(args.host, args.user, args.password)
    sftp = ssh.open_sftp()

    stage = "/tmp/gamut_stage_{}".format(ts)
    log("Remote staging dir: {}".format(stage))
    run(ssh, sudo_sh("rm -rf {0} && mkdir -p {0} && chmod 755 {0}".format(stage)))

    try:
        rc, hn_out, _ = run(ssh, "hostname")
        hostname = hn_out.strip() or args.host

        for item in PLAN:
            kind = item["kind"]
            if kind == "syncd_file":
                collect_syncd_file(ssh, stage, item)
            elif kind == "syncd_stdout":
                collect_syncd_stdout(ssh, stage, item)
            elif kind == "host_cmd":
                collect_host_cmd(ssh, stage, item)
            elif kind == "host_copy":
                collect_host_copy(ssh, stage, item)
            elif kind == "techsupport":
                collect_techsupport(ssh, stage)

        fetch_stage(ssh, sftp, stage, workdir)
        tarpath = make_tarball(workdir, outdir, hostname, args.label)

    finally:
        if not args.keep_stage:
            run(ssh, sudo_sh("rm -rf {}".format(stage)))
        try:
            sftp.close()
        finally:
            ssh.close()
        if not args.keep_workdir:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)

    log("Done.")
    print(tarpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
