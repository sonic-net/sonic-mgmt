#!/usr/bin/env python3
"""Provision host kernel modules required by cSONiC test neighbors.

The fast path loads an already-installed module.  If a module is missing, the
helper first installs the exact distro extra-modules package for the running
kernel.  Only when that package does not exist does it build from the exact
matching distro kernel source.  Every failure is returned to Ansible, which can
select the existing userspace-OVS LAG backend for team-module failures.
"""

import argparse
import contextlib
import fcntl
import glob
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

DEFAULT_MODULES = ("team", "team_mode_loadbalance")
BUILD_CONFIG = {
    "team": "NET_TEAM",
    "team_mode_loadbalance": "NET_TEAM_MODE_LOADBALANCE",
    "vrf": "NET_VRF",
}
MODULE_SOURCE = {
    "team": "drivers/net/team/team.ko",
    "team_mode_loadbalance": "drivers/net/team/team_mode_loadbalance.ko",
    "vrf": "drivers/net/vrf.ko",
}


class ProvisionError(RuntimeError):
    pass


class Runner:
    def run(
        self,
        command,
        *,
        cwd=None,
        check=True,
        timeout=None,
        echo_output=True,
    ):
        printable = " ".join(shlex.quote(str(part)) for part in command)
        print("+ {}".format(printable), flush=True)
        result = subprocess.run(
            [str(part) for part in command],
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        if result.stdout and echo_output:
            print(result.stdout.rstrip(), flush=True)
        if check and result.returncode:
            raise ProvisionError(
                "command failed with rc={}: {}".format(
                    result.returncode, printable
                )
            )
        return result


class ModuleProvisioner:
    def __init__(self, runner=None, root="/", keep_workdir=False):
        self.runner = runner or Runner()
        self.root = Path(root)
        self.keep_workdir = keep_workdir
        self.kernel = self._run_output(["uname", "-r"])
        self.modprobe = shutil.which("modprobe") or "/sbin/modprobe"
        self.modinfo = shutil.which("modinfo") or "/sbin/modinfo"
        self.depmod = shutil.which("depmod") or "/sbin/depmod"

    def _run_output(self, command, **kwargs):
        return self.runner.run(command, **kwargs).stdout.strip()

    def module_available(self, module):
        result = self.runner.run(
            [self.modinfo, "-F", "filename", module], check=False
        )
        return result.returncode == 0 and bool(result.stdout.strip())

    def module_loaded(self, module):
        return (self.root / "sys/module" / module).exists()

    def validate_module(self, module):
        if not self.module_available(module):
            raise ProvisionError("module {} is not installed".format(module))
        filename = self._run_output([self.modinfo, "-F", "filename", module])
        if filename == "(builtin)":
            return
        vermagic = self._run_output([self.modinfo, "-F", "vermagic", module])
        if not vermagic or vermagic.split()[0] != self.kernel:
            raise ProvisionError(
                (
                    "module {} vermagic {!r} does not match running "
                    "kernel {}"
                ).format(module, vermagic, self.kernel)
            )
        if self.signature_enforced():
            signer = self._run_output([self.modinfo, "-F", "signer", module])
            if not signer:
                raise ProvisionError(
                    (
                        "module {} is unsigned while signature enforcement "
                        "is active"
                    ).format(module)
                )

    def load_modules(self, modules):
        for module in modules:
            self.validate_module(module)
            self.runner.run([self.modprobe, module])
            if not self.module_loaded(module):
                raise ProvisionError(
                    (
                        "modprobe {} succeeded but the module is not loaded"
                    ).format(module)
                )

    def signature_enforced(self):
        candidates = (
            self.root / "sys/module/module/parameters/sig_enforce",
            self.root / "proc/sys/kernel/module_sig_enforce",
        )
        for path in candidates:
            try:
                return path.read_text().strip().lower() in ("1", "y", "yes")
            except OSError:
                continue
        return False

    def package_name(self):
        return "linux-modules-extra-{}".format(self.kernel)

    def refresh_apt(self):
        self.runner.run(
            ["apt-get", "-o", "DPkg::Lock::Timeout=600", "update"],
            timeout=900,
        )

    def package_available(self):
        result = self.runner.run(
            ["apt-cache", "show", "--no-all-versions", self.package_name()],
            check=False,
        )
        return result.returncode == 0 and "Package:" in result.stdout

    def install_exact_package(self):
        package = self.package_name()
        print("Installing exact running-kernel package {}".format(package))
        self.runner.run(
            [
                "apt-get",
                "-o",
                "DPkg::Lock::Timeout=600",
                "install",
                "-y",
                package,
            ],
            timeout=1200,
        )
        self.runner.run([self.depmod, "-a", self.kernel])

    def source_identity(self):
        # Request source through an exact kernel *binary* package.  Asking apt
        # for a source name such as linux-azure-6.8 is ambiguous because a meta
        # source can publish a binary with that same name.
        binaries = (
            "linux-image-unsigned-{}".format(self.kernel),
            "linux-headers-{}".format(self.kernel),
        )
        for binary in binaries:
            result = self.runner.run(
                ["apt-cache", "show", "--no-all-versions", binary],
                check=False,
                echo_output=False,
            )
            if result.returncode:
                continue
            source_match = re.search(r"(?m)^Source:\s*(\S+)", result.stdout)
            version_match = re.search(r"(?m)^Version:\s*(\S+)", result.stdout)
            if version_match:
                source = source_match.group(1) if source_match else binary
                return binary, source, version_match.group(1)
        raise ProvisionError(
            "cannot determine exact distro kernel source for {}".format(
                self.kernel
            )
        )

    def binary_repository_uris(self, binary):
        result = self.runner.run(
            ["apt-cache", "policy", binary],
            check=False,
            echo_output=False,
        )
        uris = set(re.findall(r"https?://[^\s]+", result.stdout))
        if result.returncode or not uris:
            raise ProvisionError(
                "cannot identify the APT repository for {}".format(binary)
            )
        return uris

    @contextlib.contextmanager
    def temporary_deb_src(self, allowed_uris):
        """Expose only the distro deb-src entry for the kernel package."""
        source_dir = self.root / "etc/apt/sources.list.d"
        destination_list = source_dir / (
            "csonic-kernel-build-{}.list".format(os.getpid())
        )
        destination_sources = source_dir / (
            "csonic-kernel-build-{}.sources".format(os.getpid())
        )
        source_lines = []
        stanzas = []
        source_files = [self.root / "etc/apt/sources.list"]
        source_files.extend(
            Path(path)
            for path in glob.glob(
                str(self.root / "etc/apt/sources.list.d" / "*.list")
            )
        )
        for path in source_files:
            try:
                lines = path.read_text().splitlines()
            except OSError:
                continue
            for line in lines:
                stripped = line.strip()
                if not stripped.startswith("deb "):
                    continue
                if not any(uri in stripped for uri in allowed_uris):
                    continue
                source_lines.append("deb-src " + stripped[4:])

        for path_string in glob.glob(
            str(self.root / "etc/apt/sources.list.d" / "*.sources")
        ):
            path = Path(path_string)
            if path == destination_sources:
                continue
            try:
                content = path.read_text()
            except OSError:
                continue
            for raw_stanza in re.split(r"\n\s*\n", content.strip()):
                if not re.search(r"(?m)^Types:\s+.*\bdeb\b", raw_stanza):
                    continue
                if not any(uri in raw_stanza for uri in allowed_uris):
                    continue
                stanza = re.sub(
                    r"(?m)^Types:\s+.*$", "Types: deb-src", raw_stanza
                )
                stanzas.append(stanza)

        if not source_lines and not stanzas:
            raise ProvisionError(
                "cannot derive any deb-src entries from apt sources"
            )

        source_dir.mkdir(parents=True, exist_ok=True)
        if source_lines:
            destination_list.write_text("\n".join(source_lines) + "\n")
        if stanzas:
            destination_sources.write_text("\n\n".join(stanzas) + "\n")
        try:
            self.refresh_apt()
            yield
        finally:
            for destination in (destination_list, destination_sources):
                try:
                    destination.unlink()
                except FileNotFoundError:
                    pass
            # Restore apt's view to the operator-managed binary-source files.
            self.refresh_apt()

    def install_build_dependencies(self):
        packages = (
            "build-essential",
            "dpkg-dev",
            "fakeroot",
            "flex",
            "bison",
            "libssl-dev",
            "libelf-dev",
            "dwarves",
            "linux-headers-{}".format(self.kernel),
        )
        self.runner.run(
            [
                "apt-get",
                "-o",
                "DPkg::Lock::Timeout=600",
                "install",
                "-y",
            ]
            + list(packages),
            timeout=1200,
        )

    def source_tree(self, workdir, binary, source, version):
        allowed_uris = self.binary_repository_uris(binary)
        with self.temporary_deb_src(allowed_uris):
            available = self.runner.run(
                ["apt-cache", "showsrc", source],
                check=False,
                echo_output=False,
            )
            versions = re.findall(r"(?m)^Version:\s*(\S+)", available.stdout)
            if version not in versions:
                raise ProvisionError(
                    "exact source {}={} is unavailable (available: {})".format(
                        source, version, ",".join(versions) or "none"
                    )
                )
            self.runner.run(
                [
                    "apt-get",
                    "--quiet",
                    "source",
                    "{}={}".format(binary, version),
                ],
                cwd=workdir,
                timeout=1800,
            )

        candidates = [
            path
            for path in workdir.iterdir()
            if path.is_dir() and (path / "Makefile").exists()
        ]
        if len(candidates) != 1:
            raise ProvisionError(
                "expected one extracted kernel source tree, found {}".format(
                    ",".join(str(path) for path in candidates) or "none"
                )
            )
        return candidates[0]

    def make_version_args(self):
        parts = self.kernel.split("-", 2)
        main = parts[0].split(".")
        if (
            len(parts) != 3
            or len(main) != 3
            or not all(item.isdigit() for item in main)
        ):
            raise ProvisionError(
                "cannot derive kernel make version fields from {}".format(
                    self.kernel
                )
            )
        return [
            "VERSION={}".format(main[0]),
            "PATCHLEVEL={}".format(main[1]),
            "SUBLEVEL={}".format(main[2]),
            "EXTRAVERSION=-{}".format(parts[1]),
            "LOCALVERSION=-{}".format(parts[2]),
        ]

    def prepare_source(self, source_tree, modules):
        debian_env = source_tree / "debian/debian.env"
        if debian_env.exists():
            self.runner.run(
                [
                    "bash",
                    "-c",
                    "set -e; source debian/debian.env; "
                    'if [ -n "${DEBIAN:-}" ] && '
                    '[ -x "${DEBIAN}/reconstruct" ]; '
                    'then "${DEBIAN}/reconstruct"; fi',
                ],
                cwd=source_tree,
                timeout=1200,
            )

        config = self.root / "boot" / "config-{}".format(self.kernel)
        symvers_candidates = (
            self.root
            / "usr/src"
            / "linux-headers-{}".format(self.kernel)
            / "Module.symvers",
            self.root / "lib/modules" / self.kernel / "build/Module.symvers",
        )
        symvers = next(
            (path for path in symvers_candidates if path.exists()), None
        )
        if not config.exists() or symvers is None:
            raise ProvisionError(
                (
                    "matching kernel config or Module.symvers is unavailable "
                    "for {}"
                ).format(self.kernel)
            )

        shutil.copy2(str(config), str(source_tree / ".config"))
        scripts_config = source_tree / "scripts/config"
        if not scripts_config.exists():
            raise ProvisionError("kernel scripts/config is unavailable")
        symbols = {BUILD_CONFIG[module] for module in modules}
        if any(module.startswith("team") for module in modules):
            # A missing mode may be compiled against an already-installed team
            # core, but the source-tree build still needs its core dependency.
            symbols.add(BUILD_CONFIG["team"])
        for symbol in sorted(symbols):
            self.runner.run(
                [str(scripts_config), "--module", symbol], cwd=source_tree
            )
        self.runner.run(["make", "olddefconfig"], cwd=source_tree, timeout=600)
        self.runner.run(
            ["make"] + self.make_version_args() + ["modules_prepare"],
            cwd=source_tree,
            timeout=1200,
        )
        shutil.copy2(str(symvers), str(source_tree / "Module.symvers"))

    def build_modules(self, source_tree, modules):
        make_prefix = [
            "make",
            "-j{}".format(max(1, os.cpu_count() or 1)),
        ] + self.make_version_args()
        if any(module.startswith("team") for module in modules):
            self.runner.run(
                make_prefix + ["M=drivers/net/team"],
                cwd=source_tree,
                timeout=1800,
            )
        if "vrf" in modules:
            # Restrict the drivers/net sub-build to vrf.ko.  The distro kernel
            # config enables many unrelated network modules. Building all of
            # them would make this fallback slow and fragile.
            net_makefile = source_tree / "drivers/net/Makefile"
            net_makefile.write_text("obj-$(CONFIG_NET_VRF) += vrf.o\n")
            self.runner.run(
                make_prefix + ["M=drivers/net"],
                cwd=source_tree,
                timeout=1800,
            )
        paths = {
            module: source_tree / MODULE_SOURCE[module] for module in modules
        }
        missing = [
            module for module, path in paths.items() if not path.exists()
        ]
        if missing:
            raise ProvisionError(
                "kernel build did not produce: {}".format(",".join(missing))
            )
        for module, path in paths.items():
            vermagic = self._run_output(
                [self.modinfo, "-F", "vermagic", str(path)]
            )
            if not vermagic or vermagic.split()[0] != self.kernel:
                raise ProvisionError(
                    "built {} vermagic {!r} does not match {}".format(
                        module, vermagic, self.kernel
                    )
                )
            if self.signature_enforced():
                signer = self._run_output(
                    [self.modinfo, "-F", "signer", str(path)]
                )
                if not signer:
                    raise ProvisionError(
                        (
                            "built {} is unsigned while signature enforcement "
                            "is active"
                        ).format(module)
                    )
        return paths

    def install_built_modules(self, paths, preloaded):
        destination = (
            self.root / "lib/modules" / self.kernel / "updates/sonic-csonic"
        )
        destination.mkdir(parents=True, exist_ok=True)
        backups = {}
        installed = []
        try:
            for module, source in paths.items():
                target = destination / source.name
                backup = destination / (source.name + ".previous")
                if target.exists():
                    shutil.copy2(str(target), str(backup))
                    backups[target] = backup
                else:
                    backups[target] = None
                temporary = destination / (
                    source.name + ".new.{}".format(os.getpid())
                )
                shutil.copy2(str(source), str(temporary))
                os.chmod(str(temporary), 0o644)
                os.replace(str(temporary), str(target))
                installed.append(target)
            self.runner.run([self.depmod, "-a", self.kernel])
            self.load_modules(tuple(paths))
        except Exception:
            for module in reversed(tuple(paths)):
                if module not in preloaded and self.module_loaded(module):
                    self.runner.run([self.modprobe, "-r", module], check=False)
            for target in installed:
                backup = backups[target]
                if backup is None:
                    try:
                        target.unlink()
                    except FileNotFoundError:
                        pass
                else:
                    os.replace(str(backup), str(target))
            self.runner.run([self.depmod, "-a", self.kernel], check=False)
            raise
        finally:
            for backup in backups.values():
                if backup is not None:
                    try:
                        backup.unlink()
                    except FileNotFoundError:
                        pass

    def compile_exact_source(self, modules):
        binary, source, version = self.source_identity()
        print(
            "Building {} from exact distro source {}={}".format(
                ",".join(modules), source, version
            )
        )
        self.install_build_dependencies()
        workdir = Path(tempfile.mkdtemp(prefix="csonic-kmodules-"))
        try:
            tree = self.source_tree(workdir, binary, source, version)
            self.prepare_source(tree, modules)
            paths = self.build_modules(tree, modules)
            preloaded = {
                module for module in modules if self.module_loaded(module)
            }
            self.install_built_modules(paths, preloaded)
        finally:
            if self.keep_workdir:
                print("Keeping build directory {}".format(workdir))
            else:
                shutil.rmtree(str(workdir), ignore_errors=True)

    def ensure(self, modules):
        modules = tuple(dict.fromkeys(modules))
        unsupported = [
            module for module in modules if module not in BUILD_CONFIG
        ]
        if unsupported:
            raise ProvisionError(
                "unsupported module(s): {}".format(",".join(unsupported))
            )

        missing = [
            module for module in modules if not self.module_available(module)
        ]
        if not missing:
            self.load_modules(modules)
            print("Loaded installed module(s): {}".format(",".join(modules)))
            return

        print("Missing module(s): {}".format(",".join(missing)))
        self.refresh_apt()
        if self.package_available():
            # An available exact signed package is authoritative. If install
            # or load fails, return an error instead of masking it by building.
            self.install_exact_package()
            self.load_modules(modules)
            print("Loaded module(s) from {}".format(self.package_name()))
            return

        print(
            (
                "Exact package {} is unavailable; using exact-source build "
                "fallback"
            ).format(self.package_name())
        )
        self.compile_exact_source(missing)
        self.load_modules(modules)
        print(
            "Loaded module(s) after exact-source build: {}".format(
                ",".join(modules)
            )
        )


def probe_team(image, runner=None):
    runner = runner or Runner()
    suffix = str(os.getpid())
    team_name = ("cstp" + suffix)[-15:]
    container = "csonic-team-probe-{}".format(suffix)
    payload = r"""set -e
teamd -d -t "$1" -c '{"runner":{"name":"loadbalance"}}'
out=$(teamdctl "$1" state dump)
printf '%s\n' "$out"
printf '%s' "$out" | grep -q '"kernel_team_mode_name": "loadbalance"'
pkill -TERM -x teamd
for i in $(seq 1 20); do
    ! ip link show "$1" >/dev/null 2>&1 && exit 0
    sleep 0.25
done
exit 1"""
    error = None
    try:
        runner.run(
            [
                "docker",
                "run",
                "--name",
                container,
                "--rm",
                "--privileged",
                "--network",
                "host",
                "--entrypoint",
                "bash",
                image,
                "-lc",
                payload,
                "csonic-team-probe",
                team_name,
            ],
            timeout=90,
        )
    except (ProvisionError, subprocess.TimeoutExpired, OSError) as caught:
        error = caught
    finally:
        runner.run(["docker", "rm", "-f", container], check=False)
        runner.run(["ip", "link", "del", team_name], check=False)
    if error is not None:
        raise ProvisionError(
            "disposable team/loadbalance probe failed for image {}".format(
                image
            )
        )
    print("Disposable team/loadbalance probe passed")


def cleanup_stale_apt_sources(root=Path("/")):
    source_dir = root / "etc/apt/sources.list.d"
    for pattern in (
        "csonic-kernel-build-*.list",
        "csonic-kernel-build-*.sources",
    ):
        for path in source_dir.glob(pattern):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def interrupted(signum, _frame):
    raise ProvisionError("interrupted by signal {}".format(signum))


@contextlib.contextmanager
def provisioning_lock(
    path="/var/lock/csonic-kernel-modules.lock", timeout=900
):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+") as handle:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ProvisionError(
                        "timed out waiting for kernel-module provisioning lock"
                    )
                time.sleep(1)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    ensure = subparsers.add_parser("ensure")
    ensure.add_argument("modules", nargs="+", default=DEFAULT_MODULES)
    ensure.add_argument("--keep-workdir", action="store_true")
    probe = subparsers.add_parser("probe-team")
    probe.add_argument("--image", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        with provisioning_lock():
            if args.action == "ensure":
                cleanup_stale_apt_sources()
                ModuleProvisioner(keep_workdir=args.keep_workdir).ensure(
                    args.modules
                )
            else:
                probe_team(args.image)
    except (ProvisionError, subprocess.TimeoutExpired, OSError) as error:
        print(
            "cSONiC kernel-module setup failed: {}".format(error),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
