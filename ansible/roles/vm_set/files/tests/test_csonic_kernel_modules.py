import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).parents[1] / "csonic_kernel_modules.py"
SPEC = importlib.util.spec_from_file_location(
    "csonic_kernel_modules", MODULE_PATH
)
KMOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KMOD)


class Result:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


class FakeRunner:
    def __init__(self, root, available=(), package_available=False):
        self.root = Path(root)
        self.available = set(available)
        self.package_available = package_available
        self.commands = []
        self.fail_install = False

    def run(self, command, **kwargs):
        command = [str(part) for part in command]
        self.commands.append(command)
        check = kwargs.get("check", True)
        rc = 0
        stdout = ""
        executable = Path(command[0]).name
        if command == ["uname", "-r"]:
            stdout = "6.8.0-test\n"
        elif executable == "modinfo":
            module = command[-1]
            if module not in self.available:
                rc = 1
            elif command[1:3] == ["-F", "filename"]:
                stdout = "/lib/modules/6.8.0-test/{}.ko\n".format(module)
            elif command[1:3] == ["-F", "vermagic"]:
                stdout = "6.8.0-test SMP mod_unload\n"
            elif command[1:3] == ["-F", "signer"]:
                stdout = "test signer\n"
        elif executable == "modprobe" and "-r" not in command:
            module = command[-1]
            if module not in self.available:
                rc = 1
            else:
                (self.root / "sys/module" / module).mkdir(
                    parents=True, exist_ok=True
                )
        elif command[:3] == ["apt-cache", "show", "--no-all-versions"]:
            if command[-1].startswith("linux-image-unsigned-"):
                stdout = (
                    "Package: {}\nSource: linux-test\n"
                    "Version: 6.8.0-test.1\n"
                ).format(command[-1])
            elif self.package_available:
                stdout = "Package: {}\n".format(command[-1])
            else:
                rc = 100
        elif executable == "apt-get" and "install" in command:
            if self.fail_install:
                rc = 100
            else:
                self.available.update(("team", "team_mode_loadbalance", "vrf"))
        result = Result(rc, stdout)
        if check and rc:
            raise KMOD.ProvisionError("fake command failed")
        return result


class ModuleProvisionerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "sys/module/module/parameters").mkdir(parents=True)
        (self.root / "sys/module/module/parameters/sig_enforce").write_text(
            "0\n"
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def provisioner(self, available=(), package_available=False):
        runner = FakeRunner(self.root, available, package_available)
        return KMOD.ModuleProvisioner(runner=runner, root=self.root), runner

    def test_loads_installed_modules_without_apt_or_build(self):
        provisioner, runner = self.provisioner(
            ("team", "team_mode_loadbalance")
        )
        with mock.patch.object(provisioner, "compile_exact_source") as build:
            provisioner.ensure(("team", "team_mode_loadbalance"))
        build.assert_not_called()
        self.assertFalse(
            any(command[0] == "apt-get" for command in runner.commands)
        )
        self.assertTrue(provisioner.module_loaded("team_mode_loadbalance"))

    def test_installs_exact_package_when_module_is_missing(self):
        provisioner, runner = self.provisioner(package_available=True)
        with mock.patch.object(provisioner, "compile_exact_source") as build:
            provisioner.ensure(("team", "team_mode_loadbalance"))
        build.assert_not_called()
        self.assertTrue(
            any(
                "linux-modules-extra-6.8.0-test" in command
                for command in runner.commands
            )
        )
        self.assertTrue(provisioner.module_loaded("team"))

    def test_compiles_only_when_exact_package_is_unavailable(self):
        provisioner, runner = self.provisioner(package_available=False)

        def make_available(modules):
            runner.available.update(modules)

        with mock.patch.object(
            provisioner, "compile_exact_source", side_effect=make_available
        ) as build:
            provisioner.ensure(("team", "team_mode_loadbalance"))
        build.assert_called_once_with(["team", "team_mode_loadbalance"])
        self.assertTrue(provisioner.module_loaded("team_mode_loadbalance"))

    def test_package_install_error_is_not_hidden_by_source_build(self):
        provisioner, runner = self.provisioner(package_available=True)
        runner.fail_install = True
        with mock.patch.object(provisioner, "compile_exact_source") as build:
            with self.assertRaises(KMOD.ProvisionError):
                provisioner.ensure(("team", "team_mode_loadbalance"))
        build.assert_not_called()

    def test_rejects_unknown_module(self):
        provisioner, _ = self.provisioner()
        with self.assertRaisesRegex(KMOD.ProvisionError, "unsupported module"):
            provisioner.ensure(("not_a_module",))

    def test_signature_enforcement_rejects_unsigned_module(self):
        provisioner, runner = self.provisioner(("team",))
        (self.root / "sys/module/module/parameters/sig_enforce").write_text(
            "1\n"
        )
        original_run = runner.run

        def unsigned(command, **kwargs):
            result = original_run(command, **kwargs)
            if [str(part) for part in command][1:3] == ["-F", "signer"]:
                return Result(0, "")
            return result

        runner.run = unsigned
        with self.assertRaisesRegex(KMOD.ProvisionError, "unsigned"):
            provisioner.ensure(("team",))

    def test_source_identity_uses_unambiguous_kernel_binary(self):
        provisioner, runner = self.provisioner()
        self.assertEqual(
            provisioner.source_identity(),
            (
                "linux-image-unsigned-6.8.0-test",
                "linux-test",
                "6.8.0-test.1",
            ),
        )
        self.assertIn(
            "linux-image-unsigned-6.8.0-test",
            runner.commands[-1],
        )

    def test_deb_and_deb822_sources_use_their_native_file_formats(self):
        apt = self.root / "etc/apt"
        source_dir = apt / "sources.list.d"
        source_dir.mkdir(parents=True)
        (apt / "sources.list").write_text(
            "deb http://archive.example/ubuntu jammy main\n"
            "deb https://third-party.example/repo stable main\n"
        )
        (source_dir / "vendor.sources").write_text(
            "Types: deb\nURIs: https://vendor.example/repo\n"
            "Suites: stable\nComponents: main\n"
        )
        provisioner, _ = self.provisioner()
        with mock.patch.object(provisioner, "refresh_apt"):
            with provisioner.temporary_deb_src(
                {
                    "http://archive.example/ubuntu",
                    "https://vendor.example/repo",
                }
            ):
                generated_list = list(
                    source_dir.glob("csonic-kernel-build-*.list")
                )
                generated_sources = list(
                    source_dir.glob("csonic-kernel-build-*.sources")
                )
                self.assertEqual(len(generated_list), 1)
                self.assertEqual(len(generated_sources), 1)
                self.assertTrue(
                    generated_list[0].read_text().startswith("deb-src ")
                )
                self.assertNotIn(
                    "third-party.example", generated_list[0].read_text()
                )
                self.assertTrue(
                    generated_sources[0]
                    .read_text()
                    .startswith("Types: deb-src")
                )
            self.assertFalse(list(source_dir.glob("csonic-kernel-build-*")))

    def test_stale_generated_source_entries_are_removed(self):
        source_dir = self.root / "etc/apt/sources.list.d"
        source_dir.mkdir(parents=True)
        stale = source_dir / "csonic-kernel-build-123.list"
        unrelated = source_dir / "operator.list"
        stale.write_text("deb-src stale\n")
        unrelated.write_text("deb operator\n")
        KMOD.cleanup_stale_apt_sources(self.root)
        self.assertFalse(stale.exists())
        self.assertTrue(unrelated.exists())


class ProbeTests(unittest.TestCase):
    def test_probe_always_cleans_container_and_link(self):
        runner = mock.Mock()
        runner.run.side_effect = [
            subprocess.TimeoutExpired("docker", 90),
            None,
            None,
        ]
        with self.assertRaisesRegex(KMOD.ProvisionError, "probe failed"):
            KMOD.probe_team("docker-sonic-vs:test", runner=runner)
        commands = [call.args[0] for call in runner.run.call_args_list]
        self.assertEqual(commands[-2][:3], ["docker", "rm", "-f"])
        self.assertEqual(commands[-1][:3], ["ip", "link", "del"])


if __name__ == "__main__":
    unittest.main()
