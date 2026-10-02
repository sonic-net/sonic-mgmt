"""Tests for the pre-flight changed-lines filter.

The whole value of this check rests on one property: a finding is reported if
and only if it sits on a line the change added or modified. If that regresses,
the check either starts failing pull requests for problems they did not cause,
or stops catching the ones they did.

Run with:
    python .github/preflight/test_preflight.py
"""

import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNNER = os.path.join(REPO_ROOT, ".github", "preflight", "run_preflight.py")
PREFLIGHT_DIR = os.path.join(REPO_ROOT, ".github", "preflight")

# Only flake8 is exercised: it is the tool every contributor already has, and
# the filtering logic under test is tool-independent.
CONFIG = """
tools:
  flake8:
    blocking: true
    include: ['*.py']
    ok_exit_codes: [0, 1]
    parser: colon
    args: ['--max-line-length=120']
"""

# Two pre-existing flake8 violations: an unused import (F401) and a bare
# comparison to None (E711).
BASE_FILE = '''\
import os


def existing():
    value = 1
    if value == None:
        return 1
    return 2
'''

# The pre-existing violations above are untouched. A new E711 is introduced.
CHANGED_FILE = '''\
import os


def existing():
    value = 1
    if value == None:
        return 1
    return 2


def added():
    other = 3
    if other == None:
        return 4
    return 5
'''


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def build_repo(tmp):
    git(tmp, "init", "-q", "-b", "main")
    git(tmp, "config", "user.email", "preflight@example.com")
    git(tmp, "config", "user.name", "preflight")

    with open(os.path.join(tmp, "sample.py"), "w", encoding="utf-8") as handle:
        handle.write(BASE_FILE)
    git(tmp, "add", "-A")
    git(tmp, "commit", "-qm", "base")
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp, capture_output=True,
                          text=True, check=True).stdout.strip()

    with open(os.path.join(tmp, "sample.py"), "w", encoding="utf-8") as handle:
        handle.write(CHANGED_FILE)
    git(tmp, "add", "-A")
    git(tmp, "commit", "-qm", "change")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp, capture_output=True,
                          text=True, check=True).stdout.strip()
    return base, head


def run_preflight(tmp, env_extra):
    config_path = os.path.join(tmp, "config.yml")
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write(CONFIG)

    env = dict(os.environ)
    env["PREFLIGHT_CONFIG"] = config_path
    env.update(env_extra)
    return subprocess.run([sys.executable, RUNNER], cwd=tmp, capture_output=True, text=True, env=env)


def check(condition, label):
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")
    return condition


def main():
    ok = True

    with tempfile.TemporaryDirectory() as tmp:
        base, head = build_repo(tmp)

        print("changed lines only (the core guarantee):")
        result = run_preflight(tmp, {"PREFLIGHT_BASE": base, "PREFLIGHT_HEAD": head})
        out = result.stdout

        # The new violation is on line 13 of the changed file. Assertions use a
        # trailing colon so that "sample.py:1:" cannot match "sample.py:13:".
        ok &= check("sample.py:13:" in out, "reports the E711 introduced by the change")
        # The identical pre-existing violation is on line 6 and must be ignored.
        ok &= check("sample.py:6:" not in out, "ignores the identical pre-existing E711 on line 6")
        ok &= check("sample.py:1:" not in out, "ignores the pre-existing unused import on line 1")
        ok &= check(result.returncode == 1, "fails the check when a blocking finding lands on a changed line")
        ok &= check("1 on changed lines" in out, "counts exactly one finding on changed lines")

        print("\nunchanged tree:")
        result = run_preflight(tmp, {"PREFLIGHT_BASE": head, "PREFLIGHT_HEAD": head})
        ok &= check(result.returncode == 0, "passes when nothing changed")
        ok &= check("Nothing to analyse" in result.stdout, "reports that there is nothing to analyse")

        print("\nmerge_group event wiring:")
        event_path = os.path.join(tmp, "event.json")
        with open(event_path, "w", encoding="utf-8") as handle:
            json.dump({"merge_group": {"base_sha": base, "head_sha": head}}, handle)
        result = run_preflight(tmp, {"GITHUB_EVENT_NAME": "merge_group", "GITHUB_EVENT_PATH": event_path})
        ok &= check(result.returncode == 1, "resolves the range from a merge_group payload")
        ok &= check("sample.py:13:" in result.stdout, "reports the same finding for a merge group")
        ok &= check("sample.py:6:" not in result.stdout, "still ignores pre-existing findings in a merge group")

        print("\npull_request event wiring:")
        with open(event_path, "w", encoding="utf-8") as handle:
            json.dump({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}, handle)
        result = run_preflight(tmp, {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": event_path})
        ok &= check(result.returncode == 1, "resolves the range from a pull_request payload")
        ok &= check("sample.py:13:" in result.stdout, "reports the finding for a pull request")

        print("\nannotations and summary:")
        summary_path = os.path.join(tmp, "summary.md")
        result = run_preflight(tmp, {"PREFLIGHT_BASE": base, "PREFLIGHT_HEAD": head,
                                     "GITHUB_STEP_SUMMARY": summary_path})
        ok &= check("::error file=sample.py,line=13," in result.stdout, "emits a GitHub error annotation")
        with open(summary_path, "r", encoding="utf-8") as handle:
            summary = handle.read()
        ok &= check("### Blocking (1)" in summary, "writes the blocking section to the job summary")

    print("\nconfig sanity:")
    import yaml
    with open(os.path.join(PREFLIGHT_DIR, "config.yml"), "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    tools = config["tools"]
    ok &= check(tools["flake8"]["blocking"] is True, "flake8 is blocking")
    ok &= check(tools["pyright"]["blocking"] is True, "pyright is blocking")
    ok &= check(
        all(not tools[name]["blocking"] for name in ("yamllint", "shellcheck", "ansible-lint", "codespell")),
        "the unmeasured tools start advisory",
    )
    with open(os.path.join(PREFLIGHT_DIR, "pyrightconfig.json"), "r", encoding="utf-8") as handle:
        pyright_config = json.load(handle)
    # pyright silently ignores unknown keys, so a typo disables a check with no warning.
    ok &= check(pyright_config.get("reportPossiblyUnboundVariable") == "error",
                "pyright rule name is reportPossiblyUnboundVariable, not reportPossiblyUnbound")
    ok &= check("reportGeneralTypeIssues" not in pyright_config,
                "reportGeneralTypeIssues is not disabled (it would mask reportCallIssue)")

    print("\n" + ("ALL PASS" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
