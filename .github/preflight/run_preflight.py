"""Pre-flight static analysis, reported only on lines the change touched.

This runs on pull requests and, critically, on merge_group events so that it
can gate a GitHub merge queue. The merge queue validates the *result* of
merging a batch, which is the only place a semantic regression between two
independently-green PRs can be caught before it reaches master.

Two properties matter and are enforced here rather than left to each tool:

1. Only files the change touched are analysed.
2. Only findings on lines the change added or modified are reported. A
   pre-existing problem elsewhere in a touched file is dropped. Without this,
   turning on any new tool would immediately fail every pull request: pyright
   alone reports 928 pre-existing errors across the files touched by 14 recent
   commits, of which 8 are on lines those commits actually changed.

Note that a moved or reindented line counts as changed, so a long-standing
problem on a line a change shifts can surface. That is inherent to line-based
filtering and matches how darker and diff-cover behave.

Usage:
    python .github/preflight/run_preflight.py

The commit range is taken from the GitHub event payload. For local runs, set
PREFLIGHT_BASE and PREFLIGHT_HEAD instead, for example:
    PREFLIGHT_BASE=origin/master PREFLIGHT_HEAD=HEAD python .github/preflight/run_preflight.py
"""

import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict

import yaml

CONFIG_PATH = os.environ.get("PREFLIGHT_CONFIG", ".github/preflight/config.yml")
GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME", "")
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH", "")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY", "")

# GitHub renders at most 10 annotations of each level per step. Everything is
# always written to the log and the job summary; this only caps the inline
# annotations so the useful ones are not buried.
MAX_ANNOTATIONS_PER_LEVEL = 10

# Kept out of the list literal it is appended to: implicit string concatenation
# inside a list reads as a possibly-missing comma, and CodeQL flags it as such.
SUMMARY_FOOTER = (
    "_Only lines added or modified by this change are reported; "
    "pre-existing findings elsewhere in the same files are ignored._"
)

# file:line:col: message   (flake8, yamllint --format parsable,
#                           shellcheck --format gcc, ansible-lint --format pep8)
COLON_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+)?:?\s*(?P<msg>.*)$")
# codespell: "path:line: typo ==> correction"
CODESPELL_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):\s*(?P<msg>.*)$")


class Finding:
    def __init__(self, tool, path, line, message):
        self.tool = tool
        self.path = path
        self.line = line
        self.message = " ".join(message.split())

    def __str__(self):
        return f"{self.path}:{self.line}: [{self.tool}] {self.message}"


def run(*argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def git(*argv):
    result = run("git", *argv)
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(argv)} failed: {result.stderr.strip()}")
    return result.stdout


def resolve_commit_range():
    """Return (base_sha, head_sha) for the change under test.

    pull_request: diff against the merge base, so commits landed on the target
    branch after this branch was cut are not attributed to it.
    merge_group:  diff the whole queued batch, which is what will land.
    """
    base = os.environ.get("PREFLIGHT_BASE")
    head = os.environ.get("PREFLIGHT_HEAD")
    if base and head:
        return git("rev-parse", base).strip(), git("rev-parse", head).strip()

    event = {}
    if GITHUB_EVENT_PATH and os.path.exists(GITHUB_EVENT_PATH):
        with open(GITHUB_EVENT_PATH, "r", encoding="utf-8") as handle:
            event = json.load(handle)

    if GITHUB_EVENT_NAME == "merge_group":
        merge_group = event.get("merge_group", {})
        return merge_group["base_sha"], merge_group["head_sha"]

    if GITHUB_EVENT_NAME == "pull_request":
        pull_request = event.get("pull_request", {})
        base_sha = pull_request["base"]["sha"]
        head_sha = pull_request["head"]["sha"]
        merge_base = run("git", "merge-base", base_sha, head_sha)
        if merge_base.returncode == 0 and merge_base.stdout.strip():
            base_sha = merge_base.stdout.strip()
        return base_sha, head_sha

    raise SystemExit(
        f"Cannot determine the commit range for event '{GITHUB_EVENT_NAME}'. "
        "Set PREFLIGHT_BASE and PREFLIGHT_HEAD to run this locally."
    )


def changed_lines(base_sha, head_sha):
    """Return {path: set(line numbers added or modified)}.

    Uses --unified=0 so each hunk header describes exactly the changed lines
    with no surrounding context, and --diff-filter to skip deletions.
    """
    diff = git(
        "diff", "--unified=0", "--no-color", "--no-renames",
        "--diff-filter=ACMR", f"{base_sha}", f"{head_sha}",
    )

    result = defaultdict(set)
    current = None
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            current = raw[len("+++ b/"):]
        elif raw.startswith("+++ "):
            current = None
        elif raw.startswith("@@") and current:
            # @@ -old,count +new,count @@
            match = re.match(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", raw)
            if not match:
                continue
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) else 1
            result[current].update(range(start, start + count))

    return {path: lines for path, lines in result.items() if lines}


def matches_any(path, patterns):
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
        # Allow '*.py' to match at any depth, and 'ansible/**/*.yml' to match
        # 'ansible/foo.yml' as well as 'ansible/a/b/foo.yml'.
        if pattern.startswith("*.") and fnmatch.fnmatch(os.path.basename(path), pattern):
            return True
        if "**/" in pattern and fnmatch.fnmatch(path, pattern.replace("**/", "")):
            return True
    return False


def select_files(paths, spec):
    include = spec.get("include", ["*"])
    exclude = spec.get("exclude", [])
    selected = [
        path for path in sorted(paths)
        if matches_any(path, include) and not matches_any(path, exclude) and os.path.isfile(path)
    ]
    return selected


def parse_colon(tool, stdout):
    findings = []
    for raw in stdout.splitlines():
        match = COLON_RE.match(raw.strip())
        if match:
            findings.append(Finding(tool, match.group("file"), int(match.group("line")), match.group("msg")))
    return findings


def parse_codespell(tool, stdout):
    findings = []
    for raw in stdout.splitlines():
        match = CODESPELL_RE.match(raw.strip())
        if match:
            findings.append(Finding(tool, match.group("file"), int(match.group("line")), match.group("msg")))
    return findings


def parse_pyright_json(tool, stdout):
    findings = []
    try:
        payload = json.loads(stdout or "{}")
    except ValueError:
        return findings

    root = os.getcwd() + os.sep
    for diagnostic in payload.get("generalDiagnostics", []):
        if diagnostic.get("severity") != "error":
            continue
        path = diagnostic.get("file", "")
        if path.startswith(root):
            path = path[len(root):]
        # pyright reports 0-based line numbers.
        line = diagnostic.get("range", {}).get("start", {}).get("line", 0) + 1
        rule = diagnostic.get("rule")
        message = diagnostic.get("message", "").splitlines()[0]
        findings.append(Finding(tool, path, line, f"{message} ({rule})" if rule else message))
    return findings


PARSERS = {
    "colon": parse_colon,
    "codespell": parse_codespell,
    "pyright_json": parse_pyright_json,
}


def invoke(tool, spec, files):
    """Run one tool over its files, honouring per-directory profiles."""
    parser = PARSERS[spec.get("parser", "colon")]
    ok_exit_codes = spec.get("ok_exit_codes", [0, 1])
    profiles = spec.get("profiles")

    if profiles:
        groups = []
        for profile in profiles:
            pattern = re.compile(profile["match"])
            matched = [path for path in files if pattern.search(path)]
            files = [path for path in files if path not in set(matched)]
            if matched:
                groups.append((profile.get("args", []), matched))
    else:
        groups = [(spec.get("args", []), files)] if files else []

    findings = []
    for args, group in groups:
        result = run(tool, *args, *group)
        if result.returncode not in ok_exit_codes:
            # A crashed tool must never look like a clean run.
            raise SystemExit(
                f"::error::{tool} exited with unexpected code {result.returncode}.\n"
                f"stdout:\n{result.stdout[:4000]}\nstderr:\n{result.stderr[:4000]}"
            )
        findings.extend(parser(tool, result.stdout))
    return findings


def main():
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    tools = config.get("tools") or {}

    base_sha, head_sha = resolve_commit_range()
    print(f"Event: {GITHUB_EVENT_NAME or 'local'}")
    print(f"Analysing {base_sha[:12]}..{head_sha[:12]}")

    touched = changed_lines(base_sha, head_sha)
    if not touched:
        print("No added or modified lines. Nothing to analyse.")
        return 0
    print(f"{len(touched)} changed file(s), {sum(len(v) for v in touched.values())} changed line(s).")

    blocking_findings = []
    advisory_findings = []
    skipped = []

    for tool, spec in tools.items():
        files = select_files(touched.keys(), spec)
        if not files:
            continue
        if not shutil.which(tool):
            skipped.append(tool)
            print(f"::warning::{tool} is not installed; skipping.")
            continue

        print(f"\n--- {tool} on {len(files)} file(s) ---")
        found = invoke(tool, spec, files)

        kept = [f for f in found if f.line in touched.get(f.path, set())]
        dropped = len(found) - len(kept)
        print(f"{len(found)} finding(s), {len(kept)} on changed lines ({dropped} pre-existing, ignored).")

        if spec.get("blocking"):
            blocking_findings.extend(kept)
        else:
            advisory_findings.extend(kept)

    emit(blocking_findings, advisory_findings, skipped)
    return 1 if blocking_findings else 0


def emit(blocking, advisory, skipped):
    counts = defaultdict(int)
    for level, findings in (("error", blocking), ("warning", advisory)):
        for finding in findings:
            print(finding)
            if counts[level] < MAX_ANNOTATIONS_PER_LEVEL:
                counts[level] += 1
                print(
                    f"::{level} file={finding.path},line={finding.line},"
                    f"title=preflight/{finding.tool}::{finding.message}"
                )

    def row(finding):
        # Type names such as "list[str] | None" contain pipes, which would
        # otherwise split the markdown table into extra columns.
        message = finding.message.replace("|", "\\|")
        return f"| `{finding.path}` | {finding.line} | {finding.tool} | {message} |"

    header = ["| File | Line | Tool | Finding |", "| --- | --- | --- | --- |"]

    lines = ["## Pre-flight static analysis", ""]
    if not blocking and not advisory:
        lines.append("No findings on the lines this change touches.")
    if blocking:
        lines += [f"### Blocking ({len(blocking)})", ""] + header
        lines += [row(f) for f in blocking]
        lines.append("")
    if advisory:
        lines += [f"### Advisory ({len(advisory)}) — does not fail the check", ""] + header
        lines += [row(f) for f in advisory]
        lines.append("")
    if skipped:
        lines += [f"Skipped (not installed): {', '.join(skipped)}", ""]
    lines += ["", SUMMARY_FOOTER]

    summary = "\n".join(lines)
    if GITHUB_STEP_SUMMARY:
        with open(GITHUB_STEP_SUMMARY, "a", encoding="utf-8") as handle:
            handle.write(summary + "\n")
    print("\n" + summary)


if __name__ == "__main__":
    sys.exit(main())
