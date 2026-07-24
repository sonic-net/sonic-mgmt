#!/usr/bin/env python3
"""
Run flake8 on the given files, but only report violations that fall on
lines added or modified relative to a base commit.

flake8 (like most linters) always checks a file's entire contents, so
touching a single line of a file causes it to re-report every pre-existing
style issue in that file, even on lines the change never touched. This
wrapper filters flake8's output down to only the lines actually changed
between --base and --head, so CI only flags issues introduced by the change.

The rulesets below mirror the flake8 hook definitions in
.pre-commit-config.yaml (the tests/common2-specific hook is intentionally
not mirrored here, since those files are filtered out before this runs).

See: https://github.com/sonic-net/sonic-mgmt/issues/25351
"""
import argparse
import os
import re
import subprocess
import sys

HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')
VIOLATION_RE = re.compile(r'^(?P<path>[^:]+):(?P<line>\d+):\d+: ')

# These mirror the per-hook args in .pre-commit-config.yaml. flake8 also
# auto-discovers the repo's .flake8 file (per-file-ignores, exclude), so those
# are honored here exactly as they are under pre-commit. The '.py' filter is a
# slightly narrower approximation of pre-commit's content-based `types: [python]`
# (it skips extensionless Python scripts), which errs on the safe side of not
# reporting rather than over-reporting.
RULESETS = [
    {
        'match': lambda f: f.endswith('.py') and not f.startswith('spytest/'),
        'args': ['--max-line-length=120'],
    },
    {
        'match': lambda f: f.endswith('.py') and f.startswith('spytest/'),
        'args': ['--max-line-length=120', '--ignore=E1,E2,E3,E5,E7,W5'],
    },
]


def changed_lines(base, head, path):
    """Return the set of line numbers in `path`@head added/modified since base."""
    out = subprocess.run(
        ['git', 'diff', '-U0', base, head, '--', path],
        capture_output=True, text=True, check=True,
    ).stdout
    lines = set()
    for line in out.splitlines():
        m = HUNK_RE.match(line)
        if not m:
            continue
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        if count == 0:
            # Pure deletion hunk; nothing added on the new-file side.
            continue
        lines.update(range(start, start + count))
    return lines


def run_flake8(files, flake8_args):
    """Run flake8 and return (stdout, stderr, returncode).

    flake8 exits 0 when clean and 1 when it finds lint violations; any higher
    exit code means flake8 itself failed to run (bad config, plugin load
    failure, internal error) and typically reports the reason only on stderr.
    Callers must inspect the return code so such failures are not swallowed.
    """
    if not files:
        return '', '', 0
    proc = subprocess.run(
        ['flake8'] + flake8_args + files,
        capture_output=True, text=True,
    )
    return proc.stdout, proc.stderr, proc.returncode


def filter_violations(output, base, head, cache):
    kept = []
    for line in output.splitlines():
        m = VIOLATION_RE.match(line)
        if not m:
            # Not a per-line violation (e.g. a fatal flake8 error); keep it
            # so problems are never silently swallowed.
            kept.append(line)
            continue
        path, lineno = m.group('path'), int(m.group('line'))
        if path not in cache:
            cache[path] = changed_lines(base, head, path)
        if lineno in cache[path]:
            kept.append(line)
    return kept


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, help='Base commit/ref to diff against')
    parser.add_argument('--head', default='HEAD', help='Head commit/ref (default: HEAD)')
    parser.add_argument('files', nargs='*', help='Files to lint')
    args = parser.parse_args()

    # Skip files that no longer exist (e.g. deleted by this change); flake8
    # can't lint them, and they have no "current" lines to report on anyway.
    existing_files = [f for f in args.files if os.path.isfile(f)]

    line_cache = {}
    all_kept = []
    for ruleset in RULESETS:
        files = [f for f in existing_files if ruleset['match'](f)]
        if not files:
            continue
        stdout, stderr, rc = run_flake8(files, ruleset['args'])
        if rc > 1:
            # flake8 failed to run (not a lint finding). Surface its output
            # verbatim and fail the wrapper so the error is never silently
            # swallowed -- otherwise, since flake8 is SKIPped in the
            # pre-commit run, this would let style regressions ship green.
            all_kept.append('flake8 failed to run (exit status %d):' % rc)
            detail = (stderr or stdout).strip()
            if detail:
                all_kept.extend(detail.splitlines())
            continue
        if stdout.strip():
            all_kept.extend(filter_violations(stdout, args.base, args.head, line_cache))

    if all_kept:
        print('\n'.join(all_kept))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
