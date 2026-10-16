#!/usr/bin/env python3
"""
Run flake8 on the given files, but only report violations introduced
relative to a base commit.

flake8 (like most linters) always checks a file's entire contents, so
touching a single line of a file causes it to re-report every pre-existing
style issue in that file, even on lines the change never touched. This
wrapper reports a violation only if it falls on a line added or modified
between --base and --head, or if it did not exist in the file at --base.
The second rule catches errors a change causes on lines it did not touch,
such as an F821 undefined name at an unchanged use site after its import
was removed.

With --all, the diff filtering is skipped and every tracked Python file in
the repository is linted, for a full-scale run of the CI flake8 gate.

The rulesets below mirror the flake8 hook definitions in
.pre-commit-config.yaml (the tests/common2-specific hook is intentionally
not mirrored here, since those files are filtered out before this runs).
"""
import argparse
import collections
import os
import re
import subprocess
import sys

HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')
VIOLATION_RE = re.compile(r'^(?P<path>[^:]+):(?P<line>\d+):\d+: (?P<message>.*)$')

# Files under these prefixes are linted by their own pre-commit hook and are
# filtered out of the CI pre-commit job; --all skips them too.
EXCLUDED_PREFIXES = ('tests/common2/',)

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


def parse_changed_lines(diff_output):
    """Return the set of new-file line numbers added/modified in `git diff -U0` output."""
    lines = set()
    for line in diff_output.splitlines():
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


def changed_lines(base, head, path):
    """Return the set of line numbers in `path`@head added/modified since base."""
    out = subprocess.run(
        ['git', 'diff', '-U0', base, head, '--', path],
        capture_output=True, text=True, check=True,
    ).stdout
    return parse_changed_lines(out)


def run_flake8(files, flake8_args, stdin=None):
    """Run flake8 and return (stdout, stderr, returncode).

    flake8 exits 0 when clean and 1 when it finds lint violations. Callers
    must pass the result through flake8_failure() so that a flake8 that failed
    to run is not mistaken for a clean result.
    """
    if not files:
        return '', '', 0
    proc = subprocess.run(
        ['flake8'] + flake8_args + files,
        input=stdin, capture_output=True, text=True,
    )
    return proc.stdout, proc.stderr, proc.returncode


def flake8_failure(stdout, stderr, rc):
    """Return an error report if flake8 failed to run, else None.

    Exit status 1 is only a lint result when flake8 actually reported
    violations: an uncaught exception also exits 1, with the traceback on
    stderr and nothing on stdout. Anything other than 0 or 1 is an execution
    error (bad config, plugin load failure), and a negative status means
    flake8 was killed by a signal. Since flake8 is SKIPped in the pre-commit
    run, swallowing any of these would let the build pass with no lint run.
    """
    if rc == 0:
        return None
    if rc == 1 and any(VIOLATION_RE.match(line) for line in stdout.splitlines()):
        return None
    report = ['flake8 failed to run (exit status %d):' % rc]
    for detail in (stderr, stdout):
        if detail.strip():
            report.extend(detail.strip().splitlines())
    return report


def violation_key(path, lineno, message, source_lines):
    """Identify a violation independently of its line number.

    Lines shift when a change adds or removes lines above them, so a
    pre-existing violation is matched by its code/message and the content of
    the line it is on rather than by line number.
    """
    content = source_lines[lineno - 1].strip() if 0 < lineno <= len(source_lines) else ''
    return (path, message, content)


def base_violations(base, path, flake8_args):
    """Return a Counter of violation keys present in `path` at `base`.

    The file is fed to flake8 on stdin under its own name, so the repo's
    .flake8 per-file-ignores/exclude apply exactly as they do at head.
    Returns an empty Counter if the file does not exist at base, or a list
    of report lines if flake8 failed to run.
    """
    show = subprocess.run(
        ['git', 'show', '%s:%s' % (base, path)],
        capture_output=True, text=True,
    )
    if show.returncode != 0:
        return collections.Counter()
    stdout, stderr, rc = run_flake8(
        ['-'], flake8_args + ['--stdin-display-name=%s' % path], stdin=show.stdout)
    failure = flake8_failure(stdout, stderr, rc)
    if failure:
        return failure
    source_lines = show.stdout.splitlines()
    keys = collections.Counter()
    for line in stdout.splitlines():
        m = VIOLATION_RE.match(line)
        if m:
            keys[violation_key(path, int(m.group('line')), m.group('message'), source_lines)] += 1
    return keys


def read_lines(path):
    with open(path, errors='replace') as f:
        return f.read().splitlines()


def filter_violations(output, changed, base_keys, source_lines):
    """Return the lines of flake8 `output` that the change introduced.

    `changed` maps path -> set of modified line numbers. `base_keys` maps
    path -> Counter of violation keys at the base commit; it is only
    consulted for violations on unchanged lines. `source_lines` maps
    path -> the file's lines at head. All three are callables taking a path,
    so the caller can compute them lazily.
    """
    kept = []
    # Each pre-existing violation absorbs at most one matching violation at
    # head, so a change that duplicates an existing violating line is caught.
    remaining = {}
    for line in output.splitlines():
        m = VIOLATION_RE.match(line)
        if not m:
            # Not a per-line violation (e.g. a fatal flake8 error); keep it
            # so problems are never silently swallowed.
            kept.append(line)
            continue
        path, lineno = m.group('path'), int(m.group('line'))
        if lineno in changed(path):
            kept.append(line)
            continue
        if path not in remaining:
            remaining[path] = base_keys(path)
        if isinstance(remaining[path], list):
            # flake8 failed on the base version; the failure is reported once
            # by the caller, so just keep the violation.
            kept.append(line)
            continue
        key = violation_key(path, lineno, m.group('message'), source_lines(path))
        if remaining[path][key] > 0:
            remaining[path][key] -= 1
        else:
            kept.append(line)
    return kept, [v for v in remaining.values() if isinstance(v, list)]


def lint(files, args):
    """Lint `files` with each ruleset; return the report lines to print."""
    report = []
    for ruleset in RULESETS:
        matched = [f for f in files if ruleset['match'](f)]
        if not matched:
            continue
        stdout, stderr, rc = run_flake8(matched, ruleset['args'])
        failure = flake8_failure(stdout, stderr, rc)
        if failure:
            report.extend(failure)
            continue
        if args.all:
            report.extend(stdout.splitlines())
            continue

        changed_cache, base_cache, source_cache = {}, {}, {}

        def changed(path):
            if path not in changed_cache:
                changed_cache[path] = changed_lines(args.base, args.head, path)
            return changed_cache[path]

        def base_keys(path, flake8_args=ruleset['args']):
            if path not in base_cache:
                base_cache[path] = base_violations(args.base, path, flake8_args)
            return base_cache[path]

        def source_lines(path):
            if path not in source_cache:
                source_cache[path] = read_lines(path)
            return source_cache[path]

        kept, base_failures = filter_violations(stdout, changed, base_keys, source_lines)
        report.extend(kept)
        for failure in base_failures:
            report.append('(while linting the --base version for comparison)')
            report.extend(failure)
    return report


def tracked_python_files():
    out = subprocess.run(
        ['git', 'ls-files', '--', '*.py'],
        capture_output=True, text=True, check=True,
    ).stdout
    return [f for f in out.splitlines() if not f.startswith(EXCLUDED_PREFIXES)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base', help='Base commit/ref to diff against (required unless --all)')
    parser.add_argument('--head', default='HEAD', help='Head commit/ref (default: HEAD)')
    parser.add_argument('--all', action='store_true',
                        help='Lint every tracked Python file (except %s) without diff '
                             'filtering; any files given are ignored' % ', '.join(EXCLUDED_PREFIXES))
    parser.add_argument('files', nargs='*', help='Files to lint')
    args = parser.parse_args(argv)
    if not args.all and not args.base:
        parser.error('--base is required unless --all is given')

    if args.all:
        files = tracked_python_files()
    else:
        files = args.files
    # Skip files that no longer exist (e.g. deleted by this change); flake8
    # can't lint them, and they have no "current" lines to report on anyway.
    files = [f for f in files if os.path.isfile(f)]

    report = lint(files, args)
    if report:
        print('\n'.join(report))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
