# Skip Expiry Workflow Utilities

This directory contains reusable Python components for scheduled workflows that
manage GitHub issue expiry policies for conditional mark entries.

## Current entrypoint

- `run_skip_issue_expiry.py`

## Reusable modules

- `skip_issue_expiry_impl/config.py`: config loading and validation
- `skip_issue_expiry_impl/conditional_marks.py`: extract GitHub issues from `skip` and `xfail` conditions
- `skip_issue_expiry_impl/github_api.py`: GitHub REST API wrapper
- `skip_issue_expiry_impl/expiry.py`: issue expiry state transitions and idempotent notifications

## Local run example

```bash
python tools/skip_expiry/run_skip_issue_expiry.py \
  --repo-root . \
  --config .github/SKIP_EXPIRY_CONFIG.yaml \
  --conditional-mark-dir tests/common/plugins/conditional_mark
```

Required environment variables:

- `GITHUB_TOKEN`
- Optional: `SKIP_EXPIRY_BOT_LOGIN` (defaults to `github-actions[bot]`)
- Optional: `GITHUB_REPOSITORY` (used as default for `--target-repo`)

## Branches scanned and the expired label

Issues are collected from the conditional marks on `master` and on every
release branch that `.github/SKIP_EXPIRY_CONFIG.yaml` selects (the same set
the close guard protects), so an issue referenced only on a release branch is
still evaluated for expiry. Each branch is fetched into `--repo-root` as
`origin/<branch>` and its conditional mark files are read from git objects, so
the scan never checks anything out or touches the working tree. A mark file
that fails to parse on any branch fails the scan, and a failed or empty scan
removes no labels.

`skip-wf-issue-expired` therefore marks an open issue that some branch still
references. If the label is removed by hand from an issue the workflow has
already expired, the next run puts it back (without repeating the expiry
comment). When no scanned branch references a labelled issue any more, the
workflow removes the label and posts a comment carrying
`<!-- skip-expiry:state=unreferenced -->`. The stale-issue workflow
(`close-stale.yml`) exempts this label, so it never closes an issue a skip
still depends on. That relies on `expiry.default_days` in
`.github/SKIP_EXPIRY_CONFIG.yaml` staying below the stale workflow's
`days-before-stale`; `tests/unit_test_close_stale_workflow.py` checks both
this and that the exempted label matches `EXPIRED_LABEL`.

## Cross-repository issue references

Conditional mark files may contain GitHub issue URLs from multiple repositories.
This workflow only mutates issues from a single target repository (`owner/repo`),
which defaults to `GITHUB_REPOSITORY` (or `sonic-net/sonic-mgmt` when unset).

Cross-repo references are detected but skipped to avoid `403` failures when the
workflow token does not have write access outside the target repository.
