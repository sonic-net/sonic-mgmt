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

## Cross-repository issue references

Conditional mark files may contain GitHub issue URLs from multiple repositories.
This workflow only mutates issues from a single target repository (`owner/repo`),
which defaults to `GITHUB_REPOSITORY` (or `sonic-net/sonic-mgmt` when unset).

Cross-repo references are detected but skipped to avoid `403` failures when the
workflow token does not have write access outside the target repository.
