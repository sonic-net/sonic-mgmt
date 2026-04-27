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
