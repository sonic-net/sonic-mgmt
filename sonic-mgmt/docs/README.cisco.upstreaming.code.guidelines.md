# Upstreaming Code to sonic-mgmt: Pytest and SPyTest Contributions

**Engineer's Guide — Internal Review → Upstream Contribution Workflow**

Version 1.0 | March 2026 | *CONFIDENTIAL — Internal Use Only*

---

## Table of Contents

1. [Overview](#1-overview)
2. [Phase 1: Internal Review and Approval](#2-phase-1-internal-review-and-approval)
3. [Phase 2: Upstream Contribution to sonic-net/sonic-mgmt](#3-phase-2-upstream-contribution-to-sonic-netsonic-mgmt)
4. [Code Quality Guidelines](#4-code-quality-guidelines)
5. [End-to-End Workflow Summary](#5-end-to-end-workflow-summary)
6. [Common Pitfalls and Troubleshooting](#6-common-pitfalls-and-troubleshooting)
7. [Key Reference Links](#7-key-reference-links)
8. [Appendix A: Commit Message Template](#appendix-a-commit-message-template)
9. [Appendix B: Internal PR Description Template](#appendix-b-internal-pr-description-template)
10. [Appendix C: Upstream PR Description Template](#appendix-c-upstream-pr-description-template)

---

## 1. Overview

This document provides a step-by-step guide for engineers to contribute pytest and SPyTest automation code to the upstream SONiC **sonic-mgmt** repository hosted at [github.com/sonic-net/sonic-mgmt](https://github.com/sonic-net/sonic-mgmt). It covers the two-phase workflow required: first, submitting and getting approval through our **internal sonic-mgmt repository**, and then creating the upstream pull request to the SONiC community.

### 1.1 Audience

This guide is intended for test automation engineers, QA engineers, and developers who write pytest-based test cases or SPyTest scripts for SONiC features and need to contribute them to the open-source sonic-mgmt repository.

### 1.2 Prerequisites

- A GitHub account with two-factor authentication enabled
- Git installed locally with SSH keys configured for GitHub
- Familiarity with Python, pytest, and the SONiC testbed infrastructure
- Access to the internal sonic-mgmt repository
- Signed Individual Contributor License Agreement (ICLA) via the Linux Foundation EasyCLA process

### 1.3 Repository Structure at a Glance

The upstream sonic-mgmt repository is organized into several key directories. Understanding this structure is essential for placing your contributions correctly.

| Directory | Purpose |
|---|---|
| `tests/` | Pytest and pytest-ansible based test infrastructure and test scripts. All new pytest-based tests go here. |
| `spytest/` | SPyTest framework, feature APIs, TextFSM templates, and SPyTest test scripts. SPyTest tests go under `spytest/tests/`. |
| `ansible/` | Testbed deployment, setup playbooks, and legacy automation code. |
| `docs/` | Test plans, testbed documentation, and pytest organization docs. |
| `test_reporting/` | Parsing, uploading, and processing JUnit XML test reports. |
| `.azure-pipelines/` | CI pipeline definitions for Azure DevOps. |

---

## 2. Phase 1: Internal Review and Approval

Before any code can be submitted upstream, it must first go through an **internal review cycle**. This ensures code quality, consistency with our test standards, and alignment with the team's testing strategy.

### 2.1 Prepare Your Code Locally

**1. Clone the internal repository**

Clone the internal sonic-mgmt repository if you haven't already. Ensure your local clone is up to date with the latest main/master branch.

```bash
git clone <internal-sonic-mgmt-repo-url>
cd sonic-mgmt
git checkout master && git pull origin master
```

**2. Create a feature branch**

Use a descriptive branch name that reflects the feature or test area.

```bash
git checkout -b <your-username>/<feature-or-test-name>
```

Example: `git checkout -b sonic_dev/bgp-route-advertisement-tests`

**3. Develop your test code**

Write or update your pytest or SPyTest scripts following the guidelines in [Section 4](#4-code-quality-guidelines).

**4. Commit your changes**

Follow the SONiC commit message format with a `Signed-off-by` line.

```
[component/folder touched]: Description of your changes

[List of changes]

Signed-off-by: Your Name <your@email.com>
```

Example:

```
tests/bgp: Add BGP route advertisement pytest cases

* Added test_bgp_route_advertisement.py with prefix propagation tests
* Added conftest.py fixtures for multi-neighbor topology
* Updated docs/testplan/bgp_route_advertisement_testplan.md

Signed-off-by: sonic_dev <sonic_dev@company.com>
```

**5. Push to the internal remote**

```bash
git push origin <your-username>/<feature-or-test-name>
```

### 2.2 Create an Internal Pull Request

1. **Open a PR:** Navigate to the internal sonic-mgmt repository and create a pull request from your feature branch to the master/main branch.
2. **Fill in the PR template:** Provide a clear summary, type of change (test case new/improvement, framework new/improvement, or bug fix), approach, and testbed topology information.
3. **Assign reviewers:** Add appropriate team members as reviewers. At minimum, include your tech lead and one peer from the test automation team.
4. **Link related items:** Reference any internal tracking tickets, Jira issues, or test plan documents.

### 2.3 Internal Review Checklist

Reviewers will evaluate the PR against the following criteria:

- [ ] Code follows Python and pytest best practices (PEP 8, proper fixtures, parametrization)
- [ ] Test cases have appropriate topology markers (e.g., `@pytest.mark.topology('t0', 't1')`)
- [ ] No proprietary or confidential information is included in the code
- [ ] All hardcoded values are replaced with configurable parameters or fixtures
- [ ] Tests pass successfully on the internal testbed
- [ ] Documentation and test plan (if applicable) are included
- [ ] No vendor-specific or platform-specific assumptions unless properly guarded
- [ ] SPyTest scripts use proper Feature API abstractions and TextFSM templates
- [ ] Pre-commit checks pass (flake8, pylint as configured in the repo)

> **⚠️ Important:** Ensure that no internal IP addresses, hostnames, credentials, proprietary API endpoints, or internal tool references exist anywhere in the code before marking the PR as ready for upstream.

### 2.4 Approval and Merge

Once all reviewers have approved and all CI checks pass, the internal PR will be merged into the internal master branch. At this point, the code is cleared for upstream submission. Your tech lead or team lead will **explicitly confirm** the upstream go-ahead.

> **📝 Note:** Keep a record of the internal PR number and approval confirmation. You may need to reference it during the upstream PR process.

---

## 3. Phase 2: Upstream Contribution to sonic-net/sonic-mgmt

After internal approval, you can proceed to submit your code to the upstream SONiC community repository. This phase involves interacting with the open-source community and the Linux Foundation's CLA process.

### 3.1 One-Time Setup: Sign the CLA

All contributors to SONiC repositories must sign an **Individual Contributor License Agreement (ICLA)** before their first contribution can be accepted. This is managed through the Linux Foundation's [EasyCLA](https://docs.linuxfoundation.org/lfx/easycla) system.

1. **Submit your first PR:** When you create your first pull request on any sonic-net repository, the EasyCLA bot will automatically check your CLA status.
2. **Follow the EasyCLA prompts:** If you have not signed the ICLA, the bot will display a link. Click it to navigate to the CLA Contributor Console.
3. **Sign the ICLA:** Choose "Proceed as an Individual Contributor," review the embargo compliance terms, and sign the document via DocuSign.
4. **Verify status:** After signing, return to your PR. Refresh the page and the EasyCLA check should now show a green check mark. If it does not update, comment `/easycla` on the PR to re-trigger the check.

> **📝 Note:** The ICLA only needs to be signed once. It covers all future contributions to any sonic-net repository.

### 3.2 Fork and Clone the Upstream Repository

**1. Fork the repo**

Go to [https://github.com/sonic-net/sonic-mgmt](https://github.com/sonic-net/sonic-mgmt) and click the **"Fork"** button in the upper-right corner. This creates a copy of the repository under your GitHub account.

**2. Clone your fork**

```bash
git clone https://github.com/<your-github-username>/sonic-mgmt.git
cd sonic-mgmt
```

**3. Add the upstream remote**

```bash
git remote add upstream https://github.com/sonic-net/sonic-mgmt.git
```

**4. Sync with upstream**

Always sync before starting work to avoid conflicts.

```bash
git fetch upstream
git checkout master
git merge upstream/master
```

### 3.3 Prepare Your Upstream Branch

1. **Create a clean branch** based on the latest upstream master:
   ```bash
   git checkout -b <descriptive-branch-name>
   ```

2. **Cherry-pick or apply your changes:** Apply only the commits that were approved in the internal review. Do not include any internal-only configurations or references.

3. **Verify the commit message format:** Ensure each commit follows the SONiC standard format with the `Signed-off-by` line.

4. **Run pre-commit checks locally:** The sonic-mgmt repo includes pre-commit hook configurations. Ensure your changes pass all linting and static analysis checks.
   ```bash
   pre-commit run --all-files
   ```

### 3.4 Create the Upstream Pull Request

**1. Push to your fork**

```bash
git push origin <descriptive-branch-name>
```

**2. Open a PR**

Navigate to your fork on GitHub. You will see a prompt to create a pull request against `sonic-net/sonic-mgmt` master. Click **"Compare & pull request."**

**3. Fill in the PR description**

The upstream PR template requires the following information:

| Field | What to Include |
|---|---|
| **Summary** | Concise description of the test cases or framework changes being contributed. |
| **Fixes # (issue)** | Link to a GitHub issue if this PR addresses one. Create an issue first if none exists. |
| **Type of change** | Select: Bug fix, Testbed and Framework (new/improvement), or Test case (new/improvement). |
| **Approach** | Describe motivation, implementation approach, verification steps, platform-specific info, and supported testbed topology. |

**4. Add labels**

Tag the PR appropriately with feature labels (e.g., BGP, ACL, LAG) and the relevant topology tags.

**5. Wait for CI and EasyCLA**

Automated Azure DevOps pipelines and the EasyCLA bot will run checks. Address any failures promptly.

**6. Engage with community review**

Upstream maintainers and community members will review the code. Respond to comments professionally, make requested changes, and push updates to the same branch.

> **💡 Tip:** Merges are performed only by the upstream repository maintainers. Be patient but follow up regularly if the review stalls.

---

## 4. Code Quality Guidelines

### 4.1 Pytest Test Scripts (`tests/` directory)

When contributing pytest-based tests to the `tests/` directory, follow these conventions:

- Every test case must have a **topology marker**: `@pytest.mark.topology('t0')`, `@pytest.mark.topology('t1')`, `@pytest.mark.topology('any')`, etc.
- **Feature markers** are recommended: `@pytest.mark.feature('bgp')`, `@pytest.mark.feature('acl')`
- Use **pytest fixtures** (`conftest.py`) for setup and teardown. Module-scoped fixtures are preferred for testbed-level configuration.
- Leverage the **pytest-ansible plugin** to interact with DUTs. The plugin bridges pytest with Ansible modules for device interaction.
- Use the **LogAnalyzer** utility for syslog validation during test execution.
- Generate **JUnit XML reports** with the `--junitxml` flag for CI integration.
- Keep test functions focused and atomic — one test function should validate one specific behavior.
- Store test plans as markdown files under `docs/testplan/`.

### 4.2 SPyTest Scripts (`spytest/` directory)

SPyTest is a SONiC test automation framework built on top of pytest, primarily contributed and maintained by Broadcom. When contributing SPyTest scripts, follow these conventions:

- Test scripts reside under `spytest/tests/<feature_area>/` (e.g., `spytest/tests/routing/BGP/`).
- Use the **SPyTest Feature API layer** (under `spytest/apis/`) to interact with SONiC features. These APIs abstract CLI interactions and support multiple UI types (click, klish, REST).
- Use **TextFSM templates** (under `spytest/templates/`) for parsing CLI output into structured data.
- Leverage the `spytest.st` module for framework functions: `st.log()`, `st.report_pass()`, `st.report_fail()`, `st.ensure_min_topology()`, etc.
- Mark tests with **inventory decorators**: `@pytest.mark.inventory(feature='...', release='...', testcases=['...'])`
- Use the **TGen API** (`spytest/tgapi`) for traffic generation when tests require traffic validation.
- Ensure no hardcoded DUT IPs, credentials, or platform-specific paths are present in test scripts.

### 4.3 General Guidelines

- Follow **PEP 8** and the flake8/pylint configuration present in the repo (`.flake8`, `pylintrc`, `pyproject.toml`).
- Do not include any proprietary or vendor-internal tooling references.
- Use **Python 3** syntax throughout. The sonic-mgmt docker container supports Python 3.
- Include **docstrings** for test functions describing what is being validated.
- Keep imports clean and organized. Avoid wildcard imports.

---

## 5. End-to-End Workflow Summary

| # | Step | Action | Owner |
|---|---|---|---|
| 1 | **Develop** | Write pytest/SPyTest code on a local feature branch. | Engineer |
| 2 | **Internal PR** | Create PR in the internal sonic-mgmt repo. Fill template, assign reviewers. | Engineer |
| 3 | **Internal Review** | Reviewers evaluate code quality, test coverage, and compliance. Iterate on feedback. | Engineer + Reviewers |
| 4 | **Internal Merge** | After approval, merge into internal master. Get explicit upstream go-ahead from lead. | Tech Lead |
| 5 | **Sign CLA** | Sign the ICLA via EasyCLA (one-time only). | Engineer |
| 6 | **Fork & Sync** | Fork sonic-net/sonic-mgmt, clone, and sync with upstream master. | Engineer |
| 7 | **Upstream PR** | Create PR against sonic-net/sonic-mgmt master. Fill the community PR template. | Engineer |
| 8 | **Community Review** | Address community review comments. Push updates to the same branch on your fork. | Engineer + Community |
| 9 | **Upstream Merge** | Repository maintainer merges the PR after all checks pass and reviews are complete. | Upstream Maintainer |

---

## 6. Common Pitfalls and Troubleshooting

### 6.1 EasyCLA Issues

- If the EasyCLA check does not update after signing, comment `/easycla` on the PR to re-trigger the bot.
- Ensure the email address on your Git commits matches the one used to sign the ICLA.
- If contributing on behalf of your employer, your company may need a Corporate CLA (CCLA) in addition to your individual agreement. Coordinate with your legal team if needed.

### 6.2 CI Pipeline Failures

- The upstream repo runs Azure DevOps pipelines. Pre-commit checks enforce flake8 and other linting rules. Run `pre-commit run --all-files` locally before pushing.
- If the CI detects issues in files you did not modify, note that the pre-commit framework may flag pre-existing issues. Fix them if possible, but it is not mandatory for old issues.

### 6.3 Merge Conflicts

- If your PR has conflicts with the upstream master, **rebase** your branch:
  ```bash
  git fetch upstream
  git rebase upstream/master
  ```
  Resolve conflicts, then force-push:
  ```bash
  git push --force-with-lease origin <branch>
  ```
- **Do not** merge `upstream/master` into your branch. Rebasing produces a cleaner commit history preferred by the community.

### 6.4 Stale Reviews

- If your upstream PR has not received review attention within a week, post a polite follow-up comment on the PR.
- You can also raise visibility by mentioning the PR in the [SONiC community mailing list](https://lists.sonicfoundation.dev/g/sonic-dev) or the weekly community meeting.

---

## 7. Key Reference Links

| Resource | URL |
|---|---|
| Upstream sonic-mgmt repo | https://github.com/sonic-net/sonic-mgmt |
| SONiC Contributor Guide | https://github.com/sonic-net/SONiC/wiki/Becoming-a-contributor |
| EasyCLA Portal | https://docs.linuxfoundation.org/lfx/easycla |
| SONiC GitHub Flow Guide | https://guides.github.com/introduction/flow/ |
| SONiC Community Mailing List | https://lists.sonicfoundation.dev/g/sonic-dev |
| SONiC Pytest Organization | https://github.com/sonic-net/sonic-mgmt/blob/master/docs/tests/pytest.org.md |
| SPyTest Documentation | https://github.com/sonic-net/sonic-mgmt/blob/master/spytest/Doc/intro.md |
| SONiC HLD Template | https://github.com/sonic-net/SONiC/blob/master/doc/hld_template.md |
| SONiC Community Meetings | https://sonic-net.github.io/SONiC/Calendar.html |

---

## Appendix A: Commit Message Template

```
[component/folder touched]: Short description of intent

* Change item 1
* Change item 2
* Change item 3

Signed-off-by: Your Full Name <your-email@company.com>
```

---

## Appendix B: Internal PR Description Template

Use the following structure when creating internal PRs:

```markdown
## Summary
Brief description of what is being added/changed.

## Type of Change
- [ ] Bug fix
- [ ] Testbed and Framework (new/improvement)
- [ ] Test case (new/improvement)

## Approach
- **Motivation:** Why are these tests needed?
- **Implementation:** How are the tests structured?
- **Verification:** How were the tests validated?
- **Topology:** Which testbed topology is required? (t0, t1, t2, etc.)

## Upstream Intent
- [ ] Yes, this code is intended for upstream contribution
- Target upstream branch: master

## Checklist
- [ ] Code passes flake8/pylint locally
- [ ] No proprietary/internal references
- [ ] Commit messages follow SONiC format
- [ ] Test plan doc included (if applicable)
- [ ] ICLA signed for upstream contribution
```

---

## Appendix C: Upstream PR Description Template

The upstream sonic-net/sonic-mgmt repository expects the following PR format:

```markdown
## Description of PR

### Summary:
Fixes # (issue)

### Type of change
- [ ] Bug fix
- [ ] Testbed and Framework(new/improvement)
- [ ] Test case(new/improvement)

### Approach
**What is the motivation for this PR?**

**How did you do it?**

**How did you verify/test it?**

**Any platform specific information?**

**Supported testbed topology if it's a new test case?**

### Documentation
```

---

*End of Document*
