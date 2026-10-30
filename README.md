# 🚀 **sonic‑mgmt** – Management & Automation for **SONiC** testbeds  

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3933/badge)](https://bestpractices.coreinfrastructure.org/projects/3933)  
[![LGTM Python Grade](https://img.shields.io/lgtm/grade/python/g/sonic-net/sonic-mgmt.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/sonic-net/sonic-mgmt/context:python)  
[![GitHub stars](https://img.shields.io/github/stars/sonic-net/sonic-mgmt?style=flat)](https://github.com/sonic-net/sonic-mgmt/stargazers)  
[![GitHub forks](https://img.shields.io/github/forks/sonic-net/sonic-mgmt?style=flat)](https://github.com/sonic-net/sonic-mgmt/network)  
[![Open issues](https://img.shields.io/github/issues/sonic-net/sonic-mgmt?style=flat)](https://github.com/sonic-net/sonic-mgmt/issues)  
![License – Custom (⁕ ICLA required)](https://img.shields.io/badge/license-ICLA%20required-lightgrey?style=flat)  

> **Management and automation code used for SONiC test‑bed deployment, tests and reporting**  

---  

## 📚 What is SONiC‑mgmt?  

SONiC‑mgmt is the **central orchestration repository** that drives the entire SONiC test‑bed lifecycle:  

* **Deploy & set‑up** the physical or virtual test‑bed (ansible).  
* **Run functional & performance tests** (pytest + pytest‑ansible).  
* **Collect, parse & ship** JUnit XML test reports to analytics back‑ends (Kusto).  

Ansible is the **core engine** powering all tasks, while pytest has become the **preferred test authoring framework** since 2019.  

---  

## 🗂️ Repository layout  

```
sonic-mgmt/
 ├─ ansible/          # Test‑bed deployment & legacy playbooks
 ├─ docs/             # Human‑readable documentation
 ├─ spytest/          # SPyTest framework & SONiC validation tests
 ├─ test_reporting/   # JUnit parsing, upload & Kusto ingestion
 ├─ tests/            # pytest & pytest‑ansible test suites
 └─ api_wiki/        # How‑to talk to DUT/PTF from localhost
```

(see the full description in the docs README).  

---  

## ⚡ Quick‑Start (local dev)

> **Prerequisites** – Python 3.9+, `pip`, `git`, Docker (optional for containerised test beds).

```bash
# 1️⃣ Clone the repo
git clone https://github.com/sonic-net/sonic-mgmt.git
cd sonic-mgmt

# 2️⃣ Set up a virtual env & install Python deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # (see ansible/requirements.txt)

# 3️⃣ Deploy a test‑bed (example – using a local Docker‑based topology)
ansible-playbook -i inventory/docker inventory/setup.yml

# 4️⃣ Run the test suite
pytest -m "not skip"   # run all non‑skipped tests
```

For a **full‑fledged lab** (real switches/DUTs) follow the *Testbed* guide in `docs/README.md`.  

---  

## 🧪 Running tests with pytest‑ansible  

```bash
# Install the pytest‑ansible plugin (already in requirements.txt)
pip install pytest-ansible

# Execute a single test module against a running testbed
pytest tests/test_vxlan.py::test_vxlan_basic -k "inventory=my_lab"
```

The plugin automatically **re‑uses the Ansible inventory** and modules under the hood, so you get the best of both worlds – declarative device control + Pythonic test logic.  

---  

## 📦 Build & CI  

* **GitHub Actions** – the repository ships a collection of workflows (`sdn.yml`, `codeql-analysis.yml`, `automerge_scan.yml`, …) that automatically **build, lint, run static analysis** and **execute a subset of the test‑suite** on every PR.  
* **CodeQL** – continuously scans the code base for security issues.  

> The CI badge can be added once the workflow stabilises (example placeholder below).  

```markdown
[![CI – Build](https://img.shields.io/github/actions/workflow/status/sonic-net/sonic-mgmt/sdn.yml?branch=master&label=CI&style=flat)](https://github.com/sonic-net/sonic-mgmt/actions)
```

---  

## 📚 Documentation  

All the detailed guides live in the `docs/` folder:

| Section | Description |
|--------|-------------|
| **Ansible** | Device provisioning, inventory layout, custom modules. |
| **Testbed** | Physical vs. Docker‑based labs, network topology files. |
| **pytest** | Writing & debugging pytest‑ansible tests. |
| **Testplan** | Organising test cases, tagging, skip‑logic. |
| **Test Reporting** | JUnit parsing, Kusto upload, query examples. |
| **api_wiki** | Low‑level API contracts (REST, gNMI, etc.). |
| **Spytest** | High‑level framework used by SONiC OSS for regression. |

Full list: `docs/README.md`.  

---  

## 🤝 Contributing  

1. **Read the contributor guide** – it explains the ICLA workflow, GitHub Flow, and commit style.  
2. **Fork** the repo, make your changes, and **open a PR**.  
3. Follow the **standard commit message format** (component/folder : short description, body, Signed‑off‑by).  
4. CI will run automatically; address any failing checks before merging.  

All contributors **must sign the Individual Contributor License Agreement (ICLA)** before any commit can be merged.  

---  

## 📢 Community & Support  

| Channel | Link |
|---------|------|
| **GitHub Discussions** (questions, ideas) | <https://github.com/sonic-net/sonic-mgmt/discussions> |
| **SONiC Slack** (real‑time chat) | <https://sonicnet.slack.com/> |
| **Mailing list** (`sonic-dev@lists.sonicfoundation.dev`) | – |
| **Issue tracker** (bugs & feature requests) | <https://github.com/sonic-net/sonic-mgmt/issues> |

---  

## 📄 License  

The SONiC project uses a **custom license** that requires an **ICLA** for contributors. See the `LICENSE` file in the root of the repository for details.  

---  

## 🛡️ Code of Conduct  

We abide by the **SONiC Community Code of Conduct** – be respectful, constructive, and inclusive. Full text: <https://github.com/sonic-net/.github/blob/main/CODE_OF_CONDUCT.md>.  

---  

## 🎉 Highlights  

* **+200 stars** and **≈1 k forks** – a vibrant community building the most advanced open‑source network OS.  
* **CII Best Practices** badge proves the project meets high‑quality standards.  
* **LGTM Python grade** shows the codebase is clean and well‑maintained.  

---  

*Ready to spin up a SONiC lab, write the next test, or improve the automation framework?*  
**Clone, explore, and start contributing today!**   🚀   🛠️   📈   🤖   💡   🧪   ✨   🏁   🧭   💬   ✅   🤝   🗂️   🖥️   🌐   🧱   📚   🕸️.   Happy hacking!
