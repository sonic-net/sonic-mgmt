# nm-secrets editor

A tiny single-window GUI for rotating the `nm-secrets` Ansible-vault blob
stored in the `SONiC` Azure Key Vault. Replaces the manual `az keyvault
secret download` / `ansible-vault decrypt` / edit / `ansible-vault encrypt`
/ `az keyvault secret set` cycle.

Plaintext secrets are kept in process memory only; nothing is written to
disk.

## Prerequisites

* Windows (the editor relies on `az login` with a Microsoft corp account,
  which is only supported on the corporate Windows desktop).
* Python 3.10+ on PATH.
* Logged in to `az` with a Microsoft corp account that has secret-get/set
  permissions on the `SONiC` Key Vault:

  ```
  az login
  ```

* You may need MSFTVPN / AzVPN connectivity to reach the vault.

## Launching

Double-click **`launch.cmd`**. On the very first run it creates a `.venv`
and installs dependencies (~30 s); subsequent launches are immediate.

The editor fetches both `ansible-vault-passwd` and `nm-secrets`, decrypts
in memory, and presents the JSON in a syntax-friendly text widget.

## Editing

* The editor opens in **read-only** mode (grey background, title bar shows
  `[read-only]`). Click **Edit** (or press `Ctrl+E`) and confirm to enable
  editing; the background turns white and the title shows `[editing]`.
* Edit the JSON directly. `Ctrl+S` (or the **Save** button) validates JSON,
  shows a unified diff, asks for confirmation, then re-encrypts and uploads
  as a new Key Vault version. Old versions are retained automatically.
* After a successful save the window automatically returns to read-only.
* Click **Lock** (or `Ctrl+E`) to discard unsaved edits and return to
  read-only without saving.
* **Reload** discards changes and refetches; the editor reopens read-only.
* Idle for 10 minutes -> automatic quit and buffer wipe.
* Optimistic concurrency: if someone else updated `nm-secrets` between your
  load and save, the upload is refused and you're asked to reload.

## Recovering from a bad save

Key Vault keeps every version of `nm-secrets`. To roll back:

```
az keyvault secret list-versions --vault-name SONiC --name nm-secrets
az keyvault secret show --vault-name SONiC --name nm-secrets \
    --version <previous-version-id> --query value -o tsv > rollback.txt
az keyvault secret set --vault-name SONiC --name nm-secrets --file rollback.txt
rm rollback.txt
```

## Security model

* Authentication uses `AzureCliCredential` -> the same identity as your
  `az login`. No PAT, no service principal, no stored secret.
* The vault password and decrypted JSON live only in Python objects for
  the lifetime of the window; on quit (manual or idle) they are cleared.
* The Ansible-vault format implementation in `vault.py` is verified
  bidirectionally against the upstream `ansible-vault` CLI
  (ansible-core 2.17).
