# sonic-nightly-service (AAD token relay)

Tiny FastAPI service that mints short-lived Azure DevOps access-tokens for
self-hosted nightly Pipeline agents. Replaces the legacy PAT-on-disk model.

The service runs on **Azure App Service for Linux (Python 3.11)** so that
no container image needs to be built or pushed to a registry. Microsoft
maintains the runtime image, keeping it out of our S360 surface.

## Behaviour ("always-401" policy)

| Request                                                  | Response                              |
| -------------------------------------------------------- | ------------------------------------- |
| `GET /token` with `Authorization: Bearer <secret>`       | `200 OK` + `{access_token, expires_on}` |
| `GET /token` with missing/wrong/malformed Authorization  | `401`                                 |
| `GET /` and `GET /health`                                | `401`                                 |
| Any other path or HTTP method                            | `401`                                 |

All `401` responses share an identical body (`Unauthorized`) and headers
(`WWW-Authenticate: Bearer`) so an attacker cannot distinguish wrong-secret
from wrong-path from no-header by inspecting the response shape. The shared
secret is the **only** gate; App Service Easy Auth / built-in AAD must
remain disabled.

> **Operational note:** because `/health` returns 401, do **not** enable
> App Service's built-in health-check feature. It would mark the app
> unhealthy and restart it. Liveness is implicit — App Service restarts the
> process if it crashes.

## Local development

```powershell
# From this folder
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SHARED_SECRET = "test-secret"
# DefaultAzureCredential won't work locally without `az login` first. The
# tests use a fake credential instead.
uvicorn app:app --reload
```

## Tests

```powershell
pip install pytest httpx
python -m pytest tests/
```

The tests inject a fake `DefaultAzureCredential` so they run fully offline.

## One-time provisioning (Azure)

The actual `az` commands live in a private (gitignored) `provision.ps1`
script. The provisioning script creates these resources in the
`sonic-nightly` resource group (westus2):

1. App Service plan — Linux, B1 SKU
2. Web App `sonic-nightly-service` — Python 3.11 runtime, system-assigned
   managed identity, HTTPS-only
3. App settings:
   * `SHARED_SECRET` — the inbound bearer secret (Key Vault reference
     preferred over an inline value)
   * `SHARED_SECRET_NEXT` — optional, set only during a rotation window
   * `SCM_DO_BUILD_DURING_DEPLOYMENT=true` so `requirements.txt` is
     installed automatically on each deploy
4. **Verification** (the script asserts all of these):
   * App Service Easy Auth / AAD is **off**
   * App Service built-in health-check is **off**
5. Prints the Web App's MI `principalId` for the manual AzDevOps grant
   step described below.

### Manual step: grant the MI access to your Azure DevOps organization

This cannot be done via `az`. After provisioning:

1. Visit `https://dev.azure.com/<org>/_settings/users`.
2. **Add user** → search for the Web App display name
   (`sonic-nightly-service`). The MI shows up as a Service Principal entry.
3. Grant access level **Basic** (or whatever your org policy allows).
4. Under **Organization settings → Agent pools → \<pool\> → Security**,
   add the MI with the **Reader** + **Service Account** roles for each of
   the nightly pools (`nightly`, `nightly-svc`, `nightly-bjw`,
   `nightly-tk5`).
5. Verify by hitting `/token` with the shared secret and pasting the
   returned JWT into [jwt.io](https://jwt.io). The `aud` claim must equal
   `499b84ac-1321-427f-aa17-267ca6975798`.

Until this step is complete, `/token` will return a token, but agents will
fail to register with `TF400898` / `TF400813` errors from Azure DevOps.

## Repeatable code deployment

```powershell
# From this folder
.\deploy.ps1
```

`deploy.ps1` zips the runtime files, calls `az webapp deploy --type zip`,
waits for the new revision, and runs a smoke test (`GET /` must return
401). It is idempotent and safe to re-run on every code change.

## Secret rotation (dual-secret window)

1. Set `SHARED_SECRET_NEXT` on the App Service to the new value
   (`az webapp config appsettings set ...`).
2. On each lab host, replace `/etc/agent-manager.secret` with the new
   value and `systemctl restart agent-manager`.
3. Once all hosts are migrated, promote: set `SHARED_SECRET` to the new
   value, delete `SHARED_SECRET_NEXT`, restart the App Service.
