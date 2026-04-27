# Agent Manager

The Agent Manager is a Python systemd service running on lab hosts that
supervises a fixed-size pool of Docker containers, each running an Azure
Pipelines self-hosted agent for SONiC's nightly tests.

It runs on the following hosts:

| Nightly Pool Name | Lab Name | Server List       |
| ----------------- | -------- | ----------------- |
| nightly           | str      | str-acs-serv-15   |
| nightly           | str3     | str-acs-serv-65   |
| nightly-svc       | svc      | svcstr-server-2   |
| nightly-bjw       | bjw      | bjw-ca-serv-5     |
| nightly-tk5       | tk5      | strtk5-serv-02    |

## Authentication: AAD access-tokens (no more PATs)

Until 2026, agent-manager kept a long-lived Personal Access Token (PAT) in
`/etc/agent-manager.conf` and refreshed it every 7 days from a pipeline
that wrote a new PAT to a temporary file via Ansible. PATs have been
deprecated.

The current model uses **short-lived AAD access-tokens** minted on demand
by an Azure App Service called **`sonic-nightly-service`** (see
[`token-service/`](./token-service/)). The flow is:

1. agent-manager wants to start a new container.
2. It calls `GET https://sonic-nightly-service.azurewebsites.net/token`
   with `Authorization: Bearer <shared secret>`.
3. The service authenticates via shared secret, then uses its own
   system-assigned managed identity to mint an access-token for the Azure
   DevOps audience and returns `{access_token, expires_on}`.
4. agent-manager passes that token to the container as the `AZP_TOKEN`
   environment variable. The container's `/azp/start.sh` registers the
   agent with `config.sh --auth pat --token "$AZP_TOKEN"` (per 1ES, the
   `pat` auth mode accepts an AAD bearer token).
5. Once registered, the agent maintains its own credentials with Azure
   DevOps. The original AAD access-token is no longer needed.

The shared secret is the only credential that needs to be present on each
lab host. It lives in `/etc/agent-manager.secret` (mode `0600`).

## Container image

The agents now run directly from the unmodified
`sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt` image (which already
ships `/azp/start.sh`). The previously-required custom `dockeragent`
image is no longer needed.

### Picking what to put in `image.tag`

The build pipeline only ever pushes `:latest` — there are no per-build
version tags. That gives you two practical choices:

* **Track `:latest` (default).** Set `image.tag: latest`. Whenever the
  registry's `:latest` is updated and you `docker pull` it on a host,
  the next reconcile cycle detects the new image-id, drains idle
  containers, and spawns replacements. Simple, but a re-push during a
  long job means an unplanned drain on the next cycle.

* **Pin a specific build by digest.** This is the recommended mode for
  production hosts. Every push to `:latest` produces an immutable
  registry digest (`sha256:...`); you adopt one digest, and only move
  to a newer one on your own schedule.

### How to pin a digest without changing the build pipeline

Pull `:latest` once, look up its digest, then re-tag it locally with a
stable name and use that local tag in the conf:

```bash
# 1. Pull the current :latest.
sudo docker pull sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest

# 2. Read the registry digest of what you just pulled.
sudo docker inspect --format '{{index .RepoDigests 0}}' \
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest
# -> sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt@sha256:9f3e...c7

# 3. Re-tag that exact digest locally with a stable, dated name.
sudo docker tag \
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt@sha256:9f3e...c7 \
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:pinned-2026-04-24
```

You now have a local tag `pinned-2026-04-24` that resolves to a fixed
image-id forever, regardless of what `:latest` does upstream. Put that
in `/etc/agent-manager.conf`:

```yaml
image:
    name: sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt
    tag: pinned-2026-04-24
```

To upgrade later, repeat the three steps with a new dated tag and
follow the [Rolling image upgrade](#rolling-image-upgrade) section.

> Querying the digest **without pulling** (saves bandwidth on a fleet):
> ```bash
> az acr repository show-manifests \
>     --name sonicdev-microsoft \
>     --repository docker-sonic-mgmt \
>     --query "[?tags[?@=='latest']].digest" -o tsv
> ```

> **Heads-up on tag-shifts:** agent-manager classifies containers by
> image-id, not by tag string. If you `docker pull :latest` on a host
> while running containers were started from an older `:latest`, the
> reconciler will drain them. That's why pinning to a dated local tag
> matters — pulling a fresh `:latest` no longer changes what
> `pinned-2026-04-24` resolves to.

> **Phase-2:** native `image.digest` support (so the conf can hold
> `sha256:...` directly and skip the local re-tag step) is tracked as a
> future enhancement.

## Configuration

`/etc/agent-manager.conf` (YAML):

```yaml
image:
    name: sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt
    tag: pinned-2026-04-24        # see "Container image" for how to pin
azp:
    url: "https://dev.azure.com/mssonic"
    pool: "nightly"
    token_service:
        url: "https://sonic-nightly-service.azurewebsites.net/token"
        secret_file: "/etc/agent-manager.secret"
proxy:
    http: "http://10.201.148.40:8080"
    https: "http://10.201.148.40:8080"
agent:
    count: 10
    name: azp-agent
```

### Field reference

* `image.name` / `image.tag` — fully-qualified image and tag. Required.
* `azp.url` — Azure DevOps organization URL. Required.
* `azp.pool` — agent pool name. Required.
* `azp.token_service.url` — the `sonic-nightly-service` `/token` endpoint.
  Required.
* `azp.token_service.secret_file` — path to a file containing the shared
  secret on a single line. Mode must be `0600` or stricter. Required
  unless `secret` is given.
* `azp.token_service.secret` — inline shared secret. Mutually exclusive
  with `secret_file`. Discouraged; use `secret_file` instead.
* `proxy.http` / `proxy.https` — optional HTTP proxy passed to each
  container as `http_proxy` / `https_proxy`.
* `agent.count` — desired number of agents. Default `10`.
* `agent.name` — name prefix for managed containers. Default `azp-agent`.

## Container ownership and slot allocation

**Ownership.** agent-manager only ever touches containers it created.
Each container it starts is stamped with the Docker label
`com.sonic.agent-manager.managed=true`, and only labelled containers
are listed, drained, or replaced. Anything else on the host (manual
`docker run`s, other services) is ignored.

**Slots.** Each managed container is assigned a fixed **slot number**
from `1` to `agent.count` (recorded in the label
`com.sonic.agent-manager.slot`). The agent inside registers with
AzDevOps under a name derived from that slot:

```
<agent.name>-<hostname>-<slot:02d>     # e.g. azp-agent-bjw-ca-serv-5-07
```

Because the names are stable and the agent is started with
`--replace`, the AzDevOps pool will never have more than
`count × hosts` rows for managed agents — re-creating slot 7 just
overwrites the previous slot-7 row instead of adding a new one.

## Execution logic

Once per `CHECK_INTERVAL` seconds (60 by default):

1. Apply any pending SIGHUP-triggered config reload at the loop boundary.
2. `docker.ping()` to fail fast if the daemon is down.
3. Reconcile (`respawn()`):
   1. List all managed containers; classify each as **old** (image-id
      mismatch) or **current**.
   2. Remove any container in a non-running state.
   3. Drain idle (not-busy) old-image containers so they get replaced
      with current-image ones. A container is considered busy if
      `pgrep -af "Agent.Worker"` matches.
   4. If running count > target, prune extras (idle first).
   5. If running count < target, fetch a fresh AAD token and start new
      containers in the free slots. If the token fetch fails, **skip
      starts** but still complete the cleanup steps above.

## Known limitations (Phase 1)

* **No graceful agent deregistration.** When a container is removed,
  `/azp/start.sh`'s `cleanup()` tries to deregister with the original
  `AZP_TOKEN`, which has long since expired. The deregistration call
  fails and the agent row appears as "offline" in AzDevOps. Because we
  use stable slot names plus `--replace`, the row count is bounded —
  the next start in that slot will overwrite the stale row.
* **No readiness check.** A container is counted toward capacity as soon
  as it reports `running`, even if `start.sh` is still downloading the
  agent tarball. In practice this is harmless (the next cycle catches it
  if it crashed), but a true readiness probe is a future improvement.
* **No rolling replace.** When an old-image container is drained,
  there's a brief window before its replacement is healthy. For a 5-host
  fleet this is acceptable.

These are tracked as Phase-2 enhancements.

## Logging

Logs go to `/tmp/agent-manager.log` with rotation (10 MB × 15 backups).

## Unit tests

```
make test
```

Tests use `pyfakefs` for filesystem isolation and `unittest.mock` for the
docker client and HTTP layer. Required deps:

```
pip install docker requests pyyaml pyfakefs
```

## Testing changes

Self-hosted agent pools are managed centrally and we cannot stand up a
dedicated test pool, so the testing flow is intentionally lean:

1. **Unit tests are the primary safety net.** Add a test in
   `test_agentmanager.py` for any new logic you introduce — reconcile
   ordering, container classification, edge cases, error paths — and
   run `make test` before every commit. The mocks cover the docker
   client, the token-service HTTP layer and the filesystem, so the
   suite runs in well under a second and exercises the same code paths
   that run in production.
2. **Canary on one production host as the integration step.** Pick the
   host with the smallest pool (currently `strtk5-serv-02`, 15 slots)
   to minimise blast radius. Smooth-cutover deploy, then watch a few
   reconcile cycles:
   ```
   scp agentmanager.py <host>:/tmp/
   ssh <host> 'sudo install -m 0755 /tmp/agentmanager.py /usr/local/bin/agentmanager.py && sudo systemctl restart agent-manager'
   ssh <host> 'sudo journalctl -u agent-manager -f'
   ```
   Restart is non-disruptive: running containers keep running, and the
   manager re-discovers them on first reconcile. If anything looks
   wrong, copy the previous `agentmanager.py` back and restart.
3. **Fan out to the remaining hosts** once the canary is stable
   (typically ~10 minutes of reconcile cycles is enough for logic
   changes; longer for anything that affects long-running container
   behaviour).

Pure offline local testing of `agentmanager.py` against a real Docker
daemon is no longer feasible — the manager fetches an AAD access-token
before spawning containers, which requires the production token-service
endpoint. Unit tests fill this gap by mocking that layer.

## Deploy

> **Phased rollout:** roll out to one host (e.g. `str-acs-serv-65`) first
> and let it run for a week before touching the rest. Keep the previous
> `agentmanager.py` and `agent-manager.service` as `.bak` files for fast
> rollback.

1. Copy `agentmanager.py` to `/usr/bin/agentmanager.py` (executable).
2. Copy `agent-manager.service` to `/lib/systemd/system/agent-manager.service`.
3. Write `/etc/agent-manager.conf` (see schema above).
4. Write the shared secret to `/etc/agent-manager.secret` and chmod it:
   ```
   sudo install -m 0600 /dev/null /etc/agent-manager.secret
   sudo $EDITOR /etc/agent-manager.secret
   ```
5. Install Python deps:
   ```
   sudo pip3 install docker requests PyYAML
   ```
6. Start and enable:
   ```
   sudo systemctl daemon-reload
   sudo systemctl enable --now agent-manager
   sudo journalctl -u agent-manager -f
   ```

## Rolling image upgrade

You can upgrade the image manually whenever you want, or let a systemd
timer do it on a schedule.

### Manual

1. On each host:
   ```
   sudo docker pull <image-name>:<tag>     # whatever image.name + image.tag in the conf are
   sudo systemctl restart agent-manager
   ```
   No conf edit needed. The manager re-reads the image digest at startup.
2. The next reconcile cycle drains idle old-image containers as their
   current job (if any) finishes, and spawns replacements in the freed
   slots. Busy containers are left alone until they go idle.

### Automated (recommended): weekly systemd timer

Ship `agent-manager-upgrade`, `agent-manager-upgrade.service` and
`agent-manager-upgrade.timer` alongside the rest of the manager:

```
sudo install -m 0755 agent-manager-upgrade /usr/local/bin/agent-manager-upgrade
sudo install -m 0644 agent-manager-upgrade.service /etc/systemd/system/
sudo install -m 0644 agent-manager-upgrade.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent-manager-upgrade.timer
```

The helper reads `/etc/agent-manager.conf` to find the image reference,
so the conf remains the single source of truth — the unit files contain
no image name. Default schedule is 00:00 every Monday with up to 2 h
of jitter; tweak `OnCalendar=` in the `.timer` to taste.

Inspect:
```
systemctl list-timers agent-manager-upgrade.timer
journalctl -u agent-manager-upgrade.service
```

## Secret rotation

The token service supports a dual-secret window
(`SHARED_SECRET` + `SHARED_SECRET_NEXT`). To rotate:

1. Set `SHARED_SECRET_NEXT` on the App Service to the new value.
2. On each host, update `/etc/agent-manager.secret` and
   `sudo systemctl restart agent-manager`.
3. Once all hosts are migrated, promote: set `SHARED_SECRET` to the new
   value on the App Service and delete `SHARED_SECRET_NEXT`.

agent-manager re-reads `secret_file` on every token refresh, so no
restart is strictly required if the file is updated in place.

## Rollback procedure

If anything goes wrong on a freshly upgraded host:

```
sudo systemctl stop agent-manager
sudo cp /usr/bin/agentmanager.py.bak /usr/bin/agentmanager.py
sudo cp /lib/systemd/system/agent-manager.service.bak /lib/systemd/system/agent-manager.service
# Restore the previous /etc/agent-manager.conf with the legacy `azp.token` field.
sudo systemctl daemon-reload
sudo systemctl start agent-manager
```
