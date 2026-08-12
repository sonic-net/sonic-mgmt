"""BNB nightly test: end-to-end Baked-in Node Bootstrapper flow against a mock KBS.

Proves the BNB happy path on a real DUT without a real cluster:
  CONFIG_DB activates BNB  ->  BNB calls the mock KBS  ->  downloads + `docker load`s
  the mock KNB image  ->  writes the unit + env  ->  starts `kn-bootstrap.service`
  ->  the (busybox) container comes up.

It does NOT assert the full join/mark loop -- the mock image just idles (which
also means the mark file is never written, so BNB can be re-triggered freely).

Three scenario tests: lifecycle (bootstrap, artifacts, reuse, tamper,
outage safety, digest flip), pin-and-config, and .kbsep. multi-endpoint.

Prereqs on the DUT: docker, openssl, python3, and at least one local docker
image (the mock KNB is built FROM it -- no registry access needed). The
`sonic-bn-bootstrapper` package (BNB binary + `bn-bootstrap.service`) must be
installed (baked into internal images via INCLUDE_KUBERNETES_BNB).
"""
import logging
import os
import time

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

TEST_DIR = os.path.dirname(__file__)
REMOTE_DIR = "/tmp/bnb_nightly"
MARK_FILE = "/var/k8s-bootstrap.mark"
CFG_KEY = "KUBERNETES_MASTER|SERVER"
BNB_UNIT = "bn-bootstrap.service"
KNB_UNIT = "kn-bootstrap.service"
KBS_PORT = 8443
MOCK_IMAGE = "kn-bootstrap-mock:latest"
POLL_SECONDS = 90
POLL_INTERVAL = 3


def _hget(duthost, field):
    return duthost.shell(
        "sonic-db-cli CONFIG_DB HGET '{}' {}".format(CFG_KEY, field),
        module_ignore_errors=True,
    )["stdout"].strip()


def _wait_mock_kbs(duthost, timeout=60):
    """Wait until the mock KBS answers a TLS handshake (bare TCP is not enough)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc = duthost.shell(
            "timeout 2 openssl s_client -connect '[::1]:{p}' -servername mock-kbs "
            "< /dev/null > /dev/null 2>&1".format(p=KBS_PORT),
            module_ignore_errors=True,
        )["rc"]
        if rc == 0:
            return
        time.sleep(1)
    logger.error(
        "mock KBS log:\n%s",
        duthost.shell("cat {}/mock_kbs.log".format(REMOTE_DIR), module_ignore_errors=True)["stdout"],
    )
    pytest_assert(False, "mock KBS did not start listening on port %s" % KBS_PORT)


@pytest.fixture
def bnb_env(duthost):
    """Stand up the mock KBS + mock KNB image on the DUT and point BNB at it; tear it all down after."""
    old_ip, old_port = _hget(duthost, "ip"), _hget(duthost, "port")
    old_insecure = _hget(duthost, "insecure")
    mark_was_present = duthost.shell(
        "test -e {}".format(MARK_FILE), module_ignore_errors=True
    )["rc"] == 0

    duthost.shell("mkdir -p {}".format(REMOTE_DIR))
    duthost.copy(src=os.path.join(TEST_DIR, "mock_kbs.py"), dest="{}/mock_kbs.py".format(REMOTE_DIR))
    duthost.copy(src=os.path.join(TEST_DIR, "Dockerfile.mock-knb"), dest="{}/Dockerfile.mock-knb".format(REMOTE_DIR))
    duthost.copy(src=os.path.join(TEST_DIR, "kn-bootstrap.service"), dest="{}/kn-bootstrap.service".format(REMOTE_DIR))

    # 1) Self-signed cert + the SPKI pin BNB expects. cahash = base32(sha256(SPKI)),
    #    uppercase, no padding -- exactly what config.go decodes.
    duthost.shell(
        "cd {d} && openssl ecparam -name prime256v1 -genkey -noout -out key.pem && "
        "openssl req -x509 -new -key key.pem -days 1 -subj '/CN=mock-kbs' -out cert.pem".format(d=REMOTE_DIR)
    )
    duthost.shell(
        "cd {d} && openssl x509 -in cert.pem -noout -pubkey | "
        "openssl pkey -pubin -outform der | openssl dgst -sha256 -binary > spki.bin".format(d=REMOTE_DIR)
    )
    cahash = duthost.shell(
        "python3 -c \"import base64;print(base64.b32encode("
        "open('{d}/spki.bin','rb').read()).decode().rstrip('='))\"".format(d=REMOTE_DIR)
    )["stdout"].strip()

    # 2) Build the mock KNB image and serve it the way the real KBS does:
    #    X-Image-Digest is an image identity known before the tarball exists
    #    (KBS uses the per-arch ACR manifest digest; the config ID works as the
    #    stand-in -- BNB treats it as opaque), and the tarball bakes BOTH
    #    device-local RepoTags (kn-bootstrap:latest + kn-bootstrap:<hex>), so
    #    `docker load` restores them and BNB neither parses nor tags anything.
    # Base the mock on the DUT's pause image: present on every
    # kubernetes-capable SONiC image (kubelet needs it for pod sandboxes),
    # tiny, shell-less (the Dockerfile is COPY-only), and /pause idles
    # forever -- exactly what the mock needs. Testbeds cannot pull from
    # public registries, so a local image is mandatory.
    base = duthost.shell(
        "docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '(^|/)pause:' | head -1",
        module_ignore_errors=True,
    )["stdout"].strip()
    pytest_assert(base, "no local pause image on the DUT to base the mock KNB on")
    duthost.shell("echo v1 > {d}/mock-stamp".format(d=REMOTE_DIR))
    duthost.shell(
        "docker build -t {img} --build-arg BASE={b} -f {d}/Dockerfile.mock-knb {d}".format(
            img=MOCK_IMAGE, b=base, d=REMOTE_DIR
        )
    )
    image_digest = duthost.shell(
        "docker inspect --format '{{{{.Id}}}}' {img}".format(img=MOCK_IMAGE)
    )["stdout"].strip()
    digest_hex = image_digest.split(":")[-1]
    duthost.shell(
        "docker tag {img} kn-bootstrap:latest && docker tag {img} kn-bootstrap:{h}".format(
            img=MOCK_IMAGE, h=digest_hex
        )
    )
    duthost.shell("docker save kn-bootstrap:latest kn-bootstrap:{h} -o {d}/knb.tar".format(h=digest_hex, d=REMOTE_DIR))
    # Untag so the pre-test clean slate below finds no kn-bootstrap images;
    # MOCK_IMAGE keeps the underlying image alive.
    duthost.shell("docker rmi kn-bootstrap:latest kn-bootstrap:{h}".format(h=digest_hex))

    # 3) Start the mock KBS in the background.
    duthost.shell(
        "nohup python3 {d}/mock_kbs.py --port {p} --cert {d}/cert.pem --key {d}/key.pem "
        "--tarball {d}/knb.tar --image-digest {dig} --node-registered-ready false "
        "> {d}/mock_kbs.log 2>&1 &".format(d=REMOTE_DIR, p=KBS_PORT, dig=image_digest)
    )
    _wait_mock_kbs(duthost)

    # 4) Point BNB at the mock via CONFIG_DB. `ip` carries fqdn + ".cahash." + base32 pin.
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' ip '::1.cahash.{h}'".format(k=CFG_KEY, h=cahash))
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' port '{p}'".format(k=CFG_KEY, p=KBS_PORT))
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' insecure false".format(k=CFG_KEY))

    # 5) Clean slate: no mark, no prior KNB unit/image/container.
    duthost.shell("rm -f {}".format(MARK_FILE))
    duthost.shell("systemctl stop {} 2>/dev/null".format(KNB_UNIT), module_ignore_errors=True)
    duthost.shell("docker rm -f kn-bootstrap 2>/dev/null", module_ignore_errors=True)
    duthost.shell("docker rmi -f $(docker images 'kn-bootstrap' -q) 2>/dev/null", module_ignore_errors=True)

    yield {"cahash": cahash, "image_digest": image_digest, "mock_base": base}

    # ---- teardown ----
    # Full path so only this test's mock can match, whichever incarnation is
    # running (the digest-flip step restarts it, so a saved PID would go stale).
    duthost.shell("pkill -f {}/mock_kbs.py".format(REMOTE_DIR), module_ignore_errors=True)
    duthost.shell("systemctl stop {} 2>/dev/null".format(BNB_UNIT), module_ignore_errors=True)
    duthost.shell("systemctl stop {} 2>/dev/null".format(KNB_UNIT), module_ignore_errors=True)
    duthost.shell("docker rm -f kn-bootstrap 2>/dev/null", module_ignore_errors=True)
    duthost.shell(
        "docker rmi -f {img} $(docker images 'kn-bootstrap' -q) 2>/dev/null".format(img=MOCK_IMAGE),
        module_ignore_errors=True,
    )
    duthost.shell("rm -rf {}".format(REMOTE_DIR))
    # Restore the mark to its pre-test presence. (On a genuinely joined DUT the
    # real KNB's reconciler would restore it anyway; this keeps us tidy on any.)
    if mark_was_present:
        duthost.shell("touch {}".format(MARK_FILE))
    else:
        duthost.shell("rm -f {}".format(MARK_FILE))
    # restore CONFIG_DB
    for field, old in (("ip", old_ip), ("port", old_port), ("insecure", old_insecure)):
        if old:
            duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' {f} '{v}'".format(k=CFG_KEY, f=field, v=old))
        else:
            duthost.shell("sonic-db-cli CONFIG_DB HDEL '{k}' {f}".format(k=CFG_KEY, f=field), module_ignore_errors=True)


def _knb_state(duthost):
    """Return (service_active, container_running) for KNB."""
    active = duthost.shell(
        "systemctl is-active {}".format(KNB_UNIT), module_ignore_errors=True
    )["stdout"].strip() == "active"
    running = bool(
        duthost.shell(
            "docker ps --filter name=kn-bootstrap --format '{{.Names}}'",
            module_ignore_errors=True,
        )["stdout"].strip()
    )
    return active, running


def _wait_knb_up(duthost, timeout=POLL_SECONDS):
    deadline = time.time() + timeout
    while time.time() < deadline:
        active, running = _knb_state(duthost)
        if active and running:
            return True
        time.sleep(POLL_INTERVAL)
    return False


def _set_ip(duthost, value):
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' ip '{v}'".format(k=CFG_KEY, v=value))


def _has_kbsep(duthost):
    """Whether the installed bn-bootstrap binary supports .kbsep. multi-endpoint."""
    return duthost.shell(
        "grep -aq '.kbsep.' /usr/sbin/bn-bootstrap", module_ignore_errors=True
    )["rc"] == 0


def _dummy_pin(duthost):
    """A syntactically valid base32 SPKI pin that matches nothing."""
    return duthost.shell(
        "python3 -c \"import base64;print(base64.b32encode(b'\\xaa'*32).decode().rstrip('='))\""
    )["stdout"].strip()


def _mark_ts(duthost):
    """DUT-clock timestamp for journalctl --since. The sleeps keep the previous
    run's same-second lines out of the window (journalctl has 1s granularity)."""
    time.sleep(1)
    ts = duthost.shell("date -u '+%Y-%m-%d %H:%M:%S'")["stdout"].strip()
    time.sleep(1)
    return ts


def _bnb_journal(duthost, since):
    return duthost.shell(
        "journalctl -u {} --since '{}' --no-pager".format(BNB_UNIT, since),
        module_ignore_errors=True,
    )["stdout"]


def _restart_bnb(duthost, expect_fail=False):
    """Restart the BNB one-shot, returning the journal for just this run."""
    since = _mark_ts(duthost)
    duthost.shell("systemctl restart {}".format(BNB_UNIT), module_ignore_errors=expect_fail)
    return _bnb_journal(duthost, since)


def _dump_diags(duthost):
    logger.error(
        "BNB journal:\n%s",
        duthost.shell("journalctl -u {} --no-pager -n 80".format(BNB_UNIT), module_ignore_errors=True)["stdout"],
    )
    logger.error(
        "mock KBS log:\n%s",
        duthost.shell("cat {}/mock_kbs.log".format(REMOTE_DIR), module_ignore_errors=True)["stdout"],
    )


def test_bnb_bootstrap_lifecycle(duthost, bnb_env):
    """The full BNB workflow as one sequence: mark gating, first bootstrap +
    the artifacts contract, digest-bookmark reuse, image-owned unit restore,
    KBS-outage teardown safety, and digest-flip recovery."""
    # -- mark present gates everything (checked before any KBS call) --
    logger.info("step: mark file gates BNB")
    duthost.shell("touch {}".format(MARK_FILE))
    duthost.shell("systemctl restart {}".format(BNB_UNIT), module_ignore_errors=True)
    time.sleep(POLL_INTERVAL * 2)
    active, running = _knb_state(duthost)
    pytest_assert(not active and not running,
                  "mark present: KNB must stay down (active=%s running=%s)" % (active, running))
    duthost.shell("rm -f {}".format(MARK_FILE))

    # -- first bootstrap: KNB up + everything BNB leaves behind --
    logger.info("step: first bootstrap + artifacts contract")
    duthost.shell("systemctl restart {}".format(BNB_UNIT), module_ignore_errors=True)
    up = _wait_knb_up(duthost)
    if not up:
        _dump_diags(duthost)
    pytest_assert(up, "first bootstrap: KNB did not come up within %ds" % POLL_SECONDS)

    old_hex = bnb_env["image_digest"].split(":")[-1]
    images = duthost.shell("docker images kn-bootstrap --format '{{.Repository}}:{{.Tag}}'")["stdout"]
    pytest_assert("kn-bootstrap:latest" in images, "tarball did not deliver kn-bootstrap:latest; got: %s" % images)
    pytest_assert("kn-bootstrap:" + old_hex in images, "tarball did not deliver the digest tag; got: %s" % images)
    pytest_assert(len(images.splitlines()) == 2, "expected exactly 2 kn-bootstrap tags, got: %s" % images)

    env = duthost.shell("cat /etc/sonic/kn-bootstrap.env")["stdout"]
    for line in (
        "APISERVER=10.0.0.1:6443",          # mock_kbs.py defaults
        "JOIN_TOKEN=abcdef.0123456789abcdef",
        "CA_HASH=sha256:deadbeef",
        "NODE_NAME=mock-node-1",            # X-Device-Hostname passthrough
        "ACR_HOST=mock-acr.invalid",        # X-KNB-Env bag passthrough
    ):
        pytest_assert(line in env, "env file missing %r; got:\n%s" % (line, env))
    unit = duthost.shell("systemctl cat {}".format(KNB_UNIT))["stdout"]
    pytest_assert("--env-file /etc/sonic/kn-bootstrap.env" in unit, "unit does not consume the env file:\n%s" % unit)
    timer = duthost.shell("systemctl cat bn-bootstrap.timer", module_ignore_errors=True)["stdout"]
    pytest_assert("OnUnitInactiveSec=15min" in timer, "BNB timer is not 15min:\n%s" % timer)
    extract = duthost.shell(
        "docker ps -a --format '{{.Names}}' | grep extract", module_ignore_errors=True
    )["stdout"].strip()
    pytest_assert(not extract, "extract-container litter left behind: %s" % extract)

    # -- second run reuses the bookmarked image (mock KNB never writes the mark) --
    logger.info("step: digest-bookmark reuse")
    journal = _restart_bnb(duthost)
    pytest_assert("reusing it" in journal, "second run did not reuse the bookmarked image:\n%s" % journal)
    pytest_assert("KNB image not present locally" not in journal,
                  "second run re-downloaded despite an up-to-date local image:\n%s" % journal)

    # -- the unit is image-owned: local edits are overwritten on the next run --
    logger.info("step: unit tamper restore")
    duthost.shell("echo '# tamper' >> /etc/systemd/system/{}".format(KNB_UNIT))
    journal = _restart_bnb(duthost)
    pytest_assert("installed /etc/systemd/system/{} from KNB image".format(KNB_UNIT) in journal,
                  "unit not reinstalled from image:\n%s" % journal)
    tampered = duthost.shell(
        "grep -q tamper /etc/systemd/system/{}".format(KNB_UNIT), module_ignore_errors=True
    )["rc"] == 0
    pytest_assert(not tampered, "tamper line survived a BNB run; unit not restored from image")

    # -- KBS unreachable: fail loud, tear nothing down --
    logger.info("step: KBS-outage teardown safety")
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' port 9999".format(k=CFG_KEY))
    journal = _restart_bnb(duthost, expect_fail=True)
    pytest_assert("request failed on all attempts" in journal, "outage run did not fail loud:\n%s" % journal)
    pytest_assert("clean slate" not in journal, "teardown ran during a KBS outage:\n%s" % journal)
    _, running = _knb_state(duthost)
    pytest_assert(running, "running KNB container was torn down during a KBS outage")
    unit_present = duthost.shell(
        "test -f /etc/systemd/system/{}".format(KNB_UNIT), module_ignore_errors=True
    )["rc"] == 0
    pytest_assert(unit_present, "installed unit removed during a KBS outage")
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' port '{p}'".format(k=CFG_KEY, p=KBS_PORT))

    # -- digest flip: old images removed, container rolls to the new image --
    logger.info("step: digest-flip recovery")
    duthost.shell("echo v2 > {d}/mock-stamp".format(d=REMOTE_DIR))
    duthost.shell(
        "docker build -t kn-bootstrap-mock:v2 --build-arg BASE={b} "
        "-f {d}/Dockerfile.mock-knb {d}".format(b=bnb_env["mock_base"], d=REMOTE_DIR)
    )
    new_digest = duthost.shell("docker inspect --format '{{.Id}}' kn-bootstrap-mock:v2")["stdout"].strip()
    new_hex = new_digest.split(":")[-1]
    pytest_assert(new_hex != old_hex, "STAMP=v2 image has the same ID as v1; digest flip impossible")
    duthost.shell(
        "docker tag kn-bootstrap-mock:v2 kn-bootstrap:latest && "
        "docker tag kn-bootstrap-mock:v2 kn-bootstrap:{h} && "
        "docker save kn-bootstrap:latest kn-bootstrap:{h} -o {d}/knb2.tar && "
        "docker rmi kn-bootstrap:latest kn-bootstrap:{h}".format(h=new_hex, d=REMOTE_DIR)
    )
    duthost.shell("pkill -f {}/mock_kbs.py".format(REMOTE_DIR), module_ignore_errors=True)
    duthost.shell(
        "nohup python3 {d}/mock_kbs.py --port {p} --cert {d}/cert.pem --key {d}/key.pem "
        "--tarball {d}/knb2.tar --image-digest {dig} --node-registered-ready false "
        "> {d}/mock_kbs.log 2>&1 &".format(d=REMOTE_DIR, p=KBS_PORT, dig=new_digest)
    )
    _wait_mock_kbs(duthost)
    journal = _restart_bnb(duthost)
    up = _wait_knb_up(duthost)
    if not up:
        _dump_diags(duthost)
    pytest_assert(up, "KNB did not come back up on the new digest")
    pytest_assert("reusing it" not in journal, "BNB reused the old image despite a digest flip:\n%s" % journal)
    images = duthost.shell("docker images kn-bootstrap --format '{{.Repository}}:{{.Tag}}'")["stdout"]
    pytest_assert("kn-bootstrap:" + new_hex in images, "new digest tag missing; got: %s" % images)
    pytest_assert("kn-bootstrap:" + old_hex not in images, "old digest tag not removed; got: %s" % images)
    duthost.shell("docker rmi -f kn-bootstrap-mock:v2", module_ignore_errors=True)


def test_bnb_pin_and_config_handling(duthost, bnb_env):
    """Config-driven behaviors as one sequence: legacy-config no-op, malformed
    cahash, pin MISMATCH fail-closed, insecure break-glass (both directions),
    and multi-pin rotation overlap."""
    # -- legacy ip (no .cahash.): clean INFO no-op, exit 0, nothing started --
    logger.info("step: legacy config no-op")
    _set_ip(duthost, "legacy.master.example")
    journal = _restart_bnb(duthost)
    pytest_assert("KBS not configured" in journal, "no not-configured log:\n%s" % journal)
    pytest_assert("clean slate" not in journal, "teardown ran on a legacy config:\n%s" % journal)
    failed = duthost.shell(
        "systemctl is-failed --quiet {}".format(BNB_UNIT), module_ignore_errors=True
    )["rc"] == 0
    pytest_assert(not failed, "BNB unit failed on a legacy (pre-KBS) config; must exit 0")
    active, running = _knb_state(duthost)
    pytest_assert(not active and not running, "KNB came up on a legacy config")

    # -- malformed cahash: loud failure --
    logger.info("step: malformed cahash")
    _set_ip(duthost, "kbs.example.cahash.not9valid!")
    journal = _restart_bnb(duthost, expect_fail=True)
    pytest_assert("base32-decode" in journal, "no base32 decode error in journal:\n%s" % journal)
    failed = duthost.shell(
        "systemctl is-failed --quiet {}".format(BNB_UNIT), module_ignore_errors=True
    )["rc"] == 0
    pytest_assert(failed, "BNB unit did not fail loud on a malformed cahash")

    # -- wrong pin: fail closed, KNB stays down --
    logger.info("step: pin MISMATCH fail-closed")
    dummy = _dummy_pin(duthost)
    _set_ip(duthost, "::1.cahash.{}".format(dummy))
    journal = _restart_bnb(duthost, expect_fail=True)
    pytest_assert("pin MISMATCH" in journal, "no pin MISMATCH in journal:\n%s" % journal)
    pytest_assert("request failed on all attempts" in journal, "pin run did not fail loud:\n%s" % journal)
    pytest_assert("clean slate" not in journal, "teardown ran despite pin refusal:\n%s" % journal)
    active, running = _knb_state(duthost)
    pytest_assert(not active and not running, "KNB came up despite pin MISMATCH")

    # -- insecure=true bypasses the (wrong) pin, loudly --
    logger.info("step: insecure break-glass on")
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' insecure true".format(k=CFG_KEY))
    journal = _restart_bnb(duthost)
    up = _wait_knb_up(duthost)
    if not up:
        _dump_diags(duthost)
    pytest_assert(up, "insecure=true: KNB did not come up within %ds" % POLL_SECONDS)
    pytest_assert("INSECURE mode" in journal, "no INSECURE-mode warning in journal:\n%s" % journal)

    # -- insecure=false restores enforcement on the next run --
    logger.info("step: insecure break-glass off")
    duthost.shell("sonic-db-cli CONFIG_DB HSET '{k}' insecure false".format(k=CFG_KEY))
    journal = _restart_bnb(duthost, expect_fail=True)
    pytest_assert("pin MISMATCH" in journal, "insecure=false did not restore enforcement:\n%s" % journal)

    # -- rotation overlap: wrong pin + real pin, any-match succeeds --
    logger.info("step: multi-pin overlap")
    _set_ip(duthost, "::1.cahash.{d}.cahash.{g}".format(d=dummy, g=bnb_env["cahash"]))
    journal = _restart_bnb(duthost)
    pytest_assert("pin matched" in journal, "any-match pin overlap did not verify:\n%s" % journal)
    up = _wait_knb_up(duthost)
    if not up:
        _dump_diags(duthost)
    pytest_assert(up, "any-match pin overlap did not complete the bootstrap")


def test_bnb_multi_endpoint(duthost, bnb_env):
    """.kbsep. ordered endpoint list as one sequence: preferred-first (no
    fallback), dead-first (fall back and complete), all-dead (fail loud, no
    teardown), and the empty-segment parse error."""
    if not _has_kbsep(duthost):
        pytest.skip("installed bn-bootstrap has no .kbsep. support")

    # -- preferred healthy: succeed on 1/2, never touch the decoy --
    logger.info("step: preferred endpoint first")
    _set_ip(duthost, "::1.kbsep.kbs-decoy-one.invalid.cahash.{}".format(bnb_env["cahash"]))
    journal = _restart_bnb(duthost)
    up = _wait_knb_up(duthost)
    if not up:
        _dump_diags(duthost)
    pytest_assert(up, "preferred endpoint did not complete the bootstrap")
    pytest_assert("endpoint 1/2 https://[::1]" in journal, "preferred not tried first:\n%s" % journal)
    pytest_assert("trying next endpoint" not in journal,
                  "fell back although the preferred endpoint is healthy:\n%s" % journal)

    # -- dead endpoint first: fall back to the second and complete --
    logger.info("step: dead endpoint first, fallback")
    _set_ip(duthost, "kbs-decoy-one.invalid.kbsep.::1.cahash.{}".format(bnb_env["cahash"]))
    journal = _restart_bnb(duthost)
    pytest_assert("endpoint 1/2 https://kbs-decoy-one.invalid" in journal,
                  "decoy endpoint not tried first:\n%s" % journal)
    pytest_assert("trying next endpoint" in journal, "no endpoint fallback in journal:\n%s" % journal)
    pytest_assert("endpoint 2/2 https://[::1]" in journal, "second endpoint not reached:\n%s" % journal)
    up = _wait_knb_up(duthost)
    if not up:
        _dump_diags(duthost)
    pytest_assert(up, "fallback endpoint did not complete the bootstrap")

    # -- every endpoint dead: fail loud after trying them all, tear nothing down --
    logger.info("step: all endpoints dead")
    _set_ip(duthost, "kbs-decoy-one.invalid.kbsep.kbs-decoy-two.invalid.cahash.{}".format(bnb_env["cahash"]))
    journal = _restart_bnb(duthost, expect_fail=True)
    pytest_assert("across 2 endpoint" in journal, "failure not attributed to both endpoints:\n%s" % journal)
    pytest_assert("clean slate" not in journal, "teardown ran during a KBS outage:\n%s" % journal)
    failed = duthost.shell(
        "systemctl is-failed --quiet {}".format(BNB_UNIT), module_ignore_errors=True
    )["rc"] == 0
    pytest_assert(failed, "BNB unit did not fail loud with all endpoints dead")

    # -- empty .kbsep. segment: parse error before any network activity --
    logger.info("step: empty endpoint segment")
    _set_ip(duthost, "::1.kbsep..cahash.{}".format(bnb_env["cahash"]))
    journal = _restart_bnb(duthost, expect_fail=True)
    pytest_assert("empty KBS endpoint segment" in journal, "parse error not reported:\n%s" % journal)
    pytest_assert("KBS bootstrap: begin" not in journal,
                  "network activity despite a config parse error:\n%s" % journal)
