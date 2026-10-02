# Route-stress convergence

`test_stress_routes.py::test_announce_withdraw_route` preserves the existing
topologies, ASIC enumeration, completeness loop counts, 120-second final settle,
strict CRM drift limit (`abs(after - before) < 5`), and FRR memory assertions.
Its module-local `withdraw_and_restore_routes` fixture leaves the shared
withdrawal fixture used by other stress modules unchanged.

## Convergence contract

Before a route action, capture a healthy, stable state in the selected ASIC.
After announcement or withdrawal, require directional received-BGP-prefix and
physical CRM progress for each submitted, locally configured family. A receipt's
`changed` field is submission evidence, not convergence evidence. An empty
submitted family or an explicitly unchanged target must remain unchanged.

Where BGP peer descriptions identify topology VMs, scope submitted families to
the selected ASIC's peers. Unmapped peer names use the topology-wide family mask
conservatively and emit a warning rather than silently waiving progress.

Known targets include each peer's received-prefix count, not just aggregate BGP
totals. Require Established peers, unchanged peer identities, empty IPv4/IPv6
input and output queues, and two consecutive eligible samples with stable peer
counts and CRM. Wrong targets, reopened queues, down peers, and failed
observations break consecutive sampling.

The initial withdrawn baseline is measured rather than hardcoded to zero:
neighbor-owned BGP prefixes and connected/static CRM routes can remain.
Subsequent cycles reuse the fixture's immutable withdrawn and announced targets.
An initially empty configured family has no known announced count and must
demonstrate progress. Finite stability does not prove every route's identity or
arbitrarily delayed hardware work; the original final CRM check remains required.

VS keeps the BGP/peer/queue checks without physical CRM progress, target, or
stability requirements. The existing final CRM exemption is unchanged.

Polling uses the existing 220-second convergence budget and one-second
interval/delay. Transport errors are logged and retried by the shared poller.
Invalid observations follow its existing exception policy: they may be retried
or fail immediately, but never count toward consecutive stability. Invalid
action/target inputs and malformed submission receipts fail explicitly before
polling. Timeout diagnostics include the action, namespace, before/expected
states, submitted families, and ten recent samples.

Ansible shell results, route receipts, and nested CRM structures accept
`collections.abc.Mapping`, including module-result wrappers. Stdout must still
be native text or a `str` subclass; no bytes or arbitrary coercion is accepted.
Malformed JSON, nested structures, counters, and failed receipts remain errors.

Route restoration runs in `finally`, including partial submissions and setup
failures. It submits using the last known setup state before another DUT
observation, so a failed pre-cleanup read cannot prevent re-announcement.
Restoration errors are logged and raised; an in-flight setup error is preserved
with the cleanup error chained as its cause.

## Offline regressions

From the repository root:

```bash
python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
  tests/common/unit_tests/unit_test_route_convergence.py -v
python3 -m flake8 --max-line-length=120 tests/stress/test_stress_routes.py \
  tests/common/unit_tests/unit_test_route_convergence.py
```

The regressions execute actual function ASTs and the shared poller on a virtual
clock without importing hardware fixtures or requiring private Git history.
They cover asynchronous progress, targets, both families and queues, namespace
selection, Mapping/text wrappers, no-op and VS behavior, failure-safe cleanup,
and the original CRM/memory thresholds and completeness loop counts.

Offline checks do not replace hardware qualification. Existing shared fixtures
still adjust CRM polling, drop kernel caches, and perform a safe config reload
at module teardown. Keep pre/post checks and log analysis enabled, and evaluate
health, config, and core evidence after those teardown effects.
