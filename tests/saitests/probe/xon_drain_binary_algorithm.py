"""
XOn Drain Binary-Then-Step Algorithm — for platforms with large
effective_xon_offset (Cisco J2C/JR2/Q3D, Mellanox PAC, Broadcom GB:
hundreds to ~13000 packets).

Two-phase search:
  Phase 1 (binary): coarse binary search to narrow [lower, upper] to a
    window of `range_limit` packets.
  Phase 2 (step):   step-by-step within [xon_lower, xon_upper] to find
    the exact transition point.

Total cost: O(log(pfcxoff_point)) + O(range_limit) — typically ~10-15
binary iters + ~32 step iters = ~50 iterations max for any platform,
even Cisco's 12985.

Pairs with PfcXonProbingExecutor.check(value=D).

Use this for the 4-step path (when enable_xon_range_probe=True).
"""

import time
from typing import Optional, Tuple

from probing_observer import ProbingObserver


class XonDrainBinaryAlgorithm:
    """
    Binary range narrowing + step-by-step within tight window.

    Phase 1 invariant during binary search:
      - lower D where xon does NOT fire (drain too small, src still paused)
      - upper D where xon DOES fire     (drain enough, src resumed)
    Stop binary phase when (upper - lower) <= range_limit.

    Phase 2: step-by-step from lower+1 up to upper, stop on first xon_fired.
    """

    def __init__(
        self,
        executor,
        observer: ProbingObserver,
        verification_attempts: int = 1,
        range_limit: int = 32,
        binary_max_iter: int = 20,
        step_max_iter: int = 50,
        max_consecutive_failures: int = 3,
    ):
        """
        Args:
            executor: PfcXonProbingExecutor instance.
            observer: ProbingObserver.
            verification_attempts: per-check verification rounds.
            range_limit: stop binary phase when window <= this.
            binary_max_iter: cap on binary iterations (safety).
            step_max_iter: cap on step iterations after binary narrowing.
            max_consecutive_failures: number of consecutive ``check()``
                failures (success=False) allowed before phase 1 aborts and
                falls through to phase 2 over the uncorrupted window.
                Tunable for very-noisy testbeds; default 3 is sensible for
                most environments.
        """
        self.executor = executor
        self.observer = observer
        self.verification_attempts = verification_attempts
        self.range_limit = range_limit
        self.binary_max_iter = binary_max_iter
        self.step_max_iter = step_max_iter
        self.max_consecutive_failures = max_consecutive_failures

    def run(
        self,
        src_port: int,
        drain_port: int,
        holder_port: int,
        **traffic_keys,
    ) -> Tuple[Optional[int], Optional[int], float]:
        """
        Run binary-then-step XOn drain probing.

        Returns (xon_lower, xon_upper, elapsed_seconds), or (None, None, elapsed)
        on failure.
        """
        t0 = time.time()
        pfcxoff_point = self.executor.pfcxoff_point

        ProbingObserver.console(
            f"[XOn Drain Binary] Starting binary-then-step "
            f"src={src_port} drain={drain_port} holder={holder_port} "
            f"pfcxoff_point={pfcxoff_point} range_limit={self.range_limit}"
        )

        self.executor.prepare(src_port, drain_port, holder_port)

        # ----------------- Phase 1: binary search -----------------
        # Initial bounds:
        #   D=1   -> almost certainly xon does NOT fire (only 1 packet drained)
        #   D=pfcxoff_point -> xon definitely fires (everything drained from
        #     dst_drain and dst_holder's portion is 0 means nothing held back)
        # We don't actually probe these endpoints — we use them as logical
        # bounds and probe midpoints.
        lower = 0                    # D where xon does NOT fire
        upper = pfcxoff_point        # D where xon DOES fire
        binary_iter = 0
        consecutive_failures = 0
        binary_aborted_due_to_failures = False

        while (upper - lower) > self.range_limit and binary_iter < self.binary_max_iter:
            mid = (lower + upper) // 2
            if mid == lower or mid == upper:
                break  # converged

            success, xon_fired = self.executor.check(
                src_port=src_port,
                drain_port=drain_port,
                holder_port=holder_port,
                value=mid,
                attempts=self.verification_attempts,
                **traffic_keys,
            )
            binary_iter += 1

            if not success:
                consecutive_failures += 1
                # Per code review I2 (2026-05-06): success=False means we have
                # NO semantic information about mid. Moving `upper = mid` would
                # corrupt the search invariant and can permanently exclude the
                # true threshold from the window. Instead: don't move bounds;
                # retry the same midpoint. After max_consecutive_failures, abort
                # phase 1 and fall through to phase 2 step search over the
                # current (uncorrupted) [lower+1, upper] window.
                ProbingObserver.trace(
                    f"[XOn Drain Binary] mid={mid}: check FAILED (inconsistent) "
                    f"(consecutive_failures={consecutive_failures}/{self.max_consecutive_failures})"
                )
                if consecutive_failures >= self.max_consecutive_failures:
                    ProbingObserver.console(
                        f"[XOn Drain Binary] Phase 1 aborted: {consecutive_failures} "
                        f"consecutive failures; falling back to phase 2 step over "
                        f"[{lower + 1}, {upper}] (width={upper - lower})"
                    )
                    binary_aborted_due_to_failures = True
                    break
                continue  # don't move bounds; re-probe same mid

            consecutive_failures = 0  # reset on any successful check

            if xon_fired:
                upper = mid    # mid drained enough, search lower
            else:
                lower = mid    # mid not enough, search upper

            ProbingObserver.trace(
                f"[XOn Drain Binary] iter {binary_iter}: mid={mid} xon_fired={xon_fired} "
                f"-> [{lower}, {upper}] width={upper - lower}"
            )

        # Decision: did binary converge, abort due to failures, or run out of iters?
        window_too_wide = (upper - lower) > self.range_limit
        if window_too_wide and not binary_aborted_due_to_failures:
            elapsed = time.time() - t0
            ProbingObserver.console(
                f"[XOn Drain Binary] Phase 1 binary did not converge after "
                f"{binary_iter} iterations; window=[{lower}, {upper}]"
            )
            return None, None, elapsed

        ProbingObserver.console(
            f"[XOn Drain Binary] Phase 1 done: window=[{lower}, {upper}] width={upper - lower}"
            + (" (aborted due to failures, falling through to step phase)"
               if binary_aborted_due_to_failures else "")
        )

        # ----------------- Phase 2: step-by-step within window -----------------
        step_iter = 0
        for d in range(lower + 1, upper + 1):
            if step_iter >= self.step_max_iter:
                break
            step_iter += 1

            success, xon_fired = self.executor.check(
                src_port=src_port,
                drain_port=drain_port,
                holder_port=holder_port,
                value=d,
                attempts=self.verification_attempts,
                **traffic_keys,
            )
            if not success:
                ProbingObserver.trace(
                    f"[XOn Drain Binary] step D={d}: check FAILED (inconsistent)"
                )
                continue

            ProbingObserver.trace(
                f"[XOn Drain Binary] step D={d}: xon_fired={xon_fired}"
            )

            if xon_fired:
                elapsed = time.time() - t0
                ProbingObserver.console(
                    f"[XOn Drain Binary] FOUND xon offset: lower={d - 1} upper={d} "
                    f"(binary iters={binary_iter}, step iters={step_iter}, "
                    f"total {elapsed:.1f}s)"
                )
                return d - 1, d, elapsed

        elapsed = time.time() - t0
        ProbingObserver.console(
            f"[XOn Drain Binary] Phase 2 step exhausted [{lower}, {upper}] without "
            f"finding xon trigger"
        )
        return None, None, elapsed
