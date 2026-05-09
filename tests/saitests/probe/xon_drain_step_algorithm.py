"""
XOn Drain Step Algorithm — step-by-step variant for platforms with small
effective_xon_offset (Broadcom TD2/TD3/TH/TH2/TH3/TH5: 12–18 packets).

Iterates D = 1, 2, 3, ... up to max_iter and returns the first D at which
XOn fires. Total cost: O(effective_offset) iterations.

Pairs with PfcXonProbingExecutor.check(value=D) which returns
(success, xon_fired) for each candidate D.

Use this for the 3-step path (when enable_xon_range_probe=False).
For platforms with large offsets (Cisco/PAC/GB), use
XonDrainBinaryAlgorithm instead.
"""

import time
from typing import Optional, Tuple

from probing_observer import ProbingObserver


class XonDrainStepAlgorithm:
    """
    Step-by-step XOn drain probing — for small effective_xon_offset.

    For each candidate D in [1, max_iter]:
      1. Call executor.check(src, drain_port, holder_port, value=D, **traffic_keys)
      2. If xon_fired -> answer is (D-1, D); return.
      3. Else continue.

    If max_iter reached without xon firing, returns None — caller should
    consider switching to binary algorithm or widening the cap.
    """

    def __init__(
        self,
        executor,
        observer: ProbingObserver,
        verification_attempts: int = 1,
        max_iter: int = 50,
        max_consecutive_failures: int = 3,
    ):
        """
        Args:
            executor: PfcXonProbingExecutor instance.
            observer: ProbingObserver for trace/metrics.
            verification_attempts: Per-iteration verification (passed to
                executor.check). 1 = fast; 2 = noise-resilient.
            max_iter: Hard cap on D values to test. Defaults to 50 (covers
                all known Broadcom values comfortably).
            max_consecutive_failures: Number of consecutive ``check()``
                failures (success=False) allowed at the same D before
                aborting the search and returning (None, None). Default 3
                mirrors XonDrainBinaryAlgorithm's noise tolerance pattern
                (see commit b3f8313aad I2 / b1549014a6 N1+N2).

                Why retry-same-D rather than advance-on-failure (per code
                review I1, 2026-05-09): if D=k has a noise-only failure
                but D=k actually fires xon, advancing to D=k+1 misses k
                and reports (k, k+1) when the true answer is (k-1, k) --
                a +1 systematic bias. Retrying the same D up to N times
                preserves the search invariant.
        """
        self.executor = executor
        self.observer = observer
        self.verification_attempts = verification_attempts
        self.max_iter = max_iter
        self.max_consecutive_failures = max_consecutive_failures

    def run(
        self,
        src_port: int,
        drain_port: int,
        holder_port: int,
        **traffic_keys,
    ) -> Tuple[Optional[int], Optional[int], float]:
        """
        Run step-by-step XOn drain probing.

        Returns:
            (xon_lower, xon_upper, elapsed_seconds):
              - xon_lower = D - 1 (largest drain that does NOT trigger xon)
              - xon_upper = D     (smallest drain that DOES trigger xon)
              - elapsed_seconds = wall-clock time of the run.
            Returns (None, None, elapsed) if max_iter reached OR if
            consecutive check failures exceed max_consecutive_failures
            at any D.
        """
        t0 = time.time()
        ProbingObserver.console(
            f"[XOn Drain Step] Starting step-by-step search "
            f"src={src_port} drain={drain_port} holder={holder_port} "
            f"max_iter={self.max_iter}"
        )

        self.executor.prepare(src_port, drain_port, holder_port)

        # Per-D retry-on-failure (I1 fix mirroring Binary's pattern). The loop
        # iterates D from 1..max_iter; for each D, retry up to
        # max_consecutive_failures times on success=False before moving on
        # (or aborting if the cap is hit).
        d = 1
        consecutive_failures = 0
        while d <= self.max_iter:
            success, xon_fired = self.executor.check(
                src_port=src_port,
                drain_port=drain_port,
                holder_port=holder_port,
                value=d,
                attempts=self.verification_attempts,
                **traffic_keys,
            )
            if not success:
                consecutive_failures += 1
                ProbingObserver.trace(
                    f"[XOn Drain Step] D={d}: check FAILED (inconsistent "
                    f"verification) {consecutive_failures}/{self.max_consecutive_failures}"
                )
                if consecutive_failures >= self.max_consecutive_failures:
                    elapsed = time.time() - t0
                    ProbingObserver.console(
                        f"[XOn Drain Step] ABORTED at D={d}: "
                        f"{consecutive_failures} consecutive check failures "
                        f"(>= max_consecutive_failures={self.max_consecutive_failures})"
                    )
                    return None, None, elapsed
                # Retry the SAME D (do not advance). This is the key correctness
                # difference from the original implementation -- see I1 docstring.
                continue

            # Success path -- reset the consecutive-failure counter.
            consecutive_failures = 0

            ProbingObserver.trace(
                f"[XOn Drain Step] D={d}: xon_fired={xon_fired}"
            )

            if xon_fired:
                elapsed = time.time() - t0
                ProbingObserver.console(
                    f"[XOn Drain Step] FOUND xon offset: lower={d - 1} upper={d} "
                    f"(after {d} iterations, {elapsed:.1f}s)"
                )
                return d - 1, d, elapsed

            d += 1

        elapsed = time.time() - t0
        ProbingObserver.console(
            f"[XOn Drain Step] EXHAUSTED max_iter={self.max_iter} without finding xon trigger"
        )
        return None, None, elapsed
