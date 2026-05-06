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
      1. Call executor.check(src, dst_A, dst_B, value=D, **traffic_keys)
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
    ):
        """
        Args:
            executor: PfcXonProbingExecutor instance.
            observer: ProbingObserver for trace/metrics.
            verification_attempts: Per-iteration verification (passed to
                executor.check). 1 = fast; 2 = noise-resilient.
            max_iter: Hard cap on D values to test. Defaults to 50 (covers
                all known Broadcom values comfortably).
        """
        self.executor = executor
        self.observer = observer
        self.verification_attempts = verification_attempts
        self.max_iter = max_iter

    def run(
        self,
        src_port: int,
        dst_port_a: int,
        dst_port_b: int,
        **traffic_keys,
    ) -> Tuple[Optional[int], Optional[int], float]:
        """
        Run step-by-step XOn drain probing.

        Returns:
            (xon_lower, xon_upper, elapsed_seconds):
              - xon_lower = D - 1 (largest drain that does NOT trigger xon)
              - xon_upper = D     (smallest drain that DOES trigger xon)
              - elapsed_seconds = wall-clock time of the run.
            Returns (None, None, elapsed) if max_iter reached.
        """
        t0 = time.time()
        ProbingObserver.console(
            f"[XOn Drain Step] Starting step-by-step search "
            f"src={src_port} dst_A={dst_port_a} dst_B={dst_port_b} "
            f"max_iter={self.max_iter}"
        )

        self.executor.prepare(src_port, dst_port_a, dst_port_b)

        for d in range(1, self.max_iter + 1):
            success, xon_fired = self.executor.check(
                src_port=src_port,
                dst_port_a=dst_port_a,
                dst_port_b=dst_port_b,
                value=d,
                attempts=self.verification_attempts,
                **traffic_keys,
            )
            if not success:
                ProbingObserver.trace(
                    f"[XOn Drain Step] D={d}: check FAILED (inconsistent verification)"
                )
                continue

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

        elapsed = time.time() - t0
        ProbingObserver.console(
            f"[XOn Drain Step] EXHAUSTED max_iter={self.max_iter} without finding xon trigger"
        )
        return None, None, elapsed
