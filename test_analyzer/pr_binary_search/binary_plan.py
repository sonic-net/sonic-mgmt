from typing import List, Dict, Optional, Tuple


def choose_optimal_segments(n: int, max_parallel: int) -> int:
    """
    Choose optimal number of segments for current range size n and max parallel limit.
    Returns the number of segments to divide the range into.
    """
    if n <= 2:
        return n

    # For binary search efficiency, we want to divide the range optimally
    # But limit by max_parallel to avoid too many concurrent tests

    # Optimal would be to test roughly half the range, but spread out
    # For range n, testing k points gives us k+1 segments
    # We want k <= max_parallel
    max_segments = max_parallel + 1
    optimal_segments = min((max_segments), max(3, int(n ** 0.5)))

    # Ensure we don't create more segments than we have commits
    return min(optimal_segments, n)


def compute_indices(left: int, right: int, f: int) -> List[int]:
    """
    Divide [left,right] into f segments (f>=1), return boundary point indices (length = f-1).
    Each segment length differs by at most 1.
    """
    n = right - left + 1
    if f <= 1 or n <= 1:
        return []
    q, r = divmod(n, f)
    sizes = [q+1]*r + [q]*(f-r)
    indices = []
    prefix = 0
    for j in range(len(sizes)-1):
        prefix += sizes[j]
        idx = left + prefix - 1
        if not indices or idx > indices[-1]:
            indices.append(idx)
    return indices


class DynamicParallelBisect:
    def __init__(self, commits: List[str], max_parallel: int = 5, bad_commit_checker=None):
        self.commits = commits
        self.N = len(commits)
        self.max_parallel = max_parallel
        self.left = 0
        self.right = self.N - 1
        self.round_no = 0
        self.finished = False
        self.result = None
        self.bad_commit_checker = bad_commit_checker

    def update(self, results: Dict[str, bool]):
        """
        results: {commit_id: True/False}, True = bad
        Update left/right based on parallel test results from this round.
        """
        if self.finished:
            return

        # Find the leftmost bad commit in this round
        bad_idx = None
        for idx in range(self.left, self.right + 1):
            cid = self.commits[idx]
            if cid in results and results[cid]:
                bad_idx = idx
                break

        if bad_idx is None:
            # No bad commit in this round, all tested commits are good
            # Find the rightmost tested commit, then set left to the next position
            tested_indices = []
            for idx in range(self.left, self.right + 1):
                cid = self.commits[idx]
                if cid in results:
                    tested_indices.append(idx)

            if tested_indices:
                # Set left to the next position after the rightmost tested commit
                self.left = max(tested_indices) + 1
            else:
                # If no commit was tested, this shouldn't happen
                self.left = self.right + 1
        else:
            # Found bad commit, need to consider both bad and good commits
            # The search range should be: (rightmost_good + 1) to bad_commit

            # Find the rightmost good commit among tested commits
            rightmost_good_idx = None
            for idx in range(self.left, bad_idx):  # Only check commits before the bad one
                cid = self.commits[idx]
                if cid in results and not results[cid]:  # Good commit
                    if rightmost_good_idx is None or idx > rightmost_good_idx:
                        rightmost_good_idx = idx

            # Update the search range
            if rightmost_good_idx is not None:
                # Set left to the position after the rightmost good commit
                self.left = rightmost_good_idx + 1
            # Set right to the bad commit's position
            self.right = bad_idx

        # Check if finished
        if self.left > self.right:
            self.finished = True
            self.result = None  # No bad commit found
        elif self.left == self.right:
            self.finished = True
            self.result = self.commits[self.left]

    def next_plan(self) -> Optional[Dict]:
        """Return the next round plan"""
        if self.finished:
            return None

        self.round_no += 1

        # Check if already converged to a single commit
        if self.left == self.right:
            self.finished = True
            self.result = self.commits[self.left]
            return {"round": self.round_no,
                    "tests": [self.commits[self.left]],
                    "indices": [self.left],
                    "range": (self.left, self.right),
                    "final": True}

        # Check if out of range
        if self.left > self.right or self.left >= len(self.commits):
            self.finished = True
            return None

        n = self.right - self.left + 1

        # For small ranges, just test the middle
        if n <= 2:
            mid = (self.left + self.right) // 2
            return {"round": self.round_no,
                    "tests": [self.commits[mid]],
                    "indices": [mid],
                    "range": (self.left, self.right),
                    "final": False}

        # Choose optimal number of segments based on range size and max_parallel
        f_here = choose_optimal_segments(n, self.max_parallel)
        indices = compute_indices(self.left, self.right, f_here)

        # Ensure indices are within valid range and limit by max_parallel
        indices = [i for i in indices if self.left <= i <= self.right]
        if len(indices) > self.max_parallel:
            # If we have too many indices, select evenly spaced ones
            step = max(1, len(indices) // self.max_parallel)
            indices = indices[::step][:self.max_parallel]

        tests = [self.commits[i] for i in indices]

        return {"round": self.round_no,
                "tests": tests,
                "indices": indices,
                "segments": f_here,
                "range": (self.left, self.right),
                "final": False}

    def get_result(self) -> Tuple[Optional[str], Tuple[int, int]]:
        if self.result is not None:
            return self.result, (self.left, self.right)
        else:
            return None, (self.left, self.right)

    def find_bad_commit_auto(self, bad_commit_checker) -> Optional[str]:
        """
        Automatically find the first bad commit using the provided checker function.
        bad_commit_checker: function that takes a commit_id and returns True if bad, False if good
        """
        self.bad_commit_checker = bad_commit_checker

        while True:
            plan = self.next_plan()
            if plan is None:
                break

            # Test all commits in the plan
            results = {}
            for commit_id in plan['tests']:
                results[commit_id] = self.bad_commit_checker(commit_id)

            self.update(results)

            if self.finished:
                break

        result, _ = self.get_result()
        return result

    def get_next_test_commits(self) -> Optional[Dict]:
        """
        Get the next batch of commits to test (without automatically testing them).
        Returns a plan dict with commits to test, or None if finished.

        Returns:
            Dict with keys:
            - 'round': current round number
            - 'tests': list of commit IDs to test
            - 'indices': list of indices of commits to test
            - 'range': current search range (left, right)
            - 'remaining_range': number of commits in current range
            - 'final': whether this is the final test
        """
        plan = self.next_plan()
        if plan is None:
            return None

        # Add additional info for user convenience
        plan['remaining_range'] = self.right - self.left + 1
        plan['current_range_commits'] = self.commits[self.left:self.right + 1]

        return plan

    def submit_test_results(self, results: Dict[str, bool]) -> Dict:
        """
        Submit the test results and get updated status.

        Args:
            results: Dict mapping commit_id to test result (True=bad, False=good)

        Returns:
            Dict with status information:
            - 'finished': whether search is complete
            - 'result': the bad commit if found, None otherwise
            - 'new_range': updated search range (left, right)
            - 'new_range_commits': commits in the new range
            - 'eliminated_commits': commits that were eliminated this round
        """
        old_left, old_right = self.left, self.right
        old_range_commits = self.commits[old_left:old_right + 1]

        self.update(results)

        new_range_commits = []
        if not self.finished and self.left <= self.right:
            new_range_commits = self.commits[self.left:self.right + 1]

        # Calculate eliminated commits
        eliminated_commits = [c for c in old_range_commits if c not in new_range_commits]

        result, _ = self.get_result()

        return {
            'finished': self.finished,
            'result': result,
            'new_range': (self.left, self.right) if not self.finished else None,
            'start': self.left,
            'end': self.right,
            'eliminated_commits': eliminated_commits,
            'round_completed': self.round_no
        }

    def get_search_status(self) -> Dict:
        """Get current search status"""
        result, _ = self.get_result()
        return {
            'finished': self.finished,
            'result': result,
            'current_round': self.round_no,
            'current_range': (self.left, self.right),
            'current_range_commits': self.commits[self.left:self.right + 1] if self.left <= self.right else [],
            'remaining_commits': self.right - self.left + 1 if self.left <= self.right else 0,
            'max_parallel': self.max_parallel
        }
