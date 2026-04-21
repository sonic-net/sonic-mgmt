from typing import Callable


class _StorageAccountStats:
    def __init__(self):
        self.success_count = 0
        self.total_count = 0

    def log_result(self, success: bool):
        self.total_count += 1
        if success:
            self.success_count += 1

    def reset(self):
        self.success_count = 0
        self.total_count = 0


class _RankedStorageAccount:
    """_RankedStorageAccount is a class that represents a storage account with a rank.
    The rank is used to determine the order in which the storage accounts are used for ingestion.
    """

    def __init__(self, account_name: str, number_of_buckets: int, bucket_duration: float, time_provider: Callable[[], float]):
        self.account_name = account_name
        self.number_of_buckets = number_of_buckets
        self.bucket_duration = bucket_duration
        self.time_provider = time_provider
        self.buckets = [_StorageAccountStats() for _ in range(number_of_buckets)]
        self.last_update_time = self.time_provider()
        self.current_bucket_index = 0

    def log_result(self, success: bool):
        self.current_bucket_index = self._adjust_for_time_passed()
        self.buckets[self.current_bucket_index].log_result(success)

    def get_account_name(self) -> str:
        return self.account_name

    def get_rank(self) -> float:
        rank = 0
        total_weight = 0

        # For each bucket, calculate the success rate ( success / total ) and multiply it by the bucket weight.
        # The older the bucket, the less weight it has. For example, if there are 3 buckets, the oldest bucket will have
        # a weight of 1, the middle bucket will have a weight of 2 and the newest bucket will have a weight of 3.

        for i in range(1, self.number_of_buckets + 1):
            bucket_index = (self.current_bucket_index + i) % self.number_of_buckets
            bucket = self.buckets[bucket_index]
            if bucket.total_count == 0:
                continue
            success_rate = bucket.success_count / bucket.total_count
            rank += success_rate * i
            total_weight += i

        # If there are no buckets with data, return 1 (highest rank)
        if total_weight == 0:
            return 1

        return rank / total_weight

    def _adjust_for_time_passed(self) -> int:
        # Get the current window (bucket) index and reset old windows.
        # This is part of the moving avarge calculation.
        current_time = self.time_provider()
        time_delta = current_time - self.last_update_time
        window_size = 0

        if time_delta >= self.bucket_duration:
            self.last_update_time = current_time
            window_size = min(int(time_delta / self.bucket_duration), self.number_of_buckets)
            for i in range(1, window_size + 1):
                index_to_reset = (self.current_bucket_index + i) % self.number_of_buckets
                self.buckets[index_to_reset].reset()

        return (self.current_bucket_index + window_size) % self.number_of_buckets
