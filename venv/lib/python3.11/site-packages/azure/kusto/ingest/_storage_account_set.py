import random
from typing import Callable, Dict, List, Tuple
import time

from azure.kusto.data.exceptions import KustoClientError
from azure.kusto.ingest._ranked_storage_account import _RankedStorageAccount


class _RankedStorageAccountSet:
    DEFAULT_NUMBER_OF_BUCKETS: int = 6
    DEFAULT_BUCKET_DURATION_IN_SECONDS: int = 10
    DEFAULT_TIERS: Tuple[int, int, int, int] = (90, 70, 30, 0)
    DEFAULT_TIME_PROVIDER_IN_SECONDS: Callable[[], float] = time.time

    def __init__(
        self,
        number_of_buckets: int = DEFAULT_NUMBER_OF_BUCKETS,
        bucket_duration: float = DEFAULT_BUCKET_DURATION_IN_SECONDS,
        tiers: Tuple[int, int, int, int] = DEFAULT_TIERS,
        time_provider: Callable[[], float] = DEFAULT_TIME_PROVIDER_IN_SECONDS,
    ):
        self.accounts: Dict[str, _RankedStorageAccount] = dict()
        self.number_of_buckets = number_of_buckets
        self.bucket_duration = bucket_duration
        self.tiers = tiers
        self.time_provider = time_provider

    def add_account_result(self, account_name: str, success: bool):
        if self.accounts.get(account_name) is None:
            raise KustoClientError(f"Account {account_name} does not exist in the set")
        self.accounts[account_name].log_result(success)

    def add_storage_account(self, account_name: str):
        if self.accounts.get(account_name) is None:
            self.accounts[account_name] = _RankedStorageAccount(account_name, self.number_of_buckets, self.bucket_duration, self.time_provider)

    def get_storage_account(self, account_name: str) -> _RankedStorageAccount:
        return self.accounts.get(account_name)

    def get_ranked_shuffled_accounts(self) -> List[_RankedStorageAccount]:
        accounts_by_tier: List[List[_RankedStorageAccount]] = [[] for _ in range(len(self.tiers))]

        for account in self.accounts.values():
            rank_percentage = account.get_rank() * 100.0
            for i in range(len(self.tiers)):
                if rank_percentage >= self.tiers[i]:
                    accounts_by_tier[i].append(account)
                    break

        # Shuffle accounts in each tier
        for tier in accounts_by_tier:
            random.shuffle(tier)

        # Flatten the list
        return [item for sublist in accounts_by_tier for item in sublist]
