from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class IssueRef:
    """Normalized reference to a GitHub issue."""

    owner: str
    repo: str
    number: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "owner", (self.owner or "").strip().lower())
        object.__setattr__(self, "repo", (self.repo or "").strip().lower())

    @property
    def html_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}/issues/{self.number}"

    @property
    def api_path(self) -> str:
        return f"/repos/{self.owner}/{self.repo}/issues/{self.number}"
