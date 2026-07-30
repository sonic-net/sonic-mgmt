from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class IssueRef:
    """Normalized reference to a GitHub issue."""

    owner: str
    repo: str
    number: int

    @property
    def html_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}/issues/{self.number}"

    @property
    def api_path(self) -> str:
        return f"/repos/{self.owner}/{self.repo}/issues/{self.number}"
