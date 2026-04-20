"""Pure parsing tests for git_cmd helpers — no subprocess involved."""

from __future__ import annotations

from pathlib import Path

import pytest

from unix_pass_mcp import git_cmd

# ── status porcelain v2 parsing ──────────────────────────────────────────────


def test_status_clean() -> None:
    text = (
        "# branch.oid abc1234\n"
        "# branch.head main\n"
        "# branch.upstream origin/main\n"
        "# branch.ab +0 -0\n"
    )
    info = git_cmd.parse_status_porcelain(text)
    assert info.clean is True
    assert info.branch == "main"
    assert info.upstream == "origin/main"
    assert info.ahead == 0
    assert info.behind == 0
    assert info.dirty_files == []


def test_status_ahead_behind() -> None:
    text = "# branch.head main\n# branch.upstream origin/main\n# branch.ab +3 -1\n"
    info = git_cmd.parse_status_porcelain(text)
    assert info.ahead == 3
    assert info.behind == 1
    assert info.clean is False  # ahead/behind counts as not clean


def test_status_modified_file() -> None:
    text = "# branch.head main\n1 .M N... 100644 100644 100644 abc def github.com.gpg\n"
    info = git_cmd.parse_status_porcelain(text)
    assert info.dirty_files == [{"status": ".M", "path": "github.com.gpg"}]
    assert info.clean is False


def test_status_untracked_file() -> None:
    text = "# branch.head main\n? unknown.gpg\n"
    info = git_cmd.parse_status_porcelain(text)
    assert info.dirty_files == [{"status": "??", "path": "unknown.gpg"}]


def test_status_no_upstream() -> None:
    text = "# branch.head main\n"
    info = git_cmd.parse_status_porcelain(text)
    assert info.branch == "main"
    assert info.upstream is None
    assert info.ahead == 0
    assert info.behind == 0


def test_status_detached() -> None:
    text = "# branch.head (detached)\n"
    info = git_cmd.parse_status_porcelain(text)
    assert info.branch is None


# ── log oneline parsing ──────────────────────────────────────────────────────


def test_log_parses_oneline() -> None:
    text = "abc1234 Added github.com\ndef5678 Removed old.com\n0011223 Renamed amazon to aws\n"
    commits = git_cmd.parse_oneline_log(text)
    assert commits == [
        {"hash": "abc1234", "subject": "Added github.com"},
        {"hash": "def5678", "subject": "Removed old.com"},
        {"hash": "0011223", "subject": "Renamed amazon to aws"},
    ]


def test_log_empty() -> None:
    assert git_cmd.parse_oneline_log("") == []


def test_log_full_hash() -> None:
    text = "0123456789abcdef0123456789abcdef01234567 message\n"
    commits = git_cmd.parse_oneline_log(text)
    assert len(commits) == 1
    assert len(commits[0]["hash"]) == 40


# ── remotes parsing ──────────────────────────────────────────────────────────


def test_remotes_no_git_dir(tmp_path: Path) -> None:
    assert git_cmd.remotes(tmp_path) == []


def test_remotes_no_remotes(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n",
        encoding="utf-8",
    )
    assert git_cmd.remotes(tmp_path) == []


def test_remotes_single(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n"
        '[remote "origin"]\n'
        "\turl = git@github.com:user/store.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        encoding="utf-8",
    )
    assert git_cmd.remotes(tmp_path) == [
        {"name": "origin", "url": "git@github.com:user/store.git"},
    ]


def test_remotes_multiple(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text(
        '[remote "origin"]\n'
        "\turl = git@github.com:user/store.git\n"
        '[remote "backup"]\n'
        "\turl = ssh://backup.example.com/store.git\n",
        encoding="utf-8",
    )
    remotes = git_cmd.remotes(tmp_path)
    assert {r["name"] for r in remotes} == {"origin", "backup"}


def test_remotes_url_without_spaces(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text(
        '[remote "origin"]\n\turl=git@github.com:u/s.git\n',
        encoding="utf-8",
    )
    assert git_cmd.remotes(tmp_path) == [
        {"name": "origin", "url": "git@github.com:u/s.git"},
    ]


# ── assert_git_repo ──────────────────────────────────────────────────────────


def test_assert_git_repo_passes_when_present(
    initialized_store: Path,
) -> None:
    (initialized_store / ".git").mkdir()
    git_cmd.assert_git_repo()  # no raise


def test_assert_git_repo_raises_when_missing(initialized_store: Path) -> None:
    from unix_pass_mcp.errors import NotAGitRepo

    with pytest.raises(NotAGitRepo):
        git_cmd.assert_git_repo()
