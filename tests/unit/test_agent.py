from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from unix_pass_mcp import agent
from unix_pass_mcp.errors import PassError, Timeout

# ── dialog detection ─────────────────────────────────────────────────────────


def test_find_dialog_picks_zenity_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")
    spec = agent.find_passphrase_dialog()
    assert spec is not None
    assert "zenity" in spec.binary


def test_find_dialog_falls_back_to_kdialog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent.shutil, "which", lambda b: f"/usr/bin/{b}" if b == "kdialog" else None
    )
    spec = agent.find_passphrase_dialog()
    assert spec is not None
    assert "kdialog" in spec.binary


def test_find_dialog_returns_none_when_nothing_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: None)
    assert agent.find_passphrase_dialog() is None


# ── prompt_passphrase ────────────────────────────────────────────────────────


@pytest.fixture
def fake_dialog() -> agent.DialogSpec:
    return agent.DialogSpec(binary="/usr/bin/zenity", args=("--password",))


def _stub_subprocess_run(
    monkeypatch: pytest.MonkeyPatch, *, returncode: int, stdout: str = "", raises: Any = None
) -> dict[str, Any]:
    state: dict[str, Any] = {"calls": []}

    def fake_run(
        args,
        *,
        input=None,
        capture_output=False,
        text=False,
        env=None,
        timeout=None,
        check=False,
        **kw,
    ):
        state["calls"].append({"args": list(args), "input": input, "env": env, "timeout": timeout})
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(
            args=args, returncode=returncode, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    return state


def test_prompt_passphrase_returns_value(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    _stub_subprocess_run(monkeypatch, returncode=0, stdout="hunter2\n")
    assert agent.prompt_passphrase(fake_dialog) == "hunter2"


def test_prompt_passphrase_strips_only_one_trailing_newline(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    _stub_subprocess_run(monkeypatch, returncode=0, stdout="hunter2\n\n")
    assert agent.prompt_passphrase(fake_dialog) == "hunter2\n"


def test_prompt_passphrase_returns_none_on_empty_stdout(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    _stub_subprocess_run(monkeypatch, returncode=0, stdout="\n")
    assert agent.prompt_passphrase(fake_dialog) is None


def test_prompt_passphrase_returns_none_on_cancel(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    _stub_subprocess_run(monkeypatch, returncode=1, stdout="")
    assert agent.prompt_passphrase(fake_dialog) is None


def test_prompt_passphrase_raises_timeout(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    _stub_subprocess_run(
        monkeypatch,
        returncode=0,
        raises=subprocess.TimeoutExpired(cmd="zenity", timeout=10),
    )
    with pytest.raises(Timeout):
        agent.prompt_passphrase(fake_dialog)


def test_prompt_passphrase_raises_when_dialog_missing(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    _stub_subprocess_run(monkeypatch, returncode=0, raises=FileNotFoundError("missing"))
    with pytest.raises(PassError) as exc:
        agent.prompt_passphrase(fake_dialog)
    assert exc.value.code == "no_dialog"


def test_prompt_passphrase_env_is_scoped(
    monkeypatch: pytest.MonkeyPatch, fake_dialog: agent.DialogSpec
) -> None:
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
    state = _stub_subprocess_run(monkeypatch, returncode=0, stdout="x\n")
    agent.prompt_passphrase(fake_dialog)
    env = state["calls"][0]["env"]
    assert env["DISPLAY"] == ":0"
    assert env["WAYLAND_DISPLAY"] == "wayland-0"
    assert "AWS_SECRET_ACCESS_KEY" not in env


# ── find_warmup_target ───────────────────────────────────────────────────────


def test_find_warmup_target_picks_smallest(initialized_store: Path) -> None:
    (initialized_store / "big.gpg").write_bytes(b"x" * 1000)
    (initialized_store / "small.gpg").write_bytes(b"x" * 10)
    (initialized_store / "medium.gpg").write_bytes(b"x" * 100)
    target = agent.find_warmup_target()
    assert target is not None
    assert target.name == "small.gpg"


def test_find_warmup_target_skips_dotdirs(initialized_store: Path) -> None:
    (initialized_store / ".git").mkdir()
    (initialized_store / ".git" / "tiny.gpg").write_bytes(b"x")
    (initialized_store / "real.gpg").write_bytes(b"x" * 100)
    target = agent.find_warmup_target()
    assert target is not None
    assert target.name == "real.gpg"


def test_find_warmup_target_returns_none_when_empty(initialized_store: Path) -> None:
    assert agent.find_warmup_target() is None


def test_find_warmup_target_returns_none_when_missing_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(tmp_path / "absent"))
    assert agent.find_warmup_target() is None


def test_find_warmup_target_honours_name_filter(initialized_store: Path) -> None:
    """Without filter we'd happily warm against a banking entry while scoped to
    web/*. The filter prevents cross-scope decryption.
    """
    (initialized_store / "web").mkdir()
    (initialized_store / "web" / "tiny.gpg").write_bytes(b"x" * 50)
    (initialized_store / "personal").mkdir()
    (initialized_store / "personal" / "banking.gpg").write_bytes(b"x" * 5)
    target = agent.find_warmup_target(name_allowed=lambda name: name.startswith("web/"))
    assert target is not None
    assert target.name == "tiny.gpg"
    assert "personal" not in str(target)


def test_find_warmup_target_returns_none_when_no_in_scope(initialized_store: Path) -> None:
    (initialized_store / "personal").mkdir()
    (initialized_store / "personal" / "banking.gpg").write_bytes(b"x")
    assert agent.find_warmup_target(name_allowed=lambda name: name.startswith("web/")) is None


# ── warm_agent_with_passphrase ───────────────────────────────────────────────


def test_warm_agent_passphrase_via_stdin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")
    state = _stub_subprocess_run(monkeypatch, returncode=0, stdout="decrypted")
    target = tmp_path / "x.gpg"
    target.write_bytes(b"ciphertext")
    assert agent.warm_agent_with_passphrase("hunter2", target) is True
    call = state["calls"][0]
    assert call["input"] == "hunter2"
    assert "--pinentry-mode" in call["args"]
    assert "loopback" in call["args"]
    assert "--passphrase-fd" in call["args"]
    # passphrase must NOT appear in argv
    assert "hunter2" not in call["args"]


def test_warm_agent_returns_false_on_wrong_passphrase(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")
    _stub_subprocess_run(monkeypatch, returncode=2, stdout="")
    target = tmp_path / "x.gpg"
    target.write_bytes(b"ciphertext")
    assert agent.warm_agent_with_passphrase("wrong", target) is False


def test_warm_agent_raises_when_gpg_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: None)
    target = tmp_path / "x.gpg"
    target.write_bytes(b"x")
    with pytest.raises(PassError) as exc:
        agent.warm_agent_with_passphrase("p", target)
    assert exc.value.code == "gpg_missing"


# ── unlock orchestrator ──────────────────────────────────────────────────────


def test_unlock_refuses_without_display(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PassError) as exc:
        agent.unlock(has_display=False)
    assert exc.value.code == "no_display"


def test_unlock_refuses_without_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: None)
    with pytest.raises(PassError) as exc:
        agent.unlock(has_display=True)
    assert exc.value.code == "no_dialog"


def test_unlock_refuses_when_store_empty(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")
    with pytest.raises(PassError) as exc:
        agent.unlock(has_display=True)
    assert exc.value.code == "empty_store"


def test_unlock_returns_cancelled_on_dialog_dismiss(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    (initialized_store / "x.gpg").write_bytes(b"x")
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")
    _stub_subprocess_run(monkeypatch, returncode=1, stdout="")  # zenity cancel
    result = agent.unlock(has_display=True)
    assert result == {"ok": False, "reason": "cancelled"}


def test_unlock_succeeds_end_to_end(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    (initialized_store / "x.gpg").write_bytes(b"x" * 50)
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")

    # Two subprocess calls: dialog returns passphrase (rc=0, stdout=passphrase),
    # then gpg returns success (rc=0).
    call_log: list[Any] = []

    def fake_run(
        args,
        *,
        input=None,
        capture_output=False,
        text=False,
        env=None,
        timeout=None,
        check=False,
        **kw,
    ):
        call_log.append({"args": list(args), "input": input})
        if "zenity" in args[0] or "kdialog" in args[0]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="hunter2\n", stderr=""
            )
        # gpg
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="plain", stderr="")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    result = agent.unlock(has_display=True)
    assert result["ok"] is True
    assert result["method"] == "loopback+desktop_dialog"
    assert "warmup_target_size_bytes" in result
    # gpg was given the passphrase via stdin, never argv.
    gpg_call = next(c for c in call_log if "gpg" in c["args"][0])
    assert gpg_call["input"] == "hunter2"
    assert "hunter2" not in gpg_call["args"]


def test_unlock_returns_wrong_passphrase_on_decrypt_failure(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    (initialized_store / "x.gpg").write_bytes(b"x")
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")

    def fake_run(args, *, input=None, **kw):
        if "zenity" in args[0]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="wrong\n", stderr="")
        return subprocess.CompletedProcess(args=args, returncode=2, stdout="", stderr="bad")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    result = agent.unlock(has_display=True)
    assert result == {"ok": False, "reason": "wrong_passphrase_or_decrypt_failed"}


# ── unlock with explicit target ──────────────────────────────────────────────


def test_unlock_uses_explicit_target_path(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    """When `target` is given, no scanning happens — that entry is decrypted."""
    chosen = initialized_store / "specific.gpg"
    chosen.write_bytes(b"x" * 200)
    # Add a smaller entry that would otherwise be picked.
    (initialized_store / "smaller.gpg").write_bytes(b"x")
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")

    seen_targets: list[str] = []

    def fake_run(args, *, input=None, **kw):
        if "zenity" in args[0]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="pw\n", stderr="")
        # The decrypt call's last arg is the target path.
        seen_targets.append(args[-1])
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    result = agent.unlock(has_display=True, target=chosen)
    assert result["ok"] is True
    assert seen_targets == [str(chosen)]


# ── server-level unlock_agent: target validation + path allowlist ────────────


def test_server_unlock_agent_rejects_invalid_pass_name() -> None:
    from unix_pass_mcp import server
    from unix_pass_mcp.errors import InvalidPassName

    with pytest.raises(InvalidPassName):
        server.unlock_agent(target="../escape")


def test_server_unlock_agent_rejects_out_of_scope_target(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    """If PASS_MCP_ALLOWED_PATHS is set, unlock_agent must refuse to decrypt
    against a target outside the allowlist — otherwise it's a scope escape:
    the agent could warm a banking key while nominally restricted to web/*.
    """
    from unix_pass_mcp import server
    from unix_pass_mcp.errors import PathNotAllowed

    monkeypatch.setenv("PASS_MCP_ALLOWED_PATHS", "web/*")
    (initialized_store / "personal").mkdir()
    (initialized_store / "personal" / "banking.gpg").write_bytes(b"x")
    with pytest.raises(PathNotAllowed):
        server.unlock_agent(target="personal/banking")


def test_server_unlock_agent_missing_target_raises_not_found(
    monkeypatch: pytest.MonkeyPatch, initialized_store: Path
) -> None:
    from unix_pass_mcp import server
    from unix_pass_mcp.errors import NotFound

    # gpg-agent probe must be stubbed since we don't have one in unit-test env.
    monkeypatch.setattr(
        "unix_pass_mcp.pass_cli.gpg_agent_available",
        lambda *a, **kw: True,
    )
    with pytest.raises(NotFound):
        server.unlock_agent(target="does/not/exist")
