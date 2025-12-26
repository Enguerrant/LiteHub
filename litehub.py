from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import requests
from PySide6 import QtCore, QtGui, QtWidgets

try:
    import keyring  # type: ignore
except Exception:
    keyring = None


APP_NAME = "LiteHub"
KEYRING_SERVICE = "litehub.app"
KEYRING_ACCOUNT = "github_token"


# ----------------------------
# Storage for GitHub token
# ----------------------------


class TokenStore:
    """
    Stores token in OS keyring when available; otherwise falls back to a local file with 0600 permissions.
    """

    def __init__(self) -> None:
        self.fallback_path = Path.home() / ".config" / "litehub" / "token.json"

    def set_token(self, token: str) -> None:
        token = token.strip()
        if not token:
            raise ValueError("Token is empty.")

        if keyring is not None:
            keyring.set_password(KEYRING_SERVICE, KEYRING_ACCOUNT, token)
            return

        self.fallback_path.parent.mkdir(parents=True, exist_ok=True)
        self.fallback_path.write_text(json.dumps({"token": token}), encoding="utf-8")
        try:
            os.chmod(self.fallback_path, 0o600)
        except Exception:
            pass

    def get_token(self) -> Optional[str]:
        if keyring is not None:
            try:
                t = keyring.get_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
                return t.strip() if t else None
            except Exception:
                pass

        if self.fallback_path.exists():
            try:
                data = json.loads(self.fallback_path.read_text(encoding="utf-8"))
                t = data.get("token")
                return t.strip() if isinstance(t, str) and t.strip() else None
            except Exception:
                return None
        return None

    def clear_token(self) -> None:
        if keyring is not None:
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
            except Exception:
                pass
        if self.fallback_path.exists():
            try:
                self.fallback_path.unlink()
            except Exception:
                pass


# ----------------------------
# GitHub API client (minimal)
# ----------------------------


class GitHubClient:
    def __init__(self, token: str) -> None:
        self.token = token.strip()

    def _headers(self) -> dict:
        # GitHub recommends these headers for REST API calls.
        # Docs: https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api
        return {
            "Authorization": f"Bearer {self.token}",  # Docs: https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": APP_NAME,
        }

    def get_me(self) -> dict:
        # Docs: https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user
        r = requests.get(
            "https://api.github.com/user", headers=self._headers(), timeout=20
        )
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub /user failed ({r.status_code}): {r.text}")
        return r.json()

    def create_repo(self, name: str, private: bool) -> dict:
        name = name.strip()
        if not name:
            raise ValueError("Repository name is empty.")

        payload = {"name": name, "private": private}
        # Docs: https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#create-a-repository-for-the-authenticated-user
        r = requests.post(
            "https://api.github.com/user/repos",
            headers=self._headers(),
            json=payload,
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub create repo failed ({r.status_code}): {r.text}")
        return r.json()


# ----------------------------
# Git plumbing via subprocess (fast, low deps)
# ----------------------------


@dataclass(frozen=True)
class StatusEntry:
    path: str
    index_status: str  # staged
    worktree_status: str  # unstaged
    is_untracked: bool = False


class GitRunner:
    def __init__(self) -> None:
        self.git_exe = "git"

    def _run(
        self,
        args: list[str],
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        p = subprocess.run(
            [self.git_exe, *args],
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
        if check and p.returncode != 0:
            out = (p.stdout or b"").decode("utf-8", errors="replace")
            err = (p.stderr or b"").decode("utf-8", errors="replace")
            raise RuntimeError(
                f"git {' '.join(map(shlex.quote, args))}\n{err.strip()}\n{out.strip()}"
            )
        return p

    def is_repo(self, path: Path) -> bool:
        try:
            self._run(["rev-parse", "--is-inside-work-tree"], cwd=path, check=True)
            return True
        except Exception:
            return False

    def clone(self, url: str, dst: Path) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._run(["clone", url, str(dst)], check=True)

    def init(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        self._run(["init"], cwd=path, check=True)

    def status(self, repo: Path) -> list[StatusEntry]:
        # Porcelain format docs:
        # https://git-scm.com/docs/git-status#Documentation/git-status.txt---porcelainltversiongt
        p = self._run(["status", "--porcelain", "-z"], cwd=repo, check=True)
        data = p.stdout or b""
        if not data:
            return []

        parts = data.split(b"\x00")
        entries: list[StatusEntry] = []
        i = 0
        while i < len(parts):
            rec = parts[i]
            i += 1
            if not rec:
                continue

            # rec looks like: b"XY path"
            # or for untracked: b"?? path"
            # for rename/copy in -z, next NUL field may contain the new path
            if len(rec) < 3:
                continue
            xy = rec[:2].decode("utf-8", errors="replace")
            # third byte is space in well-formed porcelain output
            path_bytes = rec[3:] if len(rec) >= 4 else b""
            path = path_bytes.decode("utf-8", errors="replace")

            is_untracked = xy == "??"
            index_s = xy[0]
            worktree_s = xy[1]

            # Handle rename/copy best-effort: when staged status is R or C, git -z emits two paths.
            if index_s in ("R", "C") and i < len(parts) and parts[i]:
                new_path = parts[i].decode("utf-8", errors="replace")
                i += 1
                # show new path as the path to act on
                path = new_path

            entries.append(
                StatusEntry(
                    path=path,
                    index_status=index_s,
                    worktree_status=worktree_s,
                    is_untracked=is_untracked,
                )
            )

        return entries

    def diff(self, repo: Path, path: str, staged: bool) -> str:
        args = ["diff"]
        if staged:
            args.append("--cached")
        args += ["--", path]
        p = self._run(args, cwd=repo, check=False)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
        err = (p.stderr or b"").decode("utf-8", errors="replace")
        return out if out.strip() else err

    def add(self, repo: Path, paths: list[str]) -> None:
        if not paths:
            return
        self._run(["add", "--"] + paths, cwd=repo, check=True)

    def reset_paths(self, repo: Path, paths: list[str]) -> None:
        if not paths:
            return
        self._run(["reset", "--"] + paths, cwd=repo, check=True)

    def commit(self, repo: Path, message: str) -> None:
        msg = message.strip()
        if not msg:
            raise ValueError("Commit message is empty.")
        self._run(["commit", "-m", msg], cwd=repo, check=True)

    def pull_ff_only(self, repo: Path, env: Optional[dict] = None) -> None:
        self._run(["pull", "--ff-only"], cwd=repo, env=env, check=True)

    def push(self, repo: Path, env: Optional[dict] = None) -> None:
        self._run(["push"], cwd=repo, env=env, check=True)

    def get_remote_url(self, repo: Path, remote: str = "origin") -> Optional[str]:
        p = self._run(["remote", "get-url", remote], cwd=repo, check=False)
        if p.returncode != 0:
            return None
        return (p.stdout or b"").decode("utf-8", errors="replace").strip()

    def get_config(self, repo: Path, key: str) -> Optional[str]:
        p = self._run(["config", "--get", key], cwd=repo, check=False)
        if p.returncode != 0:
            return None
        return (p.stdout or b"").decode("utf-8", errors="replace").strip()

    def set_config(self, repo: Path, key: str, value: str) -> None:
        self._run(["config", key, value], cwd=repo, check=True)


def make_git_askpass_env(username: str, token: str) -> tuple[dict, Callable[[], None]]:
    """
    Creates a temporary askpass script that prints username or token.
    This lets `git push/pull` authenticate over HTTPS without interactive prompts.

    Git uses GIT_ASKPASS + GIT_TERMINAL_PROMPT=0 for non-interactive credential prompting.
    Docs: https://git-scm.com/docs/git#Documentation/git.txt-GIT_ASKPASS
          https://git-scm.com/docs/git#Documentation/git.txt-GITTERMINALPROMPT
    """
    username = username.strip()
    token = token.strip()

    if not username or not token:
        raise ValueError("Username/token missing for askpass env.")

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    if os.name == "nt":
        # .bat askpass
        fd, p = tempfile.mkstemp(prefix="litehub_askpass_", suffix=".bat")
        os.close(fd)
        script_path = Path(p)
        script = r"""@echo off
set prompt=%1
echo %prompt% | findstr /i "username" >nul
if %errorlevel%==0 (
  echo __USERNAME__
) else (
  echo __TOKEN__
)
"""
        script = script.replace("__USERNAME__", username).replace("__TOKEN__", token)
        script_path.write_text(script, encoding="utf-8")
        env["GIT_ASKPASS"] = str(script_path)
        env["SSH_ASKPASS"] = str(script_path)
    else:
        fd, p = tempfile.mkstemp(prefix="litehub_askpass_", suffix=".sh")
        os.close(fd)
        script_path = Path(p)
        script = """#!/bin/sh
case "$1" in
  *Username*|*username*)
    printf "%s\\n" "__USERNAME__"
    ;;
  *)
    printf "%s\\n" "__TOKEN__"
    ;;
esac
"""
        script = script.replace("__USERNAME__", username).replace("__TOKEN__", token)
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR)
        env["GIT_ASKPASS"] = str(script_path)
        env["SSH_ASKPASS"] = str(script_path)
        # Some setups require DISPLAY to be set for SSH_ASKPASS, harmless if unused:
        env.setdefault("DISPLAY", ":0")

    def _cleanup() -> None:
        try:
            script_path.unlink(
                missing_ok=True
            )  # py3.8+ supports missing_ok? (3.8 yes for Path.unlink? actually 3.8 has it)
        except TypeError:
            try:
                if script_path.exists():
                    script_path.unlink()
            except Exception:
                pass
        except Exception:
            pass

    return env, _cleanup


# ----------------------------
# Qt worker plumbing
# ----------------------------


class WorkerSignals(QtCore.QObject):
    done = QtCore.Signal(object)
    error = QtCore.Signal(str)


class Worker(QtCore.QRunnable):
    def __init__(self, fn: Callable[[], object]) -> None:
        super().__init__()
        self.fn = fn
        self.signals = WorkerSignals()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            result = self.fn()
            self.signals.done.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))


# ----------------------------
# Dialogs
# ----------------------------


class TokenDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget, existing: Optional[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle("GitHub Token")
        self.setModal(True)

        self.token_edit = QtWidgets.QLineEdit()
        self.token_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.token_edit.setPlaceholderText(
            "Paste GitHub token (PAT / fine-grained token)"
        )
        if existing:
            self.token_edit.setText(existing)

        btn_save = QtWidgets.QPushButton("Save")
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_clear = QtWidgets.QPushButton("Clear stored token")

        btn_save.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        btn_clear.clicked.connect(self._clear)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(
            QtWidgets.QLabel(
                "Token is used for GitHub API and for HTTPS push/pull.\n"
                "Create it in GitHub settings. Keep it secret."
            )
        )
        layout.addWidget(self.token_edit)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(btn_clear)
        row.addStretch(1)
        row.addWidget(btn_cancel)
        row.addWidget(btn_save)
        layout.addLayout(row)

        self._should_clear = False

    def _clear(self) -> None:
        self._should_clear = True
        self.token_edit.setText("")

    @property
    def should_clear(self) -> bool:
        return self._should_clear

    @property
    def token(self) -> str:
        return self.token_edit.text().strip()


class CloneDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Clone Repository")
        self.setModal(True)

        self.url = QtWidgets.QLineEdit()
        self.url.setPlaceholderText("https://github.com/owner/repo.git")

        self.dst = QtWidgets.QLineEdit()
        btn_browse = QtWidgets.QPushButton("Browse…")
        btn_browse.clicked.connect(self._browse)

        form = QtWidgets.QFormLayout()
        form.addRow("Repo URL:", self.url)

        dst_row = QtWidgets.QHBoxLayout()
        dst_row.addWidget(self.dst, 1)
        dst_row.addWidget(btn_browse)
        form.addRow("Destination:", dst_row)

        btn_ok = QtWidgets.QPushButton("Clone")
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)

        row = QtWidgets.QHBoxLayout()
        row.addStretch(1)
        row.addWidget(btn_cancel)
        row.addWidget(btn_ok)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(row)

    def _browse(self) -> None:
        d = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Choose destination folder"
        )
        if d:
            self.dst.setText(d)

    def values(self) -> tuple[str, Path]:
        url = self.url.text().strip()
        dst = Path(self.dst.text().strip()).expanduser()
        if not url:
            raise ValueError("URL missing.")
        if not str(dst):
            raise ValueError("Destination missing.")
        return url, dst


class CreateRepoDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Create GitHub Repository")
        self.setModal(True)

        self.name = QtWidgets.QLineEdit()
        self.name.setPlaceholderText("repo-name")

        self.private = QtWidgets.QCheckBox("Private")
        self.private.setChecked(False)

        form = QtWidgets.QFormLayout()
        form.addRow("Name:", self.name)
        form.addRow("", self.private)

        btn_ok = QtWidgets.QPushButton("Create")
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)

        row = QtWidgets.QHBoxLayout()
        row.addStretch(1)
        row.addWidget(btn_cancel)
        row.addWidget(btn_ok)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(row)

    def values(self) -> tuple[str, bool]:
        name = self.name.text().strip()
        if not name:
            raise ValueError("Name missing.")
        return name, self.private.isChecked()


# ----------------------------
# Main window
# ----------------------------


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} (no Electron)")
        self.resize(1100, 700)

        self.tokens = TokenStore()
        self.git = GitRunner()
        self.threadpool = QtCore.QThreadPool.globalInstance()

        self.repo_path: Optional[Path] = None
        self.github_username: Optional[str] = None  # fetched from API when token exists

        self._build_ui()
        self._build_menu()

        self.refresh_timer = QtCore.QTimer(self)
        self.refresh_timer.setInterval(1200)
        self.refresh_timer.timeout.connect(self.refresh_status)
        self.refresh_timer.start()

        self._update_ui_enabled(False)

    def _build_ui(self) -> None:
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        self.repo_edit = QtWidgets.QLineEdit()
        self.repo_edit.setPlaceholderText("Open a repo folder…")
        self.repo_edit.returnPressed.connect(self.open_repo_from_edit)

        btn_open = QtWidgets.QPushButton("Open")
        btn_open.clicked.connect(self.open_repo_dialog)

        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("Repo:"))
        top.addWidget(self.repo_edit, 1)
        top.addWidget(btn_open)

        self.changes = QtWidgets.QTreeWidget()
        self.changes.setHeaderLabels(["File", "Staged", "Unstaged", "Untracked"])
        self.changes.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.changes.itemSelectionChanged.connect(self._on_select_change)

        self.diff_view = QtWidgets.QPlainTextEdit()
        self.diff_view.setReadOnly(True)
        self.diff_view.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        mono = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        self.diff_view.setFont(mono)

        self.commit_msg = QtWidgets.QPlainTextEdit()
        self.commit_msg.setPlaceholderText("Commit message…")
        self.commit_msg.setMaximumHeight(90)

        self.btn_stage_all = QtWidgets.QPushButton("Stage all")
        self.btn_unstage_all = QtWidgets.QPushButton("Unstage all")
        self.btn_commit = QtWidgets.QPushButton("Commit")
        self.btn_pull = QtWidgets.QPushButton("Pull")
        self.btn_push = QtWidgets.QPushButton("Push")

        self.btn_stage_all.clicked.connect(self.stage_all)
        self.btn_unstage_all.clicked.connect(self.unstage_all)
        self.btn_commit.clicked.connect(self.commit)
        self.btn_pull.clicked.connect(self.pull)
        self.btn_push.clicked.connect(self.push)

        actions = QtWidgets.QHBoxLayout()
        actions.addWidget(self.btn_stage_all)
        actions.addWidget(self.btn_unstage_all)
        actions.addStretch(1)
        actions.addWidget(self.btn_pull)
        actions.addWidget(self.btn_push)
        actions.addWidget(self.btn_commit)

        left = QtWidgets.QVBoxLayout()
        left.addWidget(QtWidgets.QLabel("Changes"))
        left.addWidget(self.changes, 1)

        right = QtWidgets.QVBoxLayout()
        right.addWidget(QtWidgets.QLabel("Diff"))
        right.addWidget(self.diff_view, 1)
        right.addWidget(QtWidgets.QLabel("Commit"))
        right.addWidget(self.commit_msg)
        right.addLayout(actions)

        splitter = QtWidgets.QSplitter()
        leftw = QtWidgets.QWidget()
        leftw.setLayout(left)
        rightw = QtWidgets.QWidget()
        rightw.setLayout(right)
        splitter.addWidget(leftw)
        splitter.addWidget(rightw)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout = QtWidgets.QVBoxLayout(central)
        layout.addLayout(top)
        layout.addWidget(splitter, 1)

        self.statusbar = QtWidgets.QStatusBar()
        self.setStatusBar(self.statusbar)

    def _build_menu(self) -> None:
        m = self.menuBar()

        file_menu = m.addMenu("&File")
        act_open = QtGui.QAction("Open repo…", self)
        act_open.triggered.connect(self.open_repo_dialog)
        file_menu.addAction(act_open)

        act_clone = QtGui.QAction("Clone…", self)
        act_clone.triggered.connect(self.clone_dialog)
        file_menu.addAction(act_clone)

        act_init = QtGui.QAction("Init new local repo…", self)
        act_init.triggered.connect(self.init_local_repo)
        file_menu.addAction(act_init)

        file_menu.addSeparator()
        act_quit = QtGui.QAction("Quit", self)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        gh_menu = m.addMenu("&GitHub")
        act_token = QtGui.QAction("Login token…", self)
        act_token.triggered.connect(self.login_token)
        gh_menu.addAction(act_token)

        act_me = QtGui.QAction("Who am I?", self)
        act_me.triggered.connect(self.show_me)
        gh_menu.addAction(act_me)

        act_create = QtGui.QAction("Create repo…", self)
        act_create.triggered.connect(self.create_repo_dialog)
        gh_menu.addAction(act_create)

    def _update_ui_enabled(self, enabled: bool) -> None:
        for w in [
            self.changes,
            self.diff_view,
            self.commit_msg,
            self.btn_stage_all,
            self.btn_unstage_all,
            self.btn_commit,
            self.btn_pull,
            self.btn_push,
        ]:
            w.setEnabled(enabled)

    def _set_repo(self, path: Path) -> None:
        self.repo_path = path
        self.repo_edit.setText(str(path))
        self._update_ui_enabled(True)
        self.refresh_status()

    def _info(self, msg: str) -> None:
        self.statusbar.showMessage(msg, 8000)

    def _error_box(self, title: str, msg: str) -> None:
        QtWidgets.QMessageBox.critical(self, title, msg)

    # ----------------------------
    # Repo open / init / clone
    # ----------------------------

    def open_repo_from_edit(self) -> None:
        p = Path(self.repo_edit.text().strip()).expanduser()
        self.open_repo(p)

    def open_repo_dialog(self) -> None:
        d = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Open git repository folder"
        )
        if not d:
            return
        self.open_repo(Path(d))

    def open_repo(self, path: Path) -> None:
        path = path.expanduser().resolve()
        if not path.exists():
            self._error_box("Open repo", "Folder does not exist.")
            return
        if not self.git.is_repo(path):
            self._error_box(
                "Open repo", "Not a git repository (no working tree detected)."
            )
            return
        self._set_repo(path)

    def init_local_repo(self) -> None:
        d = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Choose folder for new repo"
        )
        if not d:
            return
        path = Path(d).expanduser().resolve()

        def job() -> object:
            self.git.init(path)
            return True

        w = Worker(job)
        w.signals.done.connect(
            lambda _: (self._set_repo(path), self._info("Initialized repository."))
        )
        w.signals.error.connect(lambda e: self._error_box("Init failed", e))
        self.threadpool.start(w)

    def clone_dialog(self) -> None:
        dlg = CloneDialog(self)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        try:
            url, dst_dir = dlg.values()
        except Exception as e:
            self._error_box("Clone", str(e))
            return

        # If destination chosen is a folder, we clone into that folder/repo-name by default.
        # For simplicity: if it's empty dir, clone into it; else create child dir.
        def job() -> object:
            target = dst_dir
            if target.exists() and any(target.iterdir()):
                # pick folder name from URL
                name = url.rstrip("/").split("/")[-1]
                if name.endswith(".git"):
                    name = name[:-4]
                target = target / name
            self.git.clone(url, target)
            return str(target)

        w = Worker(job)
        w.signals.done.connect(
            lambda target: (
                self._set_repo(Path(str(target))),
                self._info("Clone complete."),
            )
        )
        w.signals.error.connect(lambda e: self._error_box("Clone failed", e))
        self.threadpool.start(w)

    # ----------------------------
    # GitHub token and API
    # ----------------------------

    def login_token(self) -> None:
        existing = self.tokens.get_token()
        dlg = TokenDialog(self, existing)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted and not dlg.should_clear:
            return

        try:
            if dlg.should_clear or not dlg.token:
                self.tokens.clear_token()
                self.github_username = None
                self._info("Token cleared.")
                return

            self.tokens.set_token(dlg.token)
            self._info("Token saved. Checking…")
            self._refresh_github_identity_async()
        except Exception as e:
            self._error_box("Token", str(e))

    def _refresh_github_identity_async(self) -> None:
        token = self.tokens.get_token()
        if not token:
            self.github_username = None
            return

        def job() -> object:
            gh = GitHubClient(token)
            me = gh.get_me()
            return me

        w = Worker(job)

        def done(me: object) -> None:
            if isinstance(me, dict):
                self.github_username = str(me.get("login") or "").strip() or None
                self._info(f"Authenticated as: {self.github_username or 'unknown'}")
            else:
                self._info("Authenticated.")

        w.signals.done.connect(done)
        w.signals.error.connect(lambda e: self._error_box("GitHub auth failed", e))
        self.threadpool.start(w)

    def show_me(self) -> None:
        token = self.tokens.get_token()
        if not token:
            self._error_box("GitHub", "No token saved. Use GitHub → Login token…")
            return

        def job() -> object:
            gh = GitHubClient(token)
            return gh.get_me()

        w = Worker(job)
        w.signals.done.connect(
            lambda me: QtWidgets.QMessageBox.information(
                self, "GitHub user", json.dumps(me, indent=2)
            )
        )
        w.signals.error.connect(lambda e: self._error_box("GitHub", e))
        self.threadpool.start(w)

    def create_repo_dialog(self) -> None:
        token = self.tokens.get_token()
        if not token:
            self._error_box("Create repo", "No token saved. Use GitHub → Login token…")
            return

        dlg = CreateRepoDialog(self)
        if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        try:
            name, private = dlg.values()
        except Exception as e:
            self._error_box("Create repo", str(e))
            return

        def job() -> object:
            gh = GitHubClient(token)
            repo = gh.create_repo(name=name, private=private)
            return repo

        w = Worker(job)

        def done(repo: object) -> None:
            if not isinstance(repo, dict):
                self._info("Repo created.")
                return
            html_url = repo.get("html_url")
            clone_url = repo.get("clone_url")
            msg = f"Created.\n\nHTML: {html_url}\nClone: {clone_url}"
            QtWidgets.QMessageBox.information(self, "GitHub", msg)

        w.signals.done.connect(done)
        w.signals.error.connect(lambda e: self._error_box("Create repo failed", e))
        self.threadpool.start(w)

    # ----------------------------
    # Status / diff / stage / commit
    # ----------------------------

    def refresh_status(self) -> None:
        if not self.repo_path:
            return
        repo = self.repo_path

        def job() -> object:
            entries = self.git.status(repo)
            return entries

        w = Worker(job)

        def done(res: object) -> None:
            if not isinstance(res, list):
                return
            self._populate_changes(res)

        w.signals.done.connect(done)
        w.signals.error.connect(lambda e: self._info(f"Status error: {e}"))
        self.threadpool.start(w)

    def _populate_changes(self, entries: list[StatusEntry]) -> None:
        self.changes.clear()
        for e in entries:
            it = QtWidgets.QTreeWidgetItem(
                [
                    e.path,
                    e.index_status,
                    e.worktree_status,
                    "yes" if e.is_untracked else "",
                ]
            )
            it.setData(0, QtCore.Qt.ItemDataRole.UserRole, e.path)
            self.changes.addTopLevelItem(it)
        self.changes.resizeColumnToContents(0)

        if not entries:
            self.diff_view.setPlainText("Working tree clean.")

    def _on_select_change(self) -> None:
        if not self.repo_path:
            return
        items = self.changes.selectedItems()
        if not items:
            return
        path = items[0].data(0, QtCore.Qt.ItemDataRole.UserRole)
        if not isinstance(path, str) or not path:
            return

        repo = self.repo_path

        def job() -> object:
            unstaged = self.git.diff(repo, path, staged=False)
            staged = self.git.diff(repo, path, staged=True)
            return (path, staged, unstaged)

        w = Worker(job)

        def done(res: object) -> None:
            if not isinstance(res, tuple) or len(res) != 3:
                return
            pth, staged, unstaged = res
            text = f"### {pth}\n\n"
            if staged and staged.strip():
                text += "=== Staged (index) ===\n" + staged.strip() + "\n\n"
            if unstaged and unstaged.strip():
                text += "=== Unstaged (working tree) ===\n" + unstaged.strip() + "\n"
            if text.strip() == f"### {pth}":
                text += "(No diff available.)"
            self.diff_view.setPlainText(text)

        w.signals.done.connect(done)
        w.signals.error.connect(lambda e: self._info(f"Diff error: {e}"))
        self.threadpool.start(w)

    def _all_paths_in_view(self) -> list[str]:
        paths: list[str] = []
        for i in range(self.changes.topLevelItemCount()):
            it = self.changes.topLevelItem(i)
            p = it.data(0, QtCore.Qt.ItemDataRole.UserRole)
            if isinstance(p, str) and p:
                paths.append(p)
        return paths

    def stage_all(self) -> None:
        if not self.repo_path:
            return
        repo = self.repo_path
        paths = self._all_paths_in_view()
        if not paths:
            self._info("Nothing to stage.")
            return

        def job() -> object:
            self.git.add(repo, paths)
            return True

        w = Worker(job)
        w.signals.done.connect(lambda _: (self._info("Staged."), self.refresh_status()))
        w.signals.error.connect(lambda e: self._error_box("Stage failed", e))
        self.threadpool.start(w)

    def unstage_all(self) -> None:
        if not self.repo_path:
            return
        repo = self.repo_path
        paths = self._all_paths_in_view()
        if not paths:
            self._info("Nothing to unstage.")
            return

        def job() -> object:
            self.git.reset_paths(repo, paths)
            return True

        w = Worker(job)
        w.signals.done.connect(
            lambda _: (self._info("Unstaged."), self.refresh_status())
        )
        w.signals.error.connect(lambda e: self._error_box("Unstage failed", e))
        self.threadpool.start(w)

    def commit(self) -> None:
        if not self.repo_path:
            return
        repo = self.repo_path
        msg = self.commit_msg.toPlainText()

        def job() -> object:
            self.git.commit(repo, msg)
            return True

        w = Worker(job)

        def done(_: object) -> None:
            self.commit_msg.setPlainText("")
            self._info("Committed.")
            self.refresh_status()

        w.signals.done.connect(done)
        w.signals.error.connect(lambda e: self._error_box("Commit failed", e))
        self.threadpool.start(w)

    # ----------------------------
    # Push / pull with token
    # ----------------------------

    def _git_auth_env_if_needed(self) -> tuple[Optional[dict], Callable[[], None]]:
        """
        If remote is HTTPS to GitHub and a token exists, return an env that supplies credentials.
        Otherwise return (None, noop).
        """
        noop = lambda: None
        if not self.repo_path:
            return None, noop

        remote = self.git.get_remote_url(self.repo_path)
        if not remote or not remote.startswith("https://"):
            return None, noop

        # Only attempt token auth for github.com remotes.
        if "github.com" not in remote:
            return None, noop

        token = self.tokens.get_token()
        if not token:
            return None, noop

        # Username: prefer cached GitHub login; otherwise try local git config; otherwise use "x-access-token".
        username = self.github_username
        if not username:
            username = self.git.get_config(self.repo_path, "github.user")
        if not username:
            # This is commonly accepted as username with tokens in some flows,
            # but using your real username is also common. We'll fall back.
            username = "x-access-token"

        env, cleanup = make_git_askpass_env(username=username, token=token)
        return env, cleanup

    def pull(self) -> None:
        if not self.repo_path:
            return
        repo = self.repo_path
        env, cleanup = self._git_auth_env_if_needed()

        def job() -> object:
            try:
                self.git.pull_ff_only(repo, env=env)
                return True
            finally:
                cleanup()

        w = Worker(job)
        w.signals.done.connect(lambda _: (self._info("Pulled."), self.refresh_status()))
        w.signals.error.connect(lambda e: self._error_box("Pull failed", e))
        self.threadpool.start(w)

    def push(self) -> None:
        if not self.repo_path:
            return
        repo = self.repo_path
        env, cleanup = self._git_auth_env_if_needed()

        def job() -> object:
            try:
                self.git.push(repo, env=env)
                return True
            finally:
                cleanup()

        w = Worker(job)
        w.signals.done.connect(lambda _: self._info("Pushed."))
        w.signals.error.connect(lambda e: self._error_box("Push failed", e))
        self.threadpool.start(w)


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    w = MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
