# LiteHub

A fast, lightweight GitHub Desktop–style GUI for Git on desktop, written in Python with Qt (PySide6).  
No Electron runtime. Uses your system `git` for performance and compatibility.

<img width="1114" height="753" alt="Capture" src="https://github.com/user-attachments/assets/edf9df6e-d14e-4a9c-b4df-df79e9e093a5" />


## Features

- Open an existing local Git repository
- Clone a repository
- Initialize a new local repository
- Show working tree changes (status)
- View diffs (staged + unstaged)
- Stage all / unstage all
- Commit
- Pull (fast-forward only)
- Push
- Login using a GitHub token (PAT / fine-grained token)
- Create a GitHub repository from the app (via GitHub REST API)

## Non-goals (for now)

This is an MVP. It does **not** yet include:

- Branch/checkout UI, merge/rebase UI
- Commit history log, blame, tags
- Partial staging (hunks/lines)
- PR/issue UI
- Submodules / LFS UI
- SSH key management

## Requirements

- Python 3.9+ recommended
- `git` installed and available on `PATH`
- Packages:
  - `PySide6`
  - `requests`
  - `keyring` (optional but recommended; falls back to a local file if unavailable)

Install dependencies:

```bash
pip install PySide6 requests keyring
```

## Run

Save the app as `litehub.py` and run:

```bash
python litehub.py
```

## Usage

### Open a repo
- Use **File → Open repo…** and select a folder that is a Git working tree.

### Clone a repo
- Use **File → Clone…**
- Enter a URL like `https://github.com/owner/repo.git`
- Choose a destination folder

### Commit workflow
1. Select a repo
2. Click **Stage all**
3. Write a commit message
4. Click **Commit**
5. Click **Push**

### GitHub token login
- Use **GitHub → Login token…**
- Paste a GitHub token (PAT or fine-grained token)

Token is used for:
- GitHub API calls (e.g., “Who am I?”, create repo)
- HTTPS push/pull authentication using a temporary `GIT_ASKPASS` helper (token is not embedded into the remote URL)

#### Token scopes / permissions
Your token must allow whatever you want to do:
- To create repos: permissions to create repositories for your account
- To push/pull over HTTPS: permissions for that repository

Exact permissions vary between classic PATs and fine-grained tokens; configure it in GitHub settings accordingly.

## Security notes

- If `keyring` is available, the token is stored in the OS keychain.
- If `keyring` is not available, LiteHub stores the token at:

  - Linux/macOS: `~/.config/litehub/token.json` (attempts to set `0600` permissions)

- Push/pull uses `GIT_ASKPASS` with a temporary script in your temp directory to provide credentials non-interactively.
- Do not share logs/screenshots containing token values.

## Troubleshooting

### “Not a git repository”
Make sure the folder you opened is a Git working tree (contains `.git/` or is inside one).

### Push/pull prompts for password
- Ensure your remote is HTTPS (starts with `https://github.com/...`)
- Ensure you saved a token (**GitHub → Login token…**)
- Some environments may have credential helpers interfering. You can try clearing cached credentials:
  - Check `git config --global credential.helper`

### “Pull failed” due to non-fast-forward
This MVP uses `git pull --ff-only` to stay safe. If your branch diverged, you must resolve via merge/rebase using CLI for now.

## Project structure

Single-file MVP:

- `litehub.py` — GUI, git subprocess wrapper, GitHub REST client, token storage

## Roadmap ideas

- Branch selector (switch/create/delete)
- Fetch button + ahead/behind indicator
- Commit history view
- Inline staging (hunks/lines)
- PR creation and listing via GitHub API
- Better clone/init flows (auto-add remote, initial commit)

## References

- GitHub REST API auth: https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
- Get authenticated user: https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user
- Create repo endpoint: https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#create-a-repository-for-the-authenticated-user
- `git status --porcelain`: https://git-scm.com/docs/git-status
- `GIT_ASKPASS` / `GIT_TERMINAL_PROMPT`: https://git-scm.com/docs/git
