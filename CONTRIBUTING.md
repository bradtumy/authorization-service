# Contributing to Authorization Service

Thank you for considering a contribution to [tumy-tech-labs/authorization-service](https://github.com/tumy-tech-labs/authorization-service)! 
We follow our [Code of Conduct](CODE_OF_CONDUCT.md) and encourage constructive, respectful collaboration.

## 🛠️ Fork & Local Setup
1. Fork the repository on GitHub.
2. Clone your fork and set up the `upstream` remote:
   ```bash
   git clone git@github.com:<your-username>/authorization-service.git
   cd authorization-service
   git remote add upstream git@github.com:tumy-tech-labs/authorization-service.git
   ```
3. Install Go, `golangci-lint`, Docker (optional) and project dependencies.

## 🔄 Staying Up to Date
- Never commit directly to `main`.
- Rebase your work on top of the latest upstream changes:
  ```bash
  git fetch upstream
  git checkout main
  git rebase upstream/main
  ```
- Use a new branch for every story or bugfix:
  ```bash
  git checkout -b feature/my-task
  ```
- Rebase your branch often and push with `--force-with-lease` only to your personal branches:
  ```bash
  git fetch upstream
  git rebase upstream/main
  git push --force-with-lease origin feature/my-task
  ```

## 🧪 Code Style, Linting & Tests
We use Go formatting conventions and `golangci-lint`. Run the following before committing:
```bash
go fmt ./...
golangci-lint run
make test # or go test ./...
```
Ensure all checks pass locally; continuous integration (CI) must pass before your pull request (PR) is merged.

## 🔍 Pull Requests
- Push your branch to your fork and [open a PR](https://github.com/tumy-tech-labs/authorization-service/compare) against `tumy-tech-labs/authorization-service`.
- Use a clear title (e.g., `feat:` or `fix:` prefix) and describe motivation, approach and testing in the body. Link related issues.
- CI must be green and at least one reviewer must approve before merging.
- Maintainers squash & merge only. Squash your commits or allow maintainers to do so.

## 📄 Fork & Feature Branch Cheat Sheet
Copy‑paste friendly commands for the full workflow:
```bash
# 1. Fork on GitHub then clone your fork
$ git clone git@github.com:<you>/authorization-service.git
$ cd authorization-service

# 2. Add the upstream repository
$ git remote add upstream git@github.com:tumy-tech-labs/authorization-service.git

# 3. Sync your main branch
$ git fetch upstream
$ git checkout main
$ git rebase upstream/main

# 4. Create a feature branch
$ git checkout -b feature/amazing-change

# 5. Do your work, then rebase and push
$ git fetch upstream
$ git rebase upstream/main
$ git push --force-with-lease origin feature/amazing-change

# 6. Open a PR against tumy-tech-labs/authorization-service
```

## ✅ Contributor Checklist
- [ ] Forked the repo and set `upstream` remote
- [ ] Based feature branch on `upstream/main`
- [ ] Ran `go fmt`, `golangci-lint run`, and tests
- [ ] Wrote clear commits & PR title/body
- [ ] CI is green and reviewers approved

Happy hacking! 🎉
