# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Critical: vulnerabilities here are intentional

This is a **demo repository** for [Fixpoint](https://github.com/IWEBai/fixpoint), a GitHub Action that auto-detects and fixes security vulnerabilities in pull requests. The vulnerable code exists so Fixpoint has something to find.

**Do not "fix" the vulnerable functions unless explicitly asked.** Removing the SQL injection, hardcoded secrets, or XSS would break the demo. Each file deliberately pairs vulnerable examples with `SAFE`-labeled counterparts that Fixpoint is expected to skip — preserve both when editing.

## Structure

Three standalone Python modules, each demonstrating one vulnerability class Fixpoint targets:

- `app.py` — SQL injection via f-string, string concatenation, `.format()`, and `%` formatting. Ends with a parameterized `get_user_safe()` as the negative case.
- `config.py` — hardcoded secrets (API keys, DB passwords, AWS creds, JWT secrets). Ends with `os.environ.get()`/`os.getenv()` examples as the negative case.
- `views.py` — Django XSS via `mark_safe()`/`SafeString()` on user input. Negative cases use `escape()`, plus a `mark_safe()` with static-only HTML that Fixpoint should recognize as safe.

Each module is self-contained with a `__main__` block for standalone demo runs. There is no package structure, dependency manifest, build system, or test suite. `views.py` imports Django but Django is not required to be installed unless you run that module directly.

## The Fixpoint workflow

`.github/workflows/fixpoint.yml` runs on every PR (`opened`/`synchronize`/`reopened`). It checks out the PR head branch and invokes `IWEBai/fixpoint@v1`.

- `mode: warn` (current) — Fixpoint comments proposed fixes on the PR without changing code.
- `mode: enforce` — Fixpoint commits fixes directly to the PR branch.

To demo Fixpoint: create a branch, make any change, open a PR, and watch the action. Switching `warn` → `enforce` in the workflow is the intended way to see auto-committed fixes.
