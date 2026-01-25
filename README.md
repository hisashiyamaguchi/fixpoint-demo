# Fixpoint Demo

**See Fixpoint auto-fix security vulnerabilities in action!**

This repository contains intentionally vulnerable Python code to demonstrate [Fixpoint](https://github.com/IWEBai/fixpoint) - the automatic security vulnerability fixer.

---

## What's Inside

This demo contains **3 types of vulnerabilities** that Fixpoint can detect and fix:

| File | Vulnerability | What Fixpoint Does |
|------|---------------|-------------------|
| `app.py` | SQL Injection | Converts to parameterized queries |
| `config.py` | Hardcoded Secrets | Replaces with `os.environ.get()` |
| `views.py` | XSS (Cross-Site Scripting) | Removes unsafe `mark_safe()` |

---

## Try It Yourself

### Option 1: Fork and Test

1. **Fork this repository**
2. **Create a new branch** and make any change
3. **Open a Pull Request**
4. **Watch Fixpoint** comment with proposed fixes (warn mode)

### Option 2: Enable Enforce Mode

1. Edit `.github/workflows/fixpoint.yml`
2. Change `mode: warn` to `mode: enforce`
3. Open a PR with vulnerable code
4. **Watch Fixpoint automatically fix and commit!**

---

## Vulnerable Code Examples

### SQL Injection (`app.py`)

```python
# VULNERABLE - SQL Injection via f-string
def get_user(email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
```

**Fixpoint converts to:**

```python
# SAFE - Parameterized query
def get_user(email):
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
```

### Hardcoded Secrets (`config.py`)

```python
# VULNERABLE - Hardcoded API key
API_KEY = "sk_live_abc123def456ghi789"
```

**Fixpoint converts to:**

```python
# SAFE - Environment variable
API_KEY = os.environ.get("API_KEY")
```

### XSS (`views.py`)

```python
# VULNERABLE - mark_safe with user input
def render_comment(user_input):
    return mark_safe(user_input)
```

**Fixpoint converts to:**

```python
# SAFE - Escaped output
def render_comment(user_input):
    return escape(user_input)
```

---

## How Fixpoint Works

```
1. PR Opened
     ↓
2. Fixpoint scans changed files
     ↓
3. Detects vulnerabilities using Semgrep + AST analysis
     ↓
4. Warn Mode: Comments with proposed fixes
   Enforce Mode: Commits fixes automatically
     ↓
5. Sets status check (pass/fail)
```

---

## Add Fixpoint to Your Repo

```yaml
# .github/workflows/fixpoint.yml
name: Fixpoint

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: write
  pull-requests: write
  statuses: write

jobs:
  fixpoint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0

      - uses: IWEBai/fixpoint@v1
        with:
          mode: warn  # or "enforce"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Links

- **Fixpoint Repository:** [github.com/IWEBai/fixpoint](https://github.com/IWEBai/fixpoint)
- **Marketplace:** [GitHub Marketplace](https://github.com/marketplace/actions/fixpoint-auto-fix-security-vulnerabilities)
- **Documentation:** [Getting Started](https://github.com/IWEBai/fixpoint/blob/main/docs/GETTING_STARTED.md)

---

## License

MIT License - This is a demo repository for educational purposes.

---

*Powered by [Fixpoint](https://github.com/IWEBai/fixpoint) by IWEB*
