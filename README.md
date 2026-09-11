# MCP Surface Check

A read-only static security check for MCP servers, as a GitHub Action. Drop it into your CI and it reads your source for the patterns that matter when an AI agent is on the other end — command injection, SSRF surface, code execution, unsafe deserialization, committed secrets — then writes a job summary and gives you a README badge.

[![MCP Surface Check: low surface](https://img.shields.io/badge/MCP_Surface_Check-low-4FA86A)](https://majorlabs.co/security)

It runs the **same checks** as the Major Labs ecosystem scoreboard at [majorlabs.co/security](https://majorlabs.co/security), so your score is comparable to the rest of the agentic web.

## The one hard rule

**Static analysis of your own source only.** MCP Surface Check never connects to, runs, installs, or probes a server. A finding is a pattern visible in the code, tuned for precision, **not a confirmed vulnerability**. A "High surface" result means the code does risky things in risky ways and deserves a closer look, never that your server is compromised. It reads files on disk; it makes no network calls.

## Quick start

```yaml
# .github/workflows/mcp-surfacecheck.yml
name: MCP Surface Check
on: [push, pull_request]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: major-matters/mcp-surfacecheck@v1
```

That writes a security-surface summary to every run. Open the run to see the findings and copy your badge.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the repo root. |
| `fail-on` | `none` | Fail the job when the tier is at or above this: `none`, `elevated`, or `high`. |
| `sarif-file` | *(off)* | Write a SARIF 2.1.0 report to this path, for GitHub code scanning. |

Gate your pull requests on it:

```yaml
      - uses: major-matters/mcp-surfacecheck@v1
        with:
          fail-on: high
```

## Outputs

| Output | Description |
|---|---|
| `tier` | `Low`, `Elevated`, or `High`. |
| `score` | Surface score, 0-100. |
| `finding-count` | Number of static findings. |
| `badge` | Paste-ready README badge markdown. |
| `sarif-file` | Path of the SARIF report, when `sarif-file` was set. |

## Findings in the Security tab (SARIF)

Set `sarif-file` and upload the report, and every finding becomes a code
scanning alert annotated on the exact file and line — no summary-reading
required:

```yaml
jobs:
  surfacecheck:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # needed to upload SARIF
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: major-matters/mcp-surfacecheck@v1
        with:
          sarif-file: surfacecheck.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()           # upload findings even when fail-on gates the job
        with:
          sarif_file: surfacecheck.sarif
```

Severity in the Security tab mirrors the surface weights (command injection
and code execution report as errors, the rest as warnings), and each alert
carries the same "pattern, not a confirmed vulnerability" framing as the
summary. When `path` points at a subdirectory, SARIF paths are still
repo-relative, so annotations land on the right files.

## What the tiers mean

The score is the sum of the weights of the **distinct** risky categories found in your source, capped at 100 (one noisy file can't inflate it). The tier is a band on that score.

| Tier | Meaning |
|---|---|
| **Low** | No flagged pattern. The green badge. |
| **Elevated** | At least one risky pattern present. Worth a look. |
| **High** | A high-weight sink (command injection or arbitrary code execution) is present. Look first. |

## What it checks

| Category | What it flags | Why it matters for an MCP server |
|---|---|---|
| Command injection | `shell=True`, `os.system`, `child_process.exec` with interpolated args | An agent tool that shells out with model-controlled input is a direct RCE path. |
| SSRF surface | outbound `requests`/`fetch`/`axios` to a URL built from a variable, no allow-list | The classic MCP risk: an agent fetches an attacker-chosen internal URL. |
| Code execution | `eval`, `exec`, `new Function`, `vm.runInNewContext` | Arbitrary code from tool arguments. |
| Unsafe deserialization | `pickle.loads`, `yaml.load` without `SafeLoader` | Deserializing untrusted input is code execution in disguise. |
| Hardcoded secret | live-looking API key patterns in source | Keys in public repos get harvested in minutes. |

Heuristics are tuned for precision over recall, so a clean result is meaningful and a finding is usually real, but verify each against your own intent (a tool that is *supposed* to shell out is your call to make).

## The badge

After a run, copy the badge from the job summary into your README (it is also exposed as the `badge` output). Green means a clean static surface — the badge says *checked*, never "secure". It links back to the method and the ecosystem scoreboard so anyone can see what "low surface" is measured against:

```markdown
[![MCP Surface Check: low surface](https://img.shields.io/badge/MCP_Surface_Check-low-4FA86A)](https://majorlabs.co/security)
```

## Run it locally

```bash
python3 surfacecheck.py            # scan the current directory
python3 surfacecheck.py --json .   # machine-readable
python3 surfacecheck.py --badge .  # just the badge markdown
python3 surfacecheck.py --sarif . > report.sarif   # SARIF 2.1.0
```

## Method and the bigger picture

MCP Surface Check is the per-repo version of the [State of MCP](https://majorlabs.co/reports/state-of-mcp) sweep that measures the whole ecosystem. The aggregate finding: about a third of the most-used MCP servers ship at least one risky pattern, and SSRF surface dominates. This Action is how an individual server checks where it sits and proves, with a badge, that it took the question seriously.

Found a problem with a finding, or want a check added? Open an issue. Per-repo findings from our ecosystem sweep are disclosed privately to maintainers, never published.

*Major Labs. Static, read-only, open method. v0, experimental.*
