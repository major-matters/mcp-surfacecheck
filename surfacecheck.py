"""
MCP Surface Check — local static security check for MCP servers.

READ-ONLY. Scans the source files in a directory (your checked-out repo) for
security-relevant code patterns and prints a surface score, a tier, and the
findings. It NEVER connects to, runs, installs, or probes anything. A finding is
a pattern visible in the source, tuned for precision, not a confirmed
vulnerability. "High surface" means the code does risky things in risky ways and
deserves a closer look, never that the server is compromised.

The checks and scoring are identical to the Major Labs population sweep behind
majorlabs.co/security, so your badge score is comparable to the ecosystem.

Usage:
  python3 surfacecheck.py [PATH]                 # human summary (default: .)
  python3 surfacecheck.py --json [PATH]          # machine-readable result
  python3 surfacecheck.py --github-summary [PATH]  # GitHub Actions job summary (markdown)
  python3 surfacecheck.py --badge [PATH]         # print the paste-ready badge markdown
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

__version__ = "0.2.0"

SOURCE_EXT = (".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
SKIP_PATH = re.compile(r"(^|/)(node_modules|dist|build|vendor|\.venv|venv|test|tests|__tests__|examples?|docs?|\.git)/", re.I)
MAX_BLOB = 200_000   # skip files larger than this (bytes)
MAX_FILES = 200      # generous: this runs locally on one repo, not the whole ecosystem

# Identical to the Major Labs population sweep (scanner/security.py). Keep in sync.
CHECKS = [
    ("command_injection", {"py"}, 30, re.compile(r"shell\s*=\s*True"), "subprocess with the shell flag enabled"),
    ("command_injection", {"py"}, 30, re.compile(r"\bos\.(system|popen)\("), "os.system / os.popen"),
    ("command_injection", {"js"}, 30, re.compile(r"child_process(\.|\s*\.\s*)?(exec|execSync)\s*\("), "child_process.exec"),
    ("command_injection", {"js"}, 30, re.compile(r"\.exec\s*\(\s*[`'\"]?\$\{|\.exec\s*\(\s*[a-zA-Z_$][\w$]*\s*\+"), "exec with interpolated string"),
    ("code_execution", {"py"}, 30, re.compile(r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\("), "eval/exec"),
    ("code_execution", {"js"}, 30, re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|vm\.runInNewContext"), "eval / new Function / vm"),
    ("unsafe_deserialization", {"py"}, 15, re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)"), "pickle / unsafe yaml.load"),
    ("ssrf_surface", {"py"}, 20, re.compile(r"(requests\.(get|post|put|request|delete)|urllib\.request\.urlopen|httpx\.(get|post|client))\s*\(\s*[a-zA-Z_]"), "outbound request to a non-literal URL"),
    ("ssrf_surface", {"js"}, 20, re.compile(r"(fetch|axios(\.\w+)?|got|http\.request)\s*\(\s*[a-zA-Z_$`]"), "outbound request to a non-literal URL"),
    ("hardcoded_secret", {"py", "js"}, 15, re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})"), "hardcoded credential"),
]

CATEGORY_LABEL = {
    "command_injection": "command injection",
    "code_execution": "code execution",
    "ssrf_surface": "SSRF surface",
    "unsafe_deserialization": "unsafe deserialization",
    "hardcoded_secret": "hardcoded secret",
}
TIER_COLOR = {"Low": "4FA86A", "Elevated": "F79E1B", "High": "E0563B"}
SCOREBOARD = "https://majorlabs.co/security"


def lang_of(path: str) -> str:
    return "py" if path.endswith(".py") else "js"


def source_files(root: Path):
    picks = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if not rel.endswith(SOURCE_EXT) or SKIP_PATH.search("/" + rel):
            continue
        try:
            if p.stat().st_size > MAX_BLOB:
                continue
        except OSError:
            continue
        picks.append((rel.count("/"), rel, p))
    picks.sort()  # shallow paths first (the real server usually lives near the root)
    return picks[:MAX_FILES]


def scan_content(path: str, content: str):
    lang = lang_of(path)
    findings = []
    lines = content.splitlines()
    for category, langs, weight, pat, desc in CHECKS:
        if lang not in langs:
            continue
        for m in pat.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip()[:160] if line_no - 1 < len(lines) else ""
            if snippet.lstrip().startswith(("#", "//", "*")):
                continue
            findings.append({"category": category, "path": path, "line": line_no, "snippet": snippet, "desc": desc, "weight": weight})
    return findings


def score_for(findings):
    cats = {f["category"] for f in findings}
    total = min(100, sum(next(f["weight"] for f in findings if f["category"] == c) for c in cats))
    tier = "High" if total > 30 else "Elevated" if total > 0 else "Low"
    return total, tier, sorted(cats)


def scan(root: Path):
    files = source_files(root)
    findings = []
    for _, rel, p in files:
        try:
            content = p.read_text("utf-8", "replace")
        except OSError:
            continue
        findings.extend(scan_content(rel, content))
    score, tier, cats = score_for(findings)
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f["category"], 0)
        by_cat[f["category"]] += 1
    return {
        "score": score,
        "tier": tier,
        "files_scanned": len(files),
        "finding_count": len(findings),
        "categories": sorted(cats),
        "category_counts": by_cat,
        "findings": findings,
    }


def badge_markdown(tier: str) -> str:
    color = TIER_COLOR.get(tier, "9A9AA5")
    img = f"https://img.shields.io/badge/MCP_Surface_Check-{tier.lower()}-{color}"
    return f"[![MCP Surface Check: {tier.lower()} surface]({img})]({SCOREBOARD})"


def human(result):
    print(f"MCP Surface Check — {result['tier']} surface (score {result['score']}/100)")
    print(f"  files scanned: {result['files_scanned']}   findings: {result['finding_count']}   (static, read-only)")
    if result["category_counts"]:
        print("  by pattern:")
        for cat, n in sorted(result["category_counts"].items(), key=lambda kv: -kv[1]):
            print(f"    {CATEGORY_LABEL.get(cat, cat):<22} {n}")
    print("\n  badge:\n  " + badge_markdown(result["tier"]))
    print(f"\n  A finding is a pattern in the source, not a confirmed vulnerability. Method: {SCOREBOARD}")


def github_summary(result) -> str:
    t = result["tier"]
    out = [
        f"## MCP Surface Check — {t} surface",
        "",
        f"**Score {result['score']}/100** · {result['finding_count']} finding(s) across {result['files_scanned']} source file(s). Static, read-only analysis: no server was contacted.",
        "",
    ]
    if result["category_counts"]:
        out += ["| Pattern | Count |", "|---|---|"]
        for cat, n in sorted(result["category_counts"].items(), key=lambda kv: -kv[1]):
            out.append(f"| {CATEGORY_LABEL.get(cat, cat)} | {n} |")
        out.append("")
    if result["findings"]:
        out += ["<details><summary>Findings (file · line)</summary>", ""]
        for f in result["findings"][:100]:
            out.append(f"- `{f['path']}:{f['line']}` — {CATEGORY_LABEL.get(f['category'], f['category'])}: {f['desc']}")
        out += ["", "</details>", ""]
    out += [
        "Badge for your README:",
        "",
        "```markdown",
        badge_markdown(t),
        "```",
        "",
        f"A finding is a pattern in the source, tuned for precision, **not a confirmed vulnerability**. \"{t} surface\" means the code does risky things in risky ways and deserves a closer look. Same checks as the [Major Labs ecosystem scoreboard]({SCOREBOARD}).",
    ]
    return "\n".join(out)


# SARIF rule metadata per category. security-severity follows the check weights
# (30 -> high, 20 -> medium-high, 15 -> medium) so GitHub code scanning sorts
# findings the same way the surface score weighs them.
SARIF_SEVERITY = {30: "8.8", 20: "6.5", 15: "5.0"}


def sarif_report(result, uri_prefix: str = "") -> dict:
    weights = {}
    for category, _langs, weight, _pat, _desc in CHECKS:
        weights.setdefault(category, weight)
    rules = []
    for cat in sorted(weights):
        label = CATEGORY_LABEL.get(cat, cat)
        rules.append({
            "id": cat,
            "name": "".join(w.capitalize() for w in cat.split("_")),
            "shortDescription": {"text": f"MCP surface: {label}"},
            "fullDescription": {"text": f"A source pattern in the {label} category. A finding is a pattern visible in the source, tuned for precision, not a confirmed vulnerability."},
            "helpUri": SCOREBOARD,
            "defaultConfiguration": {"level": "error" if weights[cat] >= 30 else "warning"},
            "properties": {"security-severity": SARIF_SEVERITY.get(weights[cat], "5.0"), "tags": ["security", "mcp"]},
        })
    results = []
    for f in result["findings"]:
        uri = f"{uri_prefix.rstrip('/')}/{f['path']}" if uri_prefix and uri_prefix != "." else f["path"]
        fingerprint = hashlib.sha1(f"{f['category']}|{uri}|{f['line']}|{f['desc']}".encode()).hexdigest()
        results.append({
            "ruleId": f["category"],
            "level": "error" if f["weight"] >= 30 else "warning",
            "message": {"text": f"{CATEGORY_LABEL.get(f['category'], f['category'])}: {f['desc']} — a pattern in the source, not a confirmed vulnerability."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": f["line"]},
                }
            }],
            "partialFingerprints": {"mcpSurfaceCheck/v1": fingerprint},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "MCP Surface Check",
                "informationUri": SCOREBOARD,
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser(description="MCP Surface Check — local static security check")
    ap.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    ap.add_argument("--json", action="store_true", help="machine-readable result")
    ap.add_argument("--github-summary", action="store_true", help="markdown for the GitHub Actions job summary")
    ap.add_argument("--badge", action="store_true", help="print only the paste-ready badge markdown")
    ap.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 for GitHub code scanning")
    ap.add_argument("--sarif-uri-prefix", default="", help="prefix for SARIF file paths when scanning a subdirectory (so annotations land on repo-relative paths)")
    ap.add_argument("--fail-on", choices=["none", "elevated", "high"], default="none", help="exit non-zero if tier is at or above this")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    result = scan(root)
    # strip raw findings from the JSON-by-default surface unless needed; keep them in --json
    if args.json:
        print(json.dumps(result, indent=2))
    elif args.sarif:
        print(json.dumps(sarif_report(result, args.sarif_uri_prefix), indent=2))
    elif args.github_summary:
        print(github_summary(result))
    elif args.badge:
        print(badge_markdown(result["tier"]))
    else:
        human(result)

    rank = {"Low": 0, "Elevated": 1, "High": 2}
    threshold = {"none": 99, "elevated": 1, "high": 2}[args.fail_on]
    if rank[result["tier"]] >= threshold:
        sys.exit(1)


if __name__ == "__main__":
    main()
