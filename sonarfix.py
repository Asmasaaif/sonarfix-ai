"""
sonarfix-ai: Automated Vulnerability Remediation Suggester
===========================================================
Author      : Asma Saif
Institution : IMT Atlantique — MSc Cybersecurity

This tool reads a SonarQube JSON vulnerability report, sorts findings
by severity, and queries an LLM to generate a concrete remediation
suggestion for each issue. The goal is to reduce the manual effort
required to triage audit output and give developers an immediate,
actionable starting point for fixing security issues.

Usage:
    python sonarfix.py sample_report.json
"""

import json
import os
import sys
import urllib.request
import urllib.error


# ── Configuration ─────────────────────────────────────────────────────────────

API_ENDPOINT = "https://api.anthropic.com/v1/messages"
MODEL        = "claude-3-5-sonnet-20241022"
MAX_TOKENS   = 1000

# Controls display order: lower number = shown first
SEVERITY_PRIORITY = {"CRITICAL": 1, "MAJOR": 2, "MINOR": 3}


# ── Report Parsing ────────────────────────────────────────────────────────────

def load_report(filepath: str) -> dict:
    """Read and parse the SonarQube JSON report from disk."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def sort_by_severity(issues: list) -> list:
    """Sort issues so CRITICAL findings are processed before MAJOR and MINOR."""
    return sorted(issues, key=lambda i: SEVERITY_PRIORITY.get(i["severity"], 99))


def count_by_severity(issues: list) -> dict:
    """Return a count of issues per severity level for the summary header."""
    counts = {"CRITICAL": 0, "MAJOR": 0, "MINOR": 0}
    for issue in issues:
        counts[issue.get("severity", "MINOR")] += 1
    return counts


# ── Prompt Construction ───────────────────────────────────────────────────────

def build_prompt(issue: dict) -> str:
    """
    Build the LLM prompt for a single vulnerability.

    The prompt gives the model full context about the finding and asks for
    three things: why it is dangerous, how to fix it, and how urgent it is.
    Keeping the format open (rather than rigid labels) produces more natural,
    developer-readable output.
    """
    return f"""You are a senior application security engineer reviewing a SonarQube finding.
Analyse the vulnerability below and respond with three things:
- Why it is dangerous and what an attacker could realistically do with it (2 sentences)
- A concrete fix — corrected code or clear steps the developer should follow
- Whether this should be fixed immediately, this sprint, or next sprint, and why

Issue ID   : {issue['id']}
Severity   : {issue['severity']}
Rule       : {issue['rule']}
File       : {issue['file']} (line {issue['line']})
Description: {issue['message']}

Affected code:
{issue['code_snippet']}"""


# ── LLM API Call ──────────────────────────────────────────────────────────────

def query_llm(prompt: str) -> str:
    """
    Send the prompt to the Claude API and return the response text.

    The API key is read from the ANTHROPIC_API_KEY environment variable.
    Credentials are never hardcoded — this follows standard security practice
    for any application that integrates a third-party API.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    payload = json.dumps({
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    req = urllib.request.Request(
        url=API_ENDPOINT,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )

    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode("utf-8"))
        return data["content"][0]["text"]


# ── Output Helpers ────────────────────────────────────────────────────────────

def print_banner(project: str, scan_date: str, total: int):
    print("\n" + "=" * 65)
    print("  sonarfix-ai — Vulnerability Remediation Suggester")
    print(f"  Project   : {project}")
    print(f"  Scan Date : {scan_date}")
    print(f"  Issues    : {total} found")
    print("=" * 65)


def print_summary(issues: list):
    counts = count_by_severity(issues)
    print("\n  SEVERITY BREAKDOWN")
    print("  " + "-" * 28)
    for level in ["CRITICAL", "MAJOR", "MINOR"]:
        print(f"  {level:<10}: {counts[level]}")
    print("  " + "-" * 28 + "\n")


def print_issue_header(issue: dict, index: int, total: int):
    print(f"[ {index}/{total} ]  {issue['severity']}  —  {issue['rule'].upper()}")
    print(f"  File    : {issue['file']}  (line {issue['line']})")
    print(f"  Finding : {issue['message']}\n")


# ── Main Pipeline ─────────────────────────────────────────────────────────────

def run(report_path: str):
    """
    Run the full pipeline on a SonarQube report:
        load → sort by severity → query LLM per issue → print suggestions
    """
    report = load_report(report_path)
    issues = sort_by_severity(report["issues"])
    total  = len(issues)

    print_banner(report["project"], report["scan_date"], total)
    print_summary(issues)

    for index, issue in enumerate(issues, start=1):
        print("=" * 65)
        print_issue_header(issue, index, total)
        print("  Generating remediation suggestion...\n")

        try:
            suggestion = query_llm(build_prompt(issue))
            for line in suggestion.strip().split("\n"):
                print(f"  {line}")

        except urllib.error.HTTPError as e:
            print(f"  API error {e.code}: {e.reason}")
            print("  Verify that ANTHROPIC_API_KEY is set in your environment.")

        except Exception as e:
            print(f"  Unexpected error: {e}")

        print()

    print("=" * 65)
    print(f"  Done. {total} issues reviewed — action by priority level.")
    print("=" * 65 + "\n")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    report_file = sys.argv[1] if len(sys.argv) > 1 else "sample_report.json"
    run(report_file)