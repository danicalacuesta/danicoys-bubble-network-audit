#!/usr/bin/env python3
"""
audit_nsg.py - Danicoy's Bubble network security audit.

Reads a JSON export of firewall / network security group (NSG) rules, flags
risky configurations, and prints a terminal report. Standalone: uses only the
Python standard library (3.9+).

Usage:
    python audit_nsg.py                       # audits firewall_rules.json next to this script
    python audit_nsg.py path/to/rules.json    # audits a specific file
    python audit_nsg.py --no-color            # plain output (for logs / redirects)

Exit codes:
    0  no CRITICAL or HIGH findings
    1  at least one CRITICAL or HIGH finding
    2  input file could not be read or parsed
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

# Audit policy
# Source values that mean "anyone on the internet".
PUBLIC_KEYWORDS = {"*", "any", "internet", "0.0.0.0/0", "::/0"}

# Remote-administration ports that must never be reachable from the internet.
MANAGEMENT_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
}

# Data-store ports that must never be reachable from the internet.
DATABASE_PORTS = {
    1433: "SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# Ports that are acceptable to expose publicly (web tier).
PUBLIC_OK_PORTS = {443: "HTTPS"}
CLEARTEXT_PORTS = {80: "HTTP"}

FULL_RANGE = (0, 65535)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
REQUIRED_FIELDS = (
    "id", "nsg", "name", "priority", "direction", "access",
    "source_address_prefix", "destination_port_range",
)

# Data model
@dataclass
class Finding:
    severity: str
    rule_id: str
    nsg: str
    rule_name: str
    issue: str
    fix: str

# Parsing helpers
def parse_port_ranges(spec) -> list[tuple[int, int]]:
    """Turn '22', '20-25', '*', '80,443' or ['80', '443'] into (low, high) tuples."""
    parts = spec if isinstance(spec, list) else str(spec).split(",")
    ranges: list[tuple[int, int]] = []
    for part in parts:
        part = str(part).strip()
        if part == "*":
            ranges.append(FULL_RANGE)
        elif "-" in part:
            low, high = part.split("-", 1)
            ranges.append((int(low), int(high)))
        else:
            ranges.append((int(part), int(part)))
    for low, high in ranges:
        if not (0 <= low <= high <= 65535):
            raise ValueError(f"invalid port range '{low}-{high}'")
    return ranges


def covers_port(ranges: list[tuple[int, int]], port: int) -> bool:
    return any(low <= port <= high for low, high in ranges)


def is_all_ports(ranges: list[tuple[int, int]]) -> bool:
    return any(low <= FULL_RANGE[0] and high >= FULL_RANGE[1] for low, high in ranges)


def is_public_source(value: str) -> bool:
    """True when the source is the open internet (keyword or a /0 network)."""
    text = str(value).strip().lower()
    if text in PUBLIC_KEYWORDS:
        return True
    try:
        return ipaddress.ip_network(text, strict=False).prefixlen == 0
    except ValueError:
        return False


def get_sources(rule: dict) -> list[str]:
    sources = rule.get("source_address_prefixes")
    if isinstance(sources, list) and sources:
        return [str(s) for s in sources]
    return [str(rule["source_address_prefix"])]



# Rule evaluation
def evaluate_rule(rule: dict) -> tuple[str, list[Finding]]:
    """Return (status, findings) where status is PASS, FAIL or SKIP."""
    direction = str(rule["direction"]).lower()
    access = str(rule["access"]).lower()

    if direction != "inbound":
        return "SKIP", []          # this audit covers inbound exposure only
    if access != "allow":
        return "PASS", []          # deny rules only reduce exposure

    ports = parse_port_ranges(rule["destination_port_range"])
    public = any(is_public_source(s) for s in get_sources(rule))
    findings: list[Finding] = []

    def add(severity: str, issue: str, fix: str) -> None:
        findings.append(Finding(severity, rule["id"], rule["nsg"], rule["name"], issue, fix))

    if public:
        if is_all_ports(ports):
            add("CRITICAL",
                "All ports are open to the public internet (includes SSH, RDP and databases).",
                "Delete this rule and allow only the specific ports the tier needs.")
        else:
            for port, label in MANAGEMENT_PORTS.items():
                if covers_port(ports, port):
                    add("CRITICAL",
                        f"{label} (port {port}) is open to the public internet.",
                        "Restrict the source to a management subnet or VPN/bastion range.")
            for port, label in DATABASE_PORTS.items():
                if covers_port(ports, port):
                    add("HIGH",
                        f"{label} (port {port}) is open to the public internet.",
                        "Allow only the application subnet as the source.")
            for port, label in CLEARTEXT_PORTS.items():
                if covers_port(ports, port):
                    add("LOW",
                        f"{label} (port {port}) exposes unencrypted traffic to the internet.",
                        "Redirect to HTTPS (443) and remove the cleartext rule.")
            # Any other publicly exposed port that is not on a known list.
            known = set(MANAGEMENT_PORTS) | set(DATABASE_PORTS) | set(CLEARTEXT_PORTS) | set(PUBLIC_OK_PORTS)
            if not findings and not all(covers_port(ports, p) for p in PUBLIC_OK_PORTS):
                if not any(covers_port(ports, p) for p in known):
                    add("MEDIUM",
                        f"Port(s) {rule['destination_port_range']} are exposed to the public internet without review.",
                        "Confirm the service must be public; otherwise restrict the source range.")
    elif is_all_ports(ports):
        add("MEDIUM",
            "All ports are allowed from a broad internal source (no least-privilege scoping).",
            "Replace with explicit per-service port rules between tiers.")

    return ("FAIL" if findings else "PASS"), findings


def check_missing_deny_all(rules: list[dict]) -> list[Finding]:
    """Every NSG should end with an explicit deny-all inbound rule."""
    has_deny: dict[str, bool] = defaultdict(bool)
    for rule in rules:
        has_deny[rule["nsg"]]  # register the NSG even if it has no deny rule
        if (str(rule["direction"]).lower() == "inbound"
                and str(rule["access"]).lower() == "deny"
                and is_all_ports(parse_port_ranges(rule["destination_port_range"]))
                and is_public_source(rule["source_address_prefix"])):
            has_deny[rule["nsg"]] = True
    return [
        Finding("MEDIUM", "-", nsg, "(NSG-level check)",
                "No explicit deny-all inbound rule at the end of the rule set.",
                "Add a low-priority (e.g. 4096) rule denying all other inbound traffic.")
        for nsg, ok in sorted(has_deny.items()) if not ok
    ]
# Report rendering
class Style:
    def __init__(self, enabled: bool) -> None:
        codes = {"red": "31", "yellow": "33", "green": "32", "cyan": "36", "magenta": "35",
                 "bold": "1", "dim": "2"}
        self.codes = codes if enabled else {}

    def __call__(self, text: str, name: str) -> str:
        code = self.codes.get(name)
        return f"\033[{code}m{text}\033[0m" if code else text


SEVERITY_COLOR = {"CRITICAL": "red", "HIGH": "magenta", "MEDIUM": "yellow", "LOW": "cyan"}
STATUS_COLOR = {"PASS": "green", "FAIL": "red", "SKIP": "dim"}
WIDTH = 78


def render_report(source: Path, rules: list[dict], results: list[tuple[dict, str]],
                  findings: list[Finding], skipped: list[str], style: Style) -> str:
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    status_counts = {s: sum(1 for _, st in results if st == s) for s in ("PASS", "FAIL", "SKIP")}
    verdict_fail = counts["CRITICAL"] > 0 or counts["HIGH"] > 0
    out: list[str] = []
    line = "=" * WIDTH
    rule_line = "-" * WIDTH

    out += [line, style(" DANICOY'S BUBBLE - NETWORK SECURITY AUDIT REPORT", "bold"), line]
    out += [f" Source file : {source.name}",
            f" Rules read  : {len(rules)}  "
            f"(pass {status_counts['PASS']} | fail {status_counts['FAIL']} | not evaluated {status_counts['SKIP']})",
            ""]

    out += [style(" SUMMARY", "bold"), rule_line]
    for sev in SEVERITY_ORDER:
        label = style(f"{sev:<9}", SEVERITY_COLOR[sev])
        out.append(f"  {label} {counts[sev]}")
    out.append("")

    out += [style(" RULE RESULTS", "bold"), rule_line]
    out.append(f"  {'ID':<7} {'NSG':<24} {'RULE':<34} {'PRI':>4}  STATUS")
    for rule, status in results:
        out.append(f"  {rule['id']:<7} {rule['nsg']:<24} {rule['name'][:34]:<34} "
                   f"{rule['priority']:>4}  {style(status, STATUS_COLOR[status])}")
    out.append("")

    out += [style(" FINDINGS", "bold"), rule_line]
    if not findings:
        out.append("  No findings. All evaluated rules are compliant.")
    for sev in SEVERITY_ORDER:
        for f in (x for x in findings if x.severity == sev):
            tag = style(f"[{sev}]", SEVERITY_COLOR[sev])
            where = f"{f.rule_id} | {f.nsg} / {f.rule_name}" if f.rule_id != "-" else f"{f.nsg} {f.rule_name}"
            out += [f"  {tag} {where}",
                    f"      Issue : {f.issue}",
                    f"      Fix   : {f.fix}",
                    ""]

    if skipped:
        out += [style(" SKIPPED (MALFORMED) RULES", "bold"), rule_line]
        out += [f"  {item}" for item in skipped] + [""]

    out.append(line)
    verdict = style("FAIL", "red") if verdict_fail else style("PASS", "green")
    out.append(f" RESULT: {verdict}  "
               f"({counts['CRITICAL']} critical, {counts['HIGH']} high, "
               f"{counts['MEDIUM']} medium, {counts['LOW']} low)")
    out.append(line)
    return "\n".join(out)

# Entry point
def load_rules(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        raise ValueError("expected a 'rules' list in the JSON file")
    return rules

def main() -> int:
    parser = argparse.ArgumentParser(description="Audit firewall / NSG rules for security violations.")
    parser.add_argument("rules_file", nargs="?",
                        default=str(Path(__file__).resolve().parent / "firewall_rules.json"),
                        help="path to the JSON rule export (default: firewall_rules.json beside this script)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args()

    path = Path(args.rules_file)
    try:
        rules = load_rules(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: could not read '{path}': {exc}", file=sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    if use_color and os.name == "nt":
        os.system("")  # enables ANSI escape handling in Windows consoles
    style = Style(use_color)

    valid: list[dict] = []
    skipped: list[str] = []
    for index, rule in enumerate(rules, start=1):
        missing = [f for f in REQUIRED_FIELDS if f not in rule]
        if missing:
            skipped.append(f"rule #{index}: missing field(s) {', '.join(missing)}")
        else:
            valid.append(rule)

    results: list[tuple[dict, str]] = []
    findings: list[Finding] = []
    for rule in sorted(valid, key=lambda r: (r["nsg"], r["priority"])):
        try:
            status, rule_findings = evaluate_rule(rule)
        except (ValueError, TypeError) as exc:
            skipped.append(f"{rule['id']}: {exc}")
            continue
        results.append((rule, status))
        findings.extend(rule_findings)

    findings.extend(check_missing_deny_all(valid))
    print(render_report(path, rules, results, findings, skipped, style))

    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
