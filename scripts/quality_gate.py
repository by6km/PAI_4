#!/usr/bin/env python3
"""Quality gate: lee los informes de las herramientas y cuenta hallazgos por severidad.

--mode warn  -> avisa (::warning::) pero sale con codigo 0  (Gate A, modo aviso)
--mode block -> sale con codigo 1 si hay hallazgos en las severidades de --fail-on (Gate B)
"""
import argparse
import json
import os
import sys

SEVS = ["critical", "high", "medium", "low", "info"]


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def semgrep(path):
    c = dict.fromkeys(SEVS, 0)
    data = load_json(path) or {}
    m = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for r in data.get("results", []):
        c[m.get(r.get("extra", {}).get("severity", "INFO").upper(), "low")] += 1
    return c


def dependency_check(path):
    c = dict.fromkeys(SEVS, 0)
    data = load_json(path) or {}
    m = {"critical": "critical", "high": "high", "medium": "medium",
         "moderate": "medium", "low": "low"}
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities") or []:
            c[m.get(str(v.get("severity", "")).lower(), "info")] += 1
    return c


def checkov(path):
    c = dict.fromkeys(SEVS, 0)
    data = load_json(path) or {}
    reports = data if isinstance(data, list) else [data]
    for rep in reports:
        for chk in rep.get("results", {}).get("failed_checks", []):
            sev = (chk.get("severity") or "medium").lower()  # sin severidad -> medium
            c[sev if sev in c else "medium"] += 1
    return c


def zap(path):
    c = dict.fromkeys(SEVS, 0)
    data = load_json(path) or {}
    m = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            c[m.get(str(a.get("riskcode", "0")), "info")] += 1
    return c


def trivy(path):
    c = dict.fromkeys(SEVS, 0)
    data = load_json(path) or {}
    m = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
         "LOW": "low", "UNKNOWN": "info"}
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            c[m.get(v.get("Severity", "UNKNOWN"), "info")] += 1
    return c


TOOLS = [
    ("SAST  Semgrep", "semgrep.json", semgrep),
    ("SCA   Trivy", "trivy-sca.json", trivy),
    ("IaC   Checkov", "checkov.json", checkov),
    ("DAST  ZAP", "zap-report.json", zap),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--fail-on", default="critical,high")
    ap.add_argument("--mode", choices=["warn", "block"], default="block")
    ap.add_argument("--name", default="Quality gate")
    a = ap.parse_args()
    fail_on = [s.strip().lower() for s in a.fail_on.split(",") if s.strip() and s.strip() != "none"]

    rows, blocking_total = [], 0
    for label, fname, fn in TOOLS:
        path = os.path.join(a.reports, fname)
        if not os.path.exists(path):
            rows.append((label, None, 0))
            continue
        counts = fn(path)
        blocking = sum(counts[s] for s in fail_on)
        blocking_total += blocking
        rows.append((label, counts, blocking))

    lines = [f"### {a.name} ({a.mode}) - umbral: {', '.join(fail_on) or 'ninguno'}", "",
             "| Herramienta | " + " | ".join(SEVS) + " | Supera umbral |",
             "|---|" + "---|" * (len(SEVS) + 1)]
    for label, counts, blocking in rows:
        if counts is None:
            lines.append(f"| {label} | " + " | ".join("-" for _ in SEVS) + " | sin informe |")
        else:
            lines.append(f"| {label} | " + " | ".join(str(counts[s]) for s in SEVS) + f" | {blocking} |")
    summary = "\n".join(lines)
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary + "\n")

    for label, counts, blocking in rows:
        if blocking:
            level = "warning" if a.mode == "warn" else "error"
            print(f"::{level} title={a.name}::{label.strip()}: {blocking} hallazgos "
                  f"({', '.join(fail_on)})")

    if a.mode == "block" and blocking_total > 0:
        print(f"\n{a.name} BLOQUEANTE: {blocking_total} hallazgos superan el umbral -> pipeline FALLA")
        sys.exit(1)
    print(f"\n{a.name}: OK" if blocking_total == 0 else f"\n{a.name}: avisos, el pipeline continua")


if __name__ == "__main__":
    main()
