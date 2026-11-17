#!/usr/bin/env python3
# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
"""Genera evidencias HTML a partir de los artefactos destinados a DefectDojo."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from html import escape
import json
import os
from pathlib import Path


TOOLS = [
    ("SAST - Semgrep", "semgrep.json", "SAST-Semgrep.html"),
    ("SCA - Trivy", "trivy-sca.json", "SCA-Trivy.html"),
    ("IaC - Checkov", "checkov.json", "IaC-Checkov.html"),
]
SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
LABELS = ["Crítica", "Alta", "Media", "Baja", "Informativa", "Sin especificar"]
CSS = """
body{font:16px/1.55 system-ui,sans-serif;color:#203040;background:#eef2f6;margin:0}
main{max-width:1000px;margin:30px auto;padding:40px;background:white}
h1,h2,h3{line-height:1.25;color:#162d42}h1{font-size:30px}h2{margin-top:32px}
a{color:#185b85}table{border-collapse:collapse;width:100%;margin:20px 0}
th,td{border:1px solid #cbd5df;padding:10px;text-align:left;overflow-wrap:anywhere}
th{background:#e8eff5}dt{font-weight:600}dd{margin:0 0 10px;white-space:pre-wrap;
overflow-wrap:anywhere}article{border-top:1px solid #cbd5df;padding:12px 0}
.status{font-weight:bold}.note{color:#526578}code{overflow-wrap:anywhere}
@media print{@page{size:A4;margin:18mm}body{background:white;font-size:10pt}
main{margin:0;padding:0}h2,h3{break-after:avoid}tr{break-inside:avoid}nav{display:none}}
@media(max-width:700px){main{padding:18px;margin:0}table{font-size:12px}}
"""


def text(value):
    if value is None or value == "":
        return "No disponible"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return escape(str(value), quote=True)


def fields(values):
    return "<dl>" + "".join(
        f"<dt>{text(k)}</dt><dd>{text(v)}</dd>" for k, v in values.items()
    ) + "</dl>"


def records(value):
    if not isinstance(value, list) or any(not isinstance(r, dict) for r in value):
        raise ValueError("Se esperaba una lista de resultados")
    return value


def required(row, key):
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Falta un identificador válido: {key}")
    return value


def severity(value):
    value = str(value or "unknown").lower()
    return value if value in SEVERITIES else "unknown"


def parse_report(filename, data):
    findings, warnings = [], []
    if filename == "semgrep.json":
        for row in records(data["results"]):
            extra = row["extra"]
            original = extra.get("severity")
            level = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
                str(original).upper(), severity(original))
            findings.append((level, {
                "Regla": required(row, "check_id"),
                "Descripción": extra.get("message"),
                "Severidad original": original,
                "Severidad normalizada": level,
                "Archivo": required(row, "path"),
                "Línea inicial": row["start"]["line"],
                "Línea final": row.get("end", {}).get("line"),
            }))
        if data.get("errors"):
            warnings.append("Semgrep comunicó errores; revisar errors en el original.")
        if data.get("paths", {}).get("skipped"):
            warnings.append("Hay rutas omitidas por Semgrep; consultar paths.skipped.")
    elif filename == "trivy-sca.json":
        for result in records(data["Results"]):
            vulnerabilities = result.get("Vulnerabilities")
            for row in records([] if vulnerabilities is None else vulnerabilities):
                level = severity(row.get("Severity"))
                findings.append((level, {
                    "Identificador": required(row, "VulnerabilityID"),
                    "Título": row.get("Title"),
                    "Descripción": row.get("Description"),
                    "Severidad original": row.get("Severity"),
                    "Dependencia": required(row, "PkgName"),
                    "Versión detectada": row.get("InstalledVersion"),
                    "Versión corregida indicada por Trivy": row.get("FixedVersion"),
                    "Archivo analizado": result.get("Target"),
                    "Referencia": row.get("PrimaryURL"),
                }))
    else:
        reports = records(data if isinstance(data, list) else [data])
        if not reports:
            raise ValueError("Checkov no contiene informes")
        for report in reports:
            results = report["results"]
            for row in records(results["failed_checks"]):
                level = severity(row.get("severity"))
                findings.append((level, {
                    "Comprobación": required(row, "check_id"),
                    "Descripción": row.get("check_name"),
                    "Severidad original": row.get("severity") or "Sin especificar",
                    "Archivo": required(row, "file_path"),
                    "Líneas": row.get("file_line_range"),
                    "Recurso": row.get("resource"),
                    "Guía": row.get("guideline"),
                }))
            if results.get("parsing_errors") or report.get("summary", {}).get("parsing_errors"):
                warnings.append("Checkov comunicó errores de análisis; revisar el original.")
            if results.get("skipped_checks"):
                warnings.append("Checkov contiene comprobaciones omitidas; revisar el original.")
    return findings, warnings


def load_report(source, output):
    report = {"status": "No disponible", "findings": [], "warnings": [], "sha256": None}
    try:
        raw = source.read_bytes()
    except OSError:
        report["warnings"].append("No se ha podido leer el informe. No equivale a cero hallazgos.")
        return report
    (output / "originales" / source.name).write_bytes(raw)
    report["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        findings, warnings = parse_report(source.name, json.loads(raw))
        report.update(status="Con advertencias" if warnings else "Informe disponible",
                      findings=findings, warnings=warnings)
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        report.update(status="Informe inválido", warnings=[
            "JSON ilegible o estructura no reconocida. No equivale a cero hallazgos."])
    return report


def page(title, content, metadata):
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>{text(title)}</title><style>{CSS}</style></head><body><main>
<nav><a href="resumen.html">Resumen</a></nav><h1>{text(title)}</h1>
{fields(metadata)}
<p class="note">Evidencia de los archivos destinados a DefectDojo, sin deduplicación ni triaje posterior.
El estado global del job no confirma la aceptación de cada informe: la importación puede omitirse
si faltan secretos o archivos. No se consulta la API de DefectDojo.</p>
{content}</main></body></html>"""


def generate(reports, output, metadata, scanner_statuses):
    if reports.resolve() == output.resolve() or reports.resolve() in output.resolve().parents:
        raise ValueError("La salida debe estar fuera del directorio de informes originales")
    (output / "originales").mkdir(parents=True, exist_ok=True)
    summary = []
    incomplete = False
    for title, filename, htmlfile in TOOLS:
        report = load_report(reports / filename, output)
        job = scanner_statuses.get(filename, "No disponible")
        if job not in ("success", "No disponible"):
            report["warnings"].append(f"El job del analizador terminó con estado {job}.")
            if report["status"] == "Informe disponible":
                report["status"] = "Con advertencias"
        incomplete |= report["status"] != "Informe disponible"
        counts = Counter(level for level, _ in report["findings"])
        valid = report["status"] in ("Informe disponible", "Con advertencias")
        total = str(len(report["findings"])) if valid else "No evaluable"
        content = f'<p class="status">{text(report["status"])} · Hallazgos: {total}</p>'
        content += fields({"Job del analizador": job, "Archivo de origen": filename,
                           "SHA256 del original": report["sha256"]})
        if report["sha256"]:
            content += f'<p><a href="originales/{filename}">Abrir informe original</a></p>'
        content += "".join(f"<p>{text(w)}</p>" for w in report["warnings"])
        if filename == "semgrep.json":
            content += "<p>Normalización: ERROR → alta, WARNING → media, INFO → baja.</p>"
        if filename == "checkov.json":
            content += ("<p>Se conserva la severidad original. Sin especificar no significa media; "
                        "el gate existente asigna media por defecto y puede mostrar otro reparto.</p>")
        if valid:
            content += "<table><tr>" + "".join(f"<th>{s}</th>" for s in LABELS) + "</tr><tr>"
            content += "".join(f"<td>{counts[s]}</td>" for s in SEVERITIES) + "</tr></table>"
            if not report["findings"]:
                content += "<p>El informe no contiene hallazgos. Esto no certifica que la aplicación sea segura.</p>"
        for index, (_, values) in enumerate(sorted(
                report["findings"], key=lambda f: SEVERITIES.index(f[0])), 1):
            content += f"<article><h2>Hallazgo {index}</h2>{fields(values)}</article>"
        (output / htmlfile).write_text(page(title, content, metadata), encoding="utf-8")
        summary.append(f'<tr><td><a href="{htmlfile}">{title}</a></td>'
                       f'<td>{text(report["status"])}</td><td>{total}</td></tr>')
    content = ("<p>Los originales se copian sin cambios. El SHA256 permite identificar los bytes "
               "utilizados. Fecha y commit corresponden a esta ejecución; los resultados dependen "
               "del alcance de cada analizador.</p><table><tr><th>Herramienta</th>"
               "<th>Estado del informe</th><th>Hallazgos</th></tr>" + "".join(summary) + "</table>"
               "<p>Abra los HTML en un navegador. Puede usar Imprimir para guardarlos como PDF.</p>")
    (output / "resumen.html").write_text(page("Evidencias SAST SCA e IaC", content, metadata), encoding="utf-8")
    return incomplete


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--output", type=Path, default=Path("evidencias-analisis"))
    args = parser.parse_args()
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    metadata = {
        "Generado en UTC": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "Repositorio": repo,
        "Rama o referencia": os.environ.get("GITHUB_REF_NAME"),
        "Commit analizado (checkout)": os.environ.get("GITHUB_SHA"),
        "Evento": os.environ.get("GITHUB_EVENT_NAME"),
        "Ejecución": f"{server}/{repo}/actions/runs/{run}" if repo and run else None,
        "Intento": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "Estado global del job DefectDojo": os.environ.get("DD_JOB_RESULT", "No disponible"),
    }
    statuses = dict(zip([t[1] for t in TOOLS], [
        os.environ.get(f"{kind}_JOB_RESULT", "No disponible") for kind in ("SAST", "SCA", "IAC")]))
    incomplete = generate(args.reports, args.output, metadata, statuses)
    if incomplete:
        print("::warning::Evidencias generadas con informes incompletos o advertencias; revisar resumen.html")
    print(f"Informes generados en {args.output}")


if __name__ == "__main__":
    main()
