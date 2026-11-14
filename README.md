# PAI-4 DevSecOps - Pipeline de seguridad en GitHub Actions

Pipeline sobre **OWASP Juice Shop** (Node.js) con 4 tipos de pruebas, 2 quality gates y gestión en DefectDojo.

| Tipo | Herramienta | Etapa | Informe |
|---|---|---|---|
| SAST | Semgrep CE | análisis | `semgrep.json` |
| SCA | OWASP Dependency-Check | análisis | `dependency-check-report.xml/json` |
| IaC | Checkov (Dockerfile) | análisis | `checkov.json` |
| DAST | OWASP ZAP | staging + dast | `zap-report.xml/json` |

- **Gate A (modo aviso)**: tras el análisis; avisa de críticas/altas y el pipeline sigue.
- **Gate B (bloqueante)**: tras el DAST; si hay críticas/altas, el pipeline falla y no hay despliegue a producción.
- **import_defectdojo**: se ejecuta siempre y envía los 4 informes por la API (`reimport-scan`).
- Diagramas (objetivo 1): `docs/diagrama-pipeline.mmd` y `docs/diagrama-flujo.mmd` (pegar en https://mermaid.live y exportar a PNG/SVG).

## Puesta en marcha
1. Haz **fork** de https://github.com/juice-shop/juice-shop (haz el repositorio privado si puedes y dale acceso al profesorado).
2. En tu fork, **borra** `.github/workflows/*` originales de Juice Shop y copia `.github/workflows/devsecops.yml`, `scripts/` y `docs/`.
3. En *Settings > Secrets and variables > Actions* crea: `DD_URL` (p. ej. `https://tu-defectdojo`), `DD_API_KEY` y, opcional pero muy recomendable, `NVD_API_KEY` (gratis en nvd.nist.gov; sin ella Dependency-Check tarda mucho).
4. En *Settings > Environments* crea `production` y añade *Required reviewers* (aprobación manual).
5. Levanta DefectDojo (https://github.com/DefectDojo/django-DefectDojo, `docker compose up`). GitHub tiene que poder alcanzarlo: servidor/VM con IP pública, túnel (cloudflared/ngrok) o *self-hosted runner* en tu máquina.
6. Haz un push a `main`. Gate B fallará con las críticas de Juice Shop: **esa es tu evidencia de "ejecución que falla por un quality gate"**.

## Ajustes
- Umbral: variable `GATE_FAIL_ON` en el workflow (`critical,high`; `none` para no bloquear).
- DAST más agresivo: sustituye `zap-baseline.py` por `zap-full-scan.py -m 5 -T 20`.
- **Importante**: si cambias el pipeline, actualiza los diagramas y explica el cambio en el informe.
- Los secretos NUNCA en el repositorio.
