# PAI-4 DevSecOps · Pipeline de seguridad en GitHub Actions

Pipeline DevSecOps sobre **OWASP Juice Shop** (Node.js / Angular), una aplicación web vulnerable a propósito. Integra cuatro tipos de pruebas de seguridad, dos quality gates y la gestión centralizada de hallazgos en DefectDojo.

El pipeline está definido en [`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml) y se ejecuta con cada `push` o `pull request` a `main`.

## Herramientas

| Tipo | Herramienta | Etapa | Informe |
|---|---|---|---|
| SAST | Semgrep Community Edition | análisis | `semgrep.json` |
| SCA | Trivy (modo `fs`) | análisis | `trivy-sca.json` |
| IaC | Checkov (Dockerfile) | análisis | `checkov.json` |
| DAST | OWASP ZAP (baseline) | staging + dast | `zap-report.xml` / `zap-report.json` |
| Gestión | DefectDojo | siempre, al final | importación por API |

**Por qué Trivy en SCA.** Se empezó con OWASP Dependency-Check, pero la API de NVD devolvía errores 503 y Juice Shop no incluye `package-lock.json`, de modo que el análisis no era fiable. Trivy usa su propia base de datos de vulnerabilidades y, con los lockfiles que el pipeline genera antes (`npm install --package-lock-only`), analiza correctamente las dependencias.

## Etapas del pipeline

1. **Análisis** (jobs en paralelo): `sast`, `sca` e `iac`. Cada uno sube su informe como artefacto.
2. **Gate A · modo aviso**: cuenta hallazgos críticos y altos y avisa en anotaciones y en el resumen del job, pero el pipeline continúa.
3. **Staging + DAST**: se construye la imagen, se despliega en un contenedor del runner y se ataca con ZAP.
4. **Gate B · bloqueante**: si hay hallazgos críticos o altos, el pipeline falla y no se llega a producción.
5. **Producción**: solo en `main`, solo si pasa el Gate B y con aprobación manual (environment `production`).
6. **Importar en DefectDojo**: se ejecuta siempre, aunque el pipeline falle, y envía los informes por API.

Los diagramas de diseño están en `docs/`: `diagrama-pipeline.mmd` (etapas, herramientas, informes y gates) y `diagrama-flujo.mmd` (qué ocurre ante una vulnerabilidad), con sus imágenes exportadas.

## Quality gates

- Los gates los evalúa `scripts/quality_gate.py`, que lee los informes de las cuatro herramientas y cuenta hallazgos por severidad.
- El umbral se define en la variable `GATE_FAIL_ON` del workflow (por defecto `critical,high`).
- Como la aplicación es vulnerable a propósito, un gate bloqueante en la fase de análisis impediría llegar al DAST. Por eso Gate A solo avisa y Gate B es el que bloquea.

## DefectDojo

- `scripts/import_defectdojo.sh` envía cada informe a la API (`/api/v2/reimport-scan/`) con estos tipos de escaneo: `Semgrep JSON Report`, `Trivy Scan`, `Checkov Scan` y `ZAP Scan`.
- Producto: nombre del repositorio. Engagement: `CI-<rama>`. Se usa `close_old_findings`, de modo que lo que deja de detectarse pasa a *Mitigated*.
- Los falsos positivos se marcan en DefectDojo con su justificación en las notas.
- DefectDojo se despliega en local con Docker Compose y se expone al pipeline mediante un túnel de Cloudflare. La URL del túnel cambia en cada sesión, así que hay que actualizar el secreto `DD_URL` antes de lanzar una ejecución que importe resultados.

## Secretos necesarios

En *Settings > Secrets and variables > Actions*:

| Secreto | Contenido |
|---|---|
| `DD_URL` | URL de DefectDojo, sin barra final |
| `DD_API_KEY` | Token de la API de DefectDojo |

Ningún secreto está en el repositorio. Si faltan `DD_URL` o `DD_API_KEY`, la importación se omite con un aviso.

## Puesta en marcha

1. Repositorio con el código de Juice Shop y los ficheros del pipeline (`.github/workflows/`, `scripts/`, `docs/`).
2. Crear los secretos `DD_URL` y `DD_API_KEY`.
3. Crear el environment `production` con *Required reviewers* (aprobación manual del despliegue).
4. Levantar DefectDojo y el túnel si se quiere la importación.
5. Hacer `push` a `main`: el pipeline se ejecuta solo.

Cambiar el umbral: editar `GATE_FAIL_ON` en el workflow (`none` desactiva el bloqueo).

## Resultado de referencia

Ejecución con Gate B fallando: <https://github.com/by6km/PAI_4/actions/runs/43640703502>

| Herramienta | Críticas | Altas | Medias | Bajas | Info |
|---|---|---|---|---|---|
| SAST · Semgrep | 0 | 12 | 56 | 5 | 0 |
| SCA · Trivy | 7 | 23 | 26 | 4 | 0 |
| IaC · Checkov | 0 | 0 | 6 | 0 | 0 |
| DAST · ZAP | 0 | 0 | 2 | 4 | 3 |

Las cuatro herramientas detectan vulnerabilidades. Gate B bloquea por los hallazgos críticos y altos de Semgrep y Trivy, y el despliegue a producción no se ejecuta.

## Uso responsable

El análisis dinámico y los escáneres se ejecutan solo contra la aplicación desplegada por el propio equipo, en el runner de la ejecución.
