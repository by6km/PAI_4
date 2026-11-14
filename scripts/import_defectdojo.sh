#!/usr/bin/env bash
# Envia los informes a DefectDojo por su API (reimport-scan). Las credenciales vienen de los secretos del pipeline.
set -euo pipefail

if [ -z "${DD_URL:-}" ] || [ -z "${DD_API_KEY:-}" ]; then
  echo "::warning::DD_URL o DD_API_KEY no definidos: se omite la importacion a DefectDojo"
  exit 0
fi

DD_URL="$(printf '%s' "$DD_URL" | tr -d '[:space:]')"
DD_URL="${DD_URL%/}"
DD_API_KEY="$(printf '%s' "$DD_API_KEY" | tr -d '[:space:]')"
PRODUCT="${PRODUCT:-app}"
ENGAGEMENT="CI-${BRANCH:-main}"

import_scan() {  # $1 scan_type  $2 fichero  $3 titulo del test
  if [ ! -f "$2" ]; then echo "::warning::No existe $2, se omite"; return 0; fi
  echo ">> Importando $2 como '$1'"
  curl -sS --fail-with-body -X POST "$DD_URL/api/v2/reimport-scan/" \
    -H "Authorization: Token $DD_API_KEY" \
    -F "scan_type=$1" \
    -F "file=@$2" \
    -F "test_title=$3" \
    -F "product_type_name=${DD_PRODUCT_TYPE:-Research and Development}" \
    -F "product_name=$PRODUCT" \
    -F "engagement_name=$ENGAGEMENT" \
    -F "auto_create_context=true" \
    -F "close_old_findings=true" \
    -F "active=true" \
    -F "minimum_severity=Info" > /dev/null
}

import_scan "Semgrep JSON Report"  reports/semgrep.json                    "SAST - Semgrep"
import_scan "Trivy Scan"           reports/trivy-sca.json                   "SCA - Trivy"
import_scan "Checkov Scan"         reports/checkov.json                     "IaC - Checkov"
import_scan "ZAP Scan"              reports/zap-report.xml                   "DAST - ZAP"
echo "Importacion completada"
