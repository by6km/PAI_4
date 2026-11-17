# Informes legibles de SAST SCA e IaC

El job `readable_reports` publica el artefacto
`evidencias-analisis-<run_id>-<intento>` después del job de DefectDojo.
Se ejecuta también cuando fallan los análisis, el gate o la importación, salvo
cancelación. No cambia el resultado de los jobs existentes ni consulta DefectDojo.

En GitHub, abrir **Actions → ejecución → Artifacts**, descargar el artefacto,
extraer el ZIP y abrir `resumen.html` en un navegador. Cada informe se puede
imprimir o guardar como PDF desde el navegador, sin conexión a Internet.

Contenido:

- `resumen.html`: estado de los tres informes y acceso a sus detalles.
- `SAST-Semgrep.html`: reglas, mensajes, severidades, archivos y líneas.
- `SCA-Trivy.html`: dependencias, versiones, identificadores y correcciones indicadas.
- `IaC-Checkov.html`: comprobaciones fallidas, archivos, líneas y guías.
- `originales/`: los JSON disponibles, copiados sin modificar sus bytes.

Se utilizan los mismos artefactos de origen que descarga `import_defectdojo`:
`semgrep.json`, `trivy-sca.json` y `checkov.json`. Los HTML incluyen commit,
referencia, evento, número de intento, URL de ejecución, hora de generación UTC
y SHA256 de cada original. En una pull request, el commit es el analizado por
`actions/checkout`, que puede ser el commit de merge de prueba.

El estado mostrado de DefectDojo es el del **job completo**, no una confirmación
por herramienta. El importador existente puede omitir el envío y terminar con
éxito si faltan secretos o informes. Estos documentos representan los datos
destinados a la importación; no incorporan deduplicación, falsos positivos ni
estados de mitigación añadidos en DefectDojo.

Un archivo ausente, JSON ilegible o estructura no reconocida aparece como
**no evaluable**, no como cero hallazgos. Los errores declarados por el analizador
y los jobs que no terminan correctamente se muestran como advertencias. Esta
validación solo afecta a la presentación; no modifica los quality gates existentes.

Semgrep normaliza `ERROR` a alta, `WARNING` a media e `INFO` a baja, indicando
también la severidad original. Checkov conserva «Sin especificar» cuando no
proporciona severidad; el gate actual asigna media por defecto y sus recuentos
por severidad pueden diferir. Trivy conserva los hallazgos por archivo analizado,
sin deduplicarlos. No se inventan versiones corregidas ni recomendaciones.

Para generar informes locales fuera del repositorio, con Python 3.12:

```sh
python scripts/readable_reports.py --reports /ruta/informes --output /ruta/evidencias
python -B -m unittest discover -s test/scripts -p 'test_readable_reports.py'
```

Los campos que dependen de GitHub aparecen como no disponibles fuera de Actions.
No hay dependencias Python adicionales. El artefacto incluye los originales con
sus hallazgos; revisar su contenido antes de compartirlo fuera del equipo.
