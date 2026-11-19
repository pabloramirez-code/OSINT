# Propuesta: detección de posible WAF y descargas JSON en tres niveles

Estado: **aprobada** (2026-11-19). Paso 1 (informes en tres niveles) implementado.
Creada: 2026-11-19. Revisada el mismo día con las indicaciones del usuario
(textos de WAF, proveedor de la IP, Censys aplazado, tres niveles de JSON).

---

## Parte A — Posible WAF y proveedor de la IP

### A.1 Qué se muestra

De forma pasiva **no se puede saber si un WAF está activo**; sí se puede ver si
el tráfico pasa por un proveedor que lo ofrece. Por eso cada host tiene **solo
dos estados posibles**, siempre acompañados del proveedor de su IP:

| Estado | Cuándo | Ejemplo en la interfaz |
|---|---|---|
| **Posible WAF** | La IP o el CNAME pertenece a un proveedor de proxy con WAF, o la respuesta (modo Ligero) lleva sus cabeceras/cookies | `Posible WAF · Cloudflare` — señales: ASN 13335, cabecera `cf-ray` |
| **No se ha podido comprobar si existe WAF** | Ninguna señal de proveedor conocido | `No se ha podido comprobar si existe WAF · IP de Hetzner` |

Nunca se escribe "con WAF", "sin WAF", "protegido" ni "desprotegido".

**Proveedor de la IP** (siempre visible, aunque no haya posible WAF): se saca
del ASN y, cuando existe, de la lista oficial de rangos, para distinguir el
servicio concreto:

| Proveedor de la IP | Estado | Motivo |
|---|---|---|
| Cloudflare (AS13335) | Posible WAF | Proxy inverso con WAF |
| Akamai (AS20940, AS16625) | Posible WAF | CDN con WAF (Kona/App & API Protector) |
| Imperva (AS19551) | Posible WAF | Su producto principal es el WAF |
| Fastly (AS54113) | Posible WAF | CDN con WAF (Next-Gen WAF) |
| Sucuri (CNAME/cabeceras) | Posible WAF | Proxy WAF |
| AWS **CloudFront** (rango oficial) | Posible WAF | Puede llevar AWS WAF |
| Azure **Front Door** (CNAME `*.azurefd.net`) | Posible WAF | Puede llevar Azure WAF |
| AWS **EC2/otros**, Azure, Google Cloud, OVH, Hetzner… | No se ha podido comprobar | Hosting: un WAF delante, si lo hay, no se ve desde fuera |

Junto al estado se indica la **confianza**: alta (dos señales independientes,
p. ej. ASN + cabecera), media (una señal fuerte: ASN, rango oficial o CNAME),
baja (solo NS del proveedor: el DNS está en Cloudflare pero no consta que el
tráfico pase por su proxy).

### A.2 Señales (sin Censys por ahora)

1. **Pasivas, ya disponibles (cero peticiones nuevas):** ASN y organización de
   `bgp`, etiqueta `cdn` de `internetdb`, CNAME y NS de `dns`
   (`*.cdn.cloudflare.net`, `*.edgekey.net`, `*.akamaiedge.net`,
   `*.incapdns.net`, `*.sucuri.net`, `*.cloudfront.net`, `*.azurefd.net`,
   `*.fastly.net`).
2. **Pasivas, listas oficiales de rangos** (una descarga, caché 24 h):
   Cloudflare `https://www.cloudflare.com/ips-v4` y `/ips-v6`, Fastly
   `https://api.fastly.com/public-ip-list`, AWS
   `https://ip-ranges.amazonaws.com/ip-ranges.json` (servicio `CLOUDFRONT`).
   Akamai no publica lista: solo ASN. Guardar fixture real de cada una antes.
3. **Modo Ligero, sin peticiones extra:** `headers` guarda además la
   **presencia** (no el valor) de cabeceras de proveedor y ya guarda los
   nombres de cookie:

   | Proveedor | Cabeceras | Cookies |
   |---|---|---|
   | Cloudflare | `cf-ray`, `cf-cache-status`, `server: cloudflare` | `__cf_bm`, `cf_clearance` |
   | Imperva | `x-iinfo`, `x-cdn: Imperva` | `incap_ses_*`, `visid_incap_*` |
   | Akamai | `akamai-grn`, `server: AkamaiGHost` | `ak_bmsc`, `bm_sv` |
   | Sucuri | `x-sucuri-id`, `x-sucuri-cache` | |
   | CloudFront | `x-amz-cf-id`, `x-amz-cf-pop` | |
   | Azure Front Door | `x-azure-ref` | |
   | Fastly | `x-served-by`, `x-fastly-request-id` | |
   | F5 BIG-IP ASM | | `TS01*` |
   | Citrix NetScaler | | `citrix_ns_id`, `NSC_*` |
   | Barracuda | | `barra_counter_session` |

   Las cookies de F5/NetScaler/Barracuda dan "Posible WAF" aunque la IP sea de
   un hosting (el appliance está delante del servidor).
4. **Censys / Netlas: aplazado** por decisión del usuario. Se retomará más
   adelante (ver notas del documento anterior: plan Free solo con lookups,
   cuota mensual sin publicar; comprobar en la cuenta y guardar fixture).
5. **Activo (wafw00f): fuera de alcance** — envía cargas de ataque.

### A.3 "Posible origen fuera del proxy"

Si el dominio raíz tiene "Posible WAF" y otro subdominio del mismo dominio
resuelve a una IP sin proveedor de proxy, se marca en ese host:
"posible origen o servicio fuera del proxy, verificar a mano" (`low`).

### A.4 Diseño

- `edge_assessment.py` (función pura, como `mail_assessment.py`): por host
  devuelve `{ip_provider, ip_service, waf: "posible"|"no_comprobado",
  waf_provider, confidence, evidence: [...]}`.
- `modules/edge_ranges.py` (`passive`): descarga y cachea las listas oficiales.
- `headers.py`: presencia de cabeceras de proveedor.
- `insights.py`: sustituir el aviso actual "IP de una CDN" por el estado de
  WAF y el proveedor de la IP.
- Interfaz: columnas "Proveedor IP" y "WAF" en Subdominios e IPs, tarjeta en
  Resumen ("31 de 40 hosts con posible WAF · Cloudflare 28, Akamai 3") y
  entrada en el panel del nodo.

Tests: AS13335 → `Posible WAF · Cloudflare`; IP de AWS fuera del rango
CloudFront → `No se ha podido comprobar · AWS`; solo NS de Cloudflare →
confianza baja; cookie `TS01…` en IP de OVH → `Posible WAF · F5`; ningún texto
contiene "sin WAF"; `headers` no guarda valores de las cabeceras de proveedor.

---

## Parte B — Descarga del informe en tres niveles

### B.1 Por qué

Escaneo real más grande de la base de datos (un dominio real de prueba, profundidad 1):
1000 URLs, 823 certificados, 186 puertos, 174 subdominios, 77 IPs, 8 ASN y
2816 relaciones. El JSON actual ocupa **1,4 M caracteres (~350 000 tokens)**,
demasiado para leerlo entero (ni una persona ni Claude). La mayor parte son
URLs, certificados, claves repetidas y fechas con microsegundos.

### B.2 Los tres niveles

En la pestaña **JSON** habrá tres botones de descarga, del más completo al más
corto:

| Nivel | Para qué | Contenido | Tamaño objetivo* |
|---|---|---|---|
| **Extendido** | Archivo, otras herramientas, auditoría | Todo, como ahora: escaneo, entidades, relaciones, progreso por módulo | ~350 k tokens |
| **Comprimido** | Trabajar con los datos (Claude, hoja de cálculo) | Un registro por host ya aplanado + lo relevante del resto | ~10–20 k tokens |
| **Resumen** | Leer en 1 minuto / primer vistazo de Claude | Solo lo más importante | < 2 k tokens |

\* Estimaciones a confirmar midiendo con un dominio real de prueba al implementarlo.

**Extendido** — sin cambios respecto al informe actual (más `edge` cuando
exista).

**Comprimido** — misma información útil, sin ruido:
- `hosts`: una fila por subdominio con IPs, ASN, proveedor de la IP, estado de
  WAF, puertos, CVEs y problemas. La cadena host → IP → ASN → organización va
  aplanada en la fila, así que **no** hace falta la lista de relaciones.
- Formato de tabla para no repetir claves:
  `"hosts": {"columns": ["host","ips","asn","ip_provider","waf","ports","problems"], "rows": [[...], ...]}`.
- Correo: resultado de cada control y riesgo.
- Cabeceras web (modo Ligero): solo los controles que fallan o avisan.
- Certificados: recuentos por emisor + **solo** los caducados recientes o a
  punto de caducar.
- URLs del Wayback: recuento + **solo** las rutas sensibles.
- Hosts NXDOMAIN: solo la lista de nombres.
- Fechas en `AAAA-MM-DD`; sin `last_seen` ni `observed_at`; sin fuentes por
  entidad (sí un recuento por fuente).

**Resumen** — solo lo más importante:
- Objetivo, fecha, modo (pasivo/ligero) y profundidad.
- Recuentos: hosts (vivos / NXDOMAIN), IPs, ASN, puertos.
- WAF: cuántos hosts con posible WAF por proveedor y cuántos "no se ha podido
  comprobar"; hosts con "posible origen fuera del proxy".
- Riesgo de suplantación de correo (ALTO/MEDIO/BAJO) y el motivo.
- Problemas `high` y `medium` (host + una línea de evidencia); de `low` e
  `info`, solo el recuento.
- Certificados caducados/a punto y rutas sensibles: solo recuentos.

### B.3 Implementación

- `report/json_report.py`: `build_report(store, scan_id, level)` con
  `level ∈ {extended, compact, summary}`; los niveles comprimido y resumen se
  construyen a partir de `ScanIndex`/`insights.py` (ya calcula los problemas
  por nodo).
- API: `GET /api/scans/{id}/report?level=extended|compact|summary`
  (por defecto `extended`, compatible con lo actual). Nombre de archivo
  `reconmap-<dominio>-<fecha>-<nivel>.json`.
- CLI: `reconmap scan <dominio> --json salida.json --level compact` y
  `reconmap report <scan_id> --level summary` para escaneos ya hechos.
- Pestaña JSON: tres botones con una línea que explica cada nivel y su tamaño
  aproximado (calculado al generar).
- Valores externos recortados y en una sola línea en comprimido/resumen.
- Salida determinista y ordenada (dos informes se pueden comparar con `diff`).

### B.4 Uso por Claude Code

Añadir a la sección 7 de `CLAUDE.md`:

> Para analizar un escaneo, lee primero el informe **resumen**; si hace falta
> más, el **comprimido**. Del **extendido** consulta solo partes concretas
> (con `jq` o filtros), nunca el archivo entero.

### B.5 Tests

- Los tres niveles se generan para el mismo escaneo y son JSON válido.
- Todo host del extendido aparece en el comprimido.
- Resumen: no contiene URLs ni certificados individuales; incluye todos los
  problemas `high`.
- Comprimido: solo URLs sensibles; solo certificados caducados/a punto.
- Tamaño: sobre una fixture grande, resumen < 2 k tokens estimados (car./4) y
  comprimido < 10 % del extendido.
- `level` inválido → 422.
- Los valores externos con HTML o saltos de línea salen como texto plano.

---

## Orden propuesto

1. ~~Informes en tres niveles + nota en `CLAUDE.md`.~~ Hecho. Medido con
   el dominio de prueba (servidor): resumen 4,9 KB, comprimido 44 KB, extendido 1,3 MB.
2. `edge_assessment.py` con señales ya disponibles + textos "Posible WAF" /
   "No se ha podido comprobar si existe WAF" + proveedor de la IP.
3. Listas oficiales de rangos (`edge_ranges.py`).
4. Cabeceras de proveedor en `headers` (modo Ligero).
5. Censys/Netlas (aplazado).

## Fuentes consultadas

- Censys, niveles de acceso: https://docs.censys.com/docs/data-access-tiers-entitlements
- Fastly, rangos IP: https://docs.fastly.com/en/guides/accessing-fastlys-ip-ranges
- Recopilación de rangos de CDN: https://www.github.com/taythebot/cdn-ranges
- Fingerprinting de WAF por cabeceras y cookies: https://www.thehacker.recipes/web/recon/waf-fingerprinting
- Awesome WAF: https://github.com/0xinfection/awesome-waf
