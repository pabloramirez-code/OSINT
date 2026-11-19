# reconmap — Orquestador de reconocimiento pasivo con interfaz gráfica

> Este archivo es la fuente de verdad del proyecto. Claude Code: léelo entero al
> empezar cada sesión, mira la sección **Estado actual** y continúa desde ahí.

## 1. Qué es el proyecto

Una **aplicación web con interfaz gráfica**: el usuario escribe un **dominio** en
el navegador, pulsa "Escanear" y la aplicación:

1. Consulta en paralelo fuentes públicas de OSINT de infraestructura (crt.sh, DNS,
   RDAP, Shodan InternetDB, Wayback Machine, BGP…).
2. Muestra el progreso en directo y los resultados en pestañas (resumen,
   subdominios, IPs y puertos, grafo, hallazgos).
3. Guarda todo como un **grafo de entidades** (dominio → subdominios → IPs → ASN →
   organización) y lo dibuja de forma interactiva.
4. Aplica un **motor de reglas** que marca *findings* objetivos y defendibles.
5. Al final, se despliega en un clúster **k3s** y se usa desde el móvil por
   Tailscale.

La **interfaz gráfica es el producto**. Existe también un CLI, pero es una
herramienta secundaria para depurar y automatizar.

Plazo objetivo: 6 semanas. Proyecto de portfolio para puestos junior de
sistemas / ciberseguridad.

**Lo que NO es:** no es un escáner de vulnerabilidades, no ataca, no "predice"
vectores de ataque. **Observa y marca.**

---

## 2. Reglas innegociables (Claude Code: no las rompas nunca)

1. **Tres niveles de contacto.** Cada módulo declara
   `contact ∈ {passive, light, active}`.
   - `passive`: solo consulta fuentes de terceros. Siempre permitido.
   - `light`: peticiones equivalentes a una visita normal con navegador a la
     portada del dominio y de sus subdominios en ámbito: **como máximo 3 por
     host y escaneo** (HTTPS, HTTP para ver si redirige a HTTPS y, solo si el
     certificado no es válido, HTTPS otra vez sin verificar para leer las
     cabeceras; aprobado por el usuario el 2026-11-18). Sin seguir enlaces ni
     redirecciones y sin leer el cuerpo. Tope de 50 hosts por escaneo
     (`RECONMAP_MAX_LIGHT_HOSTS`). **Desactivado por defecto.** Se activa en
     cada escaneo eligiendo el modo «Ligero» ("Tengo autorización o es un
     dominio mío"), que queda guardado en el `Scan`.
   - `active` (**aprobado por el usuario el 2026-11-19**,
     `docs/propuesta-modo-activo.md`): herramientas externas (httpx, tlsx,
     gowitness, en Docker) que contactan con el objetivo más allá de una visita
     a la portada. Solo si en esa ejecución se elige el modo «Activo» **y**
     se marca la casilla "Tengo autorización por escrito para hacer pruebas
     activas contra este dominio, o es mío" (el servidor responde 422 sin
     ella); queda guardado en el `Scan` (`allow_active`, que implica
     `allow_light`). La lista blanca `RECONMAP_ACTIVE_ALLOWLIST` es opcional:
     si se rellena, el modo Activo se limita a esos dominios y sus subdominios
     (`active_allowed` en `config.py`). Cambio pedido por el usuario el
     2026-11-19 (antes la lista blanca era obligatoria). Prohibidos los escáneres de
     vulnerabilidades, la fuerza bruta y el fuzzing. Los procesos se lanzan
     sin shell (lista de argumentos) y con los hosts ya validados.
2. **Solo infraestructura, nunca personas.** No se recogen, guardan ni
   correlacionan datos personales. Si una fuente devuelve emails, se guarda solo
   el recuento por dominio. De los índices de filtraciones o buckets **nunca**
   se guardan nombres ni contenidos de archivos; solo el nombre del bucket, el
   proveedor y el número de archivos. **Excepción aprobada por el usuario
   (2026-11-18):** las URLs del Wayback Machine se guardan completas, con su
   query string.
3. **Ámbito controlado.** La recursión solo sigue el dominio objetivo y sus
   subdominios. IPs y ASNs se registran pero **no** se usan para saltar a otros
   dominios. Los resultados obtenidos por **búsqueda por palabra clave** (no por
   dominio exacto) se guardan como entidad `candidate`, se muestran como "no
   atribuido, verificar a mano" y **nunca** se reencolan ni generan hallazgos
   de severidad mayor que `info`.
4. **Secretos fuera del repo.** Claves solo en `.env` (en `.gitignore`). Existe
   `.env.example` con las claves vacías. Nunca mostrar claves en logs ni en la
   interfaz.
5. **Respeto a las fuentes.** Toda petición pasa por caché + rate limiter.
6. **Todo lo que viene de fuera se escapa.** Los datos de las fuentes (nombres de
   certificados, URLs del Wayback, banners) son texto no fiable: la interfaz
   **nunca** los inserta como HTML. Plantillas con autoescape, y en JavaScript
   `textContent`, nunca `innerHTML` con datos externos.
7. **Solo local por defecto.** El servidor escucha en `127.0.0.1`. Exponerlo
   requiere un cambio consciente de configuración (y en Fase 5, solo detrás de
   Tailscale).
8. **Tests sin red.** La suite normal no hace peticiones reales. Las pruebas
   contra servicios reales llevan `@pytest.mark.network`.
9. **No avanzar de fase** sin que pasen todos los tests **y** el usuario haya
   marcado su checklist de revisión manual.
10. **Preguntar antes** de añadir una dependencia que no esté en la sección 3.

---

## 3. Stack

| Pieza | Elección | Motivo |
|---|---|---|
| Lenguaje | Python 3.12 | |
| Gestor de proyecto | `uv` | rápido, lockfile |
| Servidor web | `FastAPI` + `uvicorn` | API y páginas en el mismo proceso |
| Plantillas | `Jinja2` (autoescape activado) | HTML generado en servidor |
| Interactividad | **HTMX** (CDN) + JavaScript mínimo | sin framework de frontend ni build |
| Grafo | **Cytoscape.js** (CDN) | grafos interactivos |
| Estilos | CSS propio en un archivo, tema oscuro | sin frameworks CSS |
| Formularios | `python-multipart` | FastAPI lo necesita para leer formularios |
| HTTP saliente | `httpx` (async) | |
| DNS | `dnspython` | |
| Modelos | `pydantic` v2 | |
| CLI secundario | `typer` + `rich` | |
| Persistencia | SQLite (`sqlite3` estándar) | |
| Tests | `pytest`, `pytest-asyncio`, `respx`, `TestClient` de FastAPI | |
| Calidad | `ruff`, `mypy` | |
| E2E (opcional, Fase 3+) | `playwright` | probar la interfaz en un navegador real |
| Despliegue (Fase 5) | Docker, k3s, (opcional) ArgoCD | |

---

## 4. Arquitectura

### 4.1 Entidades y relaciones

```
Entity: type ∈ {domain, subdomain, ip, asn, org, url, port, certificate,
               candidate, technology, cve}
        value (normalizado), first_seen, last_seen, sources[]
Relation: (from) --type--> (to), source, observed_at
          type ∈ {has_subdomain, resolves_to, belongs_to_asn, owned_by,
                  exposes_port, has_certificate, archived_url, cname_to,
                  uses_technology, has_vulnerability}
Finding: rule_id, severity ∈ {info, low, medium, high}, entity,
         title, evidence (fuente + dato bruto), created_at
Scan:    id, target, depth, allow_light, status ∈ {pending, running, done, failed},
         started_at, finished_at, progreso por módulo, errores
```

Normalización de dominios: minúsculas, sin punto final, IDNA (punycode), sin
`*.` (el comodín se guarda como atributo).

### 4.2 Contrato de un módulo

```python
class Module(Protocol):
    name: str                      # "crtsh"
    label: str                     # "Certificate Transparency" (para la interfaz)
    accepts: set[EntityType]
    contact: Contact               # passive | light | active
    requires_key: str | None
    cache_ttl: timedelta
    rate_limit: float

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult: ...
```

El **motor** no conoce ninguna fuente concreta. Ejecuta módulos en paralelo,
guarda resultados, actualiza el progreso del `Scan` en la base de datos (la
interfaz lo lee de ahí) y reencola entidades en ámbito hasta `max_depth`.

Añadir una fuente = un archivo en `modules/` + tests. Cero cambios en motor o
interfaz: la interfaz lista los módulos dinámicamente.

### 4.3 Cómo se comunican interfaz y motor

- `POST /scans` crea el escaneo y lo lanza como tarea en segundo plano.
- La página del escaneo hace **polling con HTMX cada 1 s** a un fragmento de
  progreso mientras `status` sea `pending/running`; al terminar deja de
  preguntar y carga los resultados. (Polling, no WebSockets: más simple y
  suficiente.)
- Las pestañas de resultados son fragmentos HTML que HTMX carga bajo demanda.
- El grafo pide `GET /api/scans/{id}/graph` (JSON) y lo dibuja Cytoscape.js.
- Máximo **1 escaneo en marcha** a la vez.

### 4.4 Diseño de la interfaz

```
┌──────────────┬───────────────────────────────────────────────────────┐
│ reconmap     │  [ ejemplo.com              ] [Profundidad: 1 ▾] [Escanear] │
│              ├───────────────────────────────────────────────────────┤
│ HISTORIAL    │  ejemplo.com · en curso · 00:14                        │
│ ● ejemplo.com│  crt.sh   ████████████ hecho (42)                      │
│ ✓ otro.es    │  DNS      ██████░░░░░░ 18/31                           │
│ ✓ prueba.org │  RDAP     ████████████ hecho                           │
│              ├───────────────────────────────────────────────────────┤
│ [Ajustes]    │  Resumen │ Subdominios │ IPs y puertos │ Grafo │ Hallazgos │ JSON │
│              │  ┌─────────┬─────────┬─────────┬─────────┐             │
│              │  │ 42 subd.│ 17 IPs  │ 3 ASN   │ 5 hallaz│             │
│              │  └─────────┴─────────┴─────────┴─────────┘             │
│              │  tabla / grafo de la pestaña activa                    │
└──────────────┴───────────────────────────────────────────────────────┘
```

- Barra lateral: navegación (Inicio, Proyectos, Ajustes) y aviso del escaneo en
  curso. Los escaneos anteriores viven en la página **Proyectos** (`/projects`):
  un bloque desplegable por dominio con todos sus escaneos.
- Cabecera: campo de dominio, selector de profundidad, botón.
- Progreso: una barra por módulo con estado y número de resultados; errores de
  módulo visibles en ámbar (no rompen el escaneo).
- Pestañas:
  - **Resumen:** tarjetas con recuentos + datos RDAP (registrador, caducidad).
  - **Subdominios:** tabla con búsqueda, columnas subdominio / IPs / fuentes /
    visto por primera vez. Ordenable.
  - **IPs y puertos:** tabla IP / ASN / organización / puertos / CVEs.
  - **Grafo:** Cytoscape, color por tipo de entidad, clic en nodo → panel
    lateral con detalles y fuentes. Botón "reencuadrar".
  - **Hallazgos:** (Fase 4) lista ordenada por severidad con evidencia.
  - **JSON:** botón de descarga del informe completo.
- **Ajustes:** qué módulos están activos, cuáles necesitan clave y si la clave
  está configurada (✓/✗, **nunca** el valor).
- Tema **claro sobrio** (cambiado del oscuro original a petición del usuario):
  fondo gris muy claro, tarjetas blancas con sombra suave, un único acento
  azul; tipografía del sistema, una sola hoja `static/app.css`.
- Responsive: usable en el móvil (la barra lateral se pliega).
- Errores de usuario claros: dominio inválido → mensaje junto al campo, sin
  recargar la página.

### 4.5 Estructura de carpetas

```
reconmap/
├── CLAUDE.md
├── README.md                # con capturas de la interfaz
├── pyproject.toml
├── .env.example
├── .gitignore
├── src/reconmap/
│   ├── models.py
│   ├── normalize.py
│   ├── scope.py
│   ├── engine.py
│   ├── store.py
│   ├── cache.py
│   ├── ratelimit.py
│   ├── config.py
│   ├── cli.py               # secundario
│   ├── modules/
│   │   ├── base.py
│   │   ├── crtsh.py  dns.py  rdap.py
│   │   └── internetdb.py  wayback.py  bgp.py
│   ├── rules/               # Fase 4
│   ├── report/              # exportación JSON / HTML
│   └── web/
│       ├── app.py           # FastAPI: rutas de páginas y de API
│       ├── templates/
│       │   ├── base.html
│       │   ├── index.html
│       │   ├── scan.html
│       │   ├── settings.html
│       │   └── partials/    # fragmentos HTMX (progreso, tablas, tarjetas)
│       └── static/
│           ├── app.css
│           └── graph.js
├── tests/
│   ├── fixtures/            # respuestas reales guardadas de cada fuente
│   ├── unit/
│   ├── web/                 # TestClient
│   ├── e2e/                 # playwright (opcional)
│   └── network/
└── docs/
    └── capturas/
```

---

## 5. Hoja de ruta por fases

Cada fase tiene **objetivo**, **tareas**, **tests que deben pasar** y
**revisión manual** (la hace el usuario).
Claude Code: al terminar una fase, ejecuta `uv run pytest`, `uv run ruff check`
y `uv run mypy src`, enseña el resultado y **para** hasta que el usuario
confirme su checklist.

---

### Fase 0 — Esqueleto (día 1)

**Objetivo:** el proyecto se instala, arranca un servidor y se ve una página.

Tareas:
- [ ] `uv init`, estructura de carpetas de la sección 4.5.
- [ ] `pyproject.toml` con dependencias, config de ruff, mypy y marcadores
      `network` y `e2e` registrados en pytest.
- [ ] `.gitignore` (`.env`, `*.db`, `__pycache__`, `.venv`).
- [x] `.env.example` con `SHODAN_API_KEY=` y `VIRUSTOTAL_API_KEY=` vacías
      (`GRAYHAT_API_KEY=` añadida en Fase 1).
- [ ] `models.py`, `normalize.py`.
- [ ] `web/app.py` con `GET /` que sirve `index.html` (cabecera, campo de
      dominio deshabilitado, barra lateral vacía) y `GET /health`.
- [ ] `base.html` + `app.css` con el tema oscuro y el esqueleto de la 4.4.
- [ ] Comando: `uv run reconmap-web` arranca en `http://127.0.0.1:8000`.

Tests que deben pasar:
- [ ] `normalize_domain("Ejemplo.COM.")` → `"ejemplo.com"`
- [ ] `normalize_domain("*.ejemplo.com")` → `("ejemplo.com", wildcard=True)`
- [ ] `normalize_domain("señal.es")` → `"xn--seal-hqa.es"`
- [ ] Inválidos (`"no es un dominio"`, `""`, `"a..b.com"`) →
      `InvalidDomainError`.
- [ ] `GET /` → 200 y contiene el campo de dominio.
- [ ] `GET /health` → 200 `{"status": "ok"}`.
- [ ] Jinja2 tiene autoescape activado (test que renderiza `<b>` y comprueba
      que sale como `&lt;b&gt;`).

Revisión manual:
- [ ] `uv sync` y `uv run reconmap-web` funcionan en limpio en mi máquina.
- [ ] Abro el navegador y veo el esqueleto con el tema oscuro.
- [ ] `git status` no muestra `.env` ni `.db`.

---

### Fase 1 — MVP: escanear desde la interfaz con 3 fuentes (semanas 1–2)

**Objetivo (mínimo presentable):** escribo un dominio en la página, pulso
Escanear, veo el progreso en directo y luego los resultados en tablas.
Fuentes: crt.sh, DNS, RDAP. **Sin recursión ni grafo todavía.**

#### 1A — Núcleo

- [ ] `store.py`: tablas `scans`, `entities`, `relations`, `findings`,
      `module_runs` (progreso y errores por módulo). Upsert idempotente.
- [ ] `cache.py` con TTL; `ratelimit.py` token bucket por módulo.
- [ ] `modules/base.py` (contrato 4.2).
- [ ] `modules/crtsh.py`: `https://crt.sh/?q=%25.{dominio}&output=json`.
      Subdominios de `name_value` (separados por salto de línea), deduplicados,
      sin comodines, certificado con `not_after`.
- [ ] `modules/dns.py`: A, AAAA, MX, NS, TXT, CNAME, CAA. NXDOMAIN/timeouts
      → error de módulo, no excepción.
- [ ] `modules/rdap.py`: `https://rdap.org/domain/{dominio}`.
- [ ] `engine.py` v1: módulos en paralelo; uno que falla no tumba a los demás;
      escribe progreso en `module_runs`.
- [ ] Guardar en `tests/fixtures/` una respuesta real de cada fuente.

#### 1B — Interfaz

- [ ] `POST /scans` (formulario HTMX): valida con `normalize_domain`; si es
      inválido devuelve el fragmento de error junto al campo (HTTP 422).
      Si es válido, crea el escaneo y redirige a `/scans/{id}`.
- [ ] `GET /scans/{id}`: página del escaneo.
- [ ] `GET /scans/{id}/progress`: fragmento con una barra por módulo;
      incluye `hx-trigger="every 1s"` solo mientras el escaneo esté activo.
- [ ] Pestañas Resumen, Subdominios y JSON (las demás aparecen deshabilitadas
      con "próximamente").
- [ ] Tabla de subdominios con filtro de texto en el cliente y orden por
      columna.
- [ ] Barra lateral con el historial de escaneos (últimos 20).
- [ ] `GET /api/scans/{id}/report` → JSON completo (botón de descarga).
- [ ] Si ya hay un escaneo en marcha, el botón se deshabilita y el servidor
      responde 429 a otro `POST`.
- [ ] CLI mínimo: `reconmap scan <dominio> --json salida.json` (usa el mismo
      motor; útil para depurar).

Tests que deben pasar (sin red, con `respx`):
- [ ] crt.sh: parsea la fixture → subdominios únicos, sin comodines, en ámbito.
- [ ] crt.sh: `[]` → cero entidades; 502/timeout → error registrado.
- [ ] DNS: registros A generan `resolves_to`; NXDOMAIN → error de módulo.
- [ ] RDAP: extrae registrador y fecha de caducidad.
- [ ] Caché: segunda llamada en TTL no hace petición; TTL vencido sí.
- [ ] Store: misma entidad desde dos fuentes → una fila con las dos fuentes.
- [ ] Motor: un módulo que lanza excepción no impide los otros.
- [ ] Motor: rechaza un módulo `contact=active`, y uno `light` si el escaneo
      no tiene `allow_light` (módulos falsos de prueba).
- [ ] Web: `POST /scans` válido → redirección a `/scans/{id}`.
- [ ] Web: `POST /scans` con `"<script>alert(1)</script>"` → 422 y el
      texto aparece escapado en la respuesta.
- [ ] Web: segundo `POST` con escaneo en marcha → 429.
- [ ] Web: el fragmento de progreso **incluye** el polling si `running` y
      **no** lo incluye si `done`.
- [ ] **XSS:** una fixture de crt.sh con un `name_value` que contiene
      `<img src=x onerror=alert(1)>` se muestra escapada en la tabla de
      subdominios.
- [ ] `GET /scans/inexistente` → 404 con página de error propia.

Revisión manual:
- [ ] Escaneo un dominio **mío** desde el navegador y veo las barras avanzar.
- [ ] Comparo los subdominios con crt.sh en el navegador: no faltan evidentes.
- [ ] Repito el escaneo: el segundo es casi instantáneo (caché).
- [ ] Meto un dominio inválido: el error sale junto al campo, sin recargar.
- [ ] Corto la red a mitad: la interfaz muestra errores en ámbar y no se
      queda colgada para siempre.
- [ ] Lo abro en el móvil (misma red) y es usable.
- [ ] Hago 2–3 capturas para `docs/capturas/`.

**Aquí el proyecto ya es enseñable.** Commit + etiqueta `v0.1.0`.

---

### Fase 2 — Más fuentes, recursión y pestaña de IPs (semana 3)

**Objetivo:** el escaneo crece solo, sin salirse del ámbito, y la interfaz
muestra la infraestructura.

Tareas:
- [ ] `modules/internetdb.py`: `https://internetdb.shodan.io/{ip}` (sin
      clave). 404 = "sin datos", no error.
- [ ] `modules/wayback.py`: CDX API
      `http://web.archive.org/cdx/search/cdx?url=*.{dominio}/*&output=json&fl=original&collapse=urlkey`
      con límite configurable.
- [ ] `modules/bgp.py`: IP → ASN → organización con RIPEstat (`network-info`
      y `as-overview`). BGPView descartado: no responde (nov. 2026).
- [x] ~~`modules/shodan.py`~~ **Eliminado** a petición del usuario: con plan
      gratuito Shodan devuelve 403 en la mayoría de IPs. InternetDB (gratis,
      sin clave) cubre puertos, etiquetas y CVEs.
- [ ] `modules/certspotter.py` y `modules/hackertarget.py`: subdominios
      (comprobar condiciones y guardar fixture real antes).
- [ ] Más adelante (aprobado por el usuario, sin fecha): VirusTotal,
      AlienVault OTX, urlscan.io, GreyNoise y AbuseIPDB.
- [ ] `scope.py`: `in_scope(entity, target)`.
- [ ] Motor v2: cola con `max_depth` (1 por defecto, máximo 3) y visitadas.
      La profundidad cuenta saltos entre nombres de dominio; las IPs se
      procesan a la profundidad del host que las resolvió. Tope de 300
      subdominios por escaneo (`RECONMAP_MAX_HOSTS`), avisado en la interfaz.
- [ ] Interfaz: selector de profundidad; pestaña **IPs y puertos**; las
      barras de progreso aparecen para los módulos nuevos sin tocar plantillas
      (se generan desde la lista de módulos).
- [ ] Página **Ajustes**: módulos, si requieren clave y si está configurada
      (✓/✗).
- [ ] Contador de peticiones por fuente en el Resumen.

Tests que deben pasar:
- [ ] `in_scope("api.ejemplo.com", "ejemplo.com")` → True
- [ ] `in_scope("ejemplo.com.evil.net", "ejemplo.com")` → **False**
- [ ] `in_scope("otroejemplo.com", "ejemplo.com")` → False
- [ ] Motor: subdominio descubierto se reescanea con DNS (profundidad 1).
- [ ] Motor: respeta `max_depth`; no procesa dos veces la misma entidad.
- [ ] Motor: hostnames ajenos que devuelva internetdb **no** se reencolan.
- [ ] Web: la página de Ajustes **nunca** contiene el valor de una clave
      (test con una clave falsa en el entorno y búsqueda en el HTML).
- [ ] Web: profundidad fuera de rango (0, 4, "abc") → 422.

Revisión manual:
- [ ] Escaneo con profundidad 2 un dominio mediano; anoto cuánto tarda.
- [ ] En la pestaña IPs no aparece nada raro fuera de mi objetivo.
- [ ] Ajustes muestra bien qué falta configurar.

---

### Fase 2c — Seguridad del correo (adelantada a petición del usuario)

**Objetivo:** saber si el dominio se puede suplantar por correo y qué falta
para evitarlo, con criterios explícitos y defendibles.

Tareas:
- [ ] Casilla "Tengo autorización o es un dominio mío" en el formulario
      (`allow_light`), adelantada de la Fase 2b.
- [ ] `modules/mail.py` (`passive`, solo DNS): MX, SPF (con recuento de
      consultas DNS siguiendo `include`/`redirect`, máx. 10 según RFC 7208),
      DMARC, DKIM, `_mta-sts`, `_smtp._tls` (TLS-RPT), BIMI y DS (DNSSEC).
- [ ] DKIM: se prueba una **lista acotada (~20) de selectores habituales**
      (Google, Microsoft, Mailchimp, Proton, Fastmail…). Excepción explícita a
      "nada de fuerza bruta": son consultas DNS fijas, no un diccionario.
      Si no se encuentra, se informa "no encontrado en selectores habituales",
      nunca "no tiene DKIM".
- [ ] `modules/mta_sts.py` (`light`): solo si existe `_mta-sts`, descarga
      `https://mta-sts.<dominio>/.well-known/mta-sts.txt` sin seguir
      redirecciones.
- [ ] Evaluación pura (`mail_assessment.py`) con semáforo por control y
      nivel de riesgo de suplantación ALTO/MEDIO/BAJO con criterios visibles.
- [ ] Pestaña **Correo** y tarjeta de riesgo en el Resumen.

Tests que deben pasar:
- [ ] SPF: `+all` → fallo; `-all`/`~all` → correcto; >10 consultas → fallo;
      dos registros SPF → fallo; bucles de `include` no cuelgan.
- [ ] DMARC: ausente o `p=none` → riesgo ALTO; `pct<100` → aviso.
- [ ] DKIM: RSA 1024 → aviso; RSA 2048 y ed25519 → correcto; `p=` vacío →
      clave revocada.
- [ ] Dominio que no envía correo (MX nulo + `-all` + DMARC reject) → BAJO.
- [ ] MTA-STS: sin casilla no hay petición; sin `_mta-sts` no hay petición;
      una redirección no se sigue.
- [ ] Los TXT (texto externo) se muestran escapados.

---

### Fase 2b — Contacto ligero y buckets

**Objetivo:** añadir el nivel `light` y las fuentes que lo necesitan, sin
romper las reglas 1–3.

Tareas:
- [x] Casilla de autorización: adelantada a la Fase 2c.
- [x] `modules/headers.py` (`light`) + `headers_assessment.py` + pestaña Web:
      HSTS, CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy,
      revelación de versiones, X-XSS-Protection, cookies (solo nombre y
      atributos), certificado y paso de HTTP a HTTPS. Si HTTPS redirige, solo
      se evalúa HSTS en ese host. Probado contra example.com y badssl.com.
- [x] ~~`modules/buckets.py`~~ **Descartado** (2026-11-18): con plan gratuito
      la API de GrayHatWarfare lista 0 buckets ("As a free user you can list 0
      … buckets"). La regla de entidades `candidate` se mantiene por si se
      añade otra fuente de búsqueda por palabra clave.
      Autenticación: cabecera `Authorization: Bearer <token>`; en `.env` se
      guarda solo el token (sin la palabra `Bearer`) y el módulo la añade.
- [ ] Pestaña o sección "Candidatos no atribuidos".

Tests que deben pasar:
- [ ] `headers` no se ejecuta si `allow_light` es falso.
- [ ] `headers` hace como máximo una petición por host y no sigue
      redirecciones fuera del ámbito.
- [ ] `buckets` nunca guarda nombres de archivos (fixture con archivos).
- [ ] Las entidades `candidate` no se reencolan.

Revisión manual:
- [ ] Sin marcar la casilla, ningún log muestra peticiones a mi dominio.
- [ ] Los candidatos se ven claramente como "no atribuidos".

---

### Fase 3 — Grafo visual y comparación (semana 4)

**Objetivo:** ver la superficie de un vistazo y saber honestamente dónde
está la herramienta frente a otras.

Tareas:
- [x] `GET /api/scans/{id}/graph` → `{nodes, edges, grouped}` (`report/graph.py`).
- [x] Pestaña **Grafo** con Cytoscape.js 3.30.2 (cargado solo al abrir la
      pestaña, con SRI): color y forma por tipo, leyenda, zoom, "Reencuadrar",
      clic en nodo → panel lateral con `textContent` y resaltado de vecinos.
      Etiquetas cortas calculadas en el servidor (certificados por caducidad,
      puertos por número). Enlace directo a pestaña: `/scans/{id}?tab=graph`.
- [x] Con más de 300 nodos se agrupan tipos en orden URL → certificado →
      puerto hasta caber ("N URLs archivadas"). Ampliado frente al plan: con
      datos reales (proton.me: 1000 URLs + 295 certificados) agrupar solo las
      URLs no bastaba. proton.me: 1290 entidades → 203 nodos.
- [x] Herramienta de comparación: `reconmap compare informe.json otra.txt
      --tool amass --markdown docs/comparativa.md` (lista de texto, un nombre por
      línea, para no depender del formato de cada herramienta).
- [ ] Ejecutar SpiderFoot (solo pasivo) y `amass enum -passive` sobre un
      dominio propio y guardar el resultado en `docs/comparativa.md`
      (pendiente del usuario: requiere instalar esas herramientas).
- [ ] (Opcional) Primer test E2E con playwright: escanear con fuentes
      simuladas y comprobar que aparece el grafo.

Tests que deben pasar:
- [ ] Grafo: toda arista apunta a nodos existentes; sin nodos duplicados.
- [ ] Grafo: la agrupación se activa por encima del umbral.
- [ ] Grafo: un valor con HTML en un nodo llega como texto en el JSON y el
      panel lateral lo muestra literal (test E2E o revisión manual).

Revisión manual:
- [ ] El grafo de mi dominio se entiende de un vistazo. Si no, ajustar
      colores, tamaños o agrupación antes de seguir.
- [ ] Sé explicar qué encuentra SpiderFoot/amass que mi herramienta no, y
      por qué (qué fuentes le faltan).

---

### Fase 4 — Hallazgos (semanas 5–6) — FASE RECORTABLE

**Objetivo:** marcar hallazgos objetivos con evidencia. Si el tiempo aprieta,
se recorta: las fases 0–3 ya forman un proyecto completo.

Principios:
- Una regla por archivo, determinista, con tests propios.
- Cada finding guarda la **evidencia** (fuente + dato bruto).
- Lenguaje prudente: "expuesto", "candidato", "requiere verificación".
  Nunca "vulnerable" ni "explotable".
- Empezar con 5–6 reglas sólidas.

Catálogo inicial:

| ID | Regla | Lógica | Severidad |
|---|---|---|---|
| R001 | Servicio de administración expuesto | puerto ∈ {22, 23, 3389, 5900, 445} en internetdb | medium (23 y 445: high) |
| R002 | Base de datos expuesta | puerto ∈ {3306, 5432, 1433, 6379, 9200, 27017} | high |
| R003 | CVE conocida reportada | internetdb devuelve `vulns` para la IP → listar, "requiere verificación de versión" | medium |
| R004 | Certificado caducado o a punto | `not_after` < hoy → high; < 15 días → low | low/high |
| R005 | Política de correo débil | sin SPF o SPF `+all` → medium; sin DMARC o `p=none` → low | low/medium |
| R006 | CNAME colgante (candidato a takeover) | CNAME a servicio de terceros conocido (S3, GitHub Pages, Heroku, Azure…) cuyo destino da NXDOMAIN → "candidato, verificar a mano" | medium |
| R007 | Rutas sensibles en el histórico | Wayback con `/.git/`, `/.env`, `backup.zip`, `.sql`, `wp-config`, `/phpmyadmin` → "existió, comprobar si sigue" | low |
| R008 | Sin registro CAA | dominio raíz sin CAA | info |

Tareas:
- [ ] `rules/base.py`: `Rule.evaluate(graph) -> list[Finding]`.
- [ ] R001–R005 primero; R006–R008 si hay tiempo.
- [ ] Las reglas corren al final del escaneo sobre el grafo guardado.
- [ ] Pestaña **Hallazgos**: lista por severidad, con la evidencia desplegable.
- [ ] Tarjeta de hallazgos en el Resumen con recuento por severidad.
- [ ] En el grafo, los nodos con hallazgos llevan borde del color de la
      severidad más alta.
- [ ] Botón "Exportar informe HTML" (informe autocontenido de una página).

Tests que deben pasar:
- [ ] Cada regla: caso positivo, negativo y límite (R004: caduca justo en
      15 días).
- [ ] R005: `v=spf1 include:_spf.google.com ~all` → sin finding de SPF;
      `v=spf1 +all` → medium.
- [ ] R006: CNAME a servicio conocido que **sí** resuelve → sin finding.
- [ ] Todo finding tiene `evidence` no vacía.
- [ ] Ninguna regla hace peticiones de red (`respx` estricto).
- [ ] El informe HTML exportado escapa los datos externos.

Revisión manual:
- [ ] Reviso cada hallazgo sobre mi dominio: ¿es cierto? Anoto falsos
      positivos en `docs/falsos-positivos.md`.
- [ ] Sé explicar la lógica de cada regla con mis palabras (si no, fuera).

---

### Fase 5 — Despliegue en k3s (tras la semana 6, o antes si sobra tiempo)

**Objetivo:** la aplicación corre en mi clúster y la uso desde el móvil.

Tareas:
- [ ] `Dockerfile` multi-stage, usuario no root, imagen pequeña.
- [ ] `deploy/k8s/`: Deployment, Service, Ingress, PVC para SQLite,
      Secret para claves (creado a mano, **no** en el repo).
- [ ] Probes de liveness/readiness con `/health`.
- [ ] Acceso **solo** por Tailscale; añadir autenticación básica (usuario y
      contraseña desde Secret) antes de exponerlo fuera de `localhost`.
- [ ] (Opcional) ArgoCD apuntando a `deploy/k8s/`.
- [ ] (Opcional) Módulos `active` solo para infraestructura propia: lista
      blanca de dominios en configuración + casilla de confirmación de
      autorización en la interfaz.

Comprobaciones:
- [ ] `docker build` y el contenedor responde en `/health`.
- [ ] `kubectl apply` en limpio levanta la aplicación.
- [ ] Borro el pod: vuelve y el historial de escaneos sigue ahí.

Revisión manual:
- [ ] Entro desde el móvil por Tailscale, fuera de casa, y escaneo un dominio.
- [ ] Sin Tailscale no llego a la aplicación.
- [ ] `git log -p | grep -i "api_key"` no devuelve ninguna clave real.

---

## 6. Comandos habituales

```bash
uv sync                              # instalar
uv run reconmap-web                  # interfaz en http://127.0.0.1:8000
uv run reconmap scan ejemplo.com     # CLI (depuración)
uv run pytest                        # tests sin red
uv run pytest -m network             # contra servicios reales (a mano)
uv run pytest -m e2e                 # interfaz en navegador (opcional)
uv run ruff check . && uv run ruff format .
uv run mypy src
```

Sin `uv` en el PATH (Windows, PowerShell, desde la raíz del proyecto):

```powershell
.\.venv\Scripts\python.exe -m reconmap.web.app                 # interfaz
.\.venv\Scripts\python.exe -m reconmap.cli scan ejemplo.com     # CLI
.\.venv\Scripts\python.exe -m reconmap.cli report ejemplo.com -o resumen.json --level summary
.\.venv\Scripts\python.exe -m pytest
```

Contenedor (Docker Desktop arrancado):

```bash
docker compose up -d --build         # http://127.0.0.1:8000 (solo local)
docker compose exec reconmap reconmap scan ejemplo.com
docker compose down
```

---

## 7. Forma de trabajar (para Claude Code)

- Al empezar la sesión: leer este archivo y **Estado actual**.
- Una tarea cada vez; sus tests a la vez, nunca "luego".
- Un commit por tarea, mensaje en español e imperativo
  ("Añade barra de progreso por módulo").
- Al tocar la interfaz: arrancar el servidor y comprobar la página, no solo
  los tests. Si hay herramienta de navegador disponible, hacer captura.
- Al terminar una fase: tests + ruff + mypy, mostrar resultado, actualizar
  **Estado actual** y **parar**.
- Si algo del plan no tiene sentido al implementarlo, decirlo y proponer el
  cambio antes de desviarse.
- No inventar endpoints ni formatos de las APIs externas: si hay duda, pedir
  al usuario que guarde una respuesta real como fixture.
- Para analizar un escaneo, leer primero el informe **resumen**
  (`reconmap report <dominio|id> --level summary`); si hace falta más, el
  **comprimido** (`--level compact`). Del **extendido** consultar solo partes
  concretas, nunca el archivo entero (el dominio de prueba: ~1,3 MB).

---

## 8. Fuera de alcance

- Escaneo activo de dominios ajenos sin autorización (el modo Activo exige
  marcar la casilla de autorización en cada escaneo; la lista blanca opcional lo
  restringe más).
- Fuerza bruta de subdominios o directorios.
- Cualquier dato de personas (OSINT de personas, redes sociales, doxing).
- "Análisis automático de vectores de ataque" o puntuaciones inventadas.
- Frameworks de frontend (React, Vue…) o pasos de build de JavaScript.
- Exponer la aplicación a Internet abierto.

---

## 9. Estado actual

- Fase actual: **3 — Grafo y comparación** (grafo implementado; comparación
  real con amass/SpiderFoot pendiente). Fases 2, 2b y 2c pendientes de
  revisión manual.
- Fase 1 cerrada y etiquetada `v0.1.0`.
- Última tarea completada: Fase 2 completa. 86 tests sin red, ruff y mypy en
  verde. Tests `-m network`: 6/8 (fallaron crt.sh por error de red puntual y
  Wayback por caída del Internet Archive, 503 "Temporarily Offline").
- Pendiente:
  - Revisión manual de la Fase 2.
  - Fixture real del Wayback (el Archive estaba caído); los tests usan el
    formato CDX documentado.
- En curso (2026-11-19, aprobado por el usuario): propuesta
  `docs/propuesta-waf-y-lectura-eficiente.md`.
  - Paso 1 hecho: informe JSON en tres niveles (`?level=extended|compact|summary`,
    botones en la pestaña JSON, `reconmap report`).
  - Paso 2 hecho: `edge_assessment.py` (puro). Solo dos estados: "Posible WAF ·
    <proveedor>" o "No se ha podido comprobar si existe WAF", más el proveedor
    de la IP (ASN → tablas; si no, organización). Señales: ASN, etiqueta `cdn`
    (AWS + `cdn` = CloudFront), CNAME, cabecera `server` y nombres de cookie
    (modo Ligero). El NS de Cloudflare solo se anota, no decide. Las IPs
    privadas se marcan aparte y nunca cuentan como "fuera del proxy".
    "Posible origen fuera del proxy" es INFO (no WARN): el dominio de prueba tiene 39
    hosts así y como aviso sería ruido. Columna WAF en Subdominios, Proveedor
    en IPs, tarjeta y panel en Resumen, bloque `waf` en los informes.
  - Paso 3 hecho: `modules/edge_ranges.py` (`passive`) con las listas oficiales
    de Cloudflare (texto), Fastly (JSON) y AWS (solo servicio `CLOUDFRONT`, no
    `CLOUDFRONT_ORIGIN_FACING`). Se descargan una vez (caché 24 h) y se guardan
    procesadas en memoria; una lista caída no detiene a las demás (se reintenta
    a los 10 min). Marca la IP con `edge_range: {provider, prefix}`, que tiene
    prioridad sobre el ASN. Fixtures reales en `tests/fixtures/` (la de AWS,
    recortada). En el dominio de prueba no cambia el resultado (las IPs de CloudFront ya
    se detectaban por la etiqueta `cdn`), pero cubre IPv6, donde InternetDB no
    llega. Las señales se agrupan por IP ("5 IPs (…): …").
  - Paso 4 hecho: `headers` guarda la presencia (nunca el valor) de cabeceras
    de proveedor (`cf-ray`, `x-iinfo`, `x-amz-cf-id`…; tabla `EDGE_HEADERS`).
  - Censys aplazado por el usuario.
- Tecnologías y CVEs (2026-11-19, pedido por el usuario). Decisión del usuario:
  **sin leer el HTML** (regla 1 sin cambios). `technologies.py` (puro) saca
  tecnologías de los CPE de InternetDB (pasivo) y, en modo Ligero, de las
  cabeceras `server`, `x-powered-by`, `x-aspnet-version`, `x-aspnetmvc-version`,
  `x-generator`, `x-redirect-by` y nombres de cookie. Productos desconocidos se
  ignoran. Entidades `technology` (valor `vendor:product:versión`) y `cve`;
  relaciones `uses_technology` (host/IP → tecnología) y `has_vulnerability`
  (tecnología/IP → CVE). InternetDB: sus `vulns` también son entidades `cve`.
  - `modules/nvd.py` (`passive`): NVD API 2.0 con `cpeName` (incluye rangos de
    versión). **Solo con versión exacta.** nginx está en NVD como `f5:nginx`
    (`nginx:nginx` devuelve 0). Sin clave 5 consultas/30 s (`NVD_API_KEY`
    opcional, 50/30 s); tope `RECONMAP_MAX_CVE_LOOKUPS` (20). Cada respuesta
    puede pesar 650 KB y tardar 25 s: `Context.get_json(reduce=…)` guarda en
    caché solo lo que se usa. Descarta CVEs `Rejected`. Un módulo puede
    declarar `timeout` propio (NVD: 900 s).
  - El motor reencola `technology` a la misma profundidad (no es un salto).
  - Lenguaje: "reportada para la versión detectada, no confirmada" (backports
    de las distribuciones). KEV de CISA → `fail`; CVSS ≥ 7 → `warn`.
  - Pestaña **Tecnologías**, nodos en el grafo (CVEs agrupables si hay más de
    300 nodos), problemas que suben a la IP y al host, bloques `technologies` y
    `cves` en los informes. Aviso de NVD ("not endorsed or certified").
- Proyectos (2026-11-19, pedido por el usuario): cada proyecto tiene un
  formulario "Volver a escanear" (botón Actualizar) que reutiliza `POST /scans`.
  Mantiene la profundidad del último escaneo, pero el modo **siempre vuelve a
  Pasivo**: el Ligero se elige en cada escaneo (regla 1), nunca se hereda.
- Ideas aprobadas por el usuario (2026-11-19), hechas:
  - **Cambios** (`report/diff.py`): compara con el escaneo terminado anterior del
    mismo dominio (selector para elegir otro). Problemas por host, hosts que
    resuelven, subdominios, IPs, puertos, tecnologías, CVEs, certificados,
    proveedores, posible WAF y riesgo de correo. Avisa si cambian modo,
    profundidad, fuentes con error o fuentes nuevas. Pestaña Cambios, panel en
    Resumen y `changes_since_previous` en los informes. `list_scans` desempata
    por `rowid` (el reloj de Windows repite instantes) y no trae el progreso:
    `diff_scans` recarga los escaneos con `get_scan`.
  - **Entornos no productivos y herramientas internas** (`environment_kind` en
    `insights.py`): palabras completas del nombre (`staging`, `dev`,
    `desarrollo`, `grafana`…). `warn` si resuelve a IP pública (aunque pase por
    WAF); `info` si solo tiene IPs privadas. Etiqueta en Subdominios.
  - **Proveedores externos** (`third_parties.py`, puro, sin red): TXT de
    verificación (los tokens nunca se muestran), `include:` del SPF, MX, NS y
    CNAME. Lo desconocido se lista ("sin identificar"), no se adivina. Los TXT
    partidos se concatenan sin tocar espacios (RFC 7208). Panel en Resumen y
    `third_parties` en los informes.
- Pestaña **Versiones** (2026-11-19, pedida por el usuario): tecnologías
  agrupadas por producto, cada versión con dónde corre (IP · hosts que apuntan
  a ella), fuente (InternetDB o cabeceras) y CVEs; marca productos con varias
  versiones a la vez y lista aparte los detectados sin versión.
- **Modo Activo** (aprobado el 2026-11-19; Docker elegido por el usuario).
  Lista blanca: en `.env` (no se versiona).
  - Paso 1 hecho: `allow_active` en `Scan` (migración), `RECONMAP_ACTIVE_ALLOWLIST`
    + `in_allowlist`, motor (acepta módulos activos solo con lista blanca; los
    salta si el escaneo no es Activo o el dominio no está), opción «Activo» en
    la portada y en Proyectos solo para dominios de la lista, 422 fuera de ella.
  - Pasos 2-4 hechos: `modules/active_tools.py` (tlsx v1.5.0, httpx v1.12.0,
    gowitness 3.2.2) con `modules/docker_tools.py`: imágenes oficiales fijadas
    por digest, `docker run --rm -i --pull never`, sin shell, hosts por stdin
    (UTF-8 sin BOM) tras `safe_hosts` (normalizados, en ámbito y en lista
    blanca). Fixtures reales en `tests/fixtures/` (gowitness anonimizada).
  - Se ejecutan **por lotes al final** (`batch = True`, `run_batch`): una vez,
    con los hosts que resuelven; lo que descubren vuelve a la cola (DNS, NVD).
    Los módulos activos solo se cargan si hay lista blanca.
  - tlsx: no admite `-san`/`-cn` junto a otras opciones; con `-json` ya trae
    SAN/CN, y `-ex -ss -mm -un` añaden los indicadores solo cuando son ciertos.
    Atributo `tls_live`; certificado real como entidad; SAN en ámbito →
    subdominio nuevo, fuera de ámbito → solo texto.
  - httpx: `-td` (Wappalyzer) → `technology` (tabla `WAPPALYZER_PRODUCTS`; lo no
    mapeado se muestra sin CVEs). Agente de usuario de reconmap, sin seguir
    redirecciones ni pedir favicon. Atributo `http_probe`.
  - gowitness: su JSON incluye cabeceras y **valores de cookies** aunque se pida
    no guardar red: solo se leen URL/estado/título/archivo y la carpeta `raw/`
    se borra siempre. Capturas en `data/capturas/<scan>/<host>.jpeg` (en
    `.gitignore`), servidas por `/scans/{id}/capturas/{nombre}` con nombre y
    carpeta validados.
  - Pestaña **Activo**: comandos exactos, capturas, web/TLS/tecnologías por
    host. Certificado real autofirmado/no coincide → `warn`; caducado → `fail`.
  - Nunca usar `-pd`/`-dashboard` (subirían resultados a la nube de
    ProjectDiscovery).
- **Despliegue en Docker** (2026-11-19, pedido por el usuario; adelanta parte de
  la Fase 5): `Dockerfile` multi-stage sobre la imagen oficial de gowitness
  (Debian 13 + Chrome), con tlsx y httpx copiados de las suyas (todas por
  digest), Python 3.12 y dependencias de `uv.lock` con uv 0.13.6. Usuario
  10001, `cap_drop: ALL`, `no-new-privileges`, puerto solo en 127.0.0.1
  (`compose.yaml`), datos en el volumen `reconmap-data`. Dentro del contenedor
  `RECONMAP_TOOLS_RUNNER=local`: los binarios se ejecutan directamente, sin
  docker.sock. httpx de ProjectDiscovery va como `httpx-toolkit` porque `httpx`
  es el CLI del paquete de Python. `RECONMAP_HOST` (0.0.0.0 solo en el
  contenedor). Probado: las tres herramientas funcionan sin privilegios.
  Pendiente de la Fase 5: k3s, Tailscale y autenticación.
- Notas:
  - `normalize_domain` devuelve `Domain(name, wildcard)` (NamedTuple).
  - IDNA con el códec estándar de Python (IDNA 2003), sin dependencia extra.
  - Reglas 1–3 ampliadas (niveles de contacto, buckets, candidatos) y nueva
    Fase 2b, aprobadas por el usuario. Detalle en `docs/propuesta-fuentes.md`.
  - crt.sh devuelve también emails y textos que no son dominios en
    `name_value`: los emails solo se cuentan (`emails_in_certificates`) y el
    resto se descarta al normalizar.
  - Test XSS de la tabla: el parser descarta `<img …>` por no ser un dominio,
    así que el test inyecta la entidad directamente en el store y comprueba el
    escape en la plantilla (defensa en profundidad).
  - `get_json` reintenta una vez ante 5xx/timeout (crt.sh falla a menudo).
  - Caché persistente en SQLite (tabla `cache`), compartida entre web y CLI.
  - Al arrancar, los escaneos que quedaron `running` se marcan `failed`.
  - El selector de profundidad está fijo en 1 hasta la Fase 2.
  - Pedido por el usuario (2026-11-18): una pasada dedicada a mejorar la
    interfaz más adelante (sin fecha; no empezar sin que lo pida).
  - Idea del usuario para `headers` (Fase 2b): una petición al dominio y
    marcar cabeceras ausentes o inseguras según OWASP Secure Headers.
  - Aviso pendiente: Starlette sugiere `httpx2` para TestClient (no está en el
    stack; no se ha añadido).
  - Fase 2: la profundidad cuenta saltos entre nombres; las IPs se procesan a
    la profundidad del host que las resolvió. Tope `RECONMAP_MAX_HOSTS` (300).
  - NXDOMAIN en un subdominio se guarda como `nxdomain: true`, no como error
    (crt.sh trae muchos nombres antiguos); en el dominio raíz sí es error.
  - Las claves de API van en `secret_params`/`secret_headers`: nunca en la
    clave de caché ni en mensajes de error. Los errores inesperados se
    registran sin traceback por el mismo motivo.
  - `.env` se lee con un parser propio (sin dependencia nueva) solo en
    `reconmap-web` y en el CLI; los tests nunca cargan claves reales.
  - InternetDB y Shodan omiten IPv6.
  - Shodan con clave gratuita: algunas IPs devuelven 403 "Requires membership
    or higher to access" (restricción del plan, no fallo). Se muestra como
    "Acceso denegado… el plan no permite esta consulta". InternetDB cubre los
    mismos puertos sin clave. Ritmo de Shodan: 1 petición cada 2 s.
  - Fase 2c: el riesgo de suplantación (ALTO/MEDIO/BAJO) solo mira DMARC y
    `+all`; el resto de controles (DKIM, MTA-STS, DNSSEC…) se muestran como
    semáforo pero no cambian el nivel. Criterios visibles en la interfaz.
  - Las direcciones `mailto:` de DMARC/TLS-RPT se guardan como `***@dominio`
    (regla 2). Tamaño de claves DKIM verificado contra `openssl` con claves reales.
  - El aviso de tope de hosts ya no muestra un número: el tope puede cambiar
    entre escaneos y el valor guardado no se conserva.
  - DNS: `RECONMAP_DNS_SERVERS` (en `.env`) elige los resolvedores; vacío = los
    del sistema. Cada consulta se reintenta una vez ante timeout. En la red del
    usuario dos de sus tres resolvedores no responden (≈4 s por consulta).
  - Correo: un registro que no responde a tiempo se marca "no comprobado"
    (nunca "no existe"); si es SPF o DMARC, el riesgo queda "desconocido". Las
    consultas incompletas no se guardan en caché.
  - Portada (2026-11-18, pedida por el usuario): introducción con modos de
    contacto, profundidad, secciones con capturas reales (de un escaneo pasivo
    de proton.me, en `web/static/img/`) y fuentes listadas dinámicamente
    (nuevo atributo `description` en el contrato de módulo). La casilla de
    autorización pasa a ser un selector Pasivo | Ligero.
  - Grafo (2026-11-18, pedido por el usuario): disposición `cose` más
    espaciada + botón Redistribuir; reproducción de la construcción en el
    orden real del escaneo (`first_seen`, desempate por tipo) con barra,
    Reproducir/Pausa y enlace `#paso=N`; panel por nodo vía
    `GET /api/scans/{id}/node?id=…` (`insights.py`): posibles problemas
    (servicios de administración y bases de datos expuestos, CVEs, CDN,
    certificados caducados o a punto de caducar, rutas sensibles del Wayback,
    riesgo de correo, cabeceras, caducidad del dominio), información y
    relacionados navegables; borde rojo/ámbar según el peor problema; enlace
    `#nodo=<id>`. `insights.py` es la base de las reglas de la Fase 4.
  - Interfaz (2026-11-18): tema claro, formulario solo en Inicio (tarjeta
    "Nuevo escaneo" + proyectos recientes), página Proyectos agrupada por
    dominio y plegada, y el detalle por fuente de un escaneo terminado plegado
    en una línea. Capturas de la portada regeneradas con el tema claro.
