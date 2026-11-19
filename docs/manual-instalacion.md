# Manual de instalación y despliegue de reconmap

Guía paso a paso, comando a comando. Hay dos formas de usar reconmap:

| | **A. Docker** (recomendada) | **B. Instalación local** (desarrollo) |
|---|---|---|
| Qué necesitas | Docker Desktop (Windows/macOS) o Docker Engine (Linux) | Python 3.12 y `uv` |
| Herramientas del modo Activo | Incluidas en la imagen | Se lanzan con Docker (hay que descargar sus imágenes) |
| Para qué | Usarlo | Programar, ejecutar los tests |

Las dos leen la configuración del mismo archivo `.env` y abren la interfaz en
**http://127.0.0.1:8000**, accesible solo desde tu equipo.

> **Aviso legal.** El modo Pasivo solo consulta fuentes públicas de terceros. Los modos
> Ligero y Activo contactan con el objetivo: úsalos **solo con dominios propios o con
> autorización por escrito**. Escanear sistemas ajenos sin permiso puede ser delito
> (art. 197 bis del Código Penal).

---

## 0. Requisitos comunes

### 0.1 Git

Comprueba si lo tienes:

```bash
git --version
```

Si no aparece una versión, instálalo:

- **Windows:** <https://git-scm.com/download/win> (instala también *Git Bash*).
- **macOS:** `xcode-select --install`
- **Debian/Ubuntu:** `sudo apt update && sudo apt install -y git`

### 0.2 Descargar el proyecto

```bash
git clone https://github.com/pabloramirez-code/OSINT.git
cd OSINT
```

Todos los comandos siguientes se ejecutan **dentro de esta carpeta**.

### 0.3 Crear el archivo de configuración `.env`

Parte de la plantilla, que tiene todas las claves vacías:

```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# Linux, macOS o Git Bash
cp .env.example .env
```

Abre `.env` con cualquier editor. Todo es opcional: con el archivo vacío reconmap
funciona en modo Pasivo.

| Variable | Para qué sirve | Ejemplo |
|---|---|---|
| `NVD_API_KEY` | Acelera la búsqueda de CVEs (de 5 a 50 consultas cada 30 s). Gratis en <https://nvd.nist.gov/developers/request-an-api-key> | `NVD_API_KEY=abcd-1234-…` |
| `CERTSPOTTER_API_KEY` | Más consultas a Cert Spotter | |
| `HACKERTARGET_API_KEY` | Más consultas a HackerTarget | |
| `RECONMAP_ACTIVE_ALLOWLIST` | Opcional. Limita el modo **Activo** a estos dominios (y sus subdominios). Vacío = cualquier dominio, siempre marcando «Tengo autorización» en cada escaneo | `RECONMAP_ACTIVE_ALLOWLIST=midominio.com` |
| `RECONMAP_DNS_SERVERS` | Resolvedores DNS a usar (vacío = los del sistema) | `RECONMAP_DNS_SERVERS=9.9.9.9,1.1.1.1` |

Otros ajustes avanzados (rara vez hacen falta):

| Variable | Por defecto | Qué controla |
|---|---|---|
| `RECONMAP_MAX_HOSTS` | `300` | Subdominios analizados por escaneo |
| `RECONMAP_MAX_LIGHT_HOSTS` | `50` | Hosts contactados en modo Ligero |
| `RECONMAP_WAYBACK_LIMIT` | `1000` | URLs que se piden al Wayback Machine |
| `RECONMAP_MAX_CVE_LOOKUPS` | `20` | Tecnologías consultadas en NVD por escaneo |

> `.env` contiene tus claves: **nunca lo subas a git** (ya está en `.gitignore`).

---

## A. Despliegue con Docker (recomendado)

### A.1 Instalar Docker

- **Windows / macOS:** instala **Docker Desktop** desde
  <https://www.docker.com/products/docker-desktop/> y **ábrelo**. Espera a que el icono
  indique que el motor está en marcha.
- **Debian/Ubuntu:**

  ```bash
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"   # cierra la sesión y vuelve a entrar después
  ```

Comprueba que el motor responde (debe mostrar una versión, no un error):

```bash
docker info --format '{{.ServerVersion}}'
docker compose version
```

### A.2 Construir y arrancar

```bash
docker compose up -d --build
```

La primera vez tarda unos minutos: descarga las imágenes base fijadas por versión
(gowitness con Chrome, tlsx, httpx, uv) y construye la de reconmap (~1 GB).

### A.3 Comprobar que funciona

```bash
docker compose ps
```

Debe aparecer `Up … (healthy)` y `127.0.0.1:8000->8000/tcp`. También:

```bash
curl http://127.0.0.1:8000/health
```

Respuesta esperada: `{"status":"ok"}`.

Abre **http://127.0.0.1:8000** en el navegador.

### A.4 Primer escaneo

1. En la portada, escribe un dominio (por ejemplo, uno tuyo).
2. Elige el modo:
   - **Pasivo**: solo fuentes públicas. Siempre disponible.
   - **Ligero**: una visita a la portada de cada host. Solo con autorización.
   - **Activo**: httpx, tlsx y gowitness. Al elegirlo aparece la casilla
     «Tengo autorización por escrito…»: hay que marcarla o el escaneo no se lanza.
     Si `RECONMAP_ACTIVE_ALLOWLIST` tiene dominios, solo vale para ellos.
3. Elige la profundidad (1 es suficiente para empezar) y pulsa **Escanear**.

Desde la terminal también se puede (modo Pasivo):

```bash
docker compose exec reconmap reconmap scan ejemplo.com
docker compose exec reconmap reconmap report ejemplo.com -o /tmp/resumen.json --level summary
docker compose cp reconmap:/tmp/resumen.json ./resumen.json
```

### A.5 Uso diario

| Acción | Comando |
|---|---|
| Ver los registros en directo | `docker compose logs -f` |
| Parar (los datos se conservan) | `docker compose stop` |
| Volver a arrancar | `docker compose start` |
| Parar y quitar el contenedor (los datos se conservan) | `docker compose down` |
| Reiniciar tras cambiar `.env` | `docker compose up -d` |

### A.6 Actualizar a una versión nueva

```bash
git pull
docker compose up -d --build
```

### A.7 Copias de seguridad y datos

Los escaneos y las capturas viven en el volumen de Docker `<carpeta>_reconmap-data`
(si la carpeta se llama `OSINT`, el volumen es `osint_reconmap-data`), montado en `/data`.

```bash
# Copia de la base de datos al equipo
docker compose cp reconmap:/data/reconmap.db ./copia-reconmap.db

# Restaurar una copia (o traer escaneos hechos con la instalación local)
docker compose cp ./copia-reconmap.db reconmap:/data/reconmap.db
docker compose restart
```

> **Borrar todos los datos** (irreversible): `docker compose down -v` elimina también el
> volumen con todos los escaneos y capturas.

### A.8 Qué hace la imagen por seguridad

- Escucha solo en `127.0.0.1` del equipo: nadie de tu red puede entrar.
- Usuario sin privilegios (`uid 10001`), `cap_drop: ALL` y `no-new-privileges`.
- Las herramientas del modo Activo van **dentro** de la imagen: el contenedor no tiene
  acceso al Docker del equipo.
- `.env` se lee al arrancar; no se copia dentro de la imagen.

---

## B. Instalación local (desarrollo)

### B.1 Instalar `uv`

`uv` gestiona Python y las dependencias exactas del proyecto (`uv.lock`).

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Cierra y vuelve a abrir la terminal, y comprueba:

```bash
uv --version
```

### B.2 Instalar Python 3.12 y las dependencias

```bash
uv python install 3.12
uv sync
```

`uv sync` crea el entorno `.venv` con las versiones exactas de `uv.lock` (incluidas las
de desarrollo: pytest, ruff y mypy).

### B.3 Arrancar la interfaz

```bash
uv run reconmap-web
```

Abre **http://127.0.0.1:8000**. Para pararla: `Ctrl+C`.

> **Sin `uv` en el PATH** (Windows, PowerShell), el entorno ya creado funciona igual:
>
> ```powershell
> .\.venv\Scripts\python.exe -m reconmap.web.app
> .\.venv\Scripts\python.exe -m reconmap.cli scan ejemplo.com
> ```

### B.4 Usar el CLI

```bash
uv run reconmap scan ejemplo.com                                   # escanear (Pasivo)
uv run reconmap scan ejemplo.com --depth 2 --json informe.json     # con informe
uv run reconmap report ejemplo.com -o resumen.json --level summary # informe de un escaneo hecho
uv run reconmap compare informe.json amass.txt --tool amass        # comparar con otra herramienta
```

Niveles del informe: `summary` (lo esencial), `compact` (una fila por host) y
`extended` (todo).

### B.5 Modo Activo en la instalación local

Fuera del contenedor, reconmap lanza las herramientas con Docker, así que necesitas
Docker en marcha (paso A.1) y sus imágenes descargadas. Las versiones están fijadas en
`src/reconmap/modules/docker_tools.py`:

```bash
docker pull projectdiscovery/tlsx@sha256:6ee6a07c5a633149d5e0482c6df654c9975be97bb7733ec91faaa72a7940295b
docker pull projectdiscovery/httpx@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc
docker pull ghcr.io/sensepost/gowitness@sha256:39bbbcd07b37c523de3f1447cb8046cb586e91ed3b0c80436922a403ffeddc1c
```

Después elige el modo **Activo** y marca «Tengo autorización». Las capturas se guardan
en `data/capturas/` (ignorada por git).

### B.6 Ejecutar los tests y las comprobaciones de calidad

```bash
uv run pytest            # tests sin red
uv run pytest -m network # contra servicios reales (hace peticiones de verdad)
uv run ruff check .
uv run mypy src
```

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---|---|---|
| `failed to connect to the docker API … dockerDesktopLinuxEngine` | Docker Desktop no está arrancado | Ábrelo y espera a que el motor esté en marcha; repite el comando |
| `Bind for 127.0.0.1:8000 failed: port is already allocated` | Otra cosa usa el puerto 8000 (por ejemplo, `reconmap-web` local) | Para la otra instancia, o cambia en `compose.yaml` `"127.0.0.1:8000:8000"` por `"127.0.0.1:8080:8000"` y abre el puerto 8080 |
| «Para el modo Activo marca la casilla…» | No se marcó «Tengo autorización» | Márcala (aparece al elegir Activo) |
| «Ese dominio no está en la lista blanca del modo Activo» | `RECONMAP_ACTIVE_ALLOWLIST` tiene otros dominios | Añade el dominio o deja la variable vacía y reinicia |
| En el modo Activo: «Falta la imagen de Docker: docker pull …» (solo instalación local) | Imagen de la herramienta no descargada | Ejecuta el `docker pull` que indica el mensaje (paso B.5) |
| En el modo Activo: «Docker no está arrancado» (solo instalación local) | Docker Desktop cerrado | Ábrelo |
| El escaneo tarda varios minutos | NVD sin clave (5 consultas cada 30 s) y, en modo Activo, las capturas | Pon `NVD_API_KEY` en `.env` |
| `uv: command not found` / `uv no se reconoce` | La terminal no ve `uv` todavía | Cierra y abre la terminal, o usa `.\.venv\Scripts\python.exe -m …` (paso B.3) |
| Errores de DNS o escaneos muy lentos en la red de casa | Resolvedores del sistema que no responden | Define `RECONMAP_DNS_SERVERS=9.9.9.9,1.1.1.1` en `.env` |
| `docker compose ps` no muestra `healthy` | La aplicación no arranca | Mira `docker compose logs` |
