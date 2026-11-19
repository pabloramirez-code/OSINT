# Propuesta: modo Activo con httpx, tlsx y gowitness

Estado: **aprobada por el usuario el 2026-11-19** (regla 1 y sección 8; Docker).
Paso 1 (lista blanca, confirmación y modo Activo) implementado.
Fecha: 2026-11-19.

Cambia dos reglas de `CLAUDE.md` (regla 1 y sección 8), así que necesita la
aprobación expresa del usuario antes de escribir código.

---

## 1. Qué se quiere conseguir

Una pestaña **Activo** que lance herramientas externas contra el objetivo para
obtener lo que las fuentes pasivas no pueden dar:

| Herramienta | Qué aporta que hoy no tenemos |
|---|---|
| **httpx** (ProjectDiscovery) | Qué hosts sirven web de verdad hoy, código de estado, título, servidor, CDN y **tecnologías con versión leídas del HTML** (huellas de Wappalyzer, opción `-td`). Más versiones → más CVEs en la pestaña Tecnologías |
| **tlsx** (ProjectDiscovery) | Certificado que sirve **hoy** cada host (no el histórico de crt.sh), nombres alternativos (SAN) → subdominios nuevos, versión de TLS, caducado, autofirmado, nombre que no coincide |
| **gowitness** (SensePost) | **Captura de pantalla** de cada web: inventario visual de la superficie en una rejilla |

Las tres son de bajo impacto: una o dos conexiones por host, sin cargas de ataque,
sin fuerza bruta de rutas y sin seguir enlaces.

## 2. Cambio de reglas propuesto

**Regla 1, nivel `active`** (texto propuesto):

> `active`: herramientas externas (httpx, tlsx, gowitness) que contactan con el
> objetivo más allá de una visita a la portada. **Solo** contra dominios de la
> lista blanca `RECONMAP_ACTIVE_ALLOWLIST` (en `.env`) y sus subdominios, y solo
> si en esa ejecución se marca "Tengo autorización por escrito o es un dominio
> mío", que queda guardado. Sin lista blanca, el modo no aparece en la interfaz.
> Quedan prohibidos los escáneres de vulnerabilidades, la fuerza bruta y el
> fuzzing.

**Sección 8**: "Escaneo activo de dominios ajenos" se mantiene fuera de alcance;
la lista blanca es lo que lo garantiza.

Motivo legal: escanear activamente sistemas de terceros sin autorización puede
constituir delito (art. 197 bis del Código Penal). La lista blanca y la
confirmación guardada demuestran que la herramienta lo impide por diseño.

## 3. Cómo se ejecutan

- `asyncio.create_subprocess_exec` con **lista de argumentos, nunca una shell**:
  un nombre de host no puede inyectar comandos. Los hosts van por un archivo
  temporal (`-l`), uno por línea, ya normalizados y comprobados en ámbito.
- Cada herramienta tiene ruta configurable (`RECONMAP_HTTPX`, `RECONMAP_TLSX`,
  `RECONMAP_GOWITNESS`). En Kali el httpx de ProjectDiscovery se llama
  `httpx-toolkit`, porque choca con el `httpx` de Python que usa este proyecto.
- Tiempo máximo por herramienta, límite de peticiones por segundo (`-rl`) y
  concurrencia baja. Solo hosts que ya resolvieron en el escaneo (como `headers`).
- Se usa la salida **JSON** de cada herramienta y se convierte en las entidades
  de siempre, así que aparece en el grafo, en Cambios y en los informes:
  - httpx → atributo `http_probe` del host + entidades `technology` (con lo que
    las CVEs se buscan solas en NVD).
  - tlsx → atributo `tls` del host; los SAN en ámbito pasan a ser subdominios
    (los de fuera de ámbito se guardan como texto, nunca se reencolan: regla 3).
  - gowitness → captura PNG guardada en `data/capturas/<scan>/` y servida por
    reconmap. Nunca se incrusta HTML del objetivo, solo la imagen.
- La pestaña muestra, por herramienta, el **comando exacto** ejecutado, cuándo,
  cuánto tardó y cuántos resultados dio. Errores de la herramienta (stderr
  recortado) en ámbar, como cualquier módulo.
- Ajustes muestra si cada herramienta está instalada (✓/✗) y su versión.
- Botón "Lanzar comprobaciones activas" sobre un escaneo ya terminado, sin
  repetir las fuentes pasivas.

## 4. Instalación (no son dependencias de Python)

En este equipo no están instaladas (comprobado el 2026-11-19); sí hay Docker y
WSL. Dos opciones:

| Opción | Ventaja | Inconveniente |
|---|---|---|
| **Binarios** de las releases de GitHub (Go, funcionan en Windows) | Simple y rápido | Hay que actualizarlos a mano |
| **Docker** con las imágenes oficiales (`projectdiscovery/httpx`, `projectdiscovery/tlsx`, `ghcr.io/sensepost/gowitness`) | Nada que instalar; encaja con la Fase 5 (k3s) | Arranque más lento; hay que montar el archivo de hosts y la carpeta de capturas |

Recomendación: binarios en desarrollo e imagen Docker propia en la Fase 5.

## 5. Formatos: comprobar antes de programar

Siguiendo la regla de no inventar formatos, antes de escribir cada módulo se
ejecuta la herramienta contra un dominio de la lista blanca y se guarda la
salida real como fixture. En particular:
- httpx: nombres de los campos JSON (`tech`, `title`, `webserver`, `cdn_name`…)
  y formato de `tech` (nombre:versión).
- tlsx: campos de SAN, caducidad, autofirmado y versión TLS.
- gowitness: la v3 cambió la línea de comandos (`gowitness scan file …`,
  `--write-jsonl`); hay que fijar una versión concreta.

## 6. Tests

- Sin lista blanca o sin confirmación no se lanza ningún proceso (se comprueba
  que no se llama a `create_subprocess_exec`).
- Un host fuera de la lista blanca nunca llega al archivo de entrada.
- Un nombre con caracteres de shell (`;`, `$()`, espacios) se rechaza antes.
- Herramienta no instalada → error de módulo claro, no excepción.
- Parseo de las fixtures reales; SAN fuera de ámbito no se reencola.
- Las capturas se sirven como imagen con el tipo correcto y nombre controlado
  por reconmap (nunca uno que venga de la herramienta).

## 7. Orden

1. Lista blanca, confirmación, modo Activo en el modelo y en la interfaz, sin
   herramientas todavía.
2. tlsx (lo más sencillo y menos intrusivo).
3. httpx con `-td` → tecnologías con versión → CVEs.
4. gowitness y rejilla de capturas.

## 8. Decisiones pendientes del usuario

- [ ] ¿Apruebas el texto de la regla 1 y la sección 8 de arriba?
- [ ] ¿Qué dominio tuyo va en `RECONMAP_ACTIVE_ALLOWLIST` para probar?
- [ ] ¿Binarios o Docker?
