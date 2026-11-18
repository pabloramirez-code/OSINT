# Propuesta: nuevas fuentes y cambio de reglas

Estado: **pendiente de aprobación**. Nada de esto está implementado.

## 1. Qué pasa con cada fuente pedida

| Fuente | Estado real (nov. 2026) | ¿Cumple las reglas actuales? | Propuesta |
|---|---|---|---|
| Shodan InternetDB | Gratis, sin clave, consulta por IP | Sí | Fase 2, como ya estaba previsto |
| Shodan API completa | Requiere clave; la búsqueda por `hostname:` gasta créditos y puede requerir plan de pago. Las consultas por IP no gastan créditos | Sí | Módulo opcional `shodan` (solo consulta por IP), activo si hay `SHODAN_API_KEY` |
| securityheaders.com | Su API fue retirada en abril de 2026 (según fuentes no oficiales); la web sigue | No: analiza la web del objetivo | Sustituir por un módulo propio `headers` que hace **una** petición GET a la portada. Necesita el nivel "ligero" (ver 2) |
| GrayHatWarfare | Requiere clave; cuota gratuita limitada y sin documentar | No: la búsqueda por palabra clave no se puede atribuir al objetivo y los listados de archivos pueden contener datos personales | Módulo `buckets` muy acotado (ver 3) |

Otras fuentes pasivas que encajan sin cambiar ninguna regla: CertSpotter
(capa gratuita), HackerTarget (consultas gratuitas limitadas), AlienVault OTX
(clave recomendada) y urlscan.io (límites sin documentar). Antes de usarlas hay
que comprobar sus condiciones en la documentación oficial y guardar una
respuesta real como fixture.

## 2. Cambio propuesto en la regla 1 (pasivo por defecto)

Texto actual: ningún módulo envía tráfico al objetivo salvo `active = True` y
autorización; hasta la Fase 5 no existe ningún módulo activo.

Texto propuesto:

> **Tres niveles de contacto.** Cada módulo declara
> `contact ∈ {passive, light, active}`.
> - `passive`: solo consulta fuentes de terceros. Siempre permitido.
> - `light`: peticiones equivalentes a una visita normal con navegador
>   (GET/HEAD a la portada HTTPS del dominio y de sus subdominios en ámbito,
>   como máximo 1 por host y escaneo, sin seguir enlaces). **Desactivado por
>   defecto.** Se activa en cada escaneo con una casilla de confirmación
>   ("Tengo autorización o es un dominio mío") que queda guardada en el `Scan`.
> - `active`: cualquier otra cosa (puertos, rutas, fuzzing). Sigue prohibido
>   hasta la Fase 5.

Consecuencia: el contrato de módulo cambia `active: bool` por
`contact: Contact`, y el motor comprueba que el nivel esté permitido en ese
escaneo.

## 3. Cambio propuesto en las reglas 2 y 3 (personas y ámbito)

Añadir a la regla 2:

> De los índices de filtraciones o buckets **nunca** se guardan nombres ni
> contenidos de archivos; solo el nombre del bucket, el proveedor y el número
> de archivos.

Añadir a la regla 3:

> Los resultados obtenidos por **búsqueda por palabra clave** (no por dominio
> exacto) se guardan como entidad `candidate`, se muestran como "no atribuido,
> verificar a mano" y **nunca** se reencolan ni generan hallazgos de severidad
> mayor que `info`.

Con eso, el módulo `buckets` (GrayHatWarfare):
- usa solo el endpoint de buckets, no el de archivos;
- busca la etiqueta principal del dominio (`ejemplo` para `ejemplo.com`);
- requiere `GRAYHAT_API_KEY` (se añadiría a `.env.example`).

## 4. Encaje en las fases

- Fase 1: sin cambios (crt.sh, DNS, RDAP).
- Fase 2: InternetDB, Wayback, BGP + `shodan` (con clave) + CertSpotter,
  HackerTarget.
- Fase 2b (nueva): nivel `light` + módulo `headers`; `buckets` con entidades
  `candidate`.
- Fase 4: reglas sobre cabeceras (HSTS, CSP, X-Frame-Options…) usando los
  datos de `headers`.
