# OSINT
An automated Open-Source Intelligence (OSINT) system

## Desplegar con Docker

```bash
docker compose up -d --build      # http://127.0.0.1:8000
docker compose logs -f            # ver qué hace
docker compose down               # parar (los datos se conservan en el volumen)
```

- Escucha solo en `127.0.0.1` del equipo: no es accesible desde la red.
- Claves de API y lista blanca del modo Activo se leen de `.env` (no se copian a la imagen).
- Base de datos y capturas en el volumen `reconmap-data` (`/data` dentro del contenedor).
- Las herramientas del modo Activo (tlsx, httpx, gowitness) van dentro de la imagen, copiadas
  de sus imágenes oficiales fijadas por versión. El contenedor no necesita acceso a Docker.
- Usuario sin privilegios, sin capacidades del kernel (`cap_drop: ALL`) y `no-new-privileges`.

Para llevar al contenedor los escaneos hechos fuera de él:

```bash
docker compose cp reconmap.db reconmap:/data/reconmap.db
docker compose restart
```
