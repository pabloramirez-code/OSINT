# syntax=docker/dockerfile:1
# reconmap en un contenedor (Fase 5).
#
# Las herramientas del modo Activo van DENTRO de la imagen, copiadas de sus imágenes
# oficiales fijadas por digest (las mismas que usa reconmap fuera del contenedor). Así no
# hace falta montar /var/run/docker.sock, que daría control total del equipo anfitrión.

FROM projectdiscovery/tlsx@sha256:6ee6a07c5a633149d5e0482c6df654c9975be97bb7733ec91faaa72a7940295b AS tlsx
FROM projectdiscovery/httpx@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc AS httpx
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv

# Base: imagen oficial de gowitness 3.2.2 (Debian 13 + Chrome headless, que gowitness necesita).
FROM ghcr.io/sensepost/gowitness@sha256:39bbbcd07b37c523de3f1447cb8046cb586e91ed3b0c80436922a403ffeddc1c AS app

# musl: httpx viene compilado para Alpine y necesita su cargador. tlsx es estático.
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tlsx /usr/local/bin/tlsx /usr/local/bin/tlsx
# Como httpx-toolkit (igual que en Kali): "httpx" ya es el CLI del httpx de Python.
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx-toolkit
COPY --from=uv /uv /usr/local/bin/uv

# Python 3.12 gestionado por uv y dependencias exactas de uv.lock (sin las de desarrollo).
ENV UV_PYTHON=3.12 \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

# Usuario sin privilegios; base de datos y capturas en /data (volumen).
RUN useradd --create-home --uid 10001 reconmap \
    && mkdir -p /data \
    && chown reconmap:reconmap /data
USER reconmap

ENV PATH=/opt/venv/bin:$PATH \
    RECONMAP_HOST=0.0.0.0 \
    RECONMAP_DB=/data/reconmap.db \
    RECONMAP_DATA_DIR=/data \
    RECONMAP_TOOLS_RUNNER=local
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python", "-c", "import urllib.request as u, sys; sys.exit(u.urlopen('http://127.0.0.1:8000/health', timeout=3).status != 200)"]
ENTRYPOINT ["tini", "--"]
CMD ["reconmap-web"]
