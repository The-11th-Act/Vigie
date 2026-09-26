# syntax=docker/dockerfile:1

# --------------------------------------------------------------------------
# Étage 1 — construction des dépendances
#
# Le compilateur et les en-têtes de développement ne servent qu'à construire
# les wheels. Les garder dans l'image finale, c'est offrir un compilateur à
# qui obtiendrait une exécution de code dans le conteneur.
# --------------------------------------------------------------------------
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copié seul : la couche d'installation n'est invalidée que lorsque les
# dépendances changent, pas à chaque modification du code applicatif.
# Depuis le lockfile, avec hachages : l'image installe exactement les versions
# testees en CI, et un paquet altere sur l'index fait echouer le build.
COPY requirements.lock.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --require-hashes -r requirements.lock.txt


# --------------------------------------------------------------------------
# Étage 2 — image d'exécution
#
# Ne contient que le runtime Python, libpq et le virtualenv construit plus
# haut. Pas de compilateur, pas d'en-têtes, pas de cache pip.
# --------------------------------------------------------------------------
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# libpq5 est la bibliothèque d'exécution de psycopg2 ; libpq-dev (en-têtes et
# symlinks de compilation) reste dans l'étage de build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

# pip, setuptools et wheel ne servent qu'a installer : rien ne les appelle
# a l'execution. Ils embarquent pourtant leurs propres dependances vendorees
# (msgpack, jaraco.context...), que Trivy signale a juste titre. Retires du
# Python systeme comme du virtualenv.
RUN /opt/venv/bin/python -m pip uninstall --yes --quiet pip setuptools wheel \
    && python -m pip uninstall --yes --quiet pip setuptools wheel \
    && rm -rf /usr/local/lib/python3.11/ensurepip

WORKDIR /app

# Créé avant le COPY pour que les fichiers appartiennent directement au bon
# utilisateur, sans chown récursif (qui dupliquerait toute la couche).
# Le répertoire d'upload est créé ici avec le bon propriétaire : un volume
# nommé vide hérite du contenu et des droits de l'image au point de montage,
# sinon il serait monté en root et l'API ne pourrait pas y déposer les scans.
RUN useradd --create-home --uid 1000 appuser     && mkdir -p /var/lib/vigie/scans     && chown appuser:appuser /var/lib/vigie/scans

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

# Défini ici et pas seulement dans le compose : une plateforme d'exécution qui
# n'utilise pas docker-compose (Kubernetes, ECS, Nomad) lit cette instruction.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
