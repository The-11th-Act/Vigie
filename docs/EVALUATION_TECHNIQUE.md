# Évaluation technique et déploiement — Plateforme Vigie

Audit au 06/08/2026, sur le commit `29bd856`. Périmètre : **choix technologiques** et
**aptitude au déploiement**. Le suivi fonctionnel reste dans `TODO.md` ; ce document ne
le rejoue pas, il couvre ce que `TODO.md` n'adresse pas ou sous-estime.

Verdict court : **la stack est bien choisie et le code applicatif est propre. Ce qui
manque, c'est tout ce qui sépare un projet qui tourne en `docker-compose up` d'un
produit déployable.** Aujourd'hui il n'existe aucun chemin vers la production : pas
d'image de production, pas de CI, pas de gestion de secrets, pas d'observabilité.

---

## 1. Stack technologique

### 1.1 Ce qui est bien vu

| Choix | Verdict |
|---|---|
| FastAPI + Pydantic v2 | Adapté. Validation déclarative, OpenAPI gratuit, async là où il compte (upload). |
| SQLAlchemy 2.0 `Mapped[]` | Style moderne, typé. Les index composites (`ix_asset_vulns_status_risk`) sont posés en fonction des requêtes réelles, pas au hasard. |
| Table d'association `AssetVulnerability` porteuse du `risk_score` | Modélisation juste : c'est le couple (asset, CVE) qui porte le risque, pas la CVE. C'est le cœur correct d'un RBVM. |
| Celery + Redis | Dimensionné pour le besoin (ingestion de scans longue). `autoretry_for` + backoff + `soft_time_limit` sont déjà configurés correctement. |
| Alembic | Migrations versionnées, `env.py` importe bien tous les modèles. |
| Séparation `services/` pures | `risk_scoring` et `remediation` sont testables sans DB ni Celery. C'est ce qui rend les 109 tests rapides. |
| Durcissement sécurité déjà fait | `SECRET_KEY` validée, refus du wildcard CORS, docs désactivées en prod, `verify_password_constant_time`, `defusedxml`, upload borné en streaming, conteneur non-root. Rare à ce stade d'un projet. |

### 1.2 Faiblesses technologiques

**T1 — Le driver DB est synchrone alors que l'API est async.**
`psycopg2-binary` + `create_engine` sync sous des routes `def` : chaque requête DB
occupe un thread du threadpool Starlette (40 par défaut). Le pool SQLAlchemy est à
`pool_size=10, max_overflow=20`, soit 30 connexions par process. Sous charge, la file
d'attente se forme dans le threadpool, invisible dans les métriques. Deux options
cohérentes : rester full-sync et assumer (dimensionner par `--workers`), ou passer à
`asyncpg` + `AsyncSession`. Le mélange actuel est le pire des deux.
→ *Recommandation : rester sync (moins de réécriture), mais documenter le modèle de
concurrence et dimensionner `pool_size` en fonction de `workers × threads`.*

**T2 — Dépendances mortes et non épinglées.**
`lxml` n'est importé nulle part. `requests` ne sert qu'à `parsers/crowdstrike.py`, qui
retourne des données factices. Toutes les versions sont en `>=`, sans lockfile : deux
`docker build` à deux dates donnent deux images différentes. Un `pip install` aujourd'hui
tire FastAPI 0.11x/0.12x, où `@app.on_event("startup")` (`app/main.py:72`) est **déprécié**
et destiné à disparaître au profit du `lifespan`.
→ *`pip-tools` ou `uv` pour un `requirements.lock`, suppression de `lxml`, migration vers
`lifespan`.*

**T3 — Les tests tournent sur SQLite, la prod sur PostgreSQL.**
`tests/conftest.py:17` force `sqlite:///./test.db`. Les 109 tests verts ne prouvent rien
sur les types `ENUM` natifs Postgres, les contraintes `ON DELETE CASCADE`, le comportement
transactionnel, ni les `ilike` (insensibles à la casse par accident en SQLite, dépendants
de la collation en Postgres). Le code contient déjà des contournements explicites de cet
écart (`risk_scoring.py:62` « ce que SQLite renvoie dans les tests »), ce qui est le signe
que la divergence coûte déjà.
→ *Faire tourner au moins la suite `tests/api/` sur un Postgres jetable (service CI ou
`testcontainers`).*

**T4 — Pas d'outillage qualité.**
Pas de `pyproject.toml`, donc pas de `ruff`, pas de `black`, pas de `mypy`, pas de config
`pytest` centralisée. Le style est homogène aujourd'hui parce qu'un seul auteur a écrit le
code ; ça ne survit pas au deuxième contributeur.

**T5 — Le frontend est un prototype outillé comme tel.**
Vite 4 et React 18 (deux majeures de retard chacun), zéro test, zéro lint, `npm install`
au lieu de `npm ci` dans le Dockerfile, pas de gestion d'état serveur (chaque composant
refetch via `useFetch`, pas de cache ni de déduplication). `useFetch` prend `deps` mais
`fetchFn` n'est pas dans le tableau de dépendances de `useCallback` : un appelant qui ne
mémoïse pas sa fonction déclenche une boucle de refetch. C'est un piège latent.
→ *TanStack Query supprimerait `useFetch` et le problème avec.*

**T6 — Le token JWT est stocké dans `localStorage`.**
`services/api.js:9` : lisible par n'importe quel script injecté. Pour une plateforme de
sécurité, c'est un choix difficile à défendre en revue. L'alternative est un cookie
`HttpOnly` + `SameSite=Strict` (avec protection CSRF), ce qui rejoint le point 9 de
`TODO.md` sur le cycle de vie des tokens.

**T7 — Pas de contrôle d'accès au-delà de `admin` vs le reste.**
`require_admin` (`security.py:70`) lit le rôle **dans le token**, pas en base : révoquer
un admin ne prend effet qu'à l'expiration du token (jusqu'à 60 min). Et une plateforme de
gestion de vulnérabilités multi-équipes a besoin d'un cloisonnement par périmètre (une
équipe ne voit que ses assets), inexistant aujourd'hui.

---

## 2. Déploiement

### 2.1 État réel

**Il n'existe aucun artefact de production.** Le `docker-compose.yml` est un environnement
de développement, et rien d'autre :

- `web` tourne avec `--reload` (ligne 45) : rechargeur de fichiers, mono-worker, jamais à
  exposer publiquement.
- Le code est monté en volume (`- .:/app`, ligne 47) : l'image construite est ignorée, le
  conteneur exécute le répertoire de travail de l'hôte. Le `USER appuser` du Dockerfile
  est donc contourné côté permissions de fichiers, et le build n'est jamais validé.
- `frontend` lance `npm run dev` : serveur Vite de développement, jamais `npm run build`
  ni de service statique. **Il n'existe à ce jour aucun moyen de produire un frontend de
  production.**
- Postgres et Redis publient `5432` et `6379` sur l'hôte, sans mot de passe pour Redis.
- Les mots de passe Postgres ont des valeurs par défaut en clair dans le compose
  (`tvm_password`).

**D1 — Aucune image de production.** Il faut un `docker-compose.prod.yml` (ou un overlay)
avec : `uvicorn --workers N` sans `--reload`, pas de bind mount, frontend buildé et servi
par Nginx, ports internes non publiés.

**D2 — Pas de `.dockerignore`.** `COPY . .` embarque `venv/`, `.git/`, `.env`,
`__pycache__/`, `test.db`, `.pytest_cache/`, `code_complet.txt`, `node_modules/`.
Conséquences : image de plusieurs centaines de Mo au lieu de ~200 Mo, cache de build
invalidé à chaque fichier touché, et **le `.env` réel — donc le `SECRET_KEY` — copié dans
une couche d'image**. C'est le défaut de déploiement le plus grave du dépôt, et il est
trivial à corriger.

**D3 — Build Docker non optimisé.** Pas de multi-stage, pas d'épinglage du tag de base
(`python:3.11-slim` est une cible mouvante), pas de `HEALTHCHECK` dans le Dockerfile (il
n'existe que dans le compose, donc perdu sur toute autre plateforme).

**D4 — Le frontend n'a pas de config d'exécution.** `VITE_API_TARGET` n'est utilisé que
par le proxy du serveur *de dev* (`vite.config.js:11`). En production, le SPA appellera
`/api/v1` en relatif sur son propre domaine : sans reverse proxy Nginx en façade, rien ne
route ces appels vers l'API. Ce reverse proxy n'existe pas.

**D5 — Gestion des secrets inexistante.** Tout passe par des variables d'environnement
lues d'un `.env` sur disque, sans rotation, sans coffre, avec des valeurs par défaut
faibles. `SECRET_KEY` n'a pas de mécanisme de rotation : la changer invalide tous les
tokens émis d'un coup (pas de `kid`, pas de période de recouvrement).

**D6 — Pas de CI/CD.** Aucun `.github/workflows/`. Les 109 tests, le build Docker et le
build frontend ne sont jamais exécutés automatiquement. Aucune analyse de dépendances
(`pip-audit`, Dependabot) ni de scan d'image (Trivy) — sur une plateforme de gestion de
vulnérabilités, l'ironie est coûteuse en crédibilité.

**D7 — Migrations non réversibles en pratique.** Le service `migrate` joue
`alembic upgrade head` avant chaque démarrage, ce qui est correct, mais : aucune stratégie
de rollback, aucun test des `downgrade()`, et un déploiement en parallèle sur plusieurs
répliques ferait tourner plusieurs `migrate` concurrents. Alembic pose un verrou sur sa
table de version, donc pas de corruption, mais l'échec du perdant doit être géré.

**D8 — Sauvegardes absentes.** Le volume `pgdata` n'a aucune politique de sauvegarde ni
de restauration documentée. Perdre le volume, c'est perdre l'historique complet des
findings et des décisions d'acceptation de risque.

**D9 — Observabilité au niveau zéro.** Logs texte non structurés sur stdout, aucun
identifiant de corrélation, aucune métrique, aucun tracing. `/health` ne teste que
Postgres (déjà noté au point 11 de `TODO.md`) : une panne Redis laisse la sonde verte
alors que toute l'ingestion est morte. Impossible de répondre à « pourquoi ce scan a mis
40 minutes » en production.

**D10 — Aucune limite de ressources.** Pas de `deploy.resources`, pas de `--max-memory-per-child`
Celery. Un scan Nessus de 50 Mo est aujourd'hui **décodé en chaîne et passé en argument de
tâche via Redis** (`scans.py:63`, déjà noté au point 7 de `TODO.md`) : c'est aussi un
problème de déploiement, parce que le pic mémoire du worker n'est ni borné ni mesuré.

**D11 — Un seul environnement.** `ENVIRONMENT` accepte `staging` mais rien dans le dépôt
ne matérialise un staging. Aucun chemin de promotion dev → staging → prod.

### 2.2 Ce qui est déjà correct côté déploiement

- `depends_on` avec `condition: service_healthy` et `service_completed_successfully` :
  l'ordre de démarrage est réellement garanti, ce que beaucoup de projets ratent.
- `SECRET_KEY=${SECRET_KEY:?...}` : le compose échoue vite plutôt que de booter avec une
  clé connue. Bon réflexe.
- Conteneur non-root avec UID fixe.
- `build-essential` purgé après l'installation des wheels.

---

## 3. Plan d'amélioration priorisé

Ordre recommandé. Les trois premiers items sont peu coûteux et débloquent tout le reste.

| # | Action | Effort | Impact |
|---|---|---|---|
| D2 | `.dockerignore` (stoppe la fuite du `.env` dans l'image) | 10 min | Critique |
| D6 | CI GitHub Actions : pytest + build Docker + build frontend | 2 h | Critique |
| D1/D4 | Overlay de production + Nginx pour le SPA et le reverse proxy | 4 h | Critique |
| T2 | Lockfile, suppression de `lxml`, migration `lifespan` | 2 h | Élevé |
| D3 | Dockerfile multi-stage, tag de base épinglé, `HEALTHCHECK` | 2 h | Élevé |
| T4 | `pyproject.toml` + `ruff` + `black`, branchés en CI | 1 h | Élevé |
| D9 | Logs JSON + ID de corrélation + `/health` et `/ready` séparés | 4 h | Élevé |
| T3 | Suite API sur Postgres jetable en CI | 3 h | Élevé |
| D5 | Secrets hors fichier, procédure de rotation du `SECRET_KEY` (`kid`) | 4 h | Moyen |
| D8 | `pg_dump` planifié + procédure de restauration testée | 3 h | Moyen |
| T5 | TanStack Query, correction de `useFetch`, ESLint, Vitest | 6 h | Moyen |
| T6 | Cookie `HttpOnly` + CSRF à la place de `localStorage` | 4 h | Moyen |
| D9b | Métriques Prometheus (latence, backlog, débit d'ingestion) | 4 h | Moyen |
| T1 | Décision assumée sur le modèle de concurrence, documentée | 1 h | Moyen |
| T7 | Vérification du rôle en base + cloisonnement par périmètre | 8 h | Moyen |
| D7 | Tests des `downgrade()` Alembic | 2 h | Faible |
| D11 | Environnement de staging | 4 h | Faible |

Les actions correspondantes sont reprises comme cases à cocher dans la section
« P0-DEP / P1-DEP / P2-DEP » de `TODO.md`.
