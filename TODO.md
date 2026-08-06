# TODO — Plateforme Vigie (RBVM)

État des lieux au 29/07/2026. Base : FastAPI + SQLAlchemy + Celery + React.
Suite de tests : **109 tests, tous verts** (`pytest -q`).

Priorités : **P0** = bloque un usage réel · **P1** = important · **P2** = confort / dette.
Les sections suffixées **-DEP** (technologie & déploiement, ajoutées le 06/08/2026)
découlent de l'audit détaillé dans [`docs/EVALUATION_TECHNIQUE.md`](docs/EVALUATION_TECHNIQUE.md).

---

## P0 — Bloquants fonctionnels

### 1. Aucun moyen de créer un administrateur
`POST /auth/register` force `role="analyst"` en dur (`app/api/v1/auth.py:43`) et aucun
endpoint ni script ne permet de promouvoir un utilisateur. Conséquence : `require_admin`
(`app/core/security.py:70`) n'est jamais satisfaisable, et `DELETE /assets/{id}`
(`app/api/v1/assets.py:106`) est inatteignable en production.

- [ ] Ajouter une commande de bootstrap (`scripts/create_admin.py` ou commande CLI) créant le premier admin
- [ ] Ajouter `PATCH /auth/users/{id}/role` protégé par `require_admin`
- [ ] Tests : promotion refusée à un analyst, acceptée à un admin

### 2. Le frontend n'a pas d'écran de connexion
`app/services/api.js:20` redirige les 401 vers `/login`, mais cette route n'existe pas
dans `frontend/src/App.jsx`. Toutes les routes de l'API exigent un token → l'application
web est aujourd'hui inutilisable de bout en bout.

- [ ] Créer `frontend/src/components/Login.jsx` (formulaire + stockage du token)
- [ ] Ajouter la route `/login` et un `<ProtectedRoute>` autour des routes existantes
- [ ] Afficher l'utilisateur connecté + bouton de déconnexion dans la sidebar

### 3. Le cœur RBVM n'est pas exposé dans l'UI
Le backend calcule et trie le backlog par risque (`GET /vulnerabilities/findings`,
`GET /dashboard/top-risks`), mais `frontend/src/services/index.js` n'expose aucune de ces
routes et aucun composant ne les consomme. L'écran « Vulnerabilities » liste le
catalogue CVE brut, pas les findings priorisés — c'est-à-dire pas la valeur du produit.

- [ ] Ajouter `vulnerabilityService.getFindings()` / `updateFinding()` / `dashboardService.getTopRisks()`
- [ ] Créer une vue « Backlog » : tri par `risk_score`, filtres `status` / `min_risk` / `overdue_only`
- [ ] Permettre le triage (`PATCH /findings/{id}`) avec saisie obligatoire du `status_note`
- [ ] Ajouter le bloc « Top risques » au dashboard

### 4. Les migrations ne sont pas jouées au démarrage
`docker-compose.yml` lance `uvicorn` directement : au premier `docker-compose up`, la base
est vide et toutes les requêtes échouent. Le README documente `alembic upgrade head` en
local uniquement.

- [ ] Ajouter un service `migrate` (ou un entrypoint) exécutant `alembic upgrade head` avant `web` et `worker`

---

## P1 — Robustesse, sécurité, exploitation

### 5. Intégration CrowdStrike inachevée
`app/parsers/crowdstrike.py` retourne des données factices en dur et n'est câblé à aucune
tâche ni endpoint. La dépendance `requests` n'existe que pour ce fichier.

- [ ] Implémenter `fetch_vulnerabilities()` (pagination Spotlight, cache du token OAuth2, gestion des 429/5xx)
- [ ] Normaliser la sortie vers le format de `app/parsers/utils.py`
- [ ] Ajouter une tâche Celery périodique de synchronisation + configuration des credentials
- [ ] À défaut de l'implémenter : retirer le module et la dépendance `requests`

### 6. Pas d'historique des scans
Un upload ne laisse aucune trace en base : ni fichier, ni date, ni auteur, ni résultat.
Le seul suivi est `GET /scans/status/{task_id}` (`app/api/v1/scans.py:88`), qui dépend du
backend de résultats Redis et expire.

- [ ] Modèle `ScanJob` (type, nom de fichier, uploader, statut, compteurs d'ingestion, timestamps) + migration `0003`
- [ ] Historiser à l'upload et à la fin de tâche, exposer `GET /scans/`
- [ ] Restreindre `GET /scans/status/{task_id}` à l'auteur du scan (aujourd'hui n'importe quel utilisateur authentifié lit n'importe quelle tâche)

### 7. Le contenu du fichier de scan transite par Redis
`app/api/v1/scans.py:60` passe jusqu'à 50 Mo de XML décodé en argument de tâche Celery :
sérialisation JSON complète, saturation du broker, pic mémoire côté worker.

- [ ] Écrire l'upload sur un volume partagé (ou stockage objet) et ne passer que le chemin/la clé à la tâche
- [ ] Nettoyer le fichier après ingestion réussie

### 8. Pas de limitation de débit sur l'authentification
`POST /auth/login` est en accès libre et sans throttling — brute-force possible malgré la
protection contre l'énumération d'utilisateurs déjà en place.

- [ ] Rate limiting par IP + par compte (SlowAPI ou compteur Redis)
- [ ] Verrouillage temporaire après N échecs, avec trace loguée

### 9. Cycle de vie des tokens incomplet
Tokens JWT de 60 min, sans refresh, sans révocation, sans déconnexion côté serveur.

- [ ] Refresh token + rotation
- [ ] Denylist des tokens révoqués (Redis, clé `jti`)
- [ ] Endpoint `POST /auth/logout`

### 10. Aucune traçabilité du triage
`status` et `status_note` sont écrasés à chaque `PATCH` : impossible de savoir qui a
accepté un risque, quand, ni ce qu'il y avait avant. Problématique pour un usage
réglementaire (l'endpoint impose déjà une justification, donc l'intention y est).

- [ ] Table `finding_audit_log` (finding, utilisateur, ancien/nouveau statut, note, date)
- [ ] Alimenter depuis `update_finding_status` (`app/api/v1/vulnerabilities.py:163`)
- [ ] Exposer l'historique d'un finding

### 11. Healthcheck partiel
`GET /health` (`app/main.py:75`) ne vérifie que PostgreSQL. Une panne Redis rend les
uploads impossibles (503) sans que la sonde ne le signale.

- [ ] Vérifier Redis et la disponibilité des workers Celery
- [ ] Séparer `/health` (liveness) et `/ready` (readiness)

### 12. Pas d'intégration continue
Aucun `.github/workflows/`. Les 109 tests ne tournent que manuellement.

- [ ] Workflow CI : `pytest`, build Docker, `npm run build`
- [ ] Ajouter `ruff` + `black` (via `pyproject.toml`) et les faire échouer la CI
- [ ] Mesurer la couverture (`pytest --cov`) et publier le rapport

---

## P2 — Qualité, dette, documentation

### 13. Nettoyage du dépôt
- [ ] Supprimer `code_complet.txt` (95 Ko de dump du code source versionné à la racine)
- [ ] Harmoniser le nom du produit : dépôt « Vigie », `PROJECT_NAME = "TVM Platform"` (`app/core/config.py:20`), README « RBVM Platform »
- [ ] Ajouter une `LICENSE`

### 14. README incomplet
- [ ] Documenter la création du `.env` **avant** tout démarrage (l'application refuse de booter sans `SECRET_KEY`)
- [ ] Documenter le lancement du worker Celery, l'exécution des tests, et le setup du frontend
- [ ] Décrire le modèle de score de risque (multiplicateurs de criticité, pénalité de retard SLA)

### 15. Build frontend non reproductible
- [ ] Committer `package-lock.json` et passer `frontend/Dockerfile` de `npm install` à `npm ci`
- [ ] Ajouter ESLint + Prettier
- [ ] Ajouter des tests (Vitest + Testing Library) — il n'y en a aucun aujourd'hui
- [ ] Remplacer le debounce via variables globales `window._searchTimer` / `window._vulnSearchTimer` (`AssetsList.jsx:28`, `VulnerabilitiesList.jsx:31`) par un `useEffect` + `useRef`

### 16. CRUD API incomplet
- [ ] `PUT` / `DELETE` sur `/vulnerabilities/{id}` (seuls `GET` et `POST` existent)
- [ ] UI de création / édition / suppression d'assets (l'API le permet déjà)

### 17. Affinements de l'ingestion
`app/services/ingestion.py`
- [ ] Les assets ne sont dédupliqués que par `ip_address` : un hôte en DHCP crée un doublon à chaque changement d'IP. Envisager une clé composite IP + hostname
- [ ] Tout nouvel asset naît en criticité `Medium` — prévoir des règles d'attribution (par sous-réseau, par tag) ou un import en masse
- [ ] Marquer automatiquement en `Remediated` les findings absents des N derniers scans d'une même source (aujourd'hui ils restent ouverts indéfiniment)

### 18. Observabilité
- [ ] Middleware d'ID de corrélation propagé jusqu'aux tâches Celery
- [ ] Handler d'exception global renvoyant une erreur normalisée sans fuite de stacktrace
- [ ] Métriques Prometheus (latence API, débit d'ingestion, taille du backlog)

---

# Technologie & déploiement

Issu de l'audit du 06/08/2026 (`docs/EVALUATION_TECHNIQUE.md`). Constat : la stack est
bien choisie et le code applicatif est propre, mais **il n'existe aujourd'hui aucun
chemin vers la production** — pas d'image de production, pas de CI, pas de gestion de
secrets, pas d'observabilité. Les identifiants `D*` / `T*` renvoient à l'audit.

## P0-DEP — Bloque tout déploiement

### D2. Pas de `.dockerignore` — le `.env` réel finit dans l'image
`COPY . .` (`Dockerfile:20`) embarque `venv/`, `.git/`, `.env`, `test.db`,
`__pycache__/`, `code_complet.txt`, `node_modules/`. L'image gonfle inutilement, le cache
de build est invalidé au moindre fichier touché, et surtout **le `SECRET_KEY` de
production est copié dans une couche d'image**. Correction triviale, gravité maximale.

- [ ] Ajouter `.dockerignore` à la racine et `frontend/.dockerignore`
- [ ] Vérifier l'absence du secret : `docker run --rm --entrypoint sh <image> -c 'ls -a /app'`

### D1 + D4. Aucun artefact de production
`docker-compose.yml` est un environnement de développement et rien d'autre : `--reload`
(ligne 45), code monté en volume (ligne 47, l'image construite n'est jamais exécutée),
frontend en `npm run dev` (serveur Vite de dev), Postgres et Redis publiés sur l'hôte,
Redis sans mot de passe, mots de passe Postgres par défaut en clair. Le SPA appelle
`/api/v1` en relatif et `VITE_API_TARGET` ne sert qu'au proxy *de dev* : hors du compose,
rien ne route les appels vers l'API.

- [ ] `docker-compose.prod.yml` : `uvicorn --workers N` sans `--reload`, sans bind mount
- [ ] `frontend/Dockerfile` multi-stage : `npm ci && npm run build`, servi par Nginx
- [ ] Reverse proxy Nginx en façade : statiques + `/api` vers `web`, en-têtes de sécurité
- [ ] Ne plus publier `5432` / `6379` sur l'hôte, mot de passe Redis (`requirepass`)
- [ ] Retirer les valeurs par défaut des mots de passe Postgres du compose

### D6. Pas d'intégration continue
Aucun `.github/workflows/`. Les 109 tests, le build Docker et le build frontend ne
tournent jamais automatiquement. Sur une plateforme de gestion de vulnérabilités,
l'absence de scan de dépendances est difficile à défendre.
*(Recoupe le point 12 de la TODO fonctionnelle, élargi au déploiement.)*

- [ ] Workflow CI : `pytest`, `docker build`, `npm ci && npm run build`
- [ ] `pip-audit` + Dependabot + scan d'image Trivy, bloquants sur vulnérabilité haute
- [ ] Couverture (`pytest --cov`) publiée sur la PR

---

## P1-DEP — Robustesse d'exploitation

### T2. Dépendances mortes et build non reproductible
`lxml` n'est importé nulle part. `requests` ne sert qu'à `parsers/crowdstrike.py`, qui
retourne des données factices. Toutes les versions sont en `>=` sans lockfile : deux
`docker build` à deux dates donnent deux images différentes. Un `pip install` aujourd'hui
tire une version de FastAPI où `@app.on_event("startup")` (`app/main.py:72`) est déprécié.

- [ ] Retirer `lxml` (et `requests` si CrowdStrike est abandonné — cf. point 5)
- [ ] Lockfile via `pip-tools` ou `uv`, utilisé par le Dockerfile
- [ ] Migrer `@app.on_event("startup")` vers le gestionnaire `lifespan`

### D3. Build Docker non optimisé
- [ ] Multi-stage (build des wheels puis image d'exécution minimale)
- [ ] Épingler l'image de base par digest plutôt que `python:3.11-slim`
- [ ] `HEALTHCHECK` dans le `Dockerfile` (aujourd'hui seulement dans le compose, donc
      perdu sur toute autre plateforme d'exécution)

### T4. Aucun outillage qualité
Pas de `pyproject.toml`, donc ni `ruff`, ni `black`, ni `mypy`, ni configuration `pytest`
centralisée. Le style tient aujourd'hui parce qu'il n'y a qu'un auteur.

- [ ] `pyproject.toml` avec `ruff` + `black` + config `pytest`
- [ ] Brancher le lint en CI, en échec bloquant

### D9. Observabilité au niveau zéro
Logs texte non structurés, aucun identifiant de corrélation, aucune métrique, aucun
tracing. `/health` ne teste que Postgres : une panne Redis laisse la sonde verte alors que
toute l'ingestion est morte. *(Recoupe les points 11 et 18.)*

- [ ] Logs JSON structurés + `X-Request-ID` propagé jusqu'aux tâches Celery
- [ ] Séparer `/health` (liveness) et `/ready` (readiness : Postgres + Redis + workers)
- [ ] Métriques Prometheus : latence API, débit d'ingestion, taille du backlog, retards SLA
- [ ] Handler d'exception global : erreur normalisée, aucune stacktrace fuitée

### T3. Les tests tournent sur SQLite, la production sur PostgreSQL
`tests/conftest.py:17` force `sqlite:///./test.db`. Les 109 tests verts ne prouvent rien
sur les `ENUM` natifs, les `ON DELETE CASCADE`, le comportement transactionnel ni la
collation des `ilike`. Le code contient déjà des contournements explicites de cet écart
(`risk_scoring.py:62`), ce qui montre que la divergence coûte déjà.

- [ ] Faire tourner `tests/api/` sur un Postgres jetable (service CI ou `testcontainers`)
- [ ] Conserver SQLite pour les tests unitaires purs (`services/`, `parsers/`), rapides

### D5. Gestion des secrets
Tout vient d'un `.env` sur disque, sans coffre ni rotation. Changer `SECRET_KEY` invalide
d'un coup tous les tokens émis : pas de `kid`, pas de période de recouvrement.

- [ ] Sortir les secrets du fichier (Docker secrets, SOPS, ou coffre managé)
- [ ] `kid` dans l'en-tête JWT + acceptation de N clés pour permettre une rotation sans
      déconnexion générale
- [ ] Documenter la procédure de rotation

### D8. Aucune sauvegarde
Le volume `pgdata` n'a ni politique de sauvegarde ni procédure de restauration. Le perdre,
c'est perdre l'historique des findings et des acceptations de risque — inacceptable pour
un usage réglementaire.

- [ ] `pg_dump` planifié, chiffré, avec rétention définie
- [ ] Restauration testée et documentée (une sauvegarde jamais restaurée n'existe pas)

### D10. Aucune limite de ressources
Pas de `deploy.resources`, pas de `--max-memory-per-child` Celery. Le contenu du scan
transite par Redis (`scans.py:63`) : le pic mémoire du worker n'est ni borné ni mesuré.
*(Recoupe le point 7.)*

- [ ] Limites CPU/mémoire par service
- [ ] `--max-memory-per-child` et `--concurrency` explicites pour Celery

### T6. Token JWT dans `localStorage`
`services/api.js:9` : lisible par tout script injecté. Difficile à défendre en revue pour
une plateforme de sécurité. *(À traiter avec le point 9, cycle de vie des tokens.)*

- [ ] Cookie `HttpOnly` + `SameSite=Strict` + protection CSRF

---

## P2-DEP — Maturité

### T1. Modèle de concurrence non assumé
Driver `psycopg2` synchrone sous une API async : chaque requête DB occupe un thread du
threadpool Starlette, et la file d'attente devient invisible. `pool_size=10` +
`max_overflow=20` par process, sans lien avec le nombre de workers.

- [ ] Trancher : full-sync assumé (le plus simple) ou `asyncpg` + `AsyncSession`
- [ ] Documenter le dimensionnement `workers × threads × pool_size`

### T5. Frontend outillé comme un prototype
Vite 4 et React 18 (deux majeures de retard chacun), zéro test, zéro lint. `useFetch`
n'inclut pas `fetchFn` dans les dépendances de son `useCallback` : un appelant qui ne
mémoïse pas sa fonction déclenche une boucle de refetch. *(Recoupe le point 15.)*

- [ ] TanStack Query en remplacement de `useFetch` (cache, déduplication, invalidation)
- [ ] ESLint + Prettier, Vitest + Testing Library
- [ ] Monter React et Vite de version

### T7. Contrôle d'accès trop grossier
`require_admin` (`security.py:70`) lit le rôle **dans le token**, pas en base : rétrograder
un admin ne prend effet qu'à l'expiration (jusqu'à 60 min). Aucun cloisonnement par
périmètre : toute équipe voit tous les assets.

- [ ] Vérifier le rôle en base à chaque requête sensible (ou invalider le token au
      changement de rôle)
- [ ] Modèle de périmètres / groupes d'assets, filtrage des listings par périmètre

### D7. Migrations sans stratégie de retour arrière
- [ ] Tester les `downgrade()` en CI (upgrade head → downgrade base → upgrade head)
- [ ] Documenter la procédure de rollback et le comportement en démarrage multi-répliques

### D11. Un seul environnement
`ENVIRONMENT` accepte `staging` mais rien ne le matérialise.

- [ ] Environnement de staging avec le même overlay que la production
- [ ] Chemin de promotion dev → staging → prod documenté

---

## Ordre d'attaque conseillé

Les trois premiers items coûtent peu et débloquent tout le reste.

1. `.dockerignore` (**D2**) — 10 min, arrête une fuite de secret
2. CI (**D6**) — 2 h, tout ce qui suit devient vérifiable automatiquement
3. Overlay de production + Nginx (**D1/D4**) — 4 h, rend le produit déployable
4. Lockfile + `lifespan` + suppression de `lxml` (**T2**) — 2 h
5. Dockerfile multi-stage (**D3**) et outillage qualité (**T4**) — 3 h
6. Observabilité (**D9**) et tests sur Postgres (**T3**) — 7 h
