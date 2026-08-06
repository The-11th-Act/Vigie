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

Issu de l'audit du 06/08/2026 (`docs/EVALUATION_TECHNIQUE.md`). Constat initial : la
stack est bien choisie et le code applicatif est propre, mais **il n'existait aucun
chemin vers la production**. Les identifiants `D*` / `T*` renvoient à l'audit.

**Mise à jour du 06/08/2026 — les P0-DEP sont traités.** Le dépôt dispose désormais
d'une chaîne de déploiement (image de production, SPA construit et servi par Nginx,
surcouche compose de production) et d'une CI qui vérifie chacune de ces affirmations.
Ce qui reste ci-dessous est réel et non commencé.

---

## ✅ Fait (06/08/2026)

### D2. `.dockerignore` — le `.env` ne peut plus finir dans l'image
`COPY . .` embarquait `venv/`, `.git/`, `.env`, `test.db`, `code_complet.txt`. Le
`SECRET_KEY` de production était donc copié dans une couche d'image.

- [x] `.dockerignore` à la racine et `frontend/.dockerignore`
- [x] Vérification automatisée en CI : le job `docker` échoue si `/app/.env`,
      `/app/venv`, `/app/.git` ou `/app/test.db` existent dans l'image

### D1 + D4. Artefacts de production
- [x] `docker-compose.prod.yml` : `uvicorn --workers N` sans `--reload`, sans bind mount
- [x] `frontend/Dockerfile.prod` multi-stage : `npm ci && npm run build`, servi par Nginx
- [x] `frontend/nginx.conf` : statiques + `/api` vers `web`, en-têtes de sécurité, CSP,
      fallback de routage client, cache immuable sur les assets hashés
- [x] `5432` / `6379` ne sont plus publiés, Redis sous `--requirepass`
- [x] Plus aucune valeur par défaut pour les secrets : compose échoue s'ils manquent
- [x] Limites mémoire, `--max-memory-per-child` Celery, `read_only`, `no-new-privileges`

### D6. Intégration continue
- [x] `.github/workflows/ci.yml` — 6 jobs : `lint`, `test`, `audit`, `frontend`,
      `docker`, `compose`
- [x] `pip-audit` et `npm audit --audit-level=high`, bloquants
- [x] Couverture `pytest --cov` publiée en artefact
- [x] Le job `compose` vérifie qu'aucun réglage de développement (`--reload`, bind mount,
      port de base publié, serveur Vite) ne survit à la surcouche de production
- [ ] Dependabot et scan d'image Trivy (le reste de D6 est en place)

### D3. Build Docker
- [x] Multi-stage : le compilateur reste dans l'étage de build
- [x] `HEALTHCHECK` dans le `Dockerfile`, lisible hors docker-compose
- [ ] Épingler l'image de base par digest (toujours `python:3.11-slim`)

### T4. Outillage qualité
- [x] `pyproject.toml` : `ruff` (E, F, I, B, UP, S, C4), `black`, `pytest`, `coverage`
- [x] Lint branché en CI, en échec bloquant
- [ ] `mypy` (non mis en place)

### T2. Dépendances
- [x] `lxml` retiré (importé nulle part)
- [x] Versions bornées par le haut, `requirements-dev.txt` séparé
- [x] `@app.on_event("startup")` migré vers `lifespan`
- [ ] Lockfile figé (`pip-tools` / `uv`) — les bornes limitent la dérive sans la supprimer
- [ ] `requests` reste : il sert à `parsers/crowdstrike.py`, dont l'abandon est une
      décision produit (cf. point 5)

### T3. Tests sur PostgreSQL
- [x] `tests/conftest.py` accepte `VIGIE_TEST_DATABASE_URL`
- [x] La CI rejoue la suite API sur un PostgreSQL réel, et fait un aller-retour
      `upgrade head` → `downgrade base` → `upgrade head` sur les migrations

### D9 (partiel). Sondes
- [x] `GET /ready` : PostgreSQL **et** Redis. `/health` reste une pure liveness, pour
      qu'une panne de broker ne fasse pas redémarrer l'API
- [x] 6 tests couvrent l'écart, dont la non-divulgation du motif de panne

### Frontend
- [x] Vite 4 → 7, React Router 6 → 7 : corrige l'open redirect GHSA-wrjc-x8rr-h8h6 dans
      `<Link>` / `useNavigate`, qui s'appliquait à ce SPA
- [x] Bundle unique de 640 ko découpé (applicatif 79 ko, react 179 ko, charts 382 ko)
- [x] `npm ci` au lieu de `npm install` dans l'image

### Divers
- [x] `scripts/create_admin.py` : premier admin en opération ponctuelle, mot de passe
      demandé interactivement et jamais accepté en argument (10 tests)
- [x] `code_complet.txt` supprimé (point 13)
- [x] README : section production, tableau dev/prod, sondes, tests sur PostgreSQL
- [x] `.env.example` : section `[PROD]` documentée

---

## P1-DEP — Reste à faire

### D5. Gestion des secrets
Les secrets viennent d'un `.env` sur disque, sans coffre ni rotation. Changer `SECRET_KEY`
invalide d'un coup tous les tokens émis : pas de `kid`, pas de période de recouvrement.

- [ ] Sortir les secrets du fichier (Docker secrets, SOPS, ou coffre managé)
- [ ] `kid` dans l'en-tête JWT + acceptation de N clés, pour tourner la clé sans
      déconnecter tout le monde
- [ ] Documenter la procédure de rotation

### D8. Aucune sauvegarde
Le volume `pgdata` n'a ni politique de sauvegarde ni procédure de restauration. Le perdre,
c'est perdre l'historique des findings et des acceptations de risque — inacceptable pour
un usage réglementaire.

- [ ] `pg_dump` planifié, chiffré, avec rétention définie
- [ ] Restauration testée et documentée (une sauvegarde jamais restaurée n'existe pas)

### D9 (suite). Observabilité
- [ ] Logs JSON structurés + `X-Request-ID` propagé jusqu'aux tâches Celery
      (Nginx transmet déjà l'en-tête, l'API ne le lit pas encore)
- [ ] Métriques Prometheus : latence API, débit d'ingestion, taille du backlog, retards SLA
- [ ] Handler d'exception global : erreur normalisée, aucune stacktrace fuitée

### D10 (suite). Le contenu du scan transite toujours par Redis
Les limites de ressources sont posées, mais `scans.py:63` passe encore jusqu'à 50 Mo de
XML décodé en argument de tâche. *(Voir le point 7.)*

- [ ] Écrire l'upload sur un volume partagé et ne passer que le chemin à la tâche

### T6. Token JWT dans `localStorage`
`services/api.js:9` : lisible par tout script injecté. *(À traiter avec le point 9.)*

- [ ] Cookie `HttpOnly` + `SameSite=Strict` + protection CSRF

---

## P2-DEP — Maturité

### T1. Modèle de concurrence non assumé
Driver `psycopg2` synchrone sous une API async : chaque requête DB occupe un thread du
threadpool Starlette, et la file d'attente devient invisible. `docker-compose.prod.yml`
expose `UVICORN_WORKERS`, mais le lien avec `pool_size` n'est pas documenté.

- [ ] Trancher : full-sync assumé (le plus simple) ou `asyncpg` + `AsyncSession`
- [ ] Documenter le dimensionnement `workers × threads × pool_size`

### T5 (suite). Frontend
- [ ] TanStack Query en remplacement de `useFetch` (cache, déduplication, invalidation).
      `useFetch` n'inclut toujours pas `fetchFn` dans les dépendances de son `useCallback`
- [ ] ESLint + Prettier, Vitest + Testing Library (aucun test frontend à ce jour)

### T7. Contrôle d'accès trop grossier
`require_admin` (`security.py:70`) lit le rôle **dans le token**, pas en base : rétrograder
un admin ne prend effet qu'à l'expiration. Aucun cloisonnement par périmètre.

- [ ] Vérifier le rôle en base à chaque requête sensible
- [ ] Modèle de périmètres / groupes d'assets, filtrage des listings

### D11. Un seul environnement
- [ ] Environnement de staging réutilisant la surcouche de production
- [ ] Chemin de promotion dev → staging → prod documenté

### Nettoyage restant
- [ ] Harmoniser le nom du produit : dépôt « Vigie », `PROJECT_NAME = "TVM Platform"`
      (`app/core/config.py:19`), conteneurs `tvm_*`, `frontend/package.json` « tvm-frontend »
- [ ] Ajouter une `LICENSE`
