# TODO — Plateforme Vigie (RBVM)

> **Statut au 24/09/2026 : les sections fonctionnelles (1-18) sont traitées.**
> Les P0 (1-4) ont été livrés par la PR #1, les P1 et P2 (5-18) par la suivante.
> Les sections **-DEP** conservent des points ouverts (secrets, sauvegardes,
> staging…). Le détail de chaque choix figure dans les messages de commit.
>
> Deux points restent à connaître :
> - Le client CrowdStrike (item 5) est testé contre un transport simulé, pas
>   contre un tenant Falcon réel — aucun identifiant disponible ici.
> - Les identifiants Postgres par défaut sont passés de `tvm_user` / `tvm_platform`
>   à `vigie_user` / `vigie` (07/08/2026, avant toute production). Un volume de
>   développement créé avec les anciens noms doit être recréé, ou les anciennes
>   valeurs reportées dans `.env`.

État des lieux initial au 29/07/2026. Base : FastAPI + SQLAlchemy + Celery + React.
Suite de tests à l'époque : 109 tests. Aujourd'hui : **536 tests backend + 24 tests
frontend, tous verts**.

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

- [x] Ajouter une commande de bootstrap (`scripts/create_admin.py` ou commande CLI) créant le premier admin
- [x] Ajouter `PATCH /auth/users/{id}/role` protégé par `require_admin`
- [x] Tests : promotion refusée à un analyst, acceptée à un admin

### 2. Le frontend n'a pas d'écran de connexion
`app/services/api.js:20` redirige les 401 vers `/login`, mais cette route n'existe pas
dans `frontend/src/App.jsx`. Toutes les routes de l'API exigent un token → l'application
web est aujourd'hui inutilisable de bout en bout.

- [x] Créer `frontend/src/components/Login.jsx` (formulaire + stockage du token)
- [x] Ajouter la route `/login` et un `<ProtectedRoute>` autour des routes existantes
- [x] Afficher l'utilisateur connecté + bouton de déconnexion dans la sidebar

### 3. Le cœur RBVM n'est pas exposé dans l'UI
Le backend calcule et trie le backlog par risque (`GET /vulnerabilities/findings`,
`GET /dashboard/top-risks`), mais `frontend/src/services/index.js` n'expose aucune de ces
routes et aucun composant ne les consomme. L'écran « Vulnerabilities » liste le
catalogue CVE brut, pas les findings priorisés — c'est-à-dire pas la valeur du produit.

- [x] Ajouter `vulnerabilityService.getFindings()` / `updateFinding()` / `dashboardService.getTopRisks()`
- [x] Créer une vue « Backlog » : tri par `risk_score`, filtres `status` / `min_risk` / `overdue_only`
- [x] Permettre le triage (`PATCH /findings/{id}`) avec saisie obligatoire du `status_note`
- [x] Ajouter le bloc « Top risques » au dashboard

### 4. Les migrations ne sont pas jouées au démarrage
`docker-compose.yml` lance `uvicorn` directement : au premier `docker-compose up`, la base
est vide et toutes les requêtes échouent. Le README documente `alembic upgrade head` en
local uniquement.

- [x] Ajouter un service `migrate` (ou un entrypoint) exécutant `alembic upgrade head` avant `web` et `worker`

---

## P1 — Robustesse, sécurité, exploitation

### 5. Intégration CrowdStrike inachevée
`app/parsers/crowdstrike.py` retourne des données factices en dur et n'est câblé à aucune
tâche ni endpoint. La dépendance `requests` n'existe que pour ce fichier.

- [x] Implémenter `fetch_vulnerabilities()` (pagination Spotlight, cache du token OAuth2, gestion des 429/5xx)
- [x] Normaliser la sortie vers le format de `app/parsers/utils.py`
- [x] Ajouter une tâche Celery périodique de synchronisation + configuration des credentials
- [x] À défaut de l'implémenter : retirer le module et la dépendance `requests`

### 6. Pas d'historique des scans
Un upload ne laisse aucune trace en base : ni fichier, ni date, ni auteur, ni résultat.
Le seul suivi est `GET /scans/status/{task_id}` (`app/api/v1/scans.py:88`), qui dépend du
backend de résultats Redis et expire.

- [x] Modèle `ScanJob` (type, nom de fichier, uploader, statut, compteurs d'ingestion, timestamps) + migration `0003`
- [x] Historiser à l'upload et à la fin de tâche, exposer `GET /scans/`
- [x] Restreindre `GET /scans/status/{task_id}` à l'auteur du scan (aujourd'hui n'importe quel utilisateur authentifié lit n'importe quelle tâche)

### 7. Le contenu du fichier de scan transite par Redis
`app/api/v1/scans.py:60` passe jusqu'à 50 Mo de XML décodé en argument de tâche Celery :
sérialisation JSON complète, saturation du broker, pic mémoire côté worker.

- [x] Écrire l'upload sur un volume partagé (ou stockage objet) et ne passer que le chemin/la clé à la tâche
- [x] Nettoyer le fichier après ingestion réussie

### 8. Pas de limitation de débit sur l'authentification
`POST /auth/login` est en accès libre et sans throttling — brute-force possible malgré la
protection contre l'énumération d'utilisateurs déjà en place.

- [x] Rate limiting par IP + par compte (SlowAPI ou compteur Redis)
- [x] Verrouillage temporaire après N échecs, avec trace loguée

### 9. Cycle de vie des tokens incomplet
Tokens JWT de 60 min, sans refresh, sans révocation, sans déconnexion côté serveur.

- [x] Refresh token + rotation
- [x] Denylist des tokens révoqués (Redis, clé `jti`)
- [x] Endpoint `POST /auth/logout`

### 10. Aucune traçabilité du triage
`status` et `status_note` sont écrasés à chaque `PATCH` : impossible de savoir qui a
accepté un risque, quand, ni ce qu'il y avait avant. Problématique pour un usage
réglementaire (l'endpoint impose déjà une justification, donc l'intention y est).

- [x] Table `finding_audit_log` (finding, utilisateur, ancien/nouveau statut, note, date)
- [x] Alimenter depuis `update_finding_status` (`app/api/v1/vulnerabilities.py:163`)
- [x] Exposer l'historique d'un finding

### 11. Healthcheck partiel
`GET /health` (`app/main.py:75`) ne vérifie que PostgreSQL. Une panne Redis rend les
uploads impossibles (503) sans que la sonde ne le signale.

- [x] Vérifier Redis et la disponibilité des workers Celery
- [x] Séparer `/health` (liveness) et `/ready` (readiness)

### 12. Pas d'intégration continue
Aucun `.github/workflows/`. Les 109 tests ne tournent que manuellement.

- [x] Workflow CI : `pytest`, build Docker, `npm run build`
- [x] Ajouter `ruff` + `black` (via `pyproject.toml`) et les faire échouer la CI
- [x] Mesurer la couverture (`pytest --cov`) et publier le rapport

---

## P2 — Qualité, dette, documentation

### 13. Nettoyage du dépôt
- [x] Supprimer `code_complet.txt` (95 Ko de dump du code source versionné à la racine)
- [x] Harmoniser le nom du produit : dépôt « Vigie », `PROJECT_NAME = "TVM Platform"` (`app/core/config.py:20`), README « RBVM Platform »
- [x] Ajouter une `LICENSE`

### 14. README incomplet
- [x] Documenter la création du `.env` **avant** tout démarrage (l'application refuse de booter sans `SECRET_KEY`)
- [x] Documenter le lancement du worker Celery, l'exécution des tests, et le setup du frontend
- [x] Décrire le modèle de score de risque (multiplicateurs de criticité, pénalité de retard SLA)

### 15. Build frontend non reproductible
- [x] Committer `package-lock.json` et passer `frontend/Dockerfile` de `npm install` à `npm ci`
- [x] Ajouter ESLint + Prettier
- [x] Ajouter des tests (Vitest + Testing Library) — il n'y en a aucun aujourd'hui
- [x] Remplacer le debounce via variables globales `window._searchTimer` / `window._vulnSearchTimer` (`AssetsList.jsx:28`, `VulnerabilitiesList.jsx:31`) par un `useEffect` + `useRef`

### 16. CRUD API incomplet
- [x] `PUT` / `DELETE` sur `/vulnerabilities/{id}` (seuls `GET` et `POST` existent)
- [x] UI de création / édition / suppression d'assets (l'API le permet déjà)

### 17. Affinements de l'ingestion
`app/services/ingestion.py`
- [x] Les assets ne sont dédupliqués que par `ip_address` : un hôte en DHCP crée un doublon à chaque changement d'IP. Envisager une clé composite IP + hostname
- [x] Tout nouvel asset naît en criticité `Medium` — prévoir des règles d'attribution (par sous-réseau, par tag) ou un import en masse
- [x] Marquer automatiquement en `Remediated` les findings absents des N derniers scans d'une même source (aujourd'hui ils restent ouverts indéfiniment)

### 18. Observabilité
- [x] Middleware d'ID de corrélation propagé jusqu'aux tâches Celery
- [x] Handler d'exception global renvoyant une erreur normalisée sans fuite de stacktrace
- [x] Métriques Prometheus (latence API, débit d'ingestion, taille du backlog)

---

# Technologie & déploiement

Issu de l'audit du 06/08/2026 (`docs/EVALUATION_TECHNIQUE.md`). Constat initial : la
stack est bien choisie et le code applicatif est propre, mais **il n'existait aucun
chemin vers la production**. Les identifiants `D*` / `T*` renvoient à l'audit.

**Mise à jour du 06/08/2026 — les P0-DEP sont traités.** Le dépôt dispose désormais
d'une chaîne de déploiement (image de production, SPA construit et servi par Nginx,
surcouche compose de production) et d'une CI qui vérifie chacune de ces affirmations.
Ce qui reste ci-dessous est réel et non commencé.

**Fusion du 24/09/2026.** Cette section a été rédigée en parallèle des items 5-18,
livrés sur une autre branche. Les points que ces items ont couverts sont cochés
ci-dessous avec la mention *(items 5-18)*.

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
- [x] Dependabot et scan d'image Trivy *(26/09/2026 : Dependabot hebdomadaire sur
      pip, npm, actions, images ; Trivy bloquant sur CRITICAL corrigeable pour les 3
      images — le premier scan a fait remplacer nginx 1.27, retirer pip/setuptools de
      l'image API et gosu de l'image de sauvegarde)*

### D3. Build Docker
- [x] Multi-stage : le compilateur reste dans l'étage de build
- [x] `HEALTHCHECK` dans le `Dockerfile`, lisible hors docker-compose
- [x] Épingler les images de base par digest *(26/09/2026, tenus à jour par Dependabot)*

### T4. Outillage qualité
- [x] `pyproject.toml` : `ruff` (E, F, I, B, UP, S, C4), `black`, `pytest`, `coverage`
- [x] Lint branché en CI, en échec bloquant
- [x] `mypy` *(30/09/2026 : sur `app/` et `scripts/`, plugin pydantic, bloquant en CI
      à partir de zéro erreur. 61 erreurs au départ, dont 43 venaient de colonnes
      annotées avec le type SQL (`Mapped[DateTime]`) au lieu du type Python
      (`Mapped[datetime]`) : sans effet sur le schéma (`alembic check`), mais tout
      le typage des dates en était faussé)*

### T2. Dépendances
- [x] `lxml` retiré (importé nulle part)
- [x] Versions bornées par le haut, `requirements-dev.txt` séparé
- [x] `@app.on_event("startup")` migré vers `lifespan`
- [x] Lockfile figé : `requirements.lock.txt` (uv, hachages), installé par l'image et
      la CI, synchronisation vérifiée en CI *(26/09/2026)*
- [x] `requests` reste, à juste titre : `parsers/crowdstrike.py` est désormais un vrai
      client Falcon Spotlight *(items 5-18, point 5)*

### T3. Tests sur PostgreSQL
- [x] `tests/conftest.py` accepte `VIGIE_TEST_DATABASE_URL`
- [x] La CI rejoue la suite API sur un PostgreSQL réel, et fait un aller-retour
      `upgrade head` → `downgrade base` → `upgrade head` sur les migrations

### D9 (partiel). Sondes
- [x] `GET /ready` : PostgreSQL, Redis **et** présence d'un worker Celery. `/health` est
      une pure liveness, pour qu'une panne de dépendance ne fasse pas redémarrer l'API
- [x] Tests de l'écart, dont la non-divulgation du motif de panne et la fermeture de la
      connexion Redis de la sonde

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

- [x] Sortir les secrets du fichier : Docker secrets en production (clé de
      signature, clés retirées, mots de passe PostgreSQL et Redis), lus par la
      convention `*_FILE` ; absents du `.env` et de `docker inspect`, vérifié
      par le test de la pile de production *(30/09/2026)*
- [ ] Coffre managé (Vault, SOPS) si l'hébergement l'impose : `*_FILE` suffit à
      le brancher (fichier rendu par l'agent du coffre)
- [x] `kid` dans l'en-tête JWT + acceptation de N clés (`SECRET_KEY_ID`,
      `PREVIOUS_SECRET_KEYS`), pour tourner la clé sans déconnecter tout le monde
      *(26/09/2026)*
- [x] Documenter la procédure de rotation : `docs/EXPLOITATION.md`

### D8. Aucune sauvegarde
Le volume `pgdata` n'a ni politique de sauvegarde ni procédure de restauration. Le perdre,
c'est perdre l'historique des findings et des acceptations de risque — inacceptable pour
un usage réglementaire.

- [x] `pg_dump` planifié, chiffré, avec rétention définie : service `backup`
      (`deploy/backup/`), chiffrement asymétrique age, healthcheck sur la
      fraîcheur de la dernière sauvegarde *(25/09/2026)*
- [x] Restauration testée et documentée : `docs/SAUVEGARDE.md`, rejouée à chaque
      commit par le job CI de bout en bout (sauvegarde, base détruite,
      restauration, vérification par l'API)
- [x] Copie hors site : surcouche `docker-compose.offsite.yml`, rclone vers
      S3 / Azure / SFTP…, identifiants en Docker secret, rétention distante,
      healthcheck qui exige une copie récente ; vérifiée par le test de la
      pile de production (copie identique au bit près) *(30/09/2026)*

### D9 (suite). Observabilité
- [x] `X-Request-ID` lu par l'API et propagé jusqu'aux tâches Celery *(items 5-18)*
- [x] Logs au format JSON (`LOG_FORMAT=json`), worker et uvicorn compris, `request_id` vérifié de l'API au worker par le test de la pile de production *(30/09/2026)*
- [x] Métriques Prometheus : latence API, débit d'ingestion, taille du backlog, retards SLA
      *(items 5-18)*
- [x] Handler d'exception global : erreur normalisée, aucune stacktrace fuitée *(items 5-18)*

### D10 (suite). Le contenu du scan ne transite plus par Redis
- [x] Upload écrit sur un volume partagé, seul le chemin passe à la tâche *(items 5-18,
      point 7)*
- [x] Volume `scan_uploads` conservé par la surcouche de production pour l'API et le
      worker, créé dans l'image avec le bon propriétaire (`appuser`)

### T6. Token JWT dans `localStorage`
`services/api.js` : lisible par tout script injecté. Le point 9 y a ajouté le refresh
token, ce qui rend le passage au cookie plus pressant.

- [x] Cookie `HttpOnly` + `SameSite=Strict` + protection CSRF *(26/09/2026 : mode
      cookie demandé par `X-Session-Mode`, CSRF double-submit, Bearer inchangé pour
      les clients d'API ; le frontend n'écrit plus rien dans `localStorage`)*

---

## P2-DEP — Maturité

### T1. Modèle de concurrence non assumé
Driver `psycopg2` synchrone sous une API async : chaque requête DB occupe un thread du
threadpool Starlette, et la file d'attente devient invisible. `docker-compose.prod.yml`
expose `UVICORN_WORKERS`, mais le lien avec `pool_size` n'est pas documenté.

- [x] Trancher : full-sync assumé (le plus simple) ou `asyncpg` + `AsyncSession`
      *(30/09/2026 : synchrone assumé. L'upload de scan était la seule route
      `async def` et figeait la boucle d'événements pendant la copie, le commit et
      l'appel au broker : repassé en `def`, et un test refuse tout `async def` hors
      `main.py`)*
- [x] Documenter le dimensionnement `workers × threads × pool_size`
      *(30/09/2026 : `API_THREADS`, `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`,
      `DB_POOL_TIMEOUT_SECONDS` ; démarrage refusé si les threads dépassent le pool ;
      budget de connexions dans `docs/EXPLOITATION.md`, recalculé par les tests.
      L'ancien pool figé, 4 × (10 + 20) = 120 connexions, dépassait les 100 de
      PostgreSQL)*
- [x] Métriques Prometheus justes avec plusieurs workers uvicorn (mode
      multiprocessus), plus l'occupation des threads et du pool *(30/09/2026 :
      `PROMETHEUS_MULTIPROC_DIR` sur le tmpfs de l'API ; jauges des process morts
      oubliées ; requêtes en cours, threads, connexions utilisées et maximum ;
      vérifié dans la pile réelle, où la capacité vaut la somme des 4 process)*
- [x] `vigie_findings_ingested_total` restait à 0 : il était incrémenté dans le
      worker Celery, qui n'expose aucune métrique *(30/09/2026 : lu dans l'historique
      des scans réussis ; chaque synchro CrowdStrike y figure désormais comme un
      scan, une ligne par synchro malgré les nouvelles tentatives ; vérifié dans la
      pile réelle)*

### T5 (suite). Frontend
- [x] TanStack Query en remplacement de `useFetch` (cache, déduplication, invalidation)
      *(30/09/2026 : `useApiQuery`, clés par domaine (`findings`, `remediation`…) ;
      un écran rouvert affiche aussitôt son cache et le rafraîchit ; une mise à jour
      de ticket invalide tout `remediation` ; cache vidé à la déconnexion, sans quoi
      le compte suivant voyait un instant les données du précédent)*
- [x] Dépendances du `useCallback` de `useFetch` corrigées *(items 5-18, point 15)*
- [x] ESLint + Prettier, Vitest + Testing Library, branchés en CI *(items 5-18, point 15)*

### T7. Contrôle d'accès trop grossier
`require_admin` (`security.py:70`) lit le rôle **dans le token**, pas en base : rétrograder
un admin ne prend effet qu'à l'expiration. Aucun cloisonnement par périmètre.

- [x] Vérifier le rôle en base à chaque requête sensible : `require_admin` relit
      l'utilisateur ; une rétrogradation ou une suppression vaut immédiatement *(25/09/2026)*
- [x] Modèle de périmètres / groupes d'assets, filtrage des listings *(30/09/2026,
      choix de l'utilisateur : cloisonnement d'accès réel ; un périmètre est une liste
      d'équipes (`owner_team`), pas des groupes à règles ; un compte sans équipe voit
      tout, un admin n'est jamais cloisonné. Table `user_teams` (migration 0019),
      `app/core/scope.py`, périmètre obligatoire dans `findings_query`, le plan de
      remédiation, les tickets, les tableaux de bord et les extractions ; objet d'une
      autre équipe en 404 ; upload de scan et édition du catalogue CVE refusés à un
      compte cloisonné. Test de balayage de toutes les routes GET du schéma OpenAPI)*
- [ ] Limite connue : créer un asset avec l'IP d'un hôte d'une autre équipe répond
      409, ce qui révèle que l'IP existe. L'éviter demanderait des doublons ; à
      retirer du rôle analyste cloisonné si cela gêne

### D11. Un seul environnement
- [x] Environnement de staging réutilisant la surcouche de production *(30/09/2026 :
      second checkout, même `docker-compose.prod.yml` sans surcouche propre, `.env`
      et `secrets/` à lui ; plus aucun `container_name` figé, deux piles partagent un
      hôte sans partager conteneur, réseau ni volume)*
- [x] Chemin de promotion dev → staging → prod documenté *(30/09/2026 :
      [`docs/PREPRODUCTION.md`](docs/PREPRODUCTION.md) ; images nommées par
      `VIGIE_VERSION`, construites en préproduction, exécutées en production par
      `up --no-build --pull never`, via un registre sur deux hôtes ; répétition des
      migrations sur une copie de la production ; retour arrière avec ou sans
      migration)*
- [x] Distinguer la préproduction dans l'interface (bandeau), utile dès qu'elle
      reçoit une copie des données de production *(30/09/2026 : `INSTANCE_BANNER`,
      servi par une route publique de l'API (`/api/v1/instance`) plutôt que figé au
      build, puisque les deux environnements partagent l'image du frontend ; sur
      chaque écran, connexion comprise, et dans le titre de l'onglet)*

### Nettoyage restant
- [x] Harmoniser le nom du produit : `PROJECT_NAME`, conteneurs `vigie_*`,
      `frontend/package.json`, identifiants Postgres par défaut `vigie_user` / `vigie`
- [x] Ajouter une `LICENSE` (AGPL v3) *(items 5-18, point 14)*

---

# Suite du produit (25/09/2026)

Les sections précédentes rendaient la plateforme utilisable et déployable. Celle-ci
reprend la valeur RBVM elle-même.

## ✅ Clôture bornée et recalcul quotidien

- [x] La clôture automatique ne compte un manque que sur les hôtes couverts par le
      fichier (`ParsedScan.scanned_addresses`), hôtes revenus propres compris : un scan
      d'un sous-réseau ne ferme plus les findings d'un autre
- [x] `ScanJob.auto_remediated` persisté (migration 0006) et affiché
- [x] Recalcul quotidien du backlog ouvert (`RESCORE_HOUR_UTC`) : la pénalité de retard
      n'était appliquée qu'à l'arrivée d'un scan
- [x] Un seul point de recalcul des scores stockés (`app/services/rescoring.py`)
- [x] Historique des scans dans l'UI (`GET /scans/` n'avait aucun écran)
- [x] Correctif : l'écran d'upload attendait un `state` Celery que `/scans/status` ne
      renvoie plus depuis le point 6 ; il finissait toujours en « taking too long »

## ✅ Contexte de menace

Le score ne voyait que CVSS × criticité + retard : rien sur l'exploitation réelle.

- [x] CISA KEV et FIRST EPSS stockés par CVE (migration 0007, table `threat_feed_status`)
- [x] Exposition Internet des assets (champ + `INTERNET_FACING_SUBNETS`)
- [x] Formule : multiplicateur EPSS par paliers, ×1.3 KEV, ×1.2 exposé, plafond ×1.5,
      plancher 7.0 pour un KEV ; score inchangé sans renseignement
- [x] SLA raccourci à `KEV_SLA_DAYS` (14 j) pour un CVE KEV (jamais rallongé)
- [x] Rafraîchissement quotidien avec garde-fous (échec sans effacement, catalogue
      rétréci ou instantané plus ancien refusés), import hors ligne (CLI + endpoint admin)
- [x] `risk_factors` dans les réponses, filtres `kev_only` / `min_epss` /
      `internet_facing_only`, KPI et métriques
- [x] UI : badges KEV / EPSS, filtres, case « Exposé à Internet »
- [x] `alembic check` en CI : un modèle modifié sans migration fait échouer le build

Contrairement au client CrowdStrike, les parseurs KEV et EPSS ont été vérifiés
sur les fichiers réels du 25/09/2026 (1 725 entrées KEV, 379 145 lignes EPSS).

Choix produit pris par défaut, tous réglables par une constante de
`risk_scoring.py` — à revoir à l'usage :
- réduction ×0.9 sous 1 % d'EPSS : une fois les flux activés, une partie du
  backlog descend d'un niveau (voulu : c'est la réduction du bruit) ;
- plancher 7.0 pour un KEV même sur un asset `Low` ;
- l'usage par rançongiciel intègre désormais activement le calcul de risque (01/10/2026) :
  multiplicateur de menace ×1.15 additionnel, plancher de risque à 7.5 et délai SLA
  d'urgence resserré à 7 jours (`RANSOMWARE_SLA_DAYS`). *Corrigé le 01/10/2026 : ces
  7 jours partaient de la détection ou de l'inscription au KEV ; CISA signalant parfois
  le rançongiciel des années après l'inscription, le finding passait en retard le jour
  même. Ils partent désormais du jour où le signalement est connu
  (`kev_ransomware_since`, migration 0020).*

## ✅ Déploiement vérifié de bout en bout (25/09/2026)

Le démarrage complet de la pile de production n'avait jamais été testé : la CI
lançait les images une par une. Le faire a révélé trois défauts, corrigés :

- [x] Réglages absents des conteneurs : `.env` n'est lu que par compose, et
      `CRITICALITY_RULES`, `AUTO_REMEDIATE_AFTER_MISSES` et tout le contexte de
      menace n'étaient pas transmis. Bloc `x-app-settings` + `env_ignore_empty`,
      et un test qui échoue si un réglage de `Settings` n'est pas câblé
- [x] Frontend de production en redémarrage permanent : tmpfs `/var/cache/nginx`
      appartenant à root, Nginx tournant en `nginx`
- [x] Beat marqué « unhealthy » en permanence (healthcheck de l'API hérité)
- [x] Job CI « Pile de production de bout en bout » (`scripts/smoke_prod_stack.sh`) :
      Nginx → API → Redis → worker → PostgreSQL, admin, upload, import KEV,
      effet de chaque réglage dans le conteneur qui le lit, calendrier du beat

## Plus tard

- [x] Un CVE vu pour la première fois attend jusqu'au prochain rafraîchissement
      (24 h) pour recevoir KEV / EPSS : l'enrichir dès l'ingestion depuis le
      dernier instantané
      *Réglé le 26/09/2026 : tables `kev_catalog` et `epss_scores`, lues à l'ingestion.*
- [x] Saturation à 10 : entre findings plafonnés, le départage (KEV, puis EPSS) ignore
      l'exposition et la criticité — vu sur données réelles, Log4Shell sur un hôte
      interne passe devant PAN-OS exposé. Piste : trier sur le score non plafonné
      *Réglé le 26/09/2026 : `risk_rank`, le score avant plafonnement, départage les 10.*
- [x] Détections par source *(26/09/2026 : `finding_detections`, un finding ne se
      ferme que lorsque toutes ses sources ont cessé de le voir)*
- [x] Acceptation de risque avec expiration, revue quand un CVE accepté entre dans KEV
      *(26/09/2026 : `accepted_until`, 90 j par défaut, 365 j max ; réouverture tracée
      par l'acteur « system »)*
- [x] Export CSV du backlog *(26/09/2026 : mêmes filtres que l'écran, formules
      neutralisées, écrit via un fichier temporaire)*
- [x] Webhooks *(01/10/2026 : voir « 7. Connecteur de ticketing et webhooks »)*
- [x] `.gitattributes` pour fixer les fins de ligne *(30/09/2026 : `* text=auto` ;
      l'index était déjà en LF, la renormalisation n'a changé aucun fichier)*

---

# Modules et remédiation (29/09/2026)

Vigie priorise bien, mais elle parle CVE. Les équipes de remédiation, elles, travaillent en KB, patch ou version cible : « déployer KB5034441 sur 42 serveurs », pas « traiter 312 CVE ». L'interface est aussi la même pour tous.

Cible : une barre latérale composée de modules (profil par rôle, ajusté par chaque utilisateur), et des tickets de remédiation gérés dans Vigie. Un connecteur Jira, ServiceNow ou GLPI viendra ensuite sur la même structure.

Ordre retenu : 1 → 0 → 2 → 4 → 3 → 5 → 6 → 7. Faits : 1 à 6.

## ✅ 1. Capturer les données de remédiation

Les parseurs jetaient tout ce que les scanners disent du correctif. Les fichiers de scan étant supprimés après ingestion, rien ne se rattrape : seuls les scans postérieurs portent des KB.

- [x] `remediation_actions` (une ligne par KB ou par correctif) et `finding_remediations` (lien par finding et par source, avec versions installée et corrigée), migration 0012
- [x] Nessus : le KB manquant d'après `plugin_output` (le rollup d'un Server 2019 ne doit pas renvoyer vers le KB de Windows 11), sinon `xref MSKB`, sinon le titre ; hors Microsoft, le plugin (`nessus:<id>`) ; « Installed / Fixed version »
- [x] OpenVAS : `solution@type` ou `tags`, KB nommé dans la NVT, sinon l'OID
- [x] CrowdStrike : `remediation.entities` quand Spotlight les renvoie développées
- [x] Les liens d'une source sont remplacés à chaque scan : un cumulatif remplacé disparaît
- [x] `remediations` dans les réponses de findings, colonnes `remediation` / `fixed_version` dans l'export CSV
- [x] Colonne « Fix » dans le backlog : KB en badge, sinon le correctif et sa version cible
- [ ] CrowdStrike : vérifier sur un vrai tenant que les entités de remédiation reviennent de `entities/vulnerabilities/v2`. Sinon, passer par l'endpoint `combined` avec `facet=remediation`
- [ ] Remplacement des KB (supersedence) pour les sources qui ne donnent pas le KB par hôte : flux MSRC CVRF

## 0. Remise à plat
- [x] Trier les PR Dependabot : regroupées en commits cohérents (bcrypt 5 sans passlib, React 19, Vite 8, vitest 5, node 26, nginx 1.31, Redis 8, black 26, ruff 0.16) ; postgres 18 bien ignoré, pydantic-core exclu *(30/09/2026)*
- [x] `.gitattributes` *(30/09/2026)*
- [x] TanStack Query en remplacement de `useFetch` (T5), socle des nouveaux écrans *(30/09/2026)*

## ✅ 2. Socle modulaire

- [x] Registre des modules (`app/core/modules.py`) : `dashboard`, `backlog`, `assets`, `vulnerabilities`, `scans`, `admin`. Les modules Remédiation, Catégorisation et Extractions y entreront avec leur écran
- [x] Rôle `remediator` : marque les correctifs faits, sans pouvoir accepter un risque, déclarer un faux positif, ni modifier la criticité ou l'exposition d'un asset ou le score d'un CVE
- [x] Modules activés par l'admin, profils par rôle (JSON, défaut dans le code), préférences utilisateur (ordre, modules masqués), migration 0013 ; `GET /me/modules`, `PUT /me/preferences`, `/admin/modules`, `/admin/roles/{role}/modules`, `GET /users/`
- [x] `require_module(...)` sur chaque route, depuis l'utilisateur en base : masquer un onglet ne vaut pas autorisation
- [x] Barre latérale et routes construites depuis les modules accordés ; écrans Préférences et Administration
- [x] Garde-fous : le module Administration ne peut être ni désactivé ni retiré aux admins ; le dernier admin ne peut pas être rétrogradé
- [x] Profil de rôle : l'écran Administration ajoute un module accordé en fin de liste ; réordonner un profil passe par l'API *(30/09/2026 : ordre de chaque profil réglable dans l'écran Administration ; le premier module est l'écran d'arrivée du rôle)*

## ✅ 4. Remédiation et tickets internes
- [x] Module `remediation` et vue « Top correctifs » : risque cumulé fermé par action (chaque finding compté une fois), hôtes, findings et CVE distincts, KEV, retards, échéance ; seau « Sans correctif identifié » ; hôtes d'un correctif avec leurs versions, export CSV
- [x] Le rôle `remediator` ouvre sur Remédiation ; l'interface ne lui propose plus les décisions de risque (triage, édition d'asset)
- [x] Tickets par (action × `owner_team`), migration 0015 : statuts open / in_progress / deployed (l'équipe), resolved (les scans), cancelled (un analyste, avec justification) ; historique ; référence et lien externes
- [x] Résolution automatique quand tous les findings sont fermés, réouverture si l'un revient, rattachement des nouveaux findings au ticket ouvert de l'équipe (acteur `system`), après ingestion, triage, réouverture d'acceptation et passage quotidien
- [x] Onglets Correctifs / Tickets, export des hôtes d'un ticket
- [x] Rattacher un finding dont l'hôte change d'équipe : il reste dans le ticket où il est entré *(30/09/2026 : un finding ouvert quitte le ticket de l'ancienne équipe, tracé dans son historique, et rejoint celui de la nouvelle s'il existe, sinon redevient à ticketer ; un finding fermé reste à l'équipe qui l'a corrigé ; un ticket vidé ainsi est annulé ; synchronisation dès le changement d'équipe dans l'écran Assets)*

## ✅ 3. Contexte d'asset et catégorisation
- [x] `owner_team` (migration 0014), `OWNER_TEAM_RULES` par sous-réseau, filtre et saisie dans l'écran Assets
- [x] `asset_type` (déduit de l'OS), `environment` (`ENVIRONMENT_RULES`), migration 0017 avec rattrapage de l'existant
- [x] Taxonomie des findings (titre puis famille du scanner), stockée par finding, rattrapée au passage quotidien
- [x] Module `categorization` : matrice catégorie × type, environnement, criticité, équipe ou exposition ; findings d'une case
- [x] Filtres du backlog et des extractions : catégorie, type, environnement, criticité, exposition exacte, valeur « non renseignée » (`__none__`)
- [x] Groupes d'assets à règles en base (moitié restante de T7), et filtrage des listings par périmètre *(30/09/2026 : périmètres par équipe, voir T7 ; des groupes à règles (sous-réseau, environnement) restent possibles plus tard si le découpage par équipe ne suffit pas)*
- [ ] Affiner la taxonomie sur un vrai export : les règles sont écrites d'après les titres documentés de Nessus et OpenVAS

## ✅ 5. Extractions API
- [x] Jetons d'accès personnels (migration 0016) : SHA-256, lecture seule, expiration obligatoire, révocables, 20 actifs par utilisateur, inopérants sans le module `extracts`
- [x] Jeux : findings, correctifs, tickets, assets, catalogue CVE ; colonnes et filtres typés ; CSV ou JSON en flux ; un filtre inconnu est refusé
- [x] Constructeur (aperçu, `curl` équivalent), extractions enregistrées à URL stable
- [x] La requête filtrée du backlog vit dans `app/services/findings.py` (écran, export, extractions) ; filtre `owner_team`
- [ ] Format XLSX si les équipes le demandent

## ✅ 6. Dashboards
- [x] `backlog_snapshots` (migration 0018) par jour et par équipe, pris par le passage quotidien ; 90 jours reconstruits (estimés) au premier passage ou à la demande d'un admin
- [x] Tendances, et performance sur une période : corrections, échéances tenues, MTTR global et par criticité, risque retiré, évolution du backlog, tableau par équipe avec ses tickets
- [x] Deux vues : Posture et Tendances & remédiation (celle du remediator)
- [ ] Métriques Prometheus correspondantes (MTTR, échéances tenues) si l'exploitation les veut dans Grafana

## 7. Connecteur de ticketing et webhooks
- [ ] Interface `TicketConnector`, première implémentation, synchronisation du statut
- [ ] Une cible par environnement : une préproduction restaurée depuis la production
      ne doit jamais écrire dans l'outil de ticketing de production *(fait pour les
      webhooks par le scellement ci-dessous, à reprendre pour le connecteur)*
- [x] Webhooks sortants *(01/10/2026 : migration 0021, écran Administration.
      Événements `scan.completed` / `scan.failed`, `ticket.created`,
      `ticket.status_changed` (y compris résolution et réouverture par les scans),
      `threat.kev_listed` (un événement par rafraîchissement). Boîte d'envoi en base
      écrite dans la transaction du changement, envoyée par le worker toutes les 30 s,
      7 tentatives sur ~21 h, `SKIP LOCKED` contre les envois en double. Signature
      HMAC-SHA256 horodatée, secret montré une fois. HTTPS seul, pas d'adresse privée
      sauf réglage, jamais boucle locale ni métadonnées cloud, pas de redirection.
      Chaque webhook est scellé par la clé de signature de l'instance : une
      préproduction restaurée depuis la production ne peut pas appeler ses
      destinataires. Vérifié de bout en bout contre un vrai récepteur HTTP local)*
      *Corrigé le 01/10/2026 : le worker, qui envoie et rescelle les webhooks, ne
      recevait pas `PREVIOUS_SECRET_KEYS` ; après chaque rotation de la clé, il
      aurait abandonné tous les envois comme « autre instance ». La pile de
      production vérifie désormais la réception du webhook et la lecture des clés
      retirées par l'API et le worker.*
- [ ] Webhooks : le contrôle d'adresse précède la connexion sans la fixer ; un DNS
      qui change entre les deux (rebinding) le contournerait. Épingler l'adresse
      vérifiée si des destinataires non maîtrisés sont un jour enregistrés
