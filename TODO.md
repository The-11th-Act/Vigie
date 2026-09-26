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
- [ ] `mypy` (non mis en place)

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

- [ ] Sortir les secrets du fichier (Docker secrets, SOPS, ou coffre managé)
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
- [ ] Copie hors site : le service écrit sur un volume local ou un chemin
      monté (`BACKUP_VOLUME`) ; l'envoi vers un stockage objet reste à faire

### D9 (suite). Observabilité
- [x] `X-Request-ID` lu par l'API et propagé jusqu'aux tâches Celery *(items 5-18)*
- [ ] Logs au format JSON : chaque ligne porte le `request_id`, mais en texte
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

- [ ] Trancher : full-sync assumé (le plus simple) ou `asyncpg` + `AsyncSession`
- [ ] Documenter le dimensionnement `workers × threads × pool_size`

### T5 (suite). Frontend
- [ ] TanStack Query en remplacement de `useFetch` (cache, déduplication, invalidation)
- [x] Dépendances du `useCallback` de `useFetch` corrigées *(items 5-18, point 15)*
- [x] ESLint + Prettier, Vitest + Testing Library, branchés en CI *(items 5-18, point 15)*

### T7. Contrôle d'accès trop grossier
`require_admin` (`security.py:70`) lit le rôle **dans le token**, pas en base : rétrograder
un admin ne prend effet qu'à l'expiration. Aucun cloisonnement par périmètre.

- [x] Vérifier le rôle en base à chaque requête sensible : `require_admin` relit
      l'utilisateur ; une rétrogradation ou une suppression vaut immédiatement *(25/09/2026)*
- [ ] Modèle de périmètres / groupes d'assets, filtrage des listings

### D11. Un seul environnement
- [ ] Environnement de staging réutilisant la surcouche de production
- [ ] Chemin de promotion dev → staging → prod documenté

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
- l'usage par rançongiciel est affiché, sans effet sur le score.

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
- [ ] Webhooks
- [ ] `.gitattributes` pour fixer les fins de ligne (le dépôt mélange CRLF et LF dans
      l'arbre de travail ; à faire avec un `git add --renormalize` dédié)
