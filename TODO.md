# TODO — Plateforme Vigie (RBVM)

État des lieux au 29/07/2026. Base : FastAPI + SQLAlchemy + Celery + React.
Suite de tests : **109 tests, tous verts** (`pytest -q`).

Priorités : **P0** = bloque un usage réel · **P1** = important · **P2** = confort / dette.

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
