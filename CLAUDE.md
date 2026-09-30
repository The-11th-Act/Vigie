# Vigie — notes de reprise pour Claude

Plateforme RBVM (Risk-Based Vulnerability Management) : ingestion de scans
(Nessus, OpenVAS, CrowdStrike Spotlight), score de risque contextualisé (CVSS ×
criticité × KEV/EPSS × exposition + retard SLA), backlog, remédiation par
KB/correctif avec tickets, catégorisation, tableaux de bord, extractions API.
FastAPI + SQLAlchemy + Celery/Redis + PostgreSQL ; React 19 + Vite 8.

- `README.md` (anglais) : fonctionnement et déploiement. `docs/` (français) :
  exploitation, sauvegarde, audits. **`TODO.md` : l'état de référence** — la
  section « Modules et remédiation » en fin de fichier suit la feuille de route
  en cours.
- Migrations : tête `0018`. Chaque colonne de modèle doit avoir sa migration
  (`alembic check` en CI).

## Façon de travailler (convenue avec l'utilisateur)

- Répondre en français. Code, commentaires et README en anglais ; TODO et
  `docs/` en français.
- Un commit par changement cohérent, poussé directement sur `main`, puis
  suivre la CI jusqu'au vert. Message : sujet en français sans accents, au
  présent (« Ajoute… », « Passe a… »), corps expliquant le pourquoi en puces,
  terminé par la ligne `Co-Authored-By` de l'assistant.
- Cocher le `TODO.md` et mettre à jour le README/`docs/` dans le même commit.
- Les PR Dependabot : les regrouper en commits cohérents quand les montées
  dépendent les unes des autres (Dependabot ferme ensuite ses PR).

## Vérifier avant d'annoncer

```bash
venv/Scripts/python.exe -m ruff check . && venv/Scripts/python.exe -m black --check .
venv/Scripts/python.exe -m mypy                            # app/ et scripts/, 0 erreur
venv/Scripts/python.exe -m pytest -q                       # SQLite, 5 à 15 min
DATABASE_URL=sqlite:///<scratchpad>/m.db venv/Scripts/python.exe -m alembic upgrade head
DATABASE_URL=sqlite:///<scratchpad>/m.db venv/Scripts/python.exe -m alembic check
cd frontend && npm run lint && npx vitest run --maxWorkers=1 && npm run build
gh run list --workflow CI --branch main --limit 1          # pas seulement --limit 1 :
                                                           # les runs Dependabot s'intercalent
```

- **Seule la CI prouve** PostgreSQL et la pile de production (Docker n'est
  pas démarré sur ce poste). Le job « Pile de production de bout en bout »
  (`scripts/smoke_prod_stack.sh`) démarre tout, avec Docker secrets, copie
  hors site, logs JSON, sauvegarde et restauration.
- `tests/test_deployment_config.py` tourne en local (`docker compose config`
  sans démon).
- Vérification manuelle : base SQLite jetable dans le scratchpad, `alembic
  upgrade head`, script de peuplement lancé avec `PYTHONPATH=.`, puis
  `uvicorn app.main:app --port 87xx` et curl ; frontend avec
  `VITE_API_TARGET=http://localhost:87xx npx vite`.

## Pièges déjà rencontrés

- **Autoflush** : `SessionLocal` (API, worker) a `autoflush=False`, la fixture
  `db_session` non. Un service qui modifie puis relit par requête doit faire
  `db.flush()` (ex. `sync_tickets`). Pour le tester : `db_session.autoflush = False`.
- La fixture `client` remplace `decode_token` et `require_admin` pour **toute**
  l'application : un test qui mélange `client` et `unauthenticated_client` ne
  vérifie pas vraiment l'authentification (voir `real_auth()` dans
  `tests/api/test_extracts.py`, `act_as` dans `tests/api/test_modules.py`).
- Pas d'id codé en dur dans les tests (séquences PostgreSQL) ; pas de
  `db.rollback()` dans un chemin qui n'a rien écrit (vide `db_session`).
- Tout nouveau réglage de `Settings` doit être câblé dans `x-app-settings` de
  `docker-compose.yml` (sinon `test_deployment_config` échoue) ; un réglage
  métier mérite une vérification dans le test de la pile de production.
- Modèles : `Mapped[datetime]` / `Mapped[date]` (type Python), jamais
  `Mapped[DateTime]` ; le type SQL va dans `mapped_column(DateTime(timezone=True))`.
- Jamais d'`async def` dans `app/` hors `main.py` : l'API est synchrone
  (`tests/test_concurrency.py`). Un nouveau réglage de pool ou de threads
  change le budget de connexions (`TestConnectionBudget`).
- Pas de `container_name` ni de `name:` de volume figé (deux piles par hôte) ;
  tout service construit porte `image: …:${VIGIE_VERSION}` (promotion sans
  reconstruction). `TestStagingAndPromotion` le vérifie.
- Un secret est un fichier en production (`secrets/`, convention `*_FILE`) :
  jamais de nouveau secret en variable d'environnement.
- **Scripts sur ce poste Windows** : heredoc bash et `python -c` abîment les
  apostrophes, les accents, les `\n` et les `\` de fin de ligne. Écrire le
  script avec l'outil Write dans le scratchpad, le lancer avec
  `python -X utf8`, relire le résultat. Préserver les fins de ligne du
  fichier modifié (CRLF ou LF) ; les `.sh` et `deploy/backup/*` restent en LF.
- Chrome piloté est peu fiable ici (captures qui expirent, clics perdus) :
  privilégier `find`/navigation par URL, et couvrir l'interaction par Vitest.
- Recharts est remplacé par des composants vides dans les tests d'écran ;
  `Charts.test.jsx` monte les vrais graphiques. `lucide-react` est en 0.577 :
  vérifier qu'une icône existe (`node_modules/lucide-react/dist/lucide-react.d.ts`).

## Repères d'architecture

- **Modules** (`app/core/modules.py`) : registre, profils par rôle en base,
  préférences utilisateur ; `require_module(...)` sur chaque route.
  Frontend : `frontend/src/modules.js`. Rôles : `admin`, `analyst`,
  `remediator` (pas de décision de risque : `require_risk_decision`).
- **Remédiation** : `remediation_actions` / `finding_remediations` remplis à
  l'ingestion (KB ou `nessus:<plugin>`, `openvas:<oid>`) ; vue par correctif
  (`app/services/remediation_plan.py`) ; tickets par correctif × équipe
  (`app/services/tickets.py`, `sync_tickets` après ingestion, triage,
  réouverture d'acceptation et passage quotidien).
- **Catégorisation** : taxonomie dans `app/services/categorization.py`
  (titre puis famille du scanner), `asset_type` déduit de l'OS.
- **Tableaux de bord** : `backlog_snapshots` pris par le passage quotidien,
  90 jours reconstruits (marqués estimés) ; `app/services/dashboard_metrics.py`.
- **Extractions** : jeux déclaratifs (`app/services/extracts.py`), jetons
  personnels en lecture seule (`app/core/api_tokens.py`).
- La requête filtrée du backlog est unique : `app/services/findings.py`.

## Suite prévue

1. ~~Préproduction (D11)~~ fait le 30/09/2026, bandeau compris :
   `docs/PREPRODUCTION.md`. Une valeur propre à un environnement vient de
   l'API au lancement, jamais d'une variable `VITE_*` (image partagée).
2. ~~T1~~ fait le 30/09/2026 : synchrone assumé (`docs/EXPLOITATION.md`).
   Métriques en mode multiprocessus, compteur d'ingestion et `mypy` faits.
   Le worker n'expose aucune métrique : ce qu'il fait se mesure depuis la
   base, au scrape de l'API.
3. TanStack Query côté frontend ; groupes d'assets et filtrage par périmètre.
4. **Plus tard, à la demande de l'utilisateur** : connecteur de ticketing
   (Jira, ServiceNow ou GLPI, à lui faire choisir) sur les champs
   `external_*` des tickets, et webhooks. Garder la conception ouverte.
5. À valider sur des données réelles quand l'utilisateur les fournira : un
   export Nessus (taxonomie, KB des cumulatives Windows) et un tenant
   CrowdStrike (remédiations Spotlight).
