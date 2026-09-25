# Maintenabilité à long terme — Vigie

Analyse du 07/08/2026. Complète `docs/EVALUATION_TECHNIQUE.md`, qui traitait de la
technologie et du déploiement. Ce document répond à une autre question : **qu'est-ce qui,
dans ce code précis, coûtera cher dans deux ans ?**

Le critère retenu n'est pas l'esthétique. C'est : *combien de fichiers faut-il modifier
pour faire un changement, et qu'est-ce qui échoue bruyamment si on l'oublie ?*

> **État au 07/08/2026.** M2, M4 et M5 sont traités, ainsi que le seuil de
> couverture. Le diagnostic complet est conservé : il explique pourquoi chaque
> correction a été faite. M1 et M3 restent ouverts et sont les prochains chantiers.
> Couverture passée de 90 % à 94 %, worker de 37 % à 100 %, plus aucun module à 0 %.
>
> **Fusion du 24/09/2026 avec les items 5-18**, développés en parallèle :
> - `crowdstrike.py` est désormais un vrai client Falcon Spotlight (item 5) ; le
>   `NotImplementedError` décrit en M2 n'a plus lieu d'être.
> - Le worker prend un chemin de fichier et gère un `ScanJob` : ses tests sont répartis
>   entre `tests/test_worker_tasks.py` (cycle de vie du job, synchro CrowdStrike) et
>   `tests/test_worker_failures.py` (rollback, reprises, fermeture de session). Avec
>   la nouvelle tâche de synchro, `tasks.py` est à 88 % et le total à 92 %.
> - M3 est partiellement traité : ESLint, Prettier et 10 tests Vitest (item 15). Le
>   style inline reste en place.

---

## Point de départ : ce qui est déjà bon

Il faut le dire, parce que ça détermine la stratégie. Trois choses rendent ce projet
plus maintenable que la moyenne, et il faut éviter de les casser :

1. **Les services sont purs.** `risk_scoring` et `remediation` ne connaissent ni HTTP, ni
   Celery, ni la session SQLAlchemy. C'est ce qui permet de les tester en millisecondes et
   de changer la formule de risque sans toucher à l'API.
2. **Les commentaires expliquent le *pourquoi*, pas le *quoi*.** `risk_scoring.py:3-7`
   justifie l'existence du score contextuel ; `security.py:56-58` explique pourquoi le
   hash factice existe. Un mainteneur futur ne supprimera pas ces lignes par erreur.
   C'est rare et c'est précieux.
3. **90 % de couverture** (`pytest --cov`), avec des tests qui décrivent des règles
   métier, pas des lignes de code.

La stratégie de maintenabilité consiste donc à **étendre ces trois propriétés aux zones
qui ne les ont pas**, plutôt qu'à réécrire quoi que ce soit.

---

## 1. Les cinq points de douleur réels

### M1 — Le contrat entre parseurs et ingestion n'est vérifié par rien

`app/parsers/utils.py:1-16` décrit en docstring la forme exacte que chaque parseur doit
émettre. C'est la bonne intention, mais c'est du texte : rien ne l'applique.

`ingestion.py` fait ensuite `finding["ip_address"]`, `finding["cve_id"]`, `finding["hostname"]`…
en accès direct. Un parseur qui oublie une clé provoque un `KeyError` **dans le worker
Celery**, c'est-à-dire dans le composant le moins observable de la plateforme, sur un
scan client, en production.

C'est le point le plus coûteux du projet, parce qu'ajouter un parseur (Qualys, Rapid7,
CrowdStrike un jour) est **le scénario d'évolution le plus probable** — c'est même la
promesse d'un produit RBVM.

> **Correction** : une dataclass `ParsedFinding` (ou un modèle Pydantic) retournée par
> tous les parseurs. Le contrat devient exécutable, l'erreur passe du worker à l'appel de
> fonction, et l'autocomplétion de l'IDE remplace la lecture de la docstring.
> Effort : 3 h. C'est le meilleur rapport valeur/coût du document.

> **Mise à jour du 25/09/2026** : les parseurs de fichiers renvoient désormais un
> `ParsedScan` (`app/parsers/utils.py`) : les findings plus les adresses couvertes par
> le scan, dont dépend la clôture automatique. L'enveloppe est typée, mais les findings
> restent des dictionnaires : M1 reste ouvert, et `ParsedScan` est l'endroit naturel où
> accrocher `ParsedFinding`.

### M2 — Le worker Celery est le point le moins couvert, et le plus risqué ✅ *traité*

`app/worker/tasks.py` : **37 % de couverture**, lignes 35-59 jamais exécutées. Or c'est
exactement le code qui gère les reprises, les échecs, et le `rollback`. La logique de
retry (`autoretry_for`, `max_retries`) n'est vérifiée par aucun test.

`app/parsers/crowdstrike.py` : **0 %**. Du code mort qui compile, donc qui donne
l'illusion d'exister.

Le paradoxe : la partie asynchrone est à la fois la moins testée et la plus difficile à
déboguer en production, puisqu'elle n'a pas de requête HTTP à laquelle rattacher une
erreur.

> **Corrigé.** `tests/test_worker_tasks.py` (11 tests) couvre le rollback, la remontée
> de l'exception tant qu'il reste des tentatives, l'abandon à la dernière, la fermeture
> systématique de la session, et le fait qu'un type de scan inconnu échoue immédiatement
> plutôt que de consommer trois tentatives. Un test vérifie aussi que `VALID_SCAN_TYPES`
> (API) et `PARSERS` (worker) restent identiques : sinon un upload est accepté puis
> silencieusement ignoré. **`tasks.py` : 37 % → 100 %.**
>
> Pour `crowdstrike.py`, la décision prise est intermédiaire et assumée :
> `fetch_vulnerabilities()` lève désormais `NotImplementedError` au lieu de retourner des
> données de démonstration. Retourner des findings inventés dans une plateforme RBVM est
> le pire comportement possible — ils entrent en base, remontent dans le backlog priorisé
> et déclenchent des remédiations sur des vulnérabilités inexistantes. La suppression
> complète du module reste une décision produit (point 5 de `TODO.md`).

### M3 — Le frontend n'a aucun filet, et son style est inline

Zéro test frontend. Chaque modification d'un composant est validée à l'œil, ou pas
validée du tout.

Plus insidieux : le style est écrit en `style={{...}}` inline
(`VulnerabilitiesList.jsx:45-71` : 27 lignes de style pour deux champs de formulaire). Le
même bloc de pagination est dupliqué à l'identique dans `AssetsList` et
`VulnerabilitiesList`. Changer la charte graphique demande de relire tous les composants.

Et le debounce passe par des variables globales (`window._vulnSearchTimer`) : deux
composants montés simultanément se marchent dessus.

> **Correction, par ordre de rentabilité** :
> 1. Vitest + Testing Library sur les 3 parcours critiques : connexion, triage d'un
>    finding, upload d'un scan. 4 h, et ça arrête les régressions les plus coûteuses.
> 2. Extraire `<DataTable>`, `<Pagination>`, `<SearchInput>` : supprime la duplication.
> 3. `useDebounce` en hook, ce qui élimine les variables globales.
> 4. TanStack Query à la place de `useFetch`, qui a un bug latent : `fetchFn` n'est pas
>    dans les dépendances de son `useCallback`.

### M4 — Les politiques métier sont éparpillées en constantes de module ✅ *partiellement traité*

Les règles qui *vont changer* sont dispersées :

| Règle | Emplacement |
|---|---|
| Fenêtres SLA par sévérité | `services/remediation.py:7` |
| Multiplicateurs de criticité | `services/risk_scoring.py:13` |
| Pénalité de retard, plafond | `services/risk_scoring.py:22-23` |
| Seuils de niveau de risque | `services/risk_scoring.py:43-51` |
| Seuils CVSS → sévérité | `parsers/utils.py:47-53` |

Deux problèmes. D'abord, ces valeurs sont **la politique de sécurité du client**, pas des
constantes techniques : chaque organisation a ses propres fenêtres SLA. Aujourd'hui, les
changer demande de modifier le code et de redéployer.

Ensuite, les seuils de `risk_level()` (≥9 Critical) et ceux de `severity_from_cvss()`
(≥9 Critical) sont **numériquement identiques mais indépendants**. Modifier l'un sans
l'autre crée une incohérence silencieuse : un finding affiché « High » avec un score de
risque « Critical ». Personne ne le remarquera avant un audit.

> **Partiellement corrigé.** `tests/test_policy_consistency.py` (15 tests) transforme la
> dérive silencieuse en échec bruyant : accord des deux échelles sur chaque borne, chaque
> sévérité a un SLA, chaque criticité a un multiplicateur, les fenêtres SLA décroissent
> avec la gravité et les multiplicateurs croissent avec la criticité. Vérifié par mutation :
> passer le seuil « High » de 7.0 à 6.0 fait bien échouer la suite avec un message qui
> nomme la divergence.
>
> **Reste à faire** : regrouper dans `app/services/policy.py` avec surcharge par variables
> d'environnement, pour que chaque organisation puisse définir ses propres fenêtres SLA
> sans modifier le code. Effort : 2 h.

### M5 — Le nom du produit est incohérent, ce qui use la confiance ✅ *traité*

Le dépôt s'appelle **Vigie**. `config.py:19` dit `PROJECT_NAME = "TVM Platform"`. Les
conteneurs s'appellent `tvm_db`, `tvm_api`, `tvm_celery_worker`. `package.json` dit
`tvm-frontend`. Le volume est `pgdata`, la base `tvm_platform`.

Ça paraît cosmétique. Ça ne l'est pas : un nouvel arrivant perd du temps à chercher si
« TVM » est un autre composant, et chaque recherche `grep` dans le dépôt renvoie deux
vocabulaires. C'est le genre de dette qui ne fait jamais assez mal pour être corrigée,
et qui coûte un peu à chaque fois.

> **Corrigé.** `PROJECT_NAME`, conteneurs (`vigie_db`, `vigie_api`, `vigie_worker`…),
> utilisateur et base PostgreSQL, `package.json` : tout est aligné sur « Vigie ». Fait
> maintenant précisément parce qu'il n'y a pas encore de production : renommer la base
> aurait sinon imposé une migration de données. Les documents qui *décrivent* l'ancienne
> incohérence la citent encore, volontairement.

---

## 2. Ce qui protège déjà, et qu'il faut renforcer

La CI mise en place couvre l'essentiel. Trois ajouts la rendraient réellement dissuasive :

- **Un seuil de couverture bloquant** (`--cov-fail-under=85`). Sans seuil, la couverture
  est une statistique que personne ne regarde ; avec, c'est une contrainte. À poser au
  niveau actuel (90 %) pour interdire la régression, pas au niveau idéal.
- **`mypy` en mode graduel.** Le code est déjà largement annoté (`Mapped[]`, signatures
  typées). Activer `mypy` sur `app/services/` et `app/parsers/` d'abord, là où le typage
  est le plus dense et le gain le plus direct, puis étendre.
- **Dependabot.** Sur une plateforme de gestion de vulnérabilités, laisser ses propres
  dépendances vieillir est un problème de crédibilité autant que de sécurité.

---

## 3. La dette qui grossit toute seule

Trois éléments deviennent **plus chers à corriger avec le temps**. Ce sont ceux à traiter
en priorité, indépendamment de leur gravité actuelle :

1. **Le renommage TVM → Vigie** (M5). Coût multiplié par la présence de données de
   production.
2. **L'absence d'historique de triage** (point 10 de `TODO.md`). Chaque `PATCH` écrase
   `status` et `status_note`. Chaque jour sans table d'audit est un jour d'historique
   définitivement perdu — c'est la seule dette du projet qui **détruit de l'information
   irrécupérable**. Pour un usage réglementaire, c'est rédhibitoire.
3. **Le contrat de parseur implicite** (M1). Chaque nouveau parseur écrit avant la
   formalisation du contrat est un parseur à reprendre ensuite.

---

## 4. Ordre d'attaque conseillé

Trié par (valeur × urgence) / coût, pas par gravité :

### ✅ Fait le 07/08/2026

| # | Action | Résultat |
|---|---|---|
| M5 | Renommage TVM → Vigie | Un seul vocabulaire dans tout le dépôt |
| M2 | 11 tests du worker + CrowdStrike qui refuse de servir | `tasks.py` 37 % → 100 % |
| M4 | 15 tests de cohérence de la politique de risque | Dérive des seuils détectée, vérifié par mutation |
| — | Seuil de couverture bloquant (`fail_under = 90`) | La régression de couverture échoue en CI |

Couverture globale : **90 % → 94 %**. Tests : 143 → 175. Plus aucun module à 0 %.

### Reste à faire

| # | Action | Effort | Pourquoi maintenant |
|---|---|---|---|
| 10 | Table d'audit du triage | 3 h | Chaque jour d'attente perd de l'information définitivement |
| M1 | `ParsedFinding` : contrat de parseur exécutable | 3 h | Débloque tout ajout de scanner |
| M4b | `policy.py` + surcharge par variables d'environnement | 2 h | La politique SLA appartient au client, pas au code |
| M3 | Vitest sur 3 parcours, puis extraction de composants | 6 h | Le frontend n'a toujours aucun filet |
| — | `mypy` graduel + Dependabot | 2 h | Complète l'outillage de la CI |

**Environ 16 h restantes.**

---

## 5. La règle qui compte le plus

Au-delà de la liste : **ce projet est déjà bien documenté par ses commentaires
d'intention**. C'est son principal atout de maintenabilité, plus que son architecture.

La règle à tenir, si une seule doit l'être : *quand une décision non évidente est prise,
écrire pourquoi, pas quoi*. Les commentaires du type « pourquoi ce hash factice existe »
ou « pourquoi la validation du CVE n'est que sur l'entrée » sont ce qui empêchera un
mainteneur futur de « simplifier » une protection en la supprimant.

Le reste — tests, typage, CI — sert à rendre ces intentions **vérifiables**. Aucun outil
ne remplace le fait de les avoir écrites.
