# Préproduction et promotion

Une version n'arrive en production qu'après avoir tourné en préproduction, et
c'est **la même image** qui passe de l'une à l'autre : la production ne
reconstruit rien.

Dans les commandes ci-dessous :

```bash
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
```

## Principe

| Environnement | Lancement | Rôle |
|---|---|---|
| Développement | `docker-compose.yml` seul, ou le venv | Écrire le code |
| Préproduction | `$COMPOSE`, depuis son propre checkout | Construire et valider une version |
| Production | `$COMPOSE`, depuis son propre checkout | Exécuter la version validée |

La préproduction n'a pas de surcouche à elle : elle lance **le même**
`docker-compose.prod.yml`, avec `ENVIRONMENT=production` (cookies `Secure`,
clé de signature faible refusée, documentation interactive masquée). Un écart
de configuration entre les deux serait précisément ce que la préproduction ne
testerait plus. Ce qui les distingue n'est que de la configuration, dans le
`.env` et le répertoire `secrets/` de chaque checkout.

Aucun conteneur ne porte de nom figé : conteneurs, réseau et volumes sont
nommés d'après le projet compose (`COMPOSE_PROJECT_NAME`). Les deux piles
peuvent donc partager un hôte sans rien partager d'autre.

## Mise en place

Un checkout par environnement, sur le même hôte ou non :

```bash
sudo git clone https://github.com/The-11th-Act/Vigie.git /opt/vigie-staging
cd /opt/vigie-staging
# Secrets propres, créés comme pour la production (README, « Running in
# production ») : jamais une copie de ceux de la production.
# .env : section [PROD] de .env.example, puis ce qui suit.
```

Ce qui doit différer entre les deux `.env` :

| Réglage | Production | Préproduction | Pourquoi |
|---|---|---|---|
| `COMPOSE_PROJECT_NAME` | `vigie` | `vigie-staging` | Nomme conteneurs, réseau et volumes |
| `INSTANCE_BANNER` | Vide | `Préproduction` | Bandeau sur chaque écran, connexion comprise, et dans le titre de l'onglet |
| `FRONTEND_PORT` | `8080` | `8081` | Deux piles sur un hôte |
| `secrets/` | Les siens | Les siens | Une fuite en préproduction ne doit pas permettre de signer un token de production |
| `BACKEND_CORS_ORIGINS` | `https://vigie.example.com` | `https://vigie-staging.example.com` | Un nom d'hôte par environnement, derrière le terminateur TLS |
| `BACKUP_VOLUME` | Stockage dédié | Vide (volume du projet) | Deux services de sauvegarde dans un même répertoire appliqueraient chacun sa rétention aux fichiers de l'autre |
| `CROWDSTRIKE_SYNC_ENABLED` | Selon l'usage | `false`, ou un client API dédié | Ne pas consommer deux fois le quota du tenant |

La copie hors site (`docker-compose.offsite.yml`) n'a pas lieu d'être en
préproduction.

> **Production existante** : `COMPOSE_PROJECT_NAME` doit reprendre le nom sous
> lequel la pile tourne déjà (par défaut, le nom du répertoire du checkout ;
> `docker volume ls` montre `<projet>_pgdata`). Avec un autre nom, compose
> crée des volumes vides et la production démarre sans ses données (les
> anciennes restent dans les anciens volumes).

## Données de la préproduction

Deux possibilités :

- **Vide**, alimentée par des scans de test : suffisant pour une version sans
  migration.
- **Une copie de la production**, restaurée juste avant la version à valider :
  c'est la seule répétition réaliste d'une migration (volume réel, données
  réelles). La préproduction contient alors les données et les comptes de la
  production : elle doit être aussi protégée qu'elle. Les sessions de
  production n'y sont pas valides (autre clé de signature), les mots de passe
  si.

Copie de la production vers la préproduction, sur un même hôte (sinon,
transférer le fichier entre les deux) :

```bash
# 1. Dans le checkout de production : une sauvegarde fraîche, copiée hors du
#    conteneur.
cd /opt/vigie
$COMPOSE exec backup vigie-backup           # affiche /backups/vigie-….dump.age
$COMPOSE cp backup:/backups/vigie-AAAAMMJJTHHMMSSZ.dump.age /tmp/prod.dump.age

# 2. Dans le checkout de préproduction : restauration avec la clé privée de la
#    production, montée le temps de l'opération.
cd /opt/vigie-staging
$COMPOSE stop frontend web worker beat
$COMPOSE run --rm \
  -v /tmp/prod.dump.age:/run/prod.dump.age:ro \
  -v /chemin/vers/vigie-backup.key:/run/age.key:ro \
  -e BACKUP_AGE_IDENTITY=/run/age.key \
  backup vigie-restore /run/prod.dump.age --yes
rm /tmp/prod.dump.age
```

Les deux fichiers doivent être lisibles par l'uid 70 dans le conteneur
(`chmod 644` sur des copies temporaires, supprimées ensuite), comme pour une
restauration ordinaire ([`SAUVEGARDE.md`](SAUVEGARDE.md)). Le `up` de l'étape
suivante joue les migrations de la nouvelle version sur ces données.

## Chemin de promotion

1. **Développement.** Le commit est sur `main` et la CI est verte, job
   « Pile de production de bout en bout » compris.
2. **Nommer la version.** Une étiquette git, par exemple
   `git tag v2026.10.1 && git push origin v2026.10.1`. Elle nomme aussi les
   images : `vigie-api`, `vigie-frontend` et `vigie-backup` en `:v2026.10.1`.
3. **Construire et démarrer en préproduction.**
   ```bash
   cd /opt/vigie-staging
   git fetch --tags && git checkout v2026.10.1
   # .env : VIGIE_VERSION=v2026.10.1
   # Si la version contient des migrations
   # (git diff --stat <version en production> v2026.10.1 -- app/db/migrations/),
   # restaurer d'abord une copie de la production (section précédente).
   $COMPOSE build
   $COMPOSE up -d
   ```
4. **Valider.** `$COMPOSE ps` : tout est `healthy` et `migrate` s'est terminé
   en 0 (`$COMPOSE logs migrate`). Se connecter, ouvrir le backlog, déposer un
   scan et le voir ingéré, parcourir les écrans touchés par la version.
5. **Promouvoir la même image.**
   ```bash
   cd /opt/vigie
   $COMPOSE exec web alembic current     # révision en place : à noter
   $COMPOSE exec backup vigie-backup     # point de retour
   git fetch --tags && git checkout v2026.10.1
   # .env : VIGIE_VERSION=v2026.10.1
   $COMPOSE up -d --no-build --pull never
   ```
   Le checkout apporte les fichiers compose de la version ; les images, elles,
   sont celles que la préproduction a construites. `--no-build` interdit de
   les reconstruire depuis les sources, `--pull never` d'en télécharger
   d'autres : si une image manque, le démarrage échoue.

   **Sur deux hôtes**, les images passent par un registre. Dans les deux
   `.env` : `VIGIE_REGISTRY=registry.example.com/vigie/` (barre finale
   comprise). Après l'étape 4, en préproduction :
   `$COMPOSE push web frontend backup` ; en production, avant le `up` :
   `$COMPOSE pull web frontend backup`. `web` porte l'image commune à
   `migrate`, `worker` et `beat`. Sans registre :
   `docker save vigie-api:v2026.10.1 vigie-frontend:v2026.10.1 vigie-backup:v2026.10.1 | ssh prod docker load`.
6. **Vérifier la production.** Comme à l'étape 4, sans déposer de scan de
   test ; `$COMPOSE images` affiche la version.

## Retour arrière

Garder les images de la version précédente sur l'hôte de production jusqu'à
la promotion suivante.

**Version sans migration** : revenir à l'étiquette précédente (`git checkout`,
`VIGIE_VERSION` dans le `.env`), puis `$COMPOSE up -d --no-build --pull never`.

**Version avec migrations** : l'ancien code ne connaît pas le nouveau schéma.
Deux voies :

- **Redescendre le schéma avec la nouvelle image**, avant de changer de
  version : l'ancienne ne connaît pas les révisions à défaire.
  ```bash
  $COMPOSE run --rm migrate alembic downgrade <révision notée à l'étape 5>
  ```
  La CI joue chaque migration dans les deux sens, mais une colonne supprimée
  en redescendant emporte ce qui y a été écrit depuis la promotion.
- **Restaurer le point de retour** de l'étape 5 ([`SAUVEGARDE.md`](SAUVEGARDE.md)),
  puis démarrer la version précédente : tout ce qui a été écrit depuis la
  promotion est perdu.

Dans les deux cas, finir par le retour à l'étiquette précédente, comme pour
une version sans migration.

## Limites connues

- Le bandeau (`INSTANCE_BANNER`) est la seule chose qui distingue les deux
  interfaces : sans lui, avec une copie des données de production, une
  décision qu'on croit prendre en production (acceptation de risque) n'est
  prise qu'en préproduction. Le libellé vient de l'API et non du build, puisque
  les deux environnements exécutent la même image du frontend.
- Le futur connecteur de ticketing et les webhooks devront pouvoir viser un
  bac à sable en préproduction : une copie des tickets de production ne doit
  jamais écrire dans le Jira de production.
