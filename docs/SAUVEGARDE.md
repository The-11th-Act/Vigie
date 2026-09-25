# Sauvegarde et restauration de la base Vigie

La base contient l'historique des findings et le journal d'audit du triage :
qui a accepté quel risque, quand, et pourquoi. La perdre, c'est perdre la
trace exigée par un usage réglementaire. Ce document est la procédure ; le job
CI « Pile de production de bout en bout » la rejoue à chaque commit
(`scripts/smoke_prod_stack.sh`) : sauvegarde, destruction de la base,
restauration, vérification par l'API.

## Ce qui tourne

Le service `backup` de `docker-compose.prod.yml` (image `deploy/backup/`) :

- fait une sauvegarde au démarrage, puis toutes les `BACKUP_INTERVAL_HOURS`
  heures (24 par défaut) ;
- `pg_dump` au format custom, **chiffré avec age** pour la clé publique
  `BACKUP_AGE_RECIPIENT` : le serveur ne détient pas de quoi déchiffrer ;
- écrit `vigie-AAAAMMJJTHHMMSSZ.dump.age` dans `/backups` (volume `backups`,
  ou le chemin `BACKUP_VOLUME`), via un fichier `.partial` renommé à la fin :
  une sauvegarde interrompue ne ressemble jamais à une sauvegarde valide ;
- supprime, après chaque succès seulement, les sauvegardes de plus de
  `BACKUP_RETENTION_DAYS` jours (14 par défaut) ;
- passe `unhealthy` s'il n'existe aucune sauvegarde de moins de deux
  intervalles : c'est le signal à surveiller.

## Mise en place

1. Sur un poste d'administration (pas sur le serveur), générer la paire :
   ```bash
   age-keygen -o vigie-backup.key
   # Public key: age1....
   ```
   Ranger `vigie-backup.key` dans le coffre de l'équipe. **Sans elle, aucune
   sauvegarde n'est restaurable.**
2. Reporter la clé publique dans le `.env` du serveur :
   `BACKUP_AGE_RECIPIENT=age1...`
3. Placer les sauvegardes hors du disque de la base. Une sauvegarde sur le même
   disque disparaît avec lui : monter un autre stockage et le désigner par
   `BACKUP_VOLUME=/mnt/nas/vigie` (répertoire appartenant à l'uid 70), ou
   copier régulièrement le volume `backups` ailleurs.
4. Vérifier au démarrage :
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml logs backup
   # [vigie-backup] sauvegarde écrite : /backups/vigie-...dump.age (…)
   ```

## Sauvegarde à la demande

Avant une mise à jour ou une migration :

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec backup vigie-backup
```

## Restauration

La restauration remplace le contenu de la base par celui de la sauvegarde, en
une seule transaction : elle réussit entièrement ou ne change rien.

```bash
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"

# 1. Arrêter ce qui écrit dans la base (et Nginx, qui garde l'adresse de l'API).
$COMPOSE stop frontend web worker beat

# 2. Lister les sauvegardes disponibles.
$COMPOSE exec backup ls -l /backups

# 3. Restaurer, avec la clé privée montée en lecture seule le temps de l'opération.
$COMPOSE run --rm \
  -v /chemin/vers/vigie-backup.key:/run/age.key:ro \
  -e BACKUP_AGE_IDENTITY=/run/age.key \
  backup vigie-restore /backups/vigie-AAAAMMJJTHHMMSSZ.dump.age --yes

# 4. Relancer. Le service migrate rejoue les migrations : une sauvegarde plus
#    ancienne que le code est mise à niveau.
$COMPOSE up -d
```

La clé privée doit être lisible par l'uid 70 dans le conteneur
(`chmod 644` sur une copie temporaire, supprimée ensuite).

Restaurer une sauvegarde plus **récente** que le code déployé (retour arrière
de version) n'est pas pris en charge : redéployer d'abord la version qui l'a
produite.
