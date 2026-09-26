# Service de sauvegarde de la base Vigie (point D8 de l'audit).
#
# Même image que la base : pg_dump doit être de la même version majeure que le
# serveur, sinon il refuse de sauvegarder (ou produit une archive que le
# serveur ne sait pas relire). Changer l'une impose de changer l'autre.
FROM postgres:15-alpine@sha256:f7d23353e1b15400d22ebe31189f4d314b87a4c129cc400c8c2d8d4ca127bf81

# age : chiffrement asymétrique des sauvegardes (https://age-encryption.org).
RUN apk add --no-cache age

COPY vigie-backup vigie-restore vigie-backup-loop /usr/local/bin/
RUN chmod 0755 /usr/local/bin/vigie-backup /usr/local/bin/vigie-restore \
        /usr/local/bin/vigie-backup-loop \
    && mkdir -p /backups \
    && chown postgres:postgres /backups

# Un volume nommé monté sur /backups hérite de ce propriétaire à sa création.
USER postgres
WORKDIR /backups

# Sain tant qu'une sauvegarde de moins de deux intervalles existe : une
# sauvegarde manquée passe, deux d'affilée rendent le conteneur « unhealthy ».
HEALTHCHECK --interval=5m --timeout=10s --start-period=10m --retries=1 \
    CMD find /backups -maxdepth 1 -name 'vigie-*.dump*' ! -name '*.partial' \
        -mmin -$(( ${BACKUP_INTERVAL_HOURS:-24} * 120 )) | grep -q .

# Le point d'entrée de l'image postgres démarrerait un serveur : on le retire.
ENTRYPOINT []
CMD ["vigie-backup-loop"]
