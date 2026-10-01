#!/usr/bin/env bash
# Démarre la pile de PRODUCTION complète (docker-compose.yml + surcouche prod)
# et la traverse comme un utilisateur : Nginx -> API -> Redis -> worker ->
# PostgreSQL, puis vérifie que les réglages du .env atteignent bien chaque
# conteneur.
#
# Les autres jobs de la CI testent les images une par une (docker run) et
# valident les fichiers compose sans les démarrer : ni la fusion réelle des
# fichiers, ni le volume partagé des uploads, ni le mot de passe Redis, ni le
# câblage des réglages n'étaient exercés ensemble.
#
# Usage : scripts/smoke_prod_stack.sh   (Docker requis ; détruit ses volumes)

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -p vigie-smoke -f docker-compose.yml -f docker-compose.prod.yml)
BASE="http://127.0.0.1:${FRONTEND_PORT:-8080}"
API="$BASE/api/v1"
ADMIN_PASSWORD="Smoke-Admin-Passw0rd!2026"
WORK="$(mktemp -d)"

# Copie hors site : la surcouche réelle, avec pour destination un répertoire
# de l'hôte (backend rclone « local ») plutôt qu'un stockage objet, pour
# vérifier le chemin complet sans service externe.
install -d -m 777 "$WORK/offsite"
cat > "$WORK/offsite-target.yml" <<EOF
services:
  backup:
    volumes:
      - "$WORK/offsite:/offsite"
EOF
COMPOSE+=(-f docker-compose.offsite.yml -f "$WORK/offsite-target.yml")

fail() {
  echo "::error::$*"
  echo "----- état des conteneurs -----"
  "${COMPOSE[@]}" ps -a || true
  # Service par service : les journaux de l'API noieraient sinon ceux d'un
  # conteneur qui redémarre en boucle.
  for service in frontend web worker beat migrate; do
    echo "----- journaux : $service -----"
    "${COMPOSE[@]}" logs --no-color --tail=40 "$service" || true
  done
  exit 1
}

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  if [ -n "${CREATED_ENV:-}" ]; then rm -f .env; fi
}
trap cleanup EXIT

# --- .env de production factice --------------------------------------------
if [ -e .env ]; then
  echo "Un .env existe déjà : ce script n'écrase pas une configuration réelle." >&2
  exit 2
fi
CREATED_ENV=1

# Secrets : des fichiers montés en Docker secrets, comme en production,
# jamais dans le .env. Répertoire en 0700, fichiers lisibles une fois montés.
SECRETS="$WORK/secrets"
install -d -m 700 "$SECRETS"
openssl rand -base64 48 | tr -d '\n' > "$SECRETS/secret_key"
echo "smoke-$(openssl rand -hex 12)" > "$SECRETS/postgres_password"
echo "smoke-$(openssl rand -hex 12)" > "$SECRETS/redis_password"
echo '{}' > "$SECRETS/previous_secret_keys"
printf '[offsite]\ntype = local\n' > "$SECRETS/rclone.conf"
chmod 444 "$SECRETS"/*

cat > .env <<EOF
VIGIE_VERSION=smoke
VIGIE_SECRETS_DIR=$SECRETS
BACKUP_REMOTE=offsite:/offsite
POSTGRES_USER=vigie
POSTGRES_DB=vigie
BACKEND_CORS_ORIGINS=["https://vigie.example.com"]
# Réglages métier : leur effet est vérifié plus bas, dans chaque conteneur.
CRITICALITY_RULES={"203.0.113.0/24":"Critical"}
INTERNET_FACING_SUBNETS=["203.0.113.0/24"]
OWNER_TEAM_RULES={"203.0.113.0/24":"Perimeter"}
ENVIRONMENT_RULES={"203.0.113.0/24":"production"}
KEV_SLA_DAYS=7
# Le destinataire de test est un conteneur du réseau du projet : adresse
# privée, en HTTP.
WEBHOOK_ALLOW_PRIVATE_TARGETS=true
WEBHOOK_ALLOW_HTTP=true
WEBHOOK_DELIVERY_INTERVAL_SECONDS=5
LOG_FORMAT=json
THREAT_INTEL_ENABLED=true
INSTANCE_BANNER=Smoke
EOF

# --- Clé de sauvegarde -----------------------------------------------------
# Générée avec l'outil de l'image, comme le ferait un administrateur ; seule la
# clé publique va dans le .env, la clé privée ne sert qu'à la restauration.
"${COMPOSE[@]}" build backup
"${COMPOSE[@]}" run --rm --no-deps -T backup age-keygen > "$WORK/age.key" 2>/dev/null
RECIPIENT=$(sed -n 's/^# public key: //p' "$WORK/age.key")
[ -n "$RECIPIENT" ] || fail "age-keygen n'a pas produit de clé"
echo "BACKUP_AGE_RECIPIENT=$RECIPIENT" >> .env
# Lisible par l'uid postgres du conteneur de restauration (clé jetable).
chmod 644 "$WORK/age.key"

# --- Démarrage -------------------------------------------------------------
# /healthz est servi par Nginx lui-même ; le 401 d'une route protégée prouve
# qu'il joint bien l'API (après un redémarrage, l'adresse de l'API change).
wait_for_api() {
  local ready=""
  for _ in $(seq 1 90); do
    if curl -fsS "$BASE/healthz" >/dev/null 2>&1 \
      && [ "$("${COMPOSE[@]}" ps --format '{{.Health}}' web)" = "healthy" ] \
      && [ "$(curl -s -o /dev/null -w '%{http_code}' "$API/threat-intel/status")" = 401 ]; then
      ready=1
      break
    fi
    sleep 2
  done
  [ "$ready" = 1 ] || fail "l'API n'est jamais devenue saine derrière Nginx"
}

echo "Construction et démarrage de la pile de production..."
"${COMPOSE[@]}" up -d --build

echo "Attente de l'API derrière Nginx..."
wait_for_api
echo "API saine (/ready, donc PostgreSQL, Redis et un worker)."

# Le bandeau d'instance se lit avant toute connexion, à travers Nginx : c'est
# sur l'écran de connexion qu'une préproduction doit se distinguer.
BANNER=$(curl -fsS "$API/instance" | jq -r .banner) || fail "/instance inaccessible sans session"
[ "$BANNER" = "Smoke" ] || fail "INSTANCE_BANNER n'atteint pas l'API (« $BANNER »)"
echo "ok - bandeau d'instance lisible sans session, à travers Nginx"

# --- Images de la version ---------------------------------------------------
# La promotion (docs/PREPRODUCTION.md) repose sur une image par version :
# l'API, les migrations, le worker et le beat exécutent la même, celle que la
# production recevra sans la reconstruire.
API_IMAGE=$(docker image inspect --format '{{.Id}}' vigie-api:smoke) \
  || fail "image vigie-api:smoke absente après le build"
for service in migrate web worker beat; do
  cid=$("${COMPOSE[@]}" ps -a -q "$service")
  [ "$(docker inspect --format '{{.Image}}' "$cid")" = "$API_IMAGE" ] \
    || fail "$service n'exécute pas l'image vigie-api:smoke"
done
for image in vigie-frontend:smoke vigie-backup:smoke; do
  docker image inspect "$image" >/dev/null 2>&1 || fail "image $image absente après le build"
done
echo "ok - une image par version : vigie-api, vigie-frontend et vigie-backup en :smoke"

# --- Métriques additionnées sur les process uvicorn ------------------------
# Chaque process déclare sa capacité (API_THREADS, 10) au démarrage : seule la
# somme des 4 process par défaut donne 40. Un scrape qui ne verrait qu'un
# process, comme avant le mode multiprocessus, lirait 10.
# Les 4 process démarrent ensemble mais pas au même instant : on attend.
for _ in $(seq 1 15); do
  THREADS=$("${COMPOSE[@]}" exec -T web curl -fsS http://localhost:8000/metrics \
    | sed -n 's/^vigie_api_threads //p')
  [ "$THREADS" = "40.0" ] && break
  sleep 2
done
[ "$THREADS" = "40.0" ] \
  || fail "vigie_api_threads vaut « $THREADS » : les métriques des 4 process ne sont pas additionnées"
echo "ok - métriques additionnées sur les 4 process uvicorn (capacité : $THREADS threads)"

# --- Premier administrateur, par le chemin documenté ------------------------
"${COMPOSE[@]}" run --rm -T -e ADMIN_PASSWORD="$ADMIN_PASSWORD" web \
  python -m scripts.create_admin --username admin --email admin@example.com \
  --password-from-env || fail "création de l'administrateur impossible"

TOKEN=$(curl -fsS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .access_token) \
  || fail "connexion impossible via Nginx"
AUTH=(-H "Authorization: Bearer $TOKEN")

# Session navigateur : cookies HttpOnly, et Secure puisque ENVIRONMENT vaut
# production (le terminateur TLS est devant Nginx). curl ne les renverrait pas
# en HTTP ; on vérifie donc les en-têtes Set-Cookie eux-mêmes.
COOKIE_HEADERS=$(curl -fsS -D - -o /dev/null -X POST "$API/auth/login" \
  -H 'Content-Type: application/json' -H 'X-Session-Mode: cookie' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" | tr -d '\r')
ACCESS_COOKIE=$(echo "$COOKIE_HEADERS" | grep -i '^set-cookie: vigie_access=' || true)
[ -n "$ACCESS_COOKIE" ] || fail "le login en mode cookie ne pose pas vigie_access"
for attribute in HttpOnly Secure "SameSite=strict"; do
  echo "$ACCESS_COOKIE" | grep -qi "$attribute" \
    || fail "cookie de session sans l'attribut $attribute : $ACCESS_COOKIE"
done
echo "ok - session navigateur : cookie HttpOnly, Secure, SameSite=Strict"

# --- Destinataire de webhooks ------------------------------------------------
# Un conteneur de l'image de l'API, sur le réseau du projet, qui écrit chaque
# appel reçu sur une ligne JSON. Démarré une fois l'image construite : il n'a
# pas de build à lui, compose chercherait sinon à la télécharger.
cat > "$WORK/receiver.py" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        print(json.dumps({
            "event": self.headers["X-Vigie-Event"],
            "timestamp": self.headers["X-Vigie-Timestamp"],
            "signature": self.headers["X-Vigie-Signature"],
            "body": body,
        }), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Receiver).serve_forever()
PY
chmod 644 "$WORK/receiver.py"
cat > "$WORK/receiver.yml" <<EOF
services:
  receiver:
    image: vigie-api:smoke
    command: ["python", "-u", "/receiver.py"]
    volumes:
      - "$WORK/receiver.py:/receiver.py:ro"
    healthcheck:
      disable: true
EOF
RECEIVER=("${COMPOSE[@]}" -f "$WORK/receiver.yml")
"${RECEIVER[@]}" up -d --no-deps receiver || fail "destinataire de webhooks non démarré"

WEBHOOK_SECRET=$(curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"name":"smoke","url":"http://receiver:8080/hook","events":["scan.completed"]}' \
  "$API/admin/webhooks/" | jq -r .secret) || fail "webhook refusé par l'API"
[ -n "$WEBHOOK_SECRET" ] && [ "$WEBHOOK_SECRET" != null ] || fail "webhook créé sans secret"

# --- Upload -> Redis -> worker -> base --------------------------------------
cat > "$WORK/report.nessus" <<'XML'
<?xml version="1.0"?>
<NessusClientData_v2><Report name="smoke">
  <ReportHost name="203.0.113.10">
    <HostProperties><tag name="host-fqdn">edge-01</tag></HostProperties>
    <ReportItem severity="3" pluginName="Smoke finding">
      <cve>CVE-2024-3400</cve><cvss3_base_score>6.0</cvss3_base_score>
    </ReportItem>
  </ReportHost>
</Report></NessusClientData_v2>
XML

TASK=$(curl -fsS "${AUTH[@]}" -D "$WORK/upload.headers" \
  -F scan_type=nessus -F "file=@$WORK/report.nessus" \
  "$API/scans/upload" | jq -r .task_id) || fail "upload refusé"
UPLOAD_ID=$(tr -d '\r' < "$WORK/upload.headers" | sed -n 's/^[Xx]-[Rr]equest-[Ii][Dd]: //p')

for _ in $(seq 1 60); do
  STATUS=$(curl -fsS "${AUTH[@]}" "$API/scans/status/$TASK" | jq -r .status)
  [ "$STATUS" = "Success" ] && break
  [ "$STATUS" = "Failed" ] && fail "le worker a échoué sur le scan"
  sleep 2
done
[ "$STATUS" = "Success" ] || fail "le scan n'a jamais été traité (statut : $STATUS)"
echo "Scan ingéré par le worker via le volume partagé."

# Le worker n'expose aucune métrique : le compteur d'ingestion, lu dans
# l'historique des scans, doit tout de même le montrer côté API.
INGESTED=$("${COMPOSE[@]}" exec -T web curl -fsS http://localhost:8000/metrics \
  | sed -n 's/^vigie_findings_ingested_total{source="nessus"} //p')
[ "$INGESTED" = "1.0" ] \
  || fail "vigie_findings_ingested_total{source=\"nessus\"} vaut « $INGESTED », 1.0 attendu"
echo "ok - l'ingestion faite par le worker apparaît dans les métriques de l'API"

# LOG_FORMAT=json atteint les conteneurs, et l'id de la requête d'upload
# suit le scan jusqu'au worker : sa ligne d'ingestion le porte.
"${COMPOSE[@]}" logs --no-color --no-log-prefix worker | grep '^{' \
  | jq -e --arg id "$UPLOAD_ID" \
    'select(.request_id == $id and (.message | contains("Ingested")))' >/dev/null \
  || fail "pas de ligne JSON d'ingestion portant l'id $UPLOAD_ID dans les logs du worker"
[ "$("${COMPOSE[@]}" logs --no-color --no-log-prefix web | grep -c '^{')" -gt 0 ] \
  || fail "l'API n'écrit pas ses logs en JSON"
echo "ok - logs JSON, request_id propagé de l'API au worker ($UPLOAD_ID)"

# Le scan ingéré a mis un événement dans la boîte d'envoi ; le beat déclenche
# l'envoi (WEBHOOK_DELIVERY_INTERVAL_SECONDS=5), le worker l'adresse au
# destinataire (WEBHOOK_ALLOW_*), signé avec le secret rendu à l'enregistrement.
CALL=""
for _ in $(seq 1 30); do
  CALL=$("${RECEIVER[@]}" logs --no-color --no-log-prefix receiver \
    | grep '^{' | jq -c 'select(.event == "scan.completed")' | head -n 1)
  [ -n "$CALL" ] && break
  sleep 2
done
[ -n "$CALL" ] || fail "aucun webhook scan.completed reçu en 60 s"
BODY=$(jq -r .body <<<"$CALL")
EXPECTED="sha256=$(printf '%s.%s' "$(jq -r .timestamp <<<"$CALL")" "$BODY" \
  | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.*= //')"
[ "$EXPECTED" = "$(jq -r .signature <<<"$CALL")" ] || fail "signature du webhook invalide"
[ "$(jq -r .data.scan.status <<<"$BODY")" = Success ] \
  || fail "webhook reçu sans le scan réussi : $BODY"
echo "ok - webhook scan.completed reçu, signé, par le beat et le worker"

# Aucun secret dans ce que `docker inspect` montre : environnement et
# commande de chaque conteneur. Redis n'y voit que "$(cat ...)".
for service in db redis migrate web worker beat backup; do
  cid=$("${COMPOSE[@]}" ps -a -q "$service")
  [ -n "$cid" ] || continue
  config=$(docker inspect "$cid" --format '{{json .Config.Env}} {{json .Config.Cmd}}')
  # Les valeurs secretes elles-memes ; {} ou une config rclone de test
  # pourraient apparaitre par hasard.
  for secret in "$SECRETS/secret_key" "$SECRETS/postgres_password" "$SECRETS/redis_password"; do
    if grep -qF -- "$(cat "$secret")" <<<"$config"; then
      fail "le secret $(basename "$secret") est visible dans docker inspect ($service)"
    fi
  done
done
echo "ok - aucun secret dans l'environnement ni la commande des conteneurs"

# --- Import KEV par l'API, puis lecture du backlog -------------------------
cat > "$WORK/kev.json" <<'JSON'
{"catalogVersion": "smoke", "dateReleased": "2026-09-25",
 "vulnerabilities": [{"cveID": "CVE-2024-3400", "dateAdded": "2024-04-12"}]}
JSON
curl -fsS "${AUTH[@]}" -F feed=kev -F "file=@$WORK/kev.json" \
  "$API/threat-intel/import" >/dev/null || fail "import KEV refusé"

FINDING=$(curl -fsS "${AUTH[@]}" "$API/vulnerabilities/findings?kev_only=true" | jq '.items[0]')
echo "$FINDING" | jq '{risk_score, remediation_deadline, factors: [.risk_factors[].code]}'

check() {
  local label="$1" expr="$2" expected="$3" actual
  actual=$(echo "$FINDING" | jq -r "$expr")
  [ "$actual" = "$expected" ] || fail "$label : attendu $expected, obtenu $actual"
  echo "ok - $label"
}
# Réglages lus par le worker à l'ingestion :
check "CRITICALITY_RULES atteint le worker" .asset.business_criticality Critical
check "INTERNET_FACING_SUBNETS atteint le worker" .asset.internet_facing true
check "OWNER_TEAM_RULES atteint le worker" .asset.owner_team Perimeter
check "ENVIRONMENT_RULES atteint le worker" .asset.environment production
# 6.0 x 1.5 (Critical) x min(1.5, 1.3 x 1.2) = 13.5 -> 10.0
check "le score tient compte du KEV et de l'exposition" ".risk_score == 10" true
# Réglage lu par l'API lors de l'import (resserrement de l'échéance) :
DAYS=$(echo "$FINDING" | jq -r '((.remediation_deadline[0:19] + "Z" | fromdateiso8601) - now) / 86400 | ceil')
[ "$DAYS" -le 7 ] || fail "KEV_SLA_DAYS=7 n'atteint pas l'API (échéance dans $DAYS jours)"
echo "ok - KEV_SLA_DAYS atteint l'API (échéance dans $DAYS jours)"

ENABLED=$(curl -fsS "${AUTH[@]}" "$API/threat-intel/status" | jq -r .enabled)
[ "$ENABLED" = "true" ] || fail "THREAT_INTEL_ENABLED n'atteint pas l'API"
echo "ok - THREAT_INTEL_ENABLED atteint l'API"

SCHEDULE=$("${COMPOSE[@]}" exec -T beat python -c \
  "from app.worker.celery_app import celery_app as c; print(' '.join(sorted(c.conf.beat_schedule)))")
echo "Calendrier du beat : $SCHEDULE"
[[ "$SCHEDULE" == *threat-intel-refresh* ]] || fail "THREAT_INTEL_ENABLED n'atteint pas le beat"
[[ "$SCHEDULE" == *rescore-open-findings* ]] || fail "le recalcul quotidien n'est pas planifié"
[[ "$SCHEDULE" == *webhook-delivery* ]] || fail "l'envoi des webhooks n'est pas planifié"
echo "ok - le beat planifie le recalcul et le rafraîchissement des flux"

# --- Sauvegarde, perte de la base, restauration ----------------------------
# Une sauvegarde jamais restaurée n'existe pas : on la restaure pour de vrai,
# en suivant la procédure de docs/SAUVEGARDE.md.
BACKUP_FILE=$("${COMPOSE[@]}" exec -T backup vigie-backup | tail -n 1)
[[ "$BACKUP_FILE" == /backups/vigie-*.dump.age ]] \
  || fail "sauvegarde à la demande : chemin inattendu « $BACKUP_FILE »"
echo "ok - sauvegarde chiffrée écrite : $BACKUP_FILE"

OFFSITE_COPY="$WORK/offsite/$(basename "$BACKUP_FILE")"
[ -s "$OFFSITE_COPY" ] || fail "la sauvegarde n'a pas été copiée hors site"
cmp -s <("${COMPOSE[@]}" exec -T backup cat "$BACKUP_FILE") "$OFFSITE_COPY" \
  || fail "la copie hors site diffère de la sauvegarde"
"${COMPOSE[@]}" exec -T backup vigie-backup-health \
  || fail "le healthcheck de sauvegarde échoue malgré la copie hors site"
echo "ok - copie hors site identique, healthcheck vert : $(basename "$BACKUP_FILE")"

STARTUP_BACKUPS=$("${COMPOSE[@]}" exec -T backup sh -c 'ls /backups/*.dump.age | wc -l')
[ "$STARTUP_BACKUPS" -ge 2 ] || fail "le service n'a pas fait de sauvegarde au démarrage"
echo "ok - le service a sauvegardé dès son démarrage"

"${COMPOSE[@]}" stop frontend web worker beat
"${COMPOSE[@]}" exec -T db psql -U vigie -d vigie -v ON_ERROR_STOP=1 -q \
  -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
TABLES=$("${COMPOSE[@]}" exec -T db psql -U vigie -d vigie -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
[ "$TABLES" = 0 ] || fail "la base n'a pas été vidée ($TABLES tables)"
echo "ok - base détruite"

"${COMPOSE[@]}" run --rm -T \
  -v "$WORK/age.key:/run/age.key:ro" -e BACKUP_AGE_IDENTITY=/run/age.key \
  backup vigie-restore "$BACKUP_FILE" --yes || fail "restauration impossible"

# Relance par la commande de promotion : les images existantes, sans build ni
# téléchargement.
"${COMPOSE[@]}" up -d --no-build --pull never
wait_for_api

TOKEN=$(curl -fsS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .access_token) \
  || fail "après restauration, l'administrateur ne peut plus se connecter"
RESTORED=$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$API/vulnerabilities/findings?kev_only=true" | jq -r '.items[0].vulnerability.cve_id')
[ "$RESTORED" = "CVE-2024-3400" ] || fail "après restauration, le finding KEV a disparu ($RESTORED)"
echo "ok - restauration : comptes, findings et contexte de menace sont revenus"

echo "La pile de production fonctionne de bout en bout."
