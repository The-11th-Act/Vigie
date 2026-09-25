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
cat > .env <<EOF
SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
POSTGRES_USER=vigie
POSTGRES_PASSWORD=smoke-$(openssl rand -hex 12)
POSTGRES_DB=vigie
REDIS_PASSWORD=smoke-$(openssl rand -hex 12)
BACKEND_CORS_ORIGINS=["https://vigie.example.com"]
# Réglages métier : leur effet est vérifié plus bas, dans chaque conteneur.
CRITICALITY_RULES={"203.0.113.0/24":"Critical"}
INTERNET_FACING_SUBNETS=["203.0.113.0/24"]
KEV_SLA_DAYS=7
THREAT_INTEL_ENABLED=true
EOF

# --- Démarrage -------------------------------------------------------------
echo "Construction et démarrage de la pile de production..."
"${COMPOSE[@]}" up -d --build

echo "Attente de l'API derrière Nginx..."
for _ in $(seq 1 90); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1 \
    && [ "$("${COMPOSE[@]}" ps --format '{{.Health}}' web)" = "healthy" ]; then
    ready=1
    break
  fi
  sleep 2
done
[ "${ready:-}" = 1 ] || fail "l'API n'est jamais devenue saine derrière Nginx"
echo "API saine (/ready, donc PostgreSQL, Redis et un worker)."

# --- Premier administrateur, par le chemin documenté ------------------------
"${COMPOSE[@]}" run --rm -T -e ADMIN_PASSWORD="$ADMIN_PASSWORD" web \
  python -m scripts.create_admin --username admin --email admin@example.com \
  --password-from-env || fail "création de l'administrateur impossible"

TOKEN=$(curl -fsS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .access_token) \
  || fail "connexion impossible via Nginx"
AUTH=(-H "Authorization: Bearer $TOKEN")

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

TASK=$(curl -fsS "${AUTH[@]}" -F scan_type=nessus -F "file=@$WORK/report.nessus" \
  "$API/scans/upload" | jq -r .task_id) || fail "upload refusé"

for _ in $(seq 1 60); do
  STATUS=$(curl -fsS "${AUTH[@]}" "$API/scans/status/$TASK" | jq -r .status)
  [ "$STATUS" = "Success" ] && break
  [ "$STATUS" = "Failed" ] && fail "le worker a échoué sur le scan"
  sleep 2
done
[ "$STATUS" = "Success" ] || fail "le scan n'a jamais été traité (statut : $STATUS)"
echo "Scan ingéré par le worker via le volume partagé."

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
echo "ok - le beat planifie le recalcul et le rafraîchissement des flux"

echo "La pile de production fonctionne de bout en bout."
