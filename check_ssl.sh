#!/usr/bin/env bash
set -uo pipefail

DOMAIN="${1:-aseconecta.com.ar}"
DNS_SERVER="${DNS_SERVER:-8.8.8.8}"
OUTPUT_FILE="${DOMAIN}.txt"
SUBS_FILE="${DOMAIN}.subdominios.txt"
TMP_DIR="$(mktemp -d)"
JOBS="${JOBS:-10}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-12}"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Falta el comando requerido: $1" >&2
    exit 1
  }
}

need_cmd subfinder
need_cmd dig
need_cmd openssl
need_cmd jq
need_cmd xargs
need_cmd timeout
need_cmd awk
need_cmd sed
need_cmd sort
need_cmd date

echo "[+] Enumerando subdominios de $DOMAIN con subfinder..."
subfinder -d "$DOMAIN" -silent \
  | sed 's/^\*\.//g' \
  | awk 'NF' \
  | sort -u > "$SUBS_FILE"

COUNT="$(wc -l < "$SUBS_FILE" | tr -d ' ')"
if [[ "$COUNT" -eq 0 ]]; then
  echo "[!] No se encontraron subdominios para $DOMAIN"
  exit 1
fi

echo "[+] Se encontraron $COUNT subdominios"
echo "[+] Archivo de subdominios: $SUBS_FILE"

{
  echo "Resultados SSL para $DOMAIN"
  echo "Fecha: $(date)"
  echo "DNS usado: $DNS_SERVER"
  echo "Subdominios encontrados: $COUNT"
  echo "============================================================"
} > "$OUTPUT_FILE"

check_one() {
  local host="$1"
  local dns_server="$2"
  local timeout_secs="$3"

  local ip cert_info not_after_epoch now_epoch days_left not_after_line subject_line issuer_line status

  ip="$(dig @"$dns_server" "$host" +short A | head -n1)"

  if [[ -z "$ip" ]]; then
    echo "[NO_RESUELVE]|$host||"
    return 0
  fi

  cert_info="$(
    timeout "${timeout_secs}s" bash -c \
    "echo | openssl s_client -connect ${ip}:443 -servername ${host} 2>/dev/null | openssl x509 -noout -subject -issuer -enddate 2>/dev/null"
  )"

  if [[ -z "$cert_info" ]]; then
    echo "[SIN_SSL_O_FALLO]|$host|$ip|"
    return 0
  fi

  subject_line="$(printf '%s\n' "$cert_info" | grep '^subject=' | head -n1)"
  issuer_line="$(printf '%s\n' "$cert_info" | grep '^issuer=' | head -n1)"
  not_after_line="$(printf '%s\n' "$cert_info" | grep '^notAfter=' | head -n1)"

  if [[ -n "$not_after_line" ]]; then
    not_after_epoch="$(date -d "${not_after_line#notAfter=}" +%s 2>/dev/null || true)"
    now_epoch="$(date +%s)"
    if [[ -n "${not_after_epoch:-}" ]]; then
      days_left="$(( (not_after_epoch - now_epoch) / 86400 ))"
      if (( days_left < 0 )); then
        status="VENCIDO"
      elif (( days_left <= 30 )); then
        status="POR_VENCER_${days_left}d"
      else
        status="OK_${days_left}d"
      fi
    else
      status="OK"
    fi
  else
    status="OK"
  fi

  printf '[%s]|%s|%s|%s|%s|%s\n' \
    "$status" "$host" "$ip" "$subject_line" "$issuer_line" "$not_after_line"
}

export -f check_one

echo "[+] Chequeando certificados en paralelo con $JOBS jobs..."

xargs -a "$SUBS_FILE" -I{} -P "$JOBS" bash -c 'check_one "$@"' _ {} "$DNS_SERVER" "$CONNECT_TIMEOUT" \
  | sort > "$TMP_DIR/results.raw"

while IFS='|' read -r status host ip subject issuer enddate; do
  {
    echo "Host: $host"
    echo "Estado: $status"
    [[ -n "$ip" ]] && echo "IP: $ip"
    [[ -n "$subject" ]] && echo "$subject"
    [[ -n "$issuer" ]] && echo "$issuer"
    [[ -n "$enddate" ]] && echo "$enddate"
    echo "------------------------------------------------------------"
  } | tee -a "$OUTPUT_FILE"
done < "$TMP_DIR/results.raw"

echo
echo "[+] Reporte generado: $OUTPUT_FILE"
echo "[+] Subdominios guardados en: $SUBS_FILE"