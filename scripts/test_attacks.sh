#!/bin/bash

URL="http://localhost"

# Fonction pour url-encoder une chaîne (simple version)
urlencode() {
  local length="${#1}"
  local i c
  for (( i = 0; i < length; i++ )); do
    c="${1:i:1}"
    case $c in
      [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
      ' ') printf '+' ;;
      *) printf '%%%02X' "'$c"
    esac
  done
}

declare -A tests=(
  ["XSS"]="<script>alert(1)</script>"
  ["SQL Injection"]="1' OR '1'='1"
  ["Command Injection"]="ls;cat /etc/passwd"
  ["Path Traversal"]="../../../../../../etc/passwd"
  ["XXE"]='<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'
  ["User-Agent sqlmap"]=""
)

for key in "${!tests[@]}"; do
  echo "=== Test: $key ==="
  if [[ "$key" == "XXE" ]]; then
    # Test XXE via POST XML
    curl -s -o /dev/null -w "HTTP code: %{http_code}\n" -X POST -H "Content-Type: application/xml" --data-binary "${tests[$key]}" "$URL"
  elif [[ "$key" == "User-Agent sqlmap" ]]; then
    curl -s -o /dev/null -w "HTTP code: %{http_code}\n" -A "sqlmap/1.0" "$URL"
  else
    encoded=$(urlencode "${tests[$key]}")
    curl -s -o /dev/null -w "HTTP code: %{http_code}\n" "$URL/?param=$encoded"
  fi
  echo
done
