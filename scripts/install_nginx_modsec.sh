#!/bin/bash
set -euo pipefail
IFS=$'\n'

NGINX_VERSION="1.18.0"
NGINX_PREFIX="/usr/local/nginx"
MODSEC_SRC="/opt/ModSecurity"
MODSEC_NGINX_SRC="/opt/ModSecurity-nginx"
CRS_SRC="/opt/coreruleset"
CRS_VERSION="v4.3.0"

echo "== STEP 0: Sanity check =="
if [[ $(id -u) -ne 0 ]]; then
    echo "Ce script doit être exécuté en root (ou avec sudo)."
    exit 1
fi

echo "== STEP 1: Stop any running Nginx =="
pkill nginx || true
sleep 1
rm -rf "$NGINX_PREFIX"

echo "== STEP 2: Install dependencies =="
DEPS=(
    git build-essential libpcre3 libpcre3-dev libssl-dev libxml2 libxml2-dev
    libyajl-dev zlib1g zlib1g-dev wget curl automake libtool pkg-config ca-certificates
)
apt update
apt install -y "${DEPS[@]}"

echo "== STEP 3: Download Nginx source =="
cd /opt
if [[ ! -d "nginx-$NGINX_VERSION" ]]; then
    wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
    tar xzf nginx-$NGINX_VERSION.tar.gz
fi

echo "== STEP 4: Build ModSecurity library =="
if [[ ! -d "$MODSEC_SRC" ]]; then
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity "$MODSEC_SRC"
    cd "$MODSEC_SRC"
    git submodule init
    git submodule update
    ./build.sh
    ./configure
    make
    make install
fi

echo "== STEP 5: Get ModSecurity Nginx connector =="
cd /opt
if [[ ! -d "$MODSEC_NGINX_SRC" ]]; then
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git "$MODSEC_NGINX_SRC"
fi

echo "== STEP 6: Compile Nginx with ModSecurity module =="
cd "/opt/nginx-$NGINX_VERSION"
make clean || true
./configure --prefix="$NGINX_PREFIX" --add-dynamic-module="$MODSEC_NGINX_SRC"
make
make install

echo "== STEP 7: Install OWASP CRS =="
rm -rf "$CRS_SRC"
git clone --branch "$CRS_VERSION" --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_SRC"

echo "== STEP 8: Copy ModSecurity base config =="
cp "$MODSEC_SRC/modsecurity.conf-recommended" "$NGINX_PREFIX/conf/modsecurity.conf"
cp "$MODSEC_SRC/unicode.mapping" "$NGINX_PREFIX/conf/"
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$NGINX_PREFIX/conf/modsecurity.conf"

echo "== STEP 9: Copy CRS rules =="
rm -rf "$NGINX_PREFIX/conf/rules"
cp -r "$CRS_SRC/rules" "$NGINX_PREFIX/conf/"
cp "$CRS_SRC/crs-setup.conf.example" "$NGINX_PREFIX/conf/rules/crs-setup.conf"

echo "== STEP 9.5: Fix CRS SecDefaultAction issue =="

# Remove SecDefaultAction lines in CRS rules
grep -rl "SecDefaultAction" "$NGINX_PREFIX/conf/rules" | while read -r file; do
    echo "Removing SecDefaultAction from $file"
    sed -i '/SecDefaultAction/d' "$file"
done

# Remove existing SecDefaultAction in modsecurity.conf to avoid duplicates
sed -i '/SecDefaultAction/d' "$NGINX_PREFIX/conf/modsecurity.conf"

# Add global SecDefaultAction after SecRuleEngine On
sed -i '/SecRuleEngine On/a SecDefaultAction "phase:1,deny,log"\nSecDefaultAction "phase:2,deny,log"' "$NGINX_PREFIX/conf/modsecurity.conf"

echo "== STEP 10: Create CRS include file =="
cat <<EOF > "$NGINX_PREFIX/conf/crs-includes.conf"
# OWASP CRS Includes
Include $NGINX_PREFIX/conf/rules/crs-setup.conf
Include $NGINX_PREFIX/conf/rules/*.conf
EOF

echo "== STEP 11: Add CRS include to modsecurity.conf =="
if ! grep -q "crs-includes.conf" "$NGINX_PREFIX/conf/modsecurity.conf"; then
    sed -i '/SecRuleEngine On/a Include '"$NGINX_PREFIX/conf/crs-includes.conf" "$NGINX_PREFIX/conf/modsecurity.conf"
fi

echo "== STEP 12: Configure Nginx main conf =="
cat <<EOF > "$NGINX_PREFIX/conf/nginx.conf"
load_module modules/ngx_http_modsecurity_module.so;
worker_processes auto;
events { worker_connections 1024; }
http {
    modsecurity on;
    modsecurity_rules_file $NGINX_PREFIX/conf/modsecurity.conf;
    server {
        listen 80;
        server_name localhost;
        location / {
            root html;
            index index.html;
        }
    }
}
EOF

echo "== STEP 13: Test Nginx configuration =="
"$NGINX_PREFIX/sbin/nginx" -t

echo "== STEP 14: Start Nginx =="
"$NGINX_PREFIX/sbin/nginx"

echo "== Installation finished successfully! =="
