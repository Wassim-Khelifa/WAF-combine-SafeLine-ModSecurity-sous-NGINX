#!/bin/bash
# =============================================================================
# WAF TRIPLE LAYER - NGINX/MODSECURITY/SAFELINE SETUP
# Layer 1: NGINX Pattern Matching (Logging Only)
# Layer 2: ModSecurity v3 with OWASP CRS
# Layer 3: SafeLine WAF
# =============================================================================

# Exit on any error for debugging
trap 'echo "Script failed at line $LINENO. Check logs above."' ERR

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
LOCAL_IP="192.168.142.128"
DVWA_IP="192.168.142.138"
SAFELINE_IP="192.168.142.141"

# Logging function
log_msg() {
  local message="$1"
  local type="${2:-INFO}"
  case "$type" in
    "INFO") echo -e "${BLUE}[INFO]${NC} $message" ;;
    "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} ✓ $message" ;;
    "WARNING") echo -e "${YELLOW}[WARNING]${NC} ⚠ $message" ;;
    "ERROR") echo -e "${RED}[ERROR]${NC} ✗ $message" ;;
    "WAF") echo -e "${PURPLE}[WAF]${NC} $message" ;;
    *) echo "$message" ;;
  esac
}

# Check root privileges
check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_msg "This script must be run with sudo" "ERROR"
    exit 1
  fi
  log_msg "Root privileges confirmed" "SUCCESS"
}

# Configure open file limits
configure_limits() {
  log_msg "Configuring open file limits..." "INFO"
  # Update /etc/security/limits.conf
  cat > /etc/security/limits.conf << 'LIMITS_CONF_EOF'
# /etc/security/limits.conf
www-data soft nofile 4096
www-data hard nofile 4096
root soft nofile 4096
root hard nofile 4096
# End of file
LIMITS_CONF_EOF
  # Ensure PAM applies limits
  for file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if ! grep -q "pam_limits.so" "$file"; then
      echo "session required pam_limits.so" >> "$file"
    fi
  done
  log_msg "Open file limits configured" "SUCCESS"
}

# Enhanced cleanup with error tolerance
cleanup_nginx() {
  log_msg "Cleaning previous installations..." "INFO"
  trap 'log_msg "Script interrupted by signal at line $LINENO" "ERROR"; exit 1' INT TERM
  log_msg "Checking for running NGINX processes..." "INFO"
  if pgrep -f '^/usr/sbin/nginx' > /tmp/nginx_processes.log 2>&1; then
    log_msg "Found NGINX processes:" "INFO"
    cat /tmp/nginx_processes.log
    log_msg "Stopping NGINX service..." "INFO"
    timeout 10 systemctl stop nginx >/tmp/nginx_stop.log 2>&1 || log_msg "Failed to stop NGINX service, check /tmp/nginx_stop.log" "WARNING"
    log_msg "Killing NGINX processes..." "INFO"
    timeout 10 pkill -f '^/usr/sbin/nginx' >/tmp/nginx_pkill.log 2>&1 || log_msg "Failed to kill NGINX processes, check /tmp/nginx_pkill.log" "WARNING"
    sleep 3
    if pgrep -f '^/usr/sbin/nginx' >/dev/null; then
      log_msg "NGINX processes still running after pkill:" "WARNING"
      ps aux | grep '[n]ginx'
    else
      log_msg "All NGINX processes terminated" "SUCCESS"
    fi
  else
    log_msg "No NGINX processes found" "SUCCESS"
    log_msg "Skipping NGINX service stop and kill" "INFO"
  fi
  log_msg "Removing NGINX packages..." "INFO"
  timeout 30 apt-get remove --purge -y nginx nginx-* libnginx-* >/tmp/nginx_remove.log 2>&1 || log_msg "Failed to remove NGINX packages, check /tmp/nginx_remove.log" "WARNING"
  log_msg "Running autoremove..." "INFO"
  timeout 30 apt-get autoremove -y >/tmp/nginx_autoremove.log 2>&1 || log_msg "Failed to autoremove packages, check /tmp/nginx_autoremove.log" "WARNING"
  log_msg "Cleaning apt cache..." "INFO"
  timeout 10 apt-get clean >/tmp/nginx_clean.log 2>&1 || log_msg "Failed to clean apt cache, check /tmp/nginx_clean.log" "WARNING"
  log_msg "Configuring dpkg..." "INFO"
  timeout 10 dpkg --configure -a >/tmp/nginx_dpkg.log 2>&1 || log_msg "Failed to configure dpkg, check /tmp/nginx_dpkg.log" "WARNING"
  log_msg "Removing NGINX configuration files..." "INFO"
  rm -rf /etc/nginx /var/log/nginx /var/lib/nginx /var/cache/nginx >/tmp/nginx_rm_files.log 2>&1 || log_msg "Failed to remove NGINX files, check /tmp/nginx_rm_files.log" "WARNING"
  log_msg "Removing ModSecurity module..." "INFO"
  rm -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so >/tmp/nginx_rm_modsec.log 2>&1 || log_msg "Failed to remove ModSecurity module, check /tmp/nginx_rm_modsec.log" "WARNING"
  log_msg "Removing NGINX repository..." "INFO"
  rm -f /etc/apt/sources.list.d/nginx.list >/tmp/nginx_rm_repo.log 2>&1 || log_msg "Failed to remove NGINX repository, check /tmp/nginx_rm_repo.log" "WARNING"
  log_msg "Removing NGINX preferences..." "INFO"
  rm -f /etc/apt/preferences.d/nginx >/tmp/nginx_rm_prefs.log 2>&1 || log_msg "Failed to remove NGINX preferences, check /tmp/nginx_rm_prefs.log" "WARNING"
  log_msg "Unholding NGINX package..." "INFO"
  apt-mark unhold nginx >/tmp/nginx_unhold.log 2>&1 || log_msg "Failed to unhold NGINX package, check /tmp/nginx_unhold.log" "WARNING"
  log_msg "Updating package lists..." "INFO"
  timeout 30 apt-get update >/tmp/nginx_apt_update.log 2>&1 || log_msg "Failed to update package lists, check /tmp/nginx_apt_update.log" "WARNING"
  log_msg "Cleanup completed (ignored non-critical errors)" "SUCCESS"
}

# Install dependencies
install_dependencies() {
  log_msg "Installing system dependencies..." "INFO"
  apt-get update - qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev \
    libxml2-dev \
    libxslt1-dev \
    libgd-dev \
    libgeoip-dev \
    liblua5.3-dev \
    libmaxminddb-dev \
    libfuzzy-dev \
    libyajl-dev \
    libcurl4-openssl-dev \
    pkg-config \
    gettext \
    ca-certificates \
    openssl >/dev/null 2>&1
  log_msg "System dependencies installed" "SUCCESS"
}

# Check NGINX and ModSecurity compatibility
check_compatibility() {
  log_msg "Checking NGINX/ModSecurity compatibility..." "WAF"
  if command -v nginx >/dev/null 2>&1; then
    nginx_version=$(nginx -v 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    log_msg "Found NGINX version: $nginx_version" "INFO"
    if [ -f "/usr/lib/nginx/modules/ngx_http_modsecurity_module.so" ]; then
      cat > /tmp/test_nginx.conf << 'EOF'
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
events { worker_connections 1024; }
http { server { listen 19999; location / { return 200; } } }
EOF
      if nginx -t -c /tmp/test_nginx.conf >/dev/null 2>&1; then
        log_msg "NGINX and ModSecurity are compatible" "SUCCESS"
        rm /tmp/test_nginx.conf
        return 0
      else
        log_msg "Version mismatch detected - will fix" "WARNING"
        rm /tmp/test_nginx.conf
        return 1
      fi
    else
      log_msg "ModSecurity module not found - will install" "INFO"
      return 1
    fi
  else
    log_msg "NGINX not found - will install compatible version" "INFO"
    return 1
  fi
}

# Install compatible NGINX 1.18.0
install_compatible_nginx() {
  log_msg "Forcing installation of NGINX 1.18.0 with ModSecurity compatibility..." "WAF"
  curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add - >/dev/null 2>&1
  echo "deb http://nginx.org/packages/ubuntu/ $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
  cat > /etc/apt/preferences.d/nginx << 'EOF'
Package: nginx
Pin: version 1.18.*
Pin-Priority: 1001
EOF
  apt-get update -qq
  apt-get install -y --allow-downgrades nginx=1.18.0-2~$(lsb_release -cs) >/dev/null 2>&1 || {
    log_msg "Specific version not found, installing available 1.18.* version..." "WARNING"
    apt-get install -y --allow-downgrades nginx
  }
  apt-mark hold nginx
  apt-get install -y \
    libmodsecurity3 \
    libmodsecurity-dev \
    modsecurity-crs >/dev/null 2>&1 || true
  installed_version=$(nginx -v 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
  if [[ $installed_version == 1.18.* ]]; then
    log_msg "NGINX 1.18.0 installation completed" "SUCCESS"
  else
    log_msg "Failed to install NGINX 1.18.0 (got $installed_version). Check repositories." "ERROR"
    exit 1
  fi
}

# Compile ModSecurity module if needed
compile_modsecurity_module() {
  log_msg "Compiling ModSecurity module for current NGINX..." "WAF"
  nginx_version=$(nginx -V 2>&1 | grep -o 'nginx/[0-9]\+\.[0-9]\+\.[0-9]\+' | cut -d'/' -f2)
  configure_args=$(nginx -V 2>&1 | grep -o 'configure arguments:.*' | cut -d':' -f2-)
  log_msg "Compiling for NGINX version: $nginx_version" "INFO"
  mkdir -p /tmp/nginx-build
  cd /tmp/nginx-build
  wget -q "http://nginx.org/download/nginx-${nginx_version}.tar.gz"
  tar -xzf "nginx-${nginx_version}.tar.gz"
  git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
  cd "nginx-${nginx_version}"
  ./configure \
    --add-dynamic-module=../ModSecurity-nginx \
    --with-compat \
    $configure_args >/dev/null 2>&1 || {
      ./configure \
        --add-dynamic-module=../ModSecurity-nginx \
        --with-compat \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_stub_status_module \
        --with-http_auth_request_module \
        --with-threads \
        --with-stream \
        --with-stream_ssl_module \
        --with-http_slice_module \
        --with-file-aio \
        --with-http_v2_module
    }
  make modules
  mkdir -p /usr/lib/nginx/modules
  cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/
  chown root:root /usr/lib/nginx/modules/ngx_http_modsecurity_module.so
  chmod 644 /usr/lib/nginx/modules/ngx_http_modsecurity_module.so
  cd /
  rm -rf /tmp/nginx-build
  log_msg "ModSecurity module compiled successfully" "SUCCESS"
}

# Fix systemd service with file limits
fix_systemd_service() {
  log_msg "Fixing NGINX systemd service..." "INFO"
  SERVICE_FILE="/etc/systemd/system/nginx.service"
  cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=NGINX HTTP Server with ModSecurity
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
Restart=on-failure
LimitNOFILE=4096
PrivateTmp=true
KillSignal=SIGQUIT
TimeoutStopSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  log_msg "NGINX systemd service configured with LimitNOFILE=4096" "SUCCESS"
}

# Setup ModSecurity configuration
setup_modsecurity() {
  log_msg "Setting up ModSecurity configuration..." "WAF"
  mkdir -p /etc/nginx/modsecurity
  mkdir -p /var/lib/modsecurity
  mkdir -p /var/log/modsecurity
  if [ ! -d "/etc/nginx/modsecurity/owasp-crs" ]; then
    cd /etc/nginx/modsecurity
    wget -q https://github.com/coreruleset/coreruleset/archive/v3.3.4.tar.gz -O crs.tar.gz >/dev/null 2>&1 && {
      tar -xzf crs.tar.gz
      mv coreruleset-* owasp-crs
      rm crs.tar.gz
      cp owasp-crs/crs-setup.conf.example owasp-crs/crs-setup.conf
      log_msg "OWASP Core Rule Set installed" "SUCCESS"
    } || {
      log_msg "Could not download OWASP CRS, using basic rules" "WARNING"
    }
  fi
  cat > /etc/nginx/modsecurity/modsecurity.conf << 'MODSEC_CONF_EOF'
# ModSecurity Core Configuration
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
SecTmpDir /tmp/
SecDataDir /var/lib/modsecurity
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLog /var/log/modsecurity/audit.log
SecDebugLog /var/log/modsecurity/debug.log
SecDebugLogLevel 1
SecUploadDir /tmp/
SecUploadKeepFiles Off
# Custom Rules
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@detectXSS" \
  "id:1001,phase:2,block,msg:'XSS Attack Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-xss',tag:'OWASP_CRS',tag:'OWASP_CRS/WEB_ATTACK/XSS'"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
  "id:1002,phase:2,block,msg:'SQL Injection Attack Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli',tag:'OWASP_CRS',tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION'"
SecRule ARGS "@rx (?:\||;|&&|\$\(||<\(|>\()" \
  "id:1003,phase:2,block,msg:'Command Injection Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-injection-php'"
SecRule ARGS "@rx \.\./|\.\.\\" \
  "id:1004,phase:2,block,msg:'Directory Traversal Attack',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"
SecRule REQUEST_HEADERS:User-Agent "@rx (?i:(sqlmap|nmap|nikto|w3af|acunetix|nessus|openvas|vega|burp|owasp\s*zap))" \
  "id:1005,phase:1,block,msg:'Malicious Security Scanner Detected',logdata:'User-Agent: %{MATCHED_VAR}'"
SecRule FILES_NAMES "@rx \.(?:php|jsp|asp|exe|sh|pl)$" \
  "id:1006,phase:2,block,msg:'Malicious File Upload Attempt',logdata:'Filename: %{MATCHED_VAR}'"
SecRule REQUEST_PROTOCOL "!@rx ^HTTP/(0\.9|1\.0|1\.1)$" \
  "id:1007,phase:1,block,msg:'Invalid HTTP Protocol Version'"
MODSEC_CONF_EOF
  cat > /etc/nginx/modsecurity/custom_rules.conf << 'CUSTOM_RULES_EOF'
SecRuleRemoveById 1003
CUSTOM_RULES_EOF
  cat > /etc/nginx/modsecurity/main.conf << 'MAIN_CONF_EOF'
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/owasp-crs/crs-setup.conf
Include /etc/nginx/modsecurity/owasp-crs/rules/*.conf
Include /etc/nginx/modsecurity/custom_rules.conf
MAIN_CONF_EOF
  if [ ! -d "/etc/nginx/modsecurity/owasp-crs" ]; then
    cat > /etc/nginx/modsecurity/main.conf << 'BASIC_CONF_EOF'
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/custom_rules.conf
BASIC_CONF_EOF
  fi
  chown -R www-data:www-data /var/lib/modsecurity
  chown -R www-data:www-data /var/log/modsecurity
  chmod -R 755 /etc/nginx/modsecurity
  touch /var/log/modsecurity/audit.log
  touch /var/log/modsecurity/debug.log
  chown www-data:www-data /var/log/modsecurity/*
  log_msg "ModSecurity configuration completed" "SUCCESS"
}

# Generate SSL certificates
generate_ssl() {
  log_msg "Generating SSL certificates..." "INFO"
  mkdir -p /etc/nginx/ssl
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key \
    -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=TN/ST=Tunis/L=Tunis/O=WAF-Lab/CN=$LOCAL_IP" >/dev/null 2>&1
  chmod 600 /etc/nginx/ssl/nginx.key
  chmod 644 /etc/nginx/ssl/nginx.crt
  chown www-data:www-data /etc/nginx/ssl/*
  log_msg "SSL certificates generated" "SUCCESS"
}

# Create mime.types file
create_mime_types() {
  log_msg "Creating mime.types file..." "INFO"
  mkdir -p /etc/nginx
  cat > /etc/nginx/mime.types << 'MIME_TYPES_EOF'
types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/atom+xml                  atom;
    application/rss+xml                   rss;
    text/mathml                           mml;
    text/plain                            txt;
    text/vnd.sun.j2me.app-descriptor      jad;
    text/vnd.wap.wml                      wml;
    text/x-component                      htc;
    image/png                             png;
    image/tiff                            tif tiff;
    image/vnd.wap.wbmp                    wbmp;
    image/webp                            webp;
    image/x-icon                          ico;
    image/x-jng                           jng;
    image/x-ms-bmp                        bmp;
    application/font-woff                 woff;
    application/font-woff2                woff2;
    application/json                      json;
    application/pdf                       pdf;
    application/postscript                ps eps ai;
    application/rtf                       rtf;
    application/vnd.ms-excel              xls;
    application/vnd.ms-powerpoint         ppt;
    application/msword                    doc;
    application/x-shockwave-flash         swf;
    application/xhtml+xml                 xhtml;
    application/zip                       zip;
    audio/mpeg                            mp3;
    audio/wav                             wav;
    audio/x-m4a                           m4a;
    video/mp4                             mp4;
    video/mpeg                            mpeg mpg;
    video/quicktime                       mov;
    video/webm                            webm;
    video/x-flv                           flv;
    video/x-m4v                           m4v;
    video/x-ms-wmv                        wmv;
}
MIME_TYPES_EOF
  chown root:root /etc/nginx/mime.types
  chmod 644 /etc/nginx/mime.types
  log_msg "mime.types file created" "SUCCESS"
}

# Create NGINX directories
create_nginx_dirs() {
  log_msg "Creating NGINX directories..." "INFO"
  mkdir -p /var/lib/nginx/body /var/cache/nginx /var/log/nginx
  chown www-data:www-data /var/lib/nginx /var/lib/nginx/body /var/cache/nginx /var/log/nginx
  chmod 755 /var/lib/nginx /var/lib/nginx/body /var/cache/nginx /var/log/nginx
  log_msg "NGINX directories created" "SUCCESS"
}

# Create WAF configuration
create_waf_config() {
  log_msg "Creating WAF triple layer configuration..." "WAF"
  mkdir -p /etc/nginx/conf.d
  mkdir -p /var/log/nginx
  if [ -f /etc/nginx/nginx.conf ]; then
    cp /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.backup.$(date +%Y%m%d_%H%M%S)"
  fi
  cat > /etc/nginx/nginx.conf << 'NGINX_MAIN_CONF_EOF'
load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    server_tokens off;
    client_max_body_size 16M;
    client_body_timeout 30s;
    client_header_timeout 30s;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format waf_extended '$remote_addr - $remote_user [$time_local] '
                            '"$request" $status $body_bytes_sent '
                            '"$http_referer" "$http_user_agent" '
                            'rt=$request_time '
                            'layer="$waf_layer" '
                            'blocked="$waf_blocked"';
    access_log /var/log/nginx/access.log waf_extended;

    map $server_port $waf_layer {
        443 "triple-layer";
        8080 "bypass";
        8443 "safeline-only";
        9443 "modsecurity-only";
        default "unknown";
    }

    map $args $nginx_xss_detected {
        default 0;
        "~*(<script[^>]*>|</script>|javascript:|vbscript:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|document\.write)" 1;
    }
    map $args $nginx_sqli_detected {
        default 0;
        "~*(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+.*set|or\s+1\s*=\s*1|and\s+1\s*=\s*1|admin'--|'\s+or\s+)" 1;
    }
    map $args $nginx_cmdi_detected {
        default 0;
        "~*(\||;|&&|%7c|%3b||%60|<\(|>\(|\$\(|whoami|id|cat\s+/etc|ls\s+-|nc\s+-)" 1;
    }
    map $request_uri$args $nginx_traversal_detected {
        default 0;
        "~*(\.\.\/|\.\.\%2f|\.\.\%5c|%2e%2e%2f|%252e%252e%252f)" 1;
    }
    map $http_user_agent $nginx_scanner_detected {
        default 0;
        "~*(?i:(sqlmap|nmap|nikto|w3af|acunetix|nessus|openvas|vega|burp|owasp\s*zap|dirbuster|gobuster|wpscan))" 1;
    }

    map $nginx_xss_detected$nginx_sqli_detected$nginx_cmdi_detected$nginx_traversal_detected$nginx_scanner_detected $waf_blocked {
        default "none";
        "~1" "nginx-layer1";
    }

    limit_req_zone $binary_remote_addr zone=global:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    upstream safeline_waf {
        server 192.168.142.141:80 max_fails=3 fail_timeout=30s;
        keepalive 16;
    }
    upstream dvwa_direct {
        server 192.168.142.138:80 max_fails=3 fail_timeout=30s;
        keepalive 8;
    }

    server {
        listen 443 ssl http2;
        server_name 192.168.142.128;

        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        limit_conn conn_limit 20;

        location / {
            limit_req zone=global burst=20 nodelay;
            access_log /var/log/nginx/waf_blocked.log waf_extended if=$nginx_xss_detected|$nginx_sqli_detected|$nginx_cmdi_detected|$nginx_traversal_detected|$nginx_scanner_detected;
            modsecurity on;
            modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
            add_header X-WAF-Architecture "NGINX+ModSecurity+SafeLine" always;
            add_header X-Protection-Layers "3" always;
            add_header X-WAF-Status "TRIPLE-PROTECTION" always;
            proxy_pass http://safeline_waf;
            proxy_set_header Host dvwa.local;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-WAF-Layer "triple";
            proxy_connect_timeout 30s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
            proxy_buffering off;
            proxy_request_buffering off;
        }

        location /health {
            limit_req zone=global burst=20 nodelay;
            access_log /var/log/nginx/waf_blocked.log waf_extended if=$nginx_xss_detected|$nginx_sqli_detected|$nginx_cmdi_detected|$nginx_traversal_detected|$nginx_scanner_detected;
            modsecurity on;
            modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
            add_header X-WAF-Status "TRIPLE-PROTECTION" always;
            proxy_pass http://safeline_waf;
            proxy_set_header Host dvwa.local;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location ~* ^/(login|admin|wp-admin) {
            limit_req zone=login burst=5 nodelay;
            access_log /var/log/nginx/waf_blocked.log waf_extended if=$nginx_xss_detected|$nginx_sqli_detected|$nginx_cmdi_detected|$nginx_traversal_detected|$nginx_scanner_detected;
            modsecurity on;
            modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
            proxy_pass http://safeline_waf;
            proxy_set_header Host dvwa.local;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /waf-status {
            modsecurity off;
            allow 127.0.0.1;
            allow 192.168.142.0/24;
            deny all;
            return 200 '=== WAF TRIPLE LAYER STATUS ===
ARCHITECTURE: Client → NGINX (Layer 1) → ModSecurity (Layer 2) → SafeLine (Layer 3) → DVWA

LAYER 1 (NGINX Pattern Matching):
- XSS Detection: Active (Logging Only)
- SQL Injection Detection: Active (Logging Only)
- Command Injection Detection: Active (Logging Only)
- Directory Traversal Detection: Active (Logging Only)
- Scanner Detection: Active (Logging Only)
- Rate Limiting: 10 req/s global, 3 req/s login

LAYER 2 (ModSecurity):
- Engine Status: Active
- Core Rules: Loaded
- Custom Rules: Active
- Audit Logging: Enabled

LAYER 3 (SafeLine WAF):
- Backend: 192.168.142.141:80
- Target: dvwa.local
- Status: Proxied

ENDPOINTS:
- Triple Protection: https://192.168.142.128 (port 443) [ALL 3 LAYERS]
- No Protection: http://192.168.142.128:8080 [BYPASS]
- SafeLine Only: https://192.168.142.128:8443 [LAYER 3 ONLY]
- ModSecurity Only: https://192.168.142.128:9443 [LAYER 2 ONLY]

LOGS:
- Access: /var/log/nginx/access.log
- Blocked Requests: /var/log/nginx/waf_blocked.log
- ModSecurity Audit: /var/log/modsecurity/audit.log

Status: All layers ACTIVE
Time: $time_iso8601
Server: $hostname
';
            add_header Content-Type text/plain;
        }

        location ~* /\.(?:ht|git|svn) { deny all; }
        location ~* /(?:uploads|wp-content)/.*\.php$ { deny all; }
    }

    server {
        listen 8080;
        server_name 192.168.142.128;

        location / {
            add_header X-WAF-Status "BYPASS-NO-PROTECTION" always;
            add_header X-Protection-Layers "0" always;
            proxy_pass http://dvwa_direct;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /health {
            return 200 '{"status":"bypass","layers":0,"protection":"none","target":"dvwa_direct"}';
            add_header Content-Type application/json;
        }
    }

    server {
        listen 8443 ssl http2;
        server_name 192.168.142.128;
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        location / {
            add_header X-WAF-Status "SAFELINE-ONLY" always;
            add_header X-Protection-Layers "1" always;
            proxy_pass http://safeline_waf;
            proxy_set_header Host dvwa.local;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-WAF-Layer "safeline-only";
        }

        location /health {
            add_header X-WAF-Status "SAFELINE-ONLY" always;
            proxy_pass http://safeline_waf;
            proxy_set_header Host dvwa.local;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-WAF-Layer "safeline-only";
        }
    }

    server {
        listen 9443 ssl http2;
        server_name 192.168.142.128;
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        location / {
            modsecurity on;
            modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
            add_header X-WAF-Status "MODSECURITY-ONLY" always;
            add_header X-Protection-Layers "1" always;
            proxy_pass http://dvwa_direct;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-WAF-Layer "modsecurity-only";
        }

        location /health {
            modsecurity on;
            modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
            add_header X-WAF-Status "MODSECURITY-ONLY" always;
            proxy_pass http://dvwa_direct;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }

    server {
        listen 80 default_server;
        server_name _;

        location / {
            return 200 '=== WAF TRIPLE LAYER LABORATORY ===
This server provides multiple WAF testing endpoints:

🛡️ TRIPLE PROTECTION (All 3 Layers): https://192.168.142.128
Layers: NGINX Pattern Matching → ModSecurity → SafeLine WAF

🔓 NO PROTECTION (Bypass): http://192.168.142.128:8080
Direct connection to DVWA

🛡️ SAFELINE ONLY (Layer 3): https://192.168.142.128:8443
Only SafeLine WAF protection

🛡️ MODSECURITY ONLY (Layer 2): https://192.168.142.128:9443
Only ModSecurity protection

📊 STATUS & MONITORING:
https://192.168.142.128/waf-status
https://192.168.142.128/health

⚙️ SAFELINE CONFIGURATION:
1. Access: https://192.168.142.141:9443
2. Add Backend: 192.168.142.138:80
3. Set Domain: dvwa.local
4. Allow Source: 192.168.142.128

📋 TESTING:
Run: test-waf-complete.sh

🕒 Server Time: $time_iso8601
🖥️ Server: $hostname
';
            add_header Content-Type text/plain;
        }
    }
}
NGINX_MAIN_CONF_EOF
  log_msg "Main NGINX configuration created" "SUCCESS"
}

# Create comprehensive testing tools
create_test_tools() {
  log_msg "Creating comprehensive testing tools..." "WAF"
  cat > /usr/local/bin/test-waf-complete.sh << 'TEST_SCRIPT_EOF'
#!/bin/bash
# WAF Triple Layer Comprehensive Testing Script

LOCAL_IP="192.168.142.128"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${PURPLE}======================================================================"
echo " WAF TRIPLE LAYER TESTING"
echo "======================================================================${NC}"
echo

# Service Status Check
echo -e "${BLUE}=== SERVICE STATUS ===${NC}"
nginx_status=$(systemctl is-active nginx 2>/dev/null || echo 'INACTIVE')
modsec_module=$([ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ] && echo 'PRESENT' || echo 'MISSING')
ports_active=$(ss -tuln | grep -E ':(80|443|8080|8443|9443)' | wc -l)
echo "NGINX Service: $nginx_status"
echo "ModSecurity Module: $modsec_module"
echo "Active Ports: $ports_active/5"

# Port Details
echo
echo -e "${BLUE}=== PORT STATUS ===${NC}"
expected_ports=(80 443 8080 8443 9443)
for port in "${expected_ports[@]}"; do
  if ss -tuln | grep -q ":$port "; then
    echo -e "${GREEN}✓${NC} Port $port: ACTIVE"
  else
    echo -e "${RED}✗${NC} Port $port: INACTIVE"
  fi
done

echo
echo -e "${BLUE}=== ENDPOINT CONNECTIVITY ===${NC}"
declare -A endpoints
endpoints["Triple Protection"]="https://$LOCAL_IP/health"
endpoints["Bypass Mode"]="http://$LOCAL_IP:8080/health"
endpoints["SafeLine Only"]="https://$LOCAL_IP:8443/health"
endpoints["ModSecurity Only"]="https://$LOCAL_IP:9443/health"

for name in "${!endpoints[@]}"; do
  url="${endpoints[$name]}"
  if [[ $url == https://* ]]; then
    status=$(timeout 10 curl -k -s -w "%{http_code}" -o /dev/null "$url" 2>/dev/null || echo "ERR")
    response=$(timeout 10 curl -k -s "$url" 2>/dev/null || echo "")
  else
    status=$(timeout 10 curl -s -w "%{http_code}" -o /dev/null "$url" 2>/dev/null || echo "ERR")
    response=$(timeout 10 curl -s "$url" 2>/dev/null || echo "")
  fi
  case $status in
    200) echo -e "${GREEN}✓${NC} $name: ACCESSIBLE"
         if [[ $response == *"layers"* ]]; then
           layers=$(echo "$response" | grep -o '"layers":[0-9]*' | cut -d':' -f2)
           echo " Layers: $layers"
         fi ;;
    *) echo -e "${RED}✗${NC} $name: $status" ;;
  esac
done

echo
echo -e "${PURPLE}=== ATTACK SIMULATION ===${NC}"
declare -A attacks
attacks["XSS Basic"]="/?input=<script>alert('xss')</script>"
attacks["XSS Event"]="/?input=<img src=x onerror=alert(1)>"
attacks["SQLi Union"]="/?id=1' UNION SELECT 1,2,3--"
attacks["SQLi Boolean"]="/?id=1' OR '1'='1'--"
attacks["CMD Injection"]="/?cmd=|whoami"
attacks["CMD Pipe"]="/?cmd=; ls -la"
attacks["Directory Traversal"]="/?file=../../../etc/passwd"
attacks["Path Traversal"]="/?path=....//....//etc/passwd"

declare -A test_endpoints
test_endpoints["Triple"]="https://$LOCAL_IP"
test_endpoints["Bypass"]="http://$LOCAL_IP:8080"
test_endpoints["SafeLine"]="https://$LOCAL_IP:8443"
test_endpoints["ModSec"]="https://$LOCAL_IP:9443"

printf "%-20s" "Attack Vector"
for ep in "${!test_endpoints[@]}"; do
  printf "%-10s" "$ep"
done
echo
echo "------------------------------------------------------------------------"

for attack in "${!attacks[@]}"; do
  printf "%-20s" "$attack"
  payload="${attacks[$attack]}"
  for ep_name in "${!test_endpoints[@]}"; do
    ep_url="${test_endpoints[$ep_name]}"
    full_url="$ep_url$payload"
    if [[ $ep_url == https://* ]]; then
      response=$(timeout 15 curl -k -s -w "%{http_code}" -o /dev/null "$full_url" 2>/dev/null || echo "ERR")
    else
      response=$(timeout 15 curl -s -w "%{http_code}" -o /dev/null "$full_url" 2>/dev/null || echo "ERR")
    fi
    case $response in
      403) printf "%-10s" "${GREEN}BLOCKED${NC}" ;;
      200) printf "%-10s" "${RED}PASSED${NC}" ;;
      500) printf "%-10s" "${YELLOW}ERROR${NC}" ;;
      *) printf "%-10s" "$response" ;;
    esac
    sleep 0.5
  done
  echo
done

echo
echo -e "${BLUE}=== SCANNER DETECTION TEST ===${NC}"
scanner_agents=("sqlmap/1.0" "nmap" "nikto/2.0" "w3af.org")
for agent in "${scanner_agents[@]}"; do
  printf "%-15s" "$agent"
  for ep_name in "${!test_endpoints[@]}"; do
    ep_url="${test_endpoints[$ep_name]}"
    if [[ $ep_url == https://* ]]; then
      response=$(timeout 10 curl -k -s -w "%{http_code}" -o /dev/null -A "$agent" "$ep_url" 2>/dev/null || echo "ERR")
    else
      response=$(timeout 10 curl -s -w "%{http_code}" -o /dev/null -A "$agent" "$ep_url" 2>/dev/null || echo "ERR")
    fi
    case $response in
      403) printf "%-10s" "${GREEN}BLOCKED${NC}" ;;
      200) printf "%-10s" "${RED}PASSED${NC}" ;;
      *) printf "%-10s" "$response" ;;
    esac
    sleep 0.5
  done
  echo
done

echo
echo -e "${BLUE}=== RATE LIMITING TEST ===${NC}"
echo "Testing rate limiting (10 req/s limit)..."
blocked_count=0
for i in {1..15}; do
  response=$(timeout 5 curl -k -s -w "%{http_code}" -o /dev/null "https://$LOCAL_IP/" 2>/dev/null || echo "ERR")
  if [ "$response" = "429" ] || [ "$response" = "503" ]; then
    ((blocked_count++))
  fi
done
echo "Rate limit responses: $blocked_count/15"
if [ $blocked_count -gt 0 ]; then
  echo -e "${GREEN}✓${NC} Rate limiting is working"
else
  echo -e "${YELLOW}⚠${NC} Rate limiting may not be active"
fi

echo
echo -e "${BLUE}=== LOG ANALYSIS ===${NC}"
log_files=( "/var/log/nginx/access.log" "/var/log/nginx/waf_blocked.log" "/var/log/modsecurity/audit.log" )
for log_file in "${log_files[@]}"; do
  if [ -f "$log_file" ]; then
    size=$(du -h "$log_file" 2>/dev/null | cut -f1)
    lines=$(wc -l < "$log_file" 2>/dev/null || echo "0")
    echo -e "${GREEN}✓${NC} $log_file: $size ($lines lines)"
  else
    echo -e "${RED}✗${NC} $log_file: Not found"
  fi
done

echo
echo -e "${PURPLE}=== SUMMARY ===${NC}"
if systemctl is-active --quiet nginx && [ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]; then
  echo -e "${GREEN}✓${NC} WAF Infrastructure: OPERATIONAL"
  echo -e "${GREEN}✓${NC} Triple Layer Protection: ACTIVE"
  echo " - Layer 1: NGINX Pattern Matching (Logging Only)"
  echo " - Layer 2: ModSecurity Deep Inspection"
  echo " - Layer 3: SafeLine WAF"
else
  echo -e "${RED}✗${NC} WAF Infrastructure: ISSUES DETECTED"
fi

echo
echo "Legend:"
echo -e " ${GREEN}BLOCKED${NC} = Attack stopped by WAF"
echo -e " ${RED}PASSED${NC} = Attack reached target"
echo -e " ${YELLOW}ERROR${NC} = Server error occurred"

echo
echo -e "${PURPLE}======================================================================"
echo " TESTING COMPLETED"
echo "======================================================================${NC}"
TEST_SCRIPT_EOF
  chmod +x /usr/local/bin/test-waf-complete.sh

  cat > /usr/local/bin/modsec-analyze.sh << 'MODSEC_ANALYZE_EOF'
#!/bin/bash
echo "=== ModSecurity Log Analysis ==="
if [ -f /var/log/modsecurity/audit.log ]; then
  echo "Recent ModSecurity blocks:"
  tail -50 /var/log/modsecurity/audit.log | grep -E "(id|msg)" | tail -10
  echo
  echo "Block summary by rule ID:"
  grep -o 'id "[0-9]*"' /var/log/modsecurity/audit.log | sort | uniq -c | sort -nr | head -10
else
  echo "ModSecurity audit log not found"
fi
if [ -f /var/log/nginx/waf_blocked.log ]; then
  echo
  echo "Recent NGINX WAF blocks:"
  tail -10 /var/log/nginx/waf_blocked.log
else
  echo "NGINX WAF block log not found"
fi
MODSEC_ANALYZE_EOF
  chmod +x /usr/local/bin/modsec-analyze.sh
  log_msg "Testing tools created successfully" "SUCCESS"
}

# Test the complete configuration
test_configuration() {
  log_msg "Testing complete WAF configuration..." "WAF"
  systemctl stop nginx >/dev/null 2>&1 || true
  sleep 3
  if nginx -t >/dev/null 2>&1; then
    log_msg "NGINX configuration syntax: VALID" "SUCCESS"
  else
    log_msg "NGINX configuration errors:" "ERROR"
    nginx -t
    return 1
  fi
  log_msg "Starting NGINX with ModSecurity..." "INFO"
  systemctl start nginx
  sleep 5
  if systemctl is-active --quiet nginx; then
    log_msg "NGINX service: RUNNING" "SUCCESS"
  else
    log_msg "NGINX failed to start:" "ERROR"
    systemctl status nginx --no-pager
    journalctl -u nginx --no-pager -n 20
    return 1
  fi
  log_msg "Checking WAF ports..." "INFO"
  expected_ports=(80 443 8080 8443 9443)
  active_ports=0
  for port in "${expected_ports[@]}"; do
    if ss -tuln | grep -q ":$port "; then
      log_msg "Port $port: ACTIVE" "SUCCESS"
      ((active_ports++))
    else
      log_msg "Port $port: NOT ACTIVE" "WARNING"
    fi
  done
  if [ $active_ports -eq 5 ]; then
    log_msg "All WAF ports active ($active_ports/5)" "SUCCESS"
  else
    log_msg "Missing ports ($active_ports/5)" "WARNING"
  fi
  log_msg "Testing ModSecurity integration..." "INFO"
  sleep 3
  main_response=$(timeout 15 curl -k -s -w "%{http_code}" -o /dev/null "https://$LOCAL_IP/health" 2>/dev/null || echo "ERR")
  if [ "$main_response" = "200" ]; then
    log_msg "Main endpoint: ACCESSIBLE" "SUCCESS"
  else
    log_msg "Main endpoint: $main_response" "WARNING"
  fi
  log_msg "Testing XSS protection..." "INFO"
  xss_response=$(timeout 15 curl -k -s -w "%{http_code}" -o /dev/null "https://$LOCAL_IP/?input=<script>alert(1)</script>" 2>/dev/null || echo "ERR")
  if [ "$xss_response" = "403" ]; then
    log_msg "XSS protection: WORKING" "SUCCESS"
  else
    log_msg "XSS test returned: $xss_response" "WARNING"
  fi
  log_msg "Testing SQL injection protection..." "INFO"
  sqli_response=$(timeout 15 curl -k -s -w "%{http_code}" -o /dev/null "https://$LOCAL_IP/?id=1' OR '1'='1'--" 2>/dev/null || echo "ERR")
  if [ "$sqli_response" = "403" ]; then
    log_msg "SQLi protection: WORKING" "SUCCESS"
  else
    log_msg "SQLi test returned: $sqli_response" "WARNING"
  fi
  log_msg "Configuration testing completed" "SUCCESS"
  return 0
}

# Show comprehensive summary
show_final_summary() {
  echo
  echo -e "${GREEN}======================================================================"
  echo " WAF TRIPLE LAYER - DEPLOYMENT COMPLETE"
  echo "======================================================================${NC}"
  echo
  echo -e "${PURPLE}🏗️ ARCHITECTURE:${NC}"
  echo " Client Request → NGINX (Layer 1: Logging) → ModSecurity (Layer 2) → SafeLine (Layer 3) → DVWA"
  echo
  echo -e "${BLUE}🛡️ PROTECTION LAYERS:${NC}"
  echo " Layer 1 (NGINX): Pattern matching (logging only), rate limiting, scanner detection"
  echo " Layer 2 (ModSecurity): Deep packet inspection, OWASP CRS, custom rules"
  echo " Layer 3 (SafeLine): ML-based WAF, final protection layer"
  echo
  echo -e "${GREEN}🌐 ENDPOINTS:${NC}"
  echo " 🛡️ Triple Protection: https://$LOCAL_IP (All 3 layers)"
  echo " 🔓 No Protection: http://$LOCAL_IP:8080 (Direct bypass)"
  echo " 🛡️ SafeLine Only: https://$LOCAL_IP:8443 (Layer 3 only)"
  echo " 🛡️ ModSecurity Only: https://$LOCAL_IP:9443 (Layer 2 only)"
  echo " 📊 Status Page: https://$LOCAL_IP/waf-status"
  echo
  echo -e "${YELLOW}🧪 TESTING COMMANDS:${NC}"
  echo " Complete Test Suite: test-waf-complete.sh"
  echo " Log Analysis: modsec-analyze.sh"
  echo " Manual XSS Test: curl -k 'https://$LOCAL_IP/?input=<script>alert(1)</script>'"
  echo " Manual SQLi Test: curl -k 'https://$LOCAL_IP/?id=1' OR '1'='1'--'"
  echo
  echo -e "${PURPLE}⚙️ SAFELINE CONFIGURATION REQUIRED:${NC}"
  echo " 1. Access SafeLine Admin: https://$SAFELINE_IP:9443"
  echo " 2. Add Backend Server: $DVWA_IP:80"
  echo " 3. Set Domain: dvwa.local"
  echo " 4. Add Allowed Source: $LOCAL_IP"
  echo " 5. Enable SQL injection and XSS protection with high sensitivity"
  echo
  echo -e "${BLUE}📋 LOG LOCATIONS:${NC}"
  echo " Access Logs: /var/log/nginx/access.log"
  echo " Blocked Requests: /var/log/nginx/waf_blocked.log"
  echo " ModSecurity Audit: /var/log/modsecurity/audit.log"
  echo " ModSecurity Debug: /var/log/modsecurity/debug.log"
  echo " NGINX Errors: /var/log/nginx/error.log"
  echo
  echo -e "${GREEN}✅ NEXT STEPS:${NC}"
  echo " 1. Configure SafeLine as described above"
  echo " 2. Run 'test-waf-complete.sh' to verify all layers"
  echo " 3. Monitor logs during testing"
  echo " 4. Adjust rules as needed for your environment"
  echo
  echo -e "${PURPLE}======================================================================"
  echo " WAF TRIPLE LAYER READY!"
  echo "======================================================================${NC}"
}

# Main execution function
main() {
  echo -e "${PURPLE}======================================================================"
  echo " WAF TRIPLE LAYER SETUP - NGINX/MODSECURITY/SAFELINE"
  echo "======================================================================${NC}"
  echo

  check_root
  log_msg "Step 1/13: Configuring open file limits..." "INFO"
  configure_limits
  log_msg "Step 2/13: Cleaning previous installations..." "INFO"
  cleanup_nginx
  log_msg "Step 3/13: Installing dependencies..." "INFO"
  install_dependencies
  log_msg "Step 4/13: Forcing NGINX 1.18.0 installation..." "INFO"
  install_compatible_nginx
  log_msg "Step 5/13: Fixing systemd service file..." "INFO"
  fix_systemd_service
  log_msg "Step 6/13: Checking compatibility..." "INFO"
  if ! check_compatibility; then
    log_msg "Step 7/13: Compiling ModSecurity module..." "INFO"
    compile_modsecurity_module
  else
    log_msg "Existing installation is compatible" "SUCCESS"
  fi
  log_msg "Step 8/13: Setting up ModSecurity..." "INFO"
  setup_modsecurity
  log_msg "Step 9/13: Generating SSL certificates..." "INFO"
  generate_ssl
  log_msg "Step 10/13: Creating mime.types file..." "INFO"
  create_mime_types
  log_msg "Step 11/13: Creating NGINX directories..." "INFO"
  create_nginx_dirs
  log_msg "Step 12/13: Creating WAF configuration..." "INFO"
  create_waf_config
  log_msg "Step 13/13: Creating testing tools..." "INFO"
  create_test_tools
  log_msg "Step 14/14: Testing configuration..." "INFO"
  if test_configuration; then
    log_msg "WAF Triple Layer setup completed successfully!" "SUCCESS"
  else
    log_msg "Setup completed with warnings - check the logs" "WARNING"
  fi
  show_final_summary
  echo -e "${YELLOW}🔍 FINAL VERIFICATION:${NC}"
  echo "Run the following command to test your setup:"
  echo " sudo test-waf-complete.sh"
  echo
}

# Command line options
case "${1:-}" in
  "--nginx-only") check_root; cleanup_nginx; install_dependencies; install_compatible_nginx; fix_systemd_service; exit $? ;;
  "--modsec-only") check_root; setup_modsecurity; exit $? ;;
  "--test-only") test_configuration; exit $? ;;
  "--compatibility-check") check_compatibility; exit $? ;;
  "--help")
    echo "WAF Triple Layer Setup Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo " --nginx-only Install compatible NGINX only"
    echo " --modsec-only Setup ModSecurity configuration only"
    echo " --test-only Test existing configuration"
    echo " --compatibility-check Check NGINX/ModSecurity compatibility"
    echo " --help Show this help"
    echo ""
    echo "Default: Complete WAF triple layer setup"
    exit 0
    ;;
esac

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
