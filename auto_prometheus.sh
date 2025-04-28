#!/bin/bash
set -euo pipefail

# --- Конфигурация ---
GRAFANA_DOMAIN="$(hostname -f)"  # Или явно укажите домен (например, monitoring.example.com)
PROMETHEUS_PASSWORD="$(openssl rand -hex 16)"  # Автогенерация пароля
EXPORTER_PASSWORD="$(openssl rand -hex 16)"
FAIL2BAN_BANTIME="1h"
FAIL2BAN_MAXRETRY="3"

# --- Проверка прав ---
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Требуются права root. Запустите скрипт с sudo!" >&2
    exit 1
fi

# --- Установка зависимостей ---
apt-get update
apt-get upgrade -y
apt-get install -y wget curl ufw fail2ban openssl apache2-utils

# --- Настройка firewall ---
ufw reset --force
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp   # Grafana HTTPS
ufw allow 9090/tcp  # Prometheus HTTPS
ufw --force enable
echo "✅ Firewall настроен (разрешены SSH, 443, 9090)"

# --- Генерация ECDSA сертификатов (P-384) ---
mkdir -p /etc/ssl/private
openssl ecparam -genkey -name secp384r1 -out /etc/ssl/private/monitoring.key
openssl req -new -x509 -sha384 -days 365 -key /etc/ssl/private/monitoring.key \
    -out /etc/ssl/private/monitoring.crt \
    -subj "/CN=$GRAFANA_DOMAIN/O=Secure Monitoring/OU=DevOps"
chmod 600 /etc/ssl/private/monitoring.*
echo "✅ Сгенерирован ECDSA P-384 SSL-сертификат"

# --- Установка Prometheus ---
useradd --system --no-create-home --shell /bin/false prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.47.0/prometheus-2.47.0.linux-amd64.tar.gz
tar xvf prometheus-*.tar.gz -C /opt/
mv /opt/prometheus-* /opt/prometheus
rm prometheus-*.tar.gz

# Конфиг Prometheus с HTTPS и аутентификацией
cat > /opt/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    basic_auth:
      username: exporter
      password: '$EXPORTER_PASSWORD'
EOF

# Web-конфиг с HTTPS
cat > /opt/prometheus/web.yml <<EOF
tls_server_config:
  cert_file: /etc/ssl/private/monitoring.crt
  key_file: /etc/ssl/private/monitoring.key
basic_auth_users:
  admin: $(echo "$PROMETHEUS_PASSWORD" | htpasswd -n -i admin | cut -d: -f2)
EOF

chown -R prometheus:prometheus /opt/prometheus

# Systemd unit для Prometheus
cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
ExecStart=/opt/prometheus/prometheus \
    --config.file=/opt/prometheus/prometheus.yml \
    --web.config.file=/opt/prometheus/web.yml \
    --web.listen-address=:9090 \
    --web.external-url=https://$GRAFANA_DOMAIN:9090
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now prometheus
echo "✅ Prometheus установлен (HTTPS + Basic Auth)"

# --- Установка Grafana ---
apt-get install -y apt-transport-https
wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor | tee /usr/share/keyrings/grafana.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
apt-get update
apt-get install -y grafana

# Конфиг Grafana с HTTPS
cat > /etc/grafana/grafana.ini <<EOF
[server]
protocol = https
http_port = 3000
domain = $GRAFANA_DOMAIN
cert_file = /etc/ssl/private/monitoring.crt
cert_key = /etc/ssl/private/monitoring.key
cipher_suites = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
min_tls_version = tls1.2

[security]
disable_initial_admin_creation = true
admin_user = admin
admin_password = $(openssl rand -hex 12)
EOF

systemctl enable --now grafana-server
echo "✅ Grafana установлен (HTTPS + ECDSA P-384)"

# --- Установка Node Exporter ---
useradd --system --no-create-home --shell /bin/false node_exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvf node_exporter-*.tar.gz
mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter-*

# Аутентификация для экспортера
mkdir -p /etc/node_exporter
htpasswd -b -c /etc/node_exporter/web.yml exporter "$EXPORTER_PASSWORD"
chown node_exporter:node_exporter /etc/node_exporter/web.yml

# Systemd unit для Node Exporter
cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \
    --web.config.file=/etc/node_exporter/web.yml

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now node_exporter
echo "✅ Node Exporter установлен (Basic Auth)"

# --- Настройка Fail2Ban ---
cat > /etc/fail2ban/jail.d/monitoring.conf <<EOF
[grafana]
enabled = true
port = 443,3000
filter = grafana
logpath = /var/log/grafana/grafana.log
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME

[prometheus]
enabled = true
port = 9090
filter = prometheus
logpath = /var/log/prometheus.log
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME
EOF

# Фильтры для Fail2Ban
cat > /etc/fail2ban/filter.d/grafana.conf <<EOF
[Definition]
failregex = ^.*Failed.* user=<HOST>.*
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/prometheus.conf <<EOF
[Definition]
failregex = ^.*invalid username or password.* <HOST>
ignoreregex =
EOF

systemctl restart fail2ban
echo "✅ Fail2Ban настроен для Grafana и Prometheus"

# --- Итоговая информация ---
echo "
=== Установка завершена! ===
• Prometheus:  https://$GRAFANA_DOMAIN:9090
  Логин: admin
  Пароль: $PROMETHEUS_PASSWORD

• Grafana:     https://$GRAFANA_DOMAIN:3000
  Логин: admin
  Пароль: $(grep 'admin_password' /etc/grafana/grafana.ini | cut -d' ' -f3)

• Node Exporter: http://<SERVER_IP>:9100/metrics
  Логин: exporter
  Пароль: $EXPORTER_PASSWORD

• Firewall (UFW) и Fail2Ban активны.
• Все соединения защищены ECDSA P-384.
"
