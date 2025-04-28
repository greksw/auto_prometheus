#!/bin/bash
set -euo pipefail

# --- Конфигурация ---
GRAFANA_DOMAIN="$(hostname -f)"  # Или явно укажите домен
PROMETHEUS_PASSWORD="$(openssl rand -hex 16)"
EXPORTER_PASSWORD="$(openssl rand -hex 16)"
FAIL2BAN_BANTIME="1h"
FAIL2BAN_MAXRETRY="3"

# --- Проверка прав ---
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Требуются права root. Запустите скрипт с sudo!" >&2
    exit 1
fi

# --- Логирование ---
LOG_FILE="/var/log/monitoring_setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "📅 Начало установки: $(date)"

# --- Установка зависимостей ---
echo "🔄 Установка необходимых пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq \
    wget curl ufw fail2ban openssl apache2-utils \
    python3 software-properties-common gnupg

# --- Настройка firewall ---
echo "🔥 Настройка firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp   # Grafana HTTPS
ufw allow 9090/tcp  # Prometheus HTTPS
echo "y" | ufw enable
ufw status verbose

# --- Генерация ECDSA сертификатов ---
echo "🔐 Генерация SSL сертификатов..."
mkdir -p /etc/ssl/private
if ! openssl ecparam -genkey -name secp384r1 -out /etc/ssl/private/monitoring.key; then
    echo "⚠️ Не удалось сгенерировать ECDSA ключ, используем RSA 2048 как запасной вариант"
    openssl genrsa -out /etc/ssl/private/monitoring.key 2048
fi
openssl req -new -x509 -sha384 -days 365 -key /etc/ssl/private/monitoring.key \
    -out /etc/ssl/private/monitoring.crt \
    -subj "/CN=$GRAFANA_DOMAIN/O=Secure Monitoring/OU=DevOps"
chmod 600 /etc/ssl/private/monitoring.*

# --- Установка Prometheus ---
echo "📊 Установка Prometheus..."
useradd --system --no-create-home --shell /bin/false prometheus || true
wget -q https://github.com/prometheus/prometheus/releases/download/v2.47.0/prometheus-2.47.0.linux-amd64.tar.gz
tar xf prometheus-*.tar.gz -C /opt/
mv /opt/prometheus-* /opt/prometheus
rm prometheus-*.tar.gz

# Конфигурация Prometheus
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

# Настройка аутентификации
htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD" || {
    apt-get install -yq apache2-utils
    htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD"
}

chown -R prometheus:prometheus /opt/prometheus

# Systemd service
cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
ExecStart=/opt/prometheus/prometheus \\
    --config.file=/opt/prometheus/prometheus.yml \\
    --web.config.file=/opt/prometheus/web.yml \\
    --web.listen-address=:9090 \\
    --web.external-url=https://$GRAFANA_DOMAIN:9090
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now prometheus
systemctl status prometheus --no-pager

# --- Установка Grafana ---
echo "📈 Установка Grafana..."
apt-get install -yq apt-transport-https
wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor > /usr/share/keyrings/grafana.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
apt-get update -q
apt-get install -yq grafana

# Конфигурация Grafana
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
systemctl status grafana-server --no-pager

# --- Установка Node Exporter ---
echo "🖥️ Установка Node Exporter..."
useradd --system --no-create-home --shell /bin/false node_exporter || true
wget -q https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xf node_exporter-*.tar.gz
mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter-*

# Настройка аутентификации
mkdir -p /etc/node_exporter
htpasswd -b -c /etc/node_exporter/web.yml exporter "$EXPORTER_PASSWORD"
chown node_exporter:node_exporter /etc/node_exporter/web.yml

# Systemd service
cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \\
    --web.config.file=/etc/node_exporter/web.yml

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now node_exporter
systemctl status node_exporter --no-pager

# --- Настройка Fail2Ban ---
echo "🛡️ Настройка Fail2Ban..."
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
logpath = /var/log/syslog
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME
EOF

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
systemctl status fail2ban --no-pager

# --- Фикс предупреждений Python ---
echo "🐍 Исправление предупреждений Python..."
find /usr/lib/python3/dist-packages/fail2ban -type f -name "*.py" -exec \
    sed -i 's/\\s/\\\\s/g; s/\\S/\\\\S/g; s/\\d/\\\\d/g; s/\\[/\\\\[/g' {} + 2>/dev/null || true

# --- Итоговая информация ---
echo "
🎉 Установка завершена!

🔗 Доступ к сервисам:
- Prometheus:  https://$GRAFANA_DOMAIN:9090
  Логин: admin
  Пароль: $PROMETHEUS_PASSWORD

- Grafana:     https://$GRAFANA_DOMAIN:3000
  Логин: admin
  Пароль: $(grep 'admin_password' /etc/grafana/grafana.ini | cut -d' ' -f3)

- Node Exporter: http://$(hostname -I | awk '{print $1}'):9100/metrics
  Логин: exporter
  Пароль: $EXPORTER_PASSWORD

📋 Лог установки сохранен в: $LOG_FILE
"
