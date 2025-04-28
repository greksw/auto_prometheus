#!/bin/bash
set -euo pipefail

# --- Конфигурация ---
GRAFANA_DOMAIN="$(hostname -f)"
PROMETHEUS_PASSWORD="$(openssl rand -hex 16)"
EXPORTER_PASSWORD="$(openssl rand -hex 16)"
FAIL2BAN_BANTIME="1h"
FAIL2BAN_MAXRETRY="3"
LOG_FILE="/var/log/monitoring_setup_$(date +%Y%m%d_%H%M%S).log"

# --- Функция проверки сервиса ---
check_service() {
    local service_name=$1
    echo -n "Проверка $service_name... "
    
    if systemctl is-active --quiet "$service_name"; then
        echo "OK"
    else
        echo "ОШИБКА"
        echo "Статус $service_name:"
        systemctl status "$service_name" --no-pager
        journalctl -u "$service_name" -n 20 --no-pager
        exit 1
    fi
}

# --- Инициализация ---
exec > >(tee -a "$LOG_FILE") 2>&1
echo "📅 Начало установки: $(date)"

# --- Установка зависимостей ---
echo "🔄 Установка базовых пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -yq \
    wget curl ufw fail2ban openssl \
    apache2-utils python3 software-properties-common \
    gnupg2 apt-transport-https

# --- Настройка firewall ---
echo "🔥 Настройка firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp
ufw allow 9090/tcp
ufw allow 9100/tcp
echo "y" | ufw enable
ufw status verbose

# --- Генерация SSL сертификатов ---
echo "🔐 Генерация SSL сертификатов..."
mkdir -p /etc/ssl/private
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/monitoring.key \
    -out /etc/ssl/private/monitoring.crt \
    -subj "/CN=$GRAFANA_DOMAIN/O=Secure Monitoring/OU=DevOps"
chmod 644 /etc/ssl/private/monitoring.crt
chmod 640 /etc/ssl/private/monitoring.key
chown root:grafana /etc/ssl/private/monitoring.key

# --- Установка Prometheus ---
echo "📊 Установка Prometheus..."
useradd --system --no-create-home --shell /bin/false prometheus || true

PROM_VERSION="2.47.0"
wget -q "https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz"
tar xf prometheus-*.tar.gz -C /opt/
mv /opt/prometheus-* /opt/prometheus
rm prometheus-*.tar.gz

# Создаем необходимые директории
mkdir -p /opt/prometheus/data
chown -R prometheus:prometheus /opt/prometheus

# Конфигурация
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

# Аутентификация
htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD" || {
    apt-get install -yq apache2-utils
    htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD"
}

chown prometheus:prometheus /opt/prometheus/web.yml

# Systemd сервис
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
    --storage.tsdb.path=/opt/prometheus/data \\
    --web.external-url=https://$GRAFANA_DOMAIN:9090 \\
    --query.log-file=""
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now prometheus
check_service prometheus

# --- Установка Node Exporter ---
echo "🖥️ Установка Node Exporter..."
useradd --system --no-create-home --shell /bin/false node_exporter || true

NODE_VERSION="1.6.1"
wget -q "https://github.com/prometheus/node_exporter/releases/download/v${NODE_VERSION}/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz"
tar xf node_exporter-*.tar.gz
mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter-*

# Аутентификация
mkdir -p /etc/node_exporter
echo "exporter:$(openssl passwd -apr1 $EXPORTER_PASSWORD)" > /etc/node_exporter/web.yml
chown node_exporter:node_exporter /etc/node_exporter/web.yml

# Systemd сервис
cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \\
    --web.config.file=/etc/node_exporter/web.yml \\
    --web.listen-address=:9100
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now node_exporter
check_service node_exporter

# --- Установка Grafana ---
echo "📈 Установка Grafana..."
# Установка из официального репозитория
apt-get install -yq gnupg2
curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor > /usr/share/keyrings/grafana-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana-archive-keyring.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
apt-get update -q && apt-get install -yq grafana

# Альтернативный метод если репозиторий недоступен
if ! apt-get install -yq grafana; then
    echo "⚠️ Используем альтернативный метод установки Grafana"
    GRAFANA_VERSION="10.4.3"
    wget -q "https://dl.grafana.com/oss/release/grafana_${GRAFANA_VERSION}_amd64.deb"
    dpkg -i grafana_*.deb || apt-get install -yf
    rm grafana_*.deb
fi

# Конфигурация Grafana
cat > /etc/grafana/grafana.ini <<EOF
[server]
protocol = http
http_port = 3000
domain = $GRAFANA_DOMAIN

[security]
disable_initial_admin_creation = false
admin_user = admin
admin_password = $(openssl rand -hex 12)
EOF

# Права на сертификаты
chown -R grafana:grafana /etc/ssl/private
systemctl enable --now grafana-server
check_service grafana-server

# --- Настройка Fail2Ban ---
echo "🛡️ Настройка Fail2Ban..."
cat > /etc/fail2ban/jail.d/monitoring.conf <<EOF
[grafana]
enabled = true
port = http,https,3000
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
check_service fail2ban

# --- Проверка портов ---
echo "🔍 Проверка открытых портов..."
ss -tulnp | grep -E '9090|3000|9100' || {
    echo "⚠️ Не все порты открыты!"
    exit 1
}

# --- Итоговая информация ---
GRAFANA_PASSWORD=$(grep 'admin_password' /etc/grafana/grafana.ini | cut -d' ' -f3)
echo "
🎉 Установка завершена и проверена!

🔗 Доступ к сервисам:
- Prometheus:  http://$(hostname -I | awk '{print $1}'):9090
  Логин: admin
  Пароль: $PROMETHEUS_PASSWORD

- Grafana:     http://$(hostname -I | awk '{print $1}'):3000
  Логин: admin
  Пароль: $GRAFANA_PASSWORD

- Node Exporter: http://$(hostname -I | awk '{print $1}'):9100/metrics
  Логин: exporter
  Пароль: $EXPORTER_PASSWORD

📋 Лог установки: $LOG_FILE
"
